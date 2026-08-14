"""Archery provider adapter for the shared, reconnectable MCP harness."""

from __future__ import annotations

import inspect
import json
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4, uuid5

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client

from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPConfigurationError,
    ArcheryMCPError,
    ArcheryMCPModelError,
    ArcheryMCPProtocolError,
    ArcheryMCPToolError,
    ArcherySlowLogQueryResult,
    first_exception_leaf,
    nested_archery_error,
    safe_error_detail,
)
from app.agent_runtime import (
    ArtifactRef,
    BudgetLedger,
    BudgetLimits,
    InMemoryEventSink,
    InvocationError,
    RepositoryEventSink,
    RepositoryInvocationStore,
    RuntimeStopReason,
    ToolInvocationStatus,
    ToolSpec,
)
from app.application.sanitization import sanitize, sanitize_text
from app.domain.ports import AlertRepository
from app.domain.tool_calling import (
    MCPModelToolCall,
    ReasoningDeltaCallback,
    mcp_tool_result_messages,
)
from app.mcp_runtime import (
    DiscoveredMCPTool,
    Finish,
    HarnessObservation,
    MCPAgentHarnessRuntime,
    MCPConnector,
    MCPHarnessResult,
    MCPToolSession,
    PreparedCall,
    RepositoryMCPCheckpointStore,
    RetryDirective,
    ScenarioTransition,
)

if TYPE_CHECKING:
    from app.adapters.archery_mcp import ArcheryMCPClient


ARCHERY_HARNESS_PROVIDER = "archery_mcp"
ARCHERY_HARNESS_POLICY_VERSION = "archery-discovered-tools-v1"
ARCHERY_HARNESS_SCHEMA_VERSION = "mcp-discovery-v1"
_FINISH_TOOL_NAME = "finish_archery_investigation"
_FINISH_TOOL = {
    "type": "function",
    "function": {
        "name": _FINISH_TOOL_NAME,
        "description": (
            "Finish this Archery evidence collection after reviewing the returned data. "
            "This is a local Agent action and does not call the MCP server."
        ),
        "parameters": {
            "type": "object",
            "properties": {"reason": {"type": "string", "minLength": 1}},
            "required": ["reason"],
            "additionalProperties": False,
        },
    },
}


def _accepts_keyword_argument(callable_obj: Any, argument: str) -> bool:
    try:
        parameters = inspect.signature(callable_obj).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == argument
        or parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


@dataclass(slots=True)
class ArcheryHarnessState:
    window_start: datetime
    window_end: datetime
    occurred_at: datetime
    alert_context: dict[str, Any]
    alert_endpoint: str | None
    session_id: str | None = None
    session_attempts: int = 0
    mcp_roundtrip_count: int = 0
    attempted_model_calls: list[str] = field(default_factory=list)
    executed_model_calls: list[str] = field(default_factory=list)
    model_request_ids: list[str] = field(default_factory=list)
    model_decision_count: int = 0
    recorded_call_ids: set[str] = field(default_factory=set)
    slow_log_tables: dict[tuple[int, str], set[str]] = field(default_factory=dict)
    metadata_resolution_steps: dict[tuple[int, str], list[str]] = field(default_factory=dict)
    member_instance_ids: dict[tuple[int, str], set[int]] = field(default_factory=dict)
    resolved_endpoints: dict[tuple[int, str], set[str]] = field(default_factory=dict)
    table_columns: dict[tuple[int, str], dict[str, set[str]]] = field(default_factory=dict)
    query_trace: list[dict[str, Any]] = field(default_factory=list)
    last_query_target: tuple[int, str] | None = None
    last_query_error: str | None = None
    last_slow_log_probe_issue: str | None = None
    final_result: ArcherySlowLogQueryResult | None = None
    consecutive_model_errors: list[dict[str, str]] = field(default_factory=list)
    fatal_error_kind: str | None = None
    fatal_error_message: str | None = None
    fatal_error_diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _PlannerCallRegistry:
    pending: list[MCPModelToolCall] = field(default_factory=list)

    def take(self, *, tool_name: str, arguments: Mapping[str, Any]) -> MCPModelToolCall | None:
        if not self.pending:
            return None
        call = self.pending.pop(0)
        if call.name != tool_name or call.arguments != dict(arguments):
            return None
        return call


@dataclass(frozen=True, slots=True)
class ArcheryHarnessRuntimeDependencies:
    repository: AlertRepository


_ARCHERY_REMOTE_RESPONSE_ARTIFACT_CONTRACT = "archery-mcp-remote-response/v2"


class RepositoryArcheryRemoteResponseStore:
    """Persist complete MCP responses after the Archery investigation ends."""

    def __init__(
        self,
        repository: AlertRepository,
        *,
        outer_dispatch_id: UUID | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> None:
        if (lease_owner is None) != (fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        self.repository = repository
        self.outer_dispatch_id = outer_dispatch_id
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token

    @staticmethod
    def artifact_id(
        invocation_id: UUID,
        contract: str = _ARCHERY_REMOTE_RESPONSE_ARTIFACT_CONTRACT,
    ) -> UUID:
        return uuid5(invocation_id, contract)

    async def save(
        self,
        *,
        run_id: UUID,
        invocation_id: UUID,
        tool_name: str,
        arguments: dict[str, Any],
        response: Any,
    ) -> None:
        raw = (
            response.model_dump(mode="json", by_alias=True, exclude_none=False)
            if hasattr(response, "model_dump")
            else response
        )
        content = {
            "contract": _ARCHERY_REMOTE_RESPONSE_ARTIFACT_CONTRACT,
            "provider": ARCHERY_HARNESS_PROVIDER,
            "run_id": str(run_id),
            "invocation_id": str(invocation_id),
            "outer_dispatch_id": (
                str(self.outer_dispatch_id) if self.outer_dispatch_id is not None else None
            ),
            "tool_name": tool_name,
            "arguments": sanitize(arguments),
            "response": raw,
        }
        content_bytes = json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        artifact_id = self.artifact_id(invocation_id)
        artifact = ArtifactRef(
            artifact_id=artifact_id,
            kind="archery_mcp_remote_response",
            media_type="application/json",
            uri=f"agent-artifact://{artifact_id}",
            metadata={
                "contract": _ARCHERY_REMOTE_RESPONSE_ARTIFACT_CONTRACT,
                "provider": ARCHERY_HARNESS_PROVIDER,
                "run_id": str(run_id),
                "tool_name": tool_name,
                "invocation_id": str(invocation_id),
                "outer_dispatch_id": (
                    str(self.outer_dispatch_id)
                    if self.outer_dispatch_id is not None
                    else None
                ),
                "sanitized": False,
                "raw_response_unmodified": True,
                "internal_only": True,
            },
        )
        await self.repository.save_agent_artifact(
            str(run_id),
            artifact,
            content_bytes,
            invocation_id=str(invocation_id),
            lease_owner=self.lease_owner,
            fencing_token=self.fencing_token,
        )

    async def load(
        self,
        *,
        run_id: UUID,
        invocation_id: UUID,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any | None:
        artifact_id = self.artifact_id(invocation_id)
        stored = await self.repository.get_agent_artifact(str(artifact_id))
        if stored is None:
            return None
        artifact, stored_content = stored
        content = self._decode_artifact_content(stored_content, artifact_id)
        expected_outer_dispatch_id = (
            str(self.outer_dispatch_id) if self.outer_dispatch_id is not None else None
        )
        metadata = artifact.metadata
        if (
            artifact.artifact_id != artifact_id
            or artifact.kind != "archery_mcp_remote_response"
            or artifact.media_type != "application/json"
            or artifact.uri != f"agent-artifact://{artifact_id}"
            or metadata.get("contract") != _ARCHERY_REMOTE_RESPONSE_ARTIFACT_CONTRACT
            or metadata.get("provider") != ARCHERY_HARNESS_PROVIDER
            or metadata.get("run_id") != str(run_id)
            or metadata.get("tool_name") != tool_name
            or metadata.get("invocation_id") != str(invocation_id)
            or metadata.get("outer_dispatch_id") != expected_outer_dispatch_id
            or metadata.get("sanitized") is not False
            or metadata.get("raw_response_unmodified") is not True
            or metadata.get("internal_only") is not True
        ):
            raise RuntimeError(
                f"Archery remote-response artifact metadata is invalid: {artifact_id}"
            )
        if (
            content.get("contract") != _ARCHERY_REMOTE_RESPONSE_ARTIFACT_CONTRACT
            or content.get("provider") != ARCHERY_HARNESS_PROVIDER
            or content.get("run_id") != str(run_id)
            or content.get("invocation_id") != str(invocation_id)
            or content.get("outer_dispatch_id") != expected_outer_dispatch_id
            or content.get("tool_name") != tool_name
            or content.get("arguments") != sanitize(arguments)
            or "response" not in content
        ):
            raise RuntimeError(
                f"Archery remote-response artifact content is invalid: {artifact_id}"
            )
        return deepcopy(content["response"])

    @staticmethod
    def _decode_artifact_content(
        content: bytes | str | dict[str, Any],
        artifact_id: UUID,
    ) -> dict[str, Any]:
        if isinstance(content, bytes):
            try:
                content = json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"Archery remote-response artifact content is invalid: {artifact_id}"
                ) from exc
        elif isinstance(content, str):
            try:
                content = json.loads(content)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Archery remote-response artifact content is invalid: {artifact_id}"
                ) from exc
        if not isinstance(content, dict):
            raise RuntimeError(
                f"Archery remote-response artifact content is invalid: {artifact_id}"
            )
        return content


class ArcheryHarnessPlanner:
    """Translate the existing tool-calling model into shared harness actions."""

    def __init__(
        self,
        client: ArcheryMCPClient,
        scenario: ArcheryHarnessScenario,
        registry: _PlannerCallRegistry,
    ) -> None:
        self.client = client
        self.scenario = scenario
        self.registry = registry
        self.last_reasoning_content: str | None = None

    @property
    def state(self) -> ArcheryHarnessState:
        return self.scenario.current_state

    async def plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        reasoning_callback: ReasoningDeltaCallback | None = None,
    ) -> dict[str, Any]:
        model_messages = deepcopy(messages)
        model_tools = [
            {
                "type": "function",
                "function": {
                    "name": item.name,
                    "description": item.capability,
                    "parameters": item.input_schema,
                },
            }
            for item in tools
        ]
        model_tools.append(deepcopy(_FINISH_TOOL))
        self.last_reasoning_content = None
        try:
            model_kwargs = {"messages": model_messages, "tools": model_tools}
            if reasoning_callback is not None and _accepts_keyword_argument(
                self.client.model.request_mcp_tool_call,
                "reasoning_callback",
            ):
                call = await self.client.model.request_mcp_tool_call(
                    **model_kwargs,
                    reasoning_callback=reasoning_callback,
                )
            else:
                call = await self.client.model.request_mcp_tool_call(**model_kwargs)
            if not isinstance(call, MCPModelToolCall):
                raise TypeError("MCP model did not return MCPModelToolCall")
        except Exception as exc:
            self.state.consecutive_model_errors.append(
                {
                    "error_type": type(exc).__name__,
                    "error": sanitize_text(str(exc))[:500],
                }
            )
            raise self._selection_error(model_tools) from exc
        reasoning_content = getattr(call, "reasoning_content", None)
        self.last_reasoning_content = (
            reasoning_content
            if isinstance(reasoning_content, str) and reasoning_content.strip()
            else None
        )
        self.state.consecutive_model_errors.clear()
        self.state.attempted_model_calls.append(call.name)
        self.state.model_decision_count += 1
        if call.name == _FINISH_TOOL_NAME:
            reason = call.arguments.get("reason")
            return {
                "action": "finish",
                "reason": RuntimeStopReason.COMPLETED.value,
                "summary": (
                    sanitize_text(reason)
                    if isinstance(reason, str) and reason.strip()
                    else "Archery evidence collection is complete."
                ),
            }
        self.registry.pending.append(call)
        return {
            "action": "call_tool",
            "tool_name": call.name,
            "objective": "Collect Archery evidence for the alert window",
            "hypothesis_ids": [],
            "arguments": call.arguments,
        }

    def _selection_error(
        self,
        model_tools: list[dict[str, Any]],
    ) -> ArcheryMCPModelError:
        first = self.state.consecutive_model_errors[0]
        latest = self.state.consecutive_model_errors[-1]
        return ArcheryMCPModelError(
            "Model failed to select a discovered Archery MCP tool or finish action: "
            f"first={first['error']}; latest={latest['error']}",
            diagnostic_data={
                "errors": deepcopy(self.state.consecutive_model_errors),
                "available_tools": [item["function"]["name"] for item in model_tools],
            },
        )


class _ArcheryTransportError(ArcheryMCPProtocolError):
    def __init__(
        self,
        message: str,
        *,
        code: str,
        unknown_outcome: bool,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = True
        self.unknown_outcome = unknown_outcome


class _ArcherySDKSession:
    def __init__(
        self,
        *,
        owner: ArcheryMCPClient,
        stack: AsyncExitStack,
        session: ClientSession,
        session_id: str,
    ) -> None:
        self.owner = owner
        self.stack = stack
        self.session = session
        self._session_id = session_id
        self._closed = False

    @property
    def session_id(self) -> str:
        return self._session_id

    async def list_tools(self) -> list[DiscoveredMCPTool]:
        try:
            tools: dict[str, dict[str, Any]] = {}
            cursor: str | None = None
            seen_cursors: set[str] = set()
            while True:
                result = await self.session.list_tools(
                    params=(
                        mcp_types.PaginatedRequestParams(cursor=cursor)
                        if cursor
                        else None
                    )
                )
                for item in result.tools:
                    tools[item.name] = item.model_dump(
                        by_alias=True,
                        mode="json",
                        exclude_none=True,
                    )
                if not result.nextCursor:
                    break
                next_cursor = result.nextCursor
                if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                    raise ArcheryMCPProtocolError(
                        "Archery MCP returned an invalid or repeated tools/list cursor"
                    )
                seen_cursors.add(next_cursor)
                cursor = next_cursor
        except Exception as exc:
            raise _transport_error(exc, unknown_outcome=False) from exc
        return [
            DiscoveredMCPTool(
                name=name,
                description=(
                    str(payload.get("description") or "")[:20_000]
                    if isinstance(payload, Mapping)
                    else ""
                ),
                input_schema=(
                    dict(payload.get("inputSchema") or {})
                    if isinstance(payload, Mapping)
                    else {}
                ),
                annotations=(
                    dict(payload.get("annotations") or {})
                    if isinstance(payload, Mapping)
                    else {}
                ),
            )
            for name, payload in tools.items()
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await self.session.call_tool(
                name,
                arguments,
                read_timeout_seconds=timedelta(seconds=self.owner.timeout_seconds),
            )
            return result.model_dump(
                by_alias=True,
                mode="json",
                exclude_none=False,
            )
        except Exception as exc:
            raise _transport_error(exc, unknown_outcome=True) from exc

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.stack.aclose()


class ArcheryMCPConnector:
    """Open one SDK session per harness connection attempt."""

    provider = ARCHERY_HARNESS_PROVIDER

    def __init__(self, client: ArcheryMCPClient) -> None:
        self.client = client

    async def open_session(self) -> MCPToolSession:
        stack = AsyncExitStack()
        try:
            http_client = await stack.enter_async_context(
                httpx.AsyncClient(
                    timeout=httpx.Timeout(self.client.timeout_seconds),
                    transport=self.client.transport,
                    follow_redirects=False,
                    headers=self.client.headers,
                )
            )
            read_stream, write_stream, get_session_id = await stack.enter_async_context(
                streamable_http_client(
                    self.client.mcp_url,
                    http_client=http_client,
                )
            )
            session = await stack.enter_async_context(
                ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=self.client.timeout_seconds),
                    client_info=mcp_types.Implementation(
                        name="database-alert-agent",
                        version="0.1.0",
                    ),
                )
            )
            await session.initialize()
            session_id = str(get_session_id() or f"archery-session-{uuid4()}")
            return _ArcherySDKSession(
                owner=self.client,
                stack=stack,
                session=session,
                session_id=session_id,
            )
        except BaseException as exc:
            try:
                await stack.aclose()
            except BaseException:
                pass
            if not isinstance(exc, Exception):
                raise
            raise _transport_error(exc, unknown_outcome=False) from exc


def _transport_error(error: BaseException, *, unknown_outcome: bool) -> ArcheryMCPError:
    nested = nested_archery_error(error)
    if nested is not None:
        return nested
    leaf = first_exception_leaf(error)
    detail = safe_error_detail(leaf)
    suffix = f": {detail}" if detail else ""
    return _ArcheryTransportError(
        f"Archery MCP SDK client failed ({type(leaf).__name__}){suffix}",
        code=type(leaf).__name__,
        unknown_outcome=unknown_outcome,
    )


class ArcheryHarnessScenario:
    provider = ARCHERY_HARNESS_PROVIDER

    def __init__(
        self,
        client: ArcheryMCPClient,
        state: ArcheryHarnessState,
        registry: _PlannerCallRegistry,
    ) -> None:
        self.client = client
        self.state = state
        self.registry = registry
        self._last_failure: BaseException | None = None

    @property
    def current_state(self) -> ArcheryHarnessState:
        return self.state

    def restore_state(self, state: ArcheryHarnessState) -> None:
        self.state = state

    def initial_state(self) -> ArcheryHarnessState:
        return self.state

    def initial_messages(self, state: ArcheryHarnessState) -> list[dict[str, Any]]:
        return self.client.agent_messages(
            occurred_at=state.occurred_at,
            window_start=state.window_start,
            window_end=state.window_end,
            alert_context=state.alert_context,
        )

    async def bootstrap(
        self,
        session: MCPToolSession,
        state: ArcheryHarnessState,
    ) -> ArcheryHarnessState:
        self.state = state
        state.session_attempts += 1
        state.session_id = session.session_id
        return state

    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]:
        specs: list[ToolSpec] = []
        for item in tools:
            specs.append(
                ToolSpec(
                    name=item.name,
                    provider=self.provider,
                    capability=(item.description or f"Archery MCP tool {item.name}")[:256],
                    input_schema=deepcopy(item.input_schema),
                    policy_version=ARCHERY_HARNESS_POLICY_VERSION,
                    schema_version=ARCHERY_HARNESS_SCHEMA_VERSION,
                    timeout=self.client.timeout_seconds,
                )
            )
        return specs

    def prepare_call(
        self,
        action: Any,
        *,
        state: ArcheryHarnessState,
    ) -> PreparedCall:
        self.state = state
        model_call = self.registry.take(
            tool_name=action.tool_name,
            arguments=action.arguments,
        )
        metadata: dict[str, Any] = {}
        if model_call is not None:
            metadata = {
                "call_id": model_call.call_id,
                "request_id": model_call.request_id,
                "provider_output_items": [
                    deepcopy(item) for item in model_call.provider_output_items
                ],
            }

        if isinstance(action.arguments.get("sql_content"), str):
            trace = self.client.query_trace_entry(
                model_call
                or MCPModelToolCall(
                    call_id="harness-call",
                    name=action.tool_name,
                    arguments=action.arguments,
                )
            )
            state.query_trace.append(trace)
            metadata["trace_index"] = len(state.query_trace) - 1
            state.last_query_target = self.client.target_key(action.arguments)

        return PreparedCall(
            tool_name=action.tool_name,
            objective=action.objective,
            hypothesis_ids=action.hypothesis_ids,
            model_arguments=dict(action.arguments),
            effective_arguments=deepcopy(action.arguments),
            timeout_seconds=self.client.timeout_seconds,
            metadata=metadata,
        )

    def on_result(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[ArcheryHarnessState, dict[str, Any]]:
        self.state = state
        if not isinstance(result, dict):
            raise ArcheryMCPProtocolError("Archery MCP tool result was not an object")
        self._record_remote_call(state, call)
        payload = self.client.extract_tool_payload(result)
        self.client.validate_business_success(
            payload,
            tool_name=call.tool_name,
            supplemental_text=self.client.tool_text_blocks(result),
        )
        trace = self._trace(state, call)
        if trace is not None:
            trace["outcome"] = "ok"

        if call.tool_name == ARCHERY_MCP_TABLES_TOOL_NAME:
            target = self.client.target_key(call.effective_arguments)
            if target is not None:
                discovered = self.client.slow_log_tables_from_discovery(payload)
                if discovered:
                    state.slow_log_tables.setdefault(target, set()).update(discovered)

        if call.tool_name == ARCHERY_MCP_COLUMNS_TOOL_NAME:
            target = self.client.target_key(call.effective_arguments)
            table_name = call.effective_arguments.get("tb_name")
            if target is not None and isinstance(table_name, str):
                columns = self.client.table_columns_from_payload(payload)
                if columns:
                    state.table_columns.setdefault(target, {})[
                        self.client.clean_table_name(table_name).casefold()
                    ] = columns

        requested_sql = call.effective_arguments.get("sql_content")
        requested_sql = requested_sql if isinstance(requested_sql, str) else ""
        normalized_payload, executed_sql, actual_sql_verified = (
            self.client.normalize_query_payload(payload, requested_sql=requested_sql)
        )
        result_sql = executed_sql or requested_sql
        if not result_sql:
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )
        if self._trace(state, call) is None:
            state.query_trace.append(
                {
                    **self.client.query_trace_entry(
                        MCPModelToolCall(
                            call_id=str(call.metadata.get("call_id") or "harness-result"),
                            name=call.tool_name,
                            arguments={**call.effective_arguments, "sql_content": result_sql},
                        )
                    ),
                    "sent_to_mcp": True,
                    "outcome": "ok",
                }
            )
        is_final_history_result = self.client.is_history_result_query(result_sql)
        if not is_final_history_result:
            target = self.client.target_key(call.effective_arguments)
            if target is not None:
                self.client.record_metadata_resolution_evidence(
                    resolution_steps=state.metadata_resolution_steps,
                    member_instance_ids=state.member_instance_ids,
                    resolved_endpoints=state.resolved_endpoints,
                    target=target,
                    sql=result_sql,
                    payload=normalized_payload,
                    alert_endpoint=state.alert_endpoint,
                    table_columns=state.table_columns,
                )
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )

        target = self.client.target_key(call.effective_arguments)
        state.final_result = ArcherySlowLogQueryResult(
            payload=normalized_payload,
            requested_sql=requested_sql or result_sql,
            window_start=state.window_start,
            window_end=state.window_end,
            model_tool_calls=tuple(state.executed_model_calls),
            model_request_ids=tuple(state.model_request_ids),
            executed_sql=executed_sql,
            actual_sql_verified=actual_sql_verified,
            instance_id=target[0] if target is not None else None,
            db_name=(
                str(call.effective_arguments["db_name"]).strip()
                if isinstance(call.effective_arguments.get("db_name"), str)
                else None
            ),
            table_name=ARCHERY_SLOW_QUERY_REVIEW_TABLE,
            query_time_column=self.client.query_time_column(result_sql),
            metadata_resolution_tables=tuple(
                state.metadata_resolution_steps.get(target, []) if target is not None else []
            ),
            diagnostics=self._diagnostics(state, target=target, completed=True),
        )
        return ScenarioTransition(
            state=state,
            observation=self.client.trace_projection(
                call.tool_name,
                normalized_payload,
            ),
            message=self._tool_result_messages(
                call,
                self._raw_model_tool_result(result),
            ),
            status=(
                ToolInvocationStatus.NO_DATA
                if self.client.payload_row_count(normalized_payload) == 0
                else ToolInvocationStatus.SUCCEEDED
            ),
        )

    def result_error_directive(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        error: Exception,
    ) -> RetryDirective | None:
        if not isinstance(error, ArcheryMCPToolError):
            return None
        return self.retry_directive(state, call, error)

    def on_failure(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        error: InvocationError,
        status: ToolInvocationStatus,
    ) -> ScenarioTransition[ArcheryHarnessState, dict[str, Any]]:
        self.state = state
        self._record_remote_call(state, call)
        trace = self._trace(state, call)
        if trace is not None:
            trace["outcome"] = "tool_error"
            trace["error_type"] = error.code
            trace["error_detail"] = safe_error_detail(error.message)
        requested_sql = call.effective_arguments.get("sql_content")
        if isinstance(requested_sql, str):
            state.last_query_error = error.message

        original = self._last_failure
        raw_result = call.metadata.get("mcp_raw_response")
        if raw_result is not None:
            canonical = self._raw_model_tool_result(raw_result)
        elif isinstance(original, ArcheryMCPToolError):
            canonical = self.client.model_tool_error_result(original)
        else:
            canonical = (
                "The previous MCP call did not produce available evidence "
                "(evidence_disposition=MISSING, is_contradiction=false). "
                f"Transport status={status.value}, error={safe_error_detail(error.message)}. "
                "Preserve prior successful observations and choose the next safe probe."
            )
        return ScenarioTransition(
            state=state,
            message=self._tool_result_messages(call, canonical),
        )

    def retry_directive(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall | None,
        error: Exception,
    ) -> RetryDirective:
        self._last_failure = error
        nested = nested_archery_error(error)
        effective: BaseException = nested or error
        if isinstance(effective, ArcheryMCPToolError):
            return RetryDirective(
                reason=str(effective),
                continue_run=True,
            )
        if isinstance(
            effective,
            ArcheryMCPConfigurationError,
        ):
            self._record_fatal(state, effective)
            return RetryDirective(reason=str(effective), continue_run=False)

        retryable = bool(getattr(effective, "retryable", True))
        unknown_outcome = bool(
            call is not None and getattr(effective, "unknown_outcome", False)
        )
        if not retryable:
            self._record_fatal(state, effective)
        return RetryDirective(
            reason=str(effective) or type(effective).__name__,
            reconnect=retryable,
            continue_run=retryable,
            unknown_outcome=unknown_outcome,
        )

    def completion(
        self,
        state: ArcheryHarnessState,
        observations: Sequence[HarnessObservation[dict[str, Any]]],
    ) -> Finish | None:
        del observations
        if state.fatal_error_kind is not None:
            return Finish(
                reason=RuntimeStopReason.FAILED,
                summary=state.fatal_error_message or "Archery MCP investigation failed.",
                requires_human=True,
            )
        return None

    def _internal_only_transition(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        *,
        raw_result: Any,
    ) -> ScenarioTransition[ArcheryHarnessState, dict[str, Any]]:
        """Return raw feedback to the internal model without creating a UI observation."""

        return ScenarioTransition(
            state=state,
            message=self._tool_result_messages(
                call,
                self._raw_model_tool_result(raw_result),
            ),
        )

    @staticmethod
    def _raw_model_tool_result(result: Any) -> str:
        """Serialize the complete remote envelope for the provider-internal model."""

        raw = (
            result.model_dump(mode="json", by_alias=True, exclude_none=False)
            if hasattr(result, "model_dump")
            else result
        )
        return json.dumps(
            raw,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

    @staticmethod
    def _tool_result_messages(
        call: PreparedCall,
        content: str,
    ) -> list[dict[str, Any]]:
        provider_output_items = call.metadata.get("provider_output_items")
        call_id = str(call.metadata.get("call_id") or "harness-call")
        model_call = MCPModelToolCall(
            call_id=call_id,
            name=call.tool_name,
            arguments=deepcopy(call.effective_arguments),
            provider_output_items=tuple(
                deepcopy(item)
                for item in provider_output_items
                if isinstance(item, dict)
            )
            if isinstance(provider_output_items, list)
            else (),
        )
        return mcp_tool_result_messages(
            model_call,
            output=content,
            fallback_messages=[
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": call.tool_name,
                                "arguments": json.dumps(
                                    call.effective_arguments,
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                    default=str,
                                ),
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": call_id, "content": content},
            ],
        )

    def _record_remote_call(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
    ) -> None:
        call_id = str(call.metadata.get("call_id") or "")
        marker = call_id or json.dumps(
            {
                "arguments": call.effective_arguments,
                "tool_name": call.tool_name,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        if marker in state.recorded_call_ids:
            return
        state.recorded_call_ids.add(marker)
        state.executed_model_calls.append(call.tool_name)
        request_id = call.metadata.get("request_id")
        if isinstance(request_id, str) and request_id:
            state.model_request_ids.append(request_id)
        state.mcp_roundtrip_count += 1
        trace = self._trace(state, call)
        if trace is not None:
            trace["sent_to_mcp"] = True

    @staticmethod
    def _trace(
        state: ArcheryHarnessState,
        call: PreparedCall,
    ) -> dict[str, Any] | None:
        index = call.metadata.get("trace_index")
        if type(index) is not int or not 0 <= index < len(state.query_trace):
            return None
        return state.query_trace[index]

    def _diagnostics(
        self,
        state: ArcheryHarnessState,
        *,
        target: tuple[int, str] | None,
        completed: bool,
    ) -> dict[str, Any]:
        return {
            "model_attempted_tool_calls": list(state.attempted_model_calls),
            "model_executed_tool_calls": list(state.executed_model_calls),
            "model_decision_count": state.model_decision_count,
            "mcp_tool_call_count": len(state.executed_model_calls),
            "mcp_roundtrip_count": state.mcp_roundtrip_count,
            "mcp_session_attempts": state.session_attempts,
            "model_selection_errors": deepcopy(state.consecutive_model_errors),
            "alert_endpoint": state.alert_endpoint,
            "query_trace": deepcopy(state.query_trace),
            "metadata_resolution_stage": self.client.metadata_resolution_stage(
                target=target,
                alert_endpoint=state.alert_endpoint,
                member_instance_ids=state.member_instance_ids,
                resolved_endpoints=state.resolved_endpoints,
                table_columns=state.table_columns,
                query_trace=state.query_trace,
                history_query_completed=completed,
            ),
        }

    def _record_fatal(
        self,
        state: ArcheryHarnessState,
        error: BaseException,
    ) -> None:
        state.fatal_error_message = str(error) or type(error).__name__
        if isinstance(error, ArcheryMCPToolError):
            state.fatal_error_kind = "tool"
            state.fatal_error_diagnostics = dict(error.diagnostic_data)
        elif isinstance(error, ArcheryMCPConfigurationError):
            state.fatal_error_kind = "configuration"
        else:
            state.fatal_error_kind = "protocol"

async def execute_archery_harness(
    client: ArcheryMCPClient,
    occurred_at: datetime,
    *,
    alert_context: Mapping[str, Any],
    run_id: UUID | None = None,
    outer_dispatch_id: UUID | None = None,
    lease_owner: str | None = None,
    fencing_token: int | None = None,
    connector: MCPConnector | None = None,
    runtime_dependencies: ArcheryHarnessRuntimeDependencies | None = None,
) -> ArcherySlowLogQueryResult:
    if (lease_owner is None) != (fencing_token is None):
        raise ValueError("lease_owner and fencing_token must be provided together")
    if lease_owner is not None and (run_id is None or runtime_dependencies is None):
        raise ValueError(
            "lease fencing requires a run_id and repository runtime dependencies"
        )
    window_start, window_end = client_window(client, occurred_at)
    state = ArcheryHarnessState(
        window_start=window_start,
        window_end=window_end,
        occurred_at=occurred_at,
        alert_context=dict(alert_context),
        alert_endpoint=client.alert_endpoint_from_context(alert_context),
    )
    registry = _PlannerCallRegistry()
    scenario = ArcheryHarnessScenario(client, state, registry)
    planner = ArcheryHarnessPlanner(client, scenario, registry)
    event_sink = InMemoryEventSink()
    invocation_store = None
    remote_response_store = None
    checkpoint_store = None
    effective_run_id = run_id or uuid4()
    if runtime_dependencies is not None and run_id is not None:
        repository = runtime_dependencies.repository
        event_sink = RepositoryEventSink(
            repository,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        invocation_store = RepositoryInvocationStore(
            repository,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        remote_response_store = RepositoryArcheryRemoteResponseStore(
            repository,
            outer_dispatch_id=outer_dispatch_id,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        manifest = await repository.get_run_manifest(str(run_id))
        if manifest is not None:
            checkpoint_store = RepositoryMCPCheckpointStore[
                ArcheryHarnessState,
                dict[str, Any],
            ](
                repository,
                provider=ARCHERY_HARNESS_PROVIDER,
                manifest_hash=manifest.digest(),
                dispatch_id=outer_dispatch_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
    runtime = MCPAgentHarnessRuntime(
        connector=connector or ArcheryMCPConnector(client),
        planner=planner,
        scenario=scenario,
        dispatch_scope_id=outer_dispatch_id,
        event_sink=event_sink,
        budget=BudgetLedger(
            BudgetLimits(
                planner_requests=None,
                accepted_decisions=None,
                remote_tool_calls=None,
                host_bootstrap_calls=None,
                session_attempts=None,
                wall_time_seconds=None,
            )
        ),
        checkpoint_hook=checkpoint_store,
        invocation_store=invocation_store,
        remote_response_store=remote_response_store,
        planner_timeout_seconds=client.timeout_seconds,
        session_timeout_seconds=client.timeout_seconds,
    )
    checkpoint = (
        await checkpoint_store.load(effective_run_id)
        if checkpoint_store is not None
        else None
    )
    if checkpoint is None:
        result = await runtime.run(
            run_id=effective_run_id,
            initial_state=state,
        )
    else:
        restored_state = checkpoint.state
        scenario.restore_state(restored_state)
        result = await runtime.resume(
            checkpoint,
            restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
        )
    return _query_result(client, result)


def client_window(
    client: ArcheryMCPClient,
    occurred_at: datetime,
) -> tuple[datetime, datetime]:
    from app.adapters.archery_mcp import slow_log_window

    return slow_log_window(occurred_at, window_seconds=client.window_seconds)


def _query_result(
    client: ArcheryMCPClient,
    harness: MCPHarnessResult[ArcheryHarnessState, dict[str, Any]],
) -> ArcherySlowLogQueryResult:
    state = harness.state
    if state.final_result is not None:
        final_result = replace(
            state.final_result,
            model_tool_calls=tuple(state.executed_model_calls),
            model_request_ids=tuple(state.model_request_ids),
            metadata_resolution_tables=tuple(
                state.final_result.metadata_resolution_tables
            ),
        )
        diagnostics = dict(final_result.diagnostics or {})
        diagnostics["mcp_session_attempts"] = harness.budget.consumed.session_attempts
        diagnostics["reconnect_error_type"] = (
            ArcheryMCPProtocolError.__name__
            if harness.budget.consumed.session_attempts > 1
            else None
        )
        diagnostics["harness_stop_reason"] = (
            harness.finish.reason.value if harness.finish is not None else None
        )
        return replace(final_result, diagnostics=diagnostics)

    if state.fatal_error_kind == "configuration":
        raise ArcheryMCPConfigurationError(
            state.fatal_error_message or "Archery MCP configuration failed"
        )
    if state.fatal_error_kind == "tool":
        raise ArcheryMCPToolError(
            state.fatal_error_message or "Archery MCP tool failed",
            diagnostic_data=state.fatal_error_diagnostics,
        )

    finish_reason = (
        harness.finish.summary
        if harness.finish is not None
        else "Archery harness stopped without a final history query"
    )
    error_suffix = (
        f"; last query error: {safe_error_detail(state.last_query_error)}"
        if state.last_query_error
        else ""
    )
    probe_suffix = (
        f"; last successful slow-log probe was incomplete: {state.last_slow_log_probe_issue}"
        if state.last_slow_log_probe_issue
        else ""
    )
    raw_target = state.last_query_target
    target = (
        (raw_target[0], raw_target[1])
        if isinstance(raw_target, (list, tuple))
        and len(raw_target) == 2
        and type(raw_target[0]) is int
        and isinstance(raw_target[1], str)
        else None
    )
    partial = client.evidence_insufficient_result(
        window_start=state.window_start,
        window_end=state.window_end,
        target=target,
        attempted_model_calls=state.attempted_model_calls,
        model_calls=[],
        mcp_roundtrip_count=state.mcp_roundtrip_count,
        alert_endpoint=state.alert_endpoint,
        query_trace=state.query_trace,
        metadata_resolution_steps=state.metadata_resolution_steps,
        member_instance_ids=state.member_instance_ids,
        resolved_endpoints=state.resolved_endpoints,
        table_columns=state.table_columns,
        reason=f"{finish_reason}{error_suffix}{probe_suffix}",
    )
    diagnostics = dict(partial.diagnostics or {})
    diagnostics.update(
        {
            "model_executed_tool_calls": list(state.executed_model_calls),
            "model_decision_count": state.model_decision_count,
            "mcp_tool_call_count": len(state.executed_model_calls),
            "mcp_session_attempts": harness.budget.consumed.session_attempts,
            "reconnect_error_type": (
                ArcheryMCPProtocolError.__name__
                if harness.budget.consumed.session_attempts > 1
                else None
            ),
            "model_selection_errors": deepcopy(state.consecutive_model_errors),
            "harness_stop_reason": (
                harness.finish.reason.value if harness.finish is not None else None
            ),
        }
    )
    return replace(
        partial,
        model_tool_calls=tuple(state.executed_model_calls),
        model_request_ids=tuple(state.model_request_ids),
        diagnostics=diagnostics,
    )
