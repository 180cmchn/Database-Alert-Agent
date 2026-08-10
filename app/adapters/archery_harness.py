"""Archery provider adapter for the shared, reconnectable MCP harness."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client

from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_MAX_SESSION_ATTEMPTS,
    ARCHERY_MCP_MODEL_DECISION_MULTIPLIER,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_LOG_LIMIT,
    ARCHERY_SLOW_LOG_TABLE,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPConfigurationError,
    ArcheryMCPError,
    ArcheryMCPProtocolError,
    ArcheryMCPReadOnlyViolation,
    ArcheryMCPToolError,
    ArcherySlowLogQueryResult,
    _first_exception_leaf,
    _nested_archery_error,
    _safe_error_detail,
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
    ToolRisk,
    ToolSpec,
)
from app.application.sanitization import sanitize
from app.domain.ports import AlertRepository
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    DiscoveredMCPTool,
    Finish,
    HarnessObservation,
    HostRejection,
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
ARCHERY_HARNESS_POLICY_VERSION = "archery-read-only-harness-v1"
ARCHERY_HARNESS_SCHEMA_VERSION = "mcp-discovery-v1"


@dataclass(slots=True)
class ArcheryHarnessState:
    window_start: datetime
    window_end: datetime
    occurred_at: datetime
    alert_context: dict[str, Any]
    alert_endpoint: str | None
    login_payload: dict[str, Any] = field(default_factory=dict)
    login_text: tuple[str, ...] = ()
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
    last_host_rejection: str | None = None
    last_slow_log_probe_issue: str | None = None
    final_result: ArcherySlowLogQueryResult | None = None
    pending_artifact_content: dict[str, dict[str, Any]] = field(default_factory=dict)
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


class _ArcheryArtifactBuffer:
    def __init__(self) -> None:
        self._content: dict[UUID, dict[str, Any]] = {}
        self._pending_content: dict[UUID, dict[str, dict[str, Any]]] = {}

    def stage(
        self,
        content: Mapping[str, Any],
        *,
        pending_content: dict[str, dict[str, Any]],
    ) -> ArtifactRef:
        safe = sanitize(dict(content))
        serialized = json.dumps(
            safe,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        encoded = serialized.encode("utf-8")
        normalized = json.loads(serialized)
        if not isinstance(normalized, dict):
            raise TypeError("Archery artifact content must be a JSON object")
        artifact_id = uuid4()
        self._content[artifact_id] = normalized
        pending_content[str(artifact_id)] = deepcopy(normalized)
        self._pending_content[artifact_id] = pending_content
        return ArtifactRef(
            artifact_id=artifact_id,
            kind="archery_mcp_response",
            media_type="application/json",
            uri=f"agent-artifact://{artifact_id}",
            sha256=sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
            metadata={"provider": ARCHERY_HARNESS_PROVIDER, "sanitized": True},
        )

    def restore(self, pending_content: dict[str, dict[str, Any]]) -> None:
        for raw_artifact_id, content in pending_content.items():
            try:
                artifact_id = UUID(raw_artifact_id)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Invalid Archery pending artifact id: {raw_artifact_id!r}"
                ) from exc
            if not isinstance(content, dict):
                raise RuntimeError(
                    f"Invalid Archery pending artifact content: {raw_artifact_id}"
                )
            self._content[artifact_id] = deepcopy(content)
            self._pending_content[artifact_id] = pending_content

    def get(self, artifact_id: UUID) -> dict[str, Any] | None:
        content = self._content.get(artifact_id)
        return deepcopy(content) if content is not None else None

    def discard(self, artifact_id: UUID) -> None:
        self._content.pop(artifact_id, None)
        pending_content = self._pending_content.pop(artifact_id, None)
        if pending_content is not None:
            pending_content.pop(str(artifact_id), None)


class RepositoryArcheryArtifactStore:
    def __init__(
        self,
        repository: AlertRepository,
        buffer: _ArcheryArtifactBuffer,
        *,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> None:
        if (lease_owner is None) != (fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        self.repository = repository
        self.buffer = buffer
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token

    async def save(
        self,
        *,
        run_id: UUID,
        invocation_id: UUID,
        artifact: ArtifactRef,
    ) -> None:
        content = self.buffer.get(artifact.artifact_id)
        if content is None:
            existing = await self.repository.get_agent_artifact(str(artifact.artifact_id))
            if existing is not None and existing[0] == artifact:
                return
            raise RuntimeError(f"Archery artifact content is unavailable: {artifact.artifact_id}")
        await self.repository.save_agent_artifact(
            str(run_id),
            artifact,
            content,
            invocation_id=str(invocation_id),
            lease_owner=self.lease_owner,
            fencing_token=self.fencing_token,
        )
        self.buffer.discard(artifact.artifact_id)


class ArcheryHarnessPlanner:
    """Translate the existing tool-calling model into shared harness actions."""

    def __init__(
        self,
        client: ArcheryMCPClient,
        state: ArcheryHarnessState,
        registry: _PlannerCallRegistry,
        artifact_buffer: _ArcheryArtifactBuffer | None = None,
    ) -> None:
        self.client = client
        self.state = state
        self.registry = registry
        self.artifact_buffer = artifact_buffer

    async def plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> dict[str, Any]:
        model_messages = deepcopy(messages)
        if self.state.login_payload:
            model_messages.insert(2, self.client._host_login_message(self.state.login_payload))
        model_tools = [
            {
                "type": "function",
                "function": {
                    "name": item.name,
                    "description": f"Archery read-only MCP capability: {item.capability}",
                    "parameters": item.input_schema,
                },
            }
            for item in tools
        ]
        call = await self.client._request_model_tool_call(
            messages=model_messages,
            tools=model_tools,
        )
        self.state.attempted_model_calls.append(call.name)
        self.state.model_decision_count += 1
        self.registry.pending.append(call)
        return {
            "action": "call_tool",
            "tool_name": call.name,
            "objective": "Collect read-only Archery evidence for the fixed alert window",
            "hypothesis_ids": ["slow_query_evidence"],
            "arguments": call.arguments,
        }


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
            tools = await self.owner._list_tools(self.session)
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
            return await self.owner._call_tool(
                self.session,
                tool_name=name,
                arguments=arguments,
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
                    transport=self.client._transport,
                    follow_redirects=False,
                    headers=self.client._headers,
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
    nested = _nested_archery_error(error)
    if nested is not None:
        return nested
    leaf = _first_exception_leaf(error)
    detail = _safe_error_detail(leaf)
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
        *,
        artifact_buffer: _ArcheryArtifactBuffer | None = None,
    ) -> None:
        self.client = client
        self.state = state
        self.registry = registry
        self.artifact_buffer = artifact_buffer
        self._last_failure: BaseException | None = None

    def initial_state(self) -> ArcheryHarnessState:
        return self.state

    def initial_messages(self, state: ArcheryHarnessState) -> list[dict[str, Any]]:
        return self.client._agent_messages(
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
        state.session_attempts += 1
        result = await session.call_tool(self.client.login_tool_name, {})
        state.mcp_roundtrip_count += 1
        login_text = self.client._tool_text_blocks(result)
        try:
            login_payload = self.client._extract_tool_payload(result)
            self.client._validate_business_success(
                login_payload,
                tool_name=self.client.login_tool_name,
                supplemental_text=login_text,
            )
        except ArcheryMCPToolError as exc:
            raise ArcheryMCPToolError(
                str(exc),
                diagnostic_data=self.client._login_diagnostic_data(
                    {},
                    login_text,
                    session_id=session.session_id,
                ),
            ) from exc
        state.login_payload = login_payload
        state.login_text = login_text
        state.session_id = session.session_id
        return state

    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]:
        discovered = {item.name: item for item in tools}
        missing = {self.client.login_tool_name, self.client.query_tool_name} - discovered.keys()
        if missing:
            raise ArcheryMCPConfigurationError(
                "Archery MCP is missing required tools: " + ", ".join(sorted(missing))
            )
        approved = {
            self.client.query_tool_name,
            ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
            ARCHERY_MCP_INSTANCES_TOOL_NAME,
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            ARCHERY_MCP_TABLES_TOOL_NAME,
            ARCHERY_MCP_COLUMNS_TOOL_NAME,
        }
        return [
            ToolSpec(
                name=item.name,
                provider=self.provider,
                capability=f"archery.{item.name}"[:256],
                input_schema=item.input_schema,
                read_only=True,
                risk=ToolRisk.LOW,
                policy_version=ARCHERY_HARNESS_POLICY_VERSION,
                schema_version=ARCHERY_HARNESS_SCHEMA_VERSION,
                timeout=self.client.timeout_seconds,
            )
            for item in tools
            if item.name in approved
        ]

    def prepare_call(
        self,
        action: Any,
        *,
        state: ArcheryHarnessState,
        catalog: dict[str, ToolSpec],
    ) -> PreparedCall | HostRejection:
        del catalog
        model_call = self.registry.take(
            tool_name=action.tool_name,
            arguments=action.arguments,
        )
        metadata: dict[str, Any] = {}
        if model_call is not None:
            metadata = {
                "call_id": model_call.call_id,
                "request_id": model_call.request_id,
            }

        if action.tool_name == self.client.query_tool_name:
            trace = self.client._query_trace_entry(
                model_call
                or MCPModelToolCall(
                    call_id="harness-call",
                    name=action.tool_name,
                    arguments=action.arguments,
                )
            )
            state.query_trace.append(trace)
            metadata["trace_index"] = len(state.query_trace) - 1
            state.last_query_target = self.client._target_key(action.arguments)
            requested_sql = action.arguments.get("sql_content")
            if isinstance(requested_sql, str) and self._uses_legacy_slow_log_table(requested_sql):
                reason = (
                    f"{ARCHERY_SLOW_LOG_TABLE} is not an approved evidence source in the "
                    "shared Archery harness"
                )
                trace["outcome"] = "host_rejected"
                trace["continuation_reason"] = reason
                state.last_host_rejection = reason
                return HostRejection(
                    code="legacy_slow_log_table_not_approved",
                    message=reason,
                    repair_hint=(
                        f"Use {ARCHERY_SLOW_QUERY_REVIEW_TABLE} through the approved metadata "
                        "resolution path."
                    ),
                )
            rejection = self.client._query_call_rejection(action.arguments)
            if rejection is not None:
                trace["outcome"] = "host_rejected"
                trace["continuation_reason"] = rejection
                state.last_host_rejection = rejection
                return HostRejection(
                    code="archery_sql_policy_rejected",
                    message=rejection,
                    repair_hint="Use one bounded read-only SELECT/WITH statement.",
                )

        return PreparedCall(
            tool_name=action.tool_name,
            objective=action.objective,
            hypothesis_ids=action.hypothesis_ids,
            model_arguments=dict(action.arguments),
            effective_arguments=dict(action.arguments),
            timeout_seconds=self.client.timeout_seconds,
            metadata=metadata,
        )

    def on_result(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[ArcheryHarnessState, dict[str, Any]]:
        if not isinstance(result, dict):
            raise ArcheryMCPProtocolError("Archery MCP tool result was not an object")
        self._record_remote_call(state, call)
        result_text = self.client._tool_text_blocks(result)
        payload = self.client._extract_tool_payload(result)
        self.client._validate_business_success(
            payload,
            tool_name=call.tool_name,
            supplemental_text=result_text,
        )
        artifact_ref = (
            self.artifact_buffer.stage(
                result,
                pending_content=state.pending_artifact_content,
            )
            if self.artifact_buffer is not None
            else None
        )
        trace = self._trace(state, call)
        if trace is not None:
            trace["outcome"] = "ok"

        if call.tool_name == ARCHERY_MCP_TABLES_TOOL_NAME:
            target = self.client._target_key(call.effective_arguments)
            if target is not None:
                discovered = self.client._slow_log_tables_from_discovery(payload)
                if discovered:
                    state.slow_log_tables.setdefault(target, set()).update(discovered)

        if call.tool_name == ARCHERY_MCP_COLUMNS_TOOL_NAME:
            target = self.client._target_key(call.effective_arguments)
            table_name = call.effective_arguments.get("tb_name")
            if target is not None and isinstance(table_name, str):
                columns = self.client._table_columns_from_payload(payload)
                if columns:
                    state.table_columns.setdefault(target, {})[
                        self.client._clean_table_name(table_name).casefold()
                    ] = columns

        if call.tool_name != self.client.query_tool_name:
            return self._successful_transition(
                state,
                call,
                payload,
                artifact_ref=artifact_ref,
            )

        requested_sql = call.effective_arguments.get("sql_content")
        if not isinstance(requested_sql, str) or not self.client._is_slow_log_select(
            requested_sql
        ):
            target = self.client._target_key(call.effective_arguments)
            if target is not None and isinstance(requested_sql, str):
                normalized, _, _ = self.client._normalize_query_payload(
                    payload,
                    requested_sql=requested_sql,
                )
                self.client._record_metadata_resolution_evidence(
                    resolution_steps=state.metadata_resolution_steps,
                    member_instance_ids=state.member_instance_ids,
                    resolved_endpoints=state.resolved_endpoints,
                    target=target,
                    sql=requested_sql,
                    payload=normalized,
                    alert_endpoint=state.alert_endpoint,
                    table_columns=state.table_columns,
                )
            return self._successful_transition(
                state,
                call,
                payload,
                artifact_ref=artifact_ref,
            )

        normalized_payload, executed_sql, actual_sql_verified = (
            self.client._normalize_query_payload(payload, requested_sql=requested_sql)
        )
        normalized_payload = self.client._limit_result_rows(
            normalized_payload,
            limit=ARCHERY_SLOW_LOG_LIMIT,
        )
        completion_issue = self._completion_issue(state, call, requested_sql)
        if completion_issue is not None:
            state.last_slow_log_probe_issue = completion_issue
            if trace is not None:
                trace["outcome"] = "probe_ok"
                trace["completion"] = "probe"
                trace["continuation_reason"] = completion_issue
            message = self.client._model_slow_log_probe_result(
                normalized_payload,
                completion_issue=completion_issue,
            )
            return ScenarioTransition(
                state=state,
                observation={"payload": normalized_payload, "completion": "probe"},
                message={"role": "user", "content": self._with_budget(state, message)},
                artifact_ref=artifact_ref,
            )

        target = self.client._target_key(call.effective_arguments)
        selected_table = self.client._matching_discovered_table(
            requested_sql,
            state.slow_log_tables.get(target, set()),
        ) or self.client._first_slow_log_table(requested_sql)
        state.final_result = ArcherySlowLogQueryResult(
            payload=normalized_payload,
            requested_sql=requested_sql,
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
            table_name=selected_table,
            query_time_column=self.client._query_time_column(executed_sql or requested_sql),
            metadata_resolution_tables=tuple(
                state.metadata_resolution_steps.get(target, []) if target is not None else []
            ),
            diagnostics=self._diagnostics(state, target=target, completed=True),
        )
        return ScenarioTransition(
            state=state,
            observation={"payload": normalized_payload, "completion": "final"},
            message={"role": "user", "content": self.client._model_tool_result(normalized_payload)},
            status=(
                ToolInvocationStatus.NO_DATA
                if self.client._payload_row_count(normalized_payload) == 0
                else ToolInvocationStatus.SUCCEEDED
            ),
            artifact_ref=artifact_ref,
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
        self._record_remote_call(state, call)
        trace = self._trace(state, call)
        if trace is not None:
            trace["outcome"] = "tool_error"
            trace["error_type"] = error.code
            trace["error_detail"] = _safe_error_detail(error.message)
        requested_sql = call.effective_arguments.get("sql_content")
        if call.tool_name == self.client.query_tool_name:
            state.last_query_error = error.message

        original = self._last_failure
        if isinstance(original, ArcheryMCPToolError):
            canonical = self.client._model_tool_error_result(
                original,
                requested_sql=requested_sql,
                window_start=state.window_start,
                window_end=state.window_end,
            )
        else:
            canonical = (
                "The previous MCP call did not produce available evidence "
                "(evidence_disposition=MISSING, is_contradiction=false). "
                f"Transport status={status.value}, error={_safe_error_detail(error.message)}. "
                "Preserve prior successful observations and choose the next safe probe."
            )
        return ScenarioTransition(
            state=state,
            observation={
                "error_code": error.code,
                "evidence_disposition": "MISSING",
                "is_contradiction": False,
            },
            message={"role": "user", "content": self._with_budget(state, canonical)},
        )

    def retry_directive(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall | None,
        error: Exception,
    ) -> RetryDirective:
        self._last_failure = error
        nested = _nested_archery_error(error)
        effective: BaseException = nested or error
        if isinstance(effective, ArcheryMCPToolError):
            retryable = self.client._is_retryable_tool_error(effective)
            if not retryable:
                self._record_fatal(state, effective)
            return RetryDirective(
                reason=str(effective),
                continue_run=retryable,
            )
        if isinstance(
            effective,
            (ArcheryMCPConfigurationError, ArcheryMCPReadOnlyViolation),
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
        if state.final_result is not None:
            return Finish(
                reason=RuntimeStopReason.EVIDENCE_SUFFICIENT,
                summary="A bounded Archery history query completed for the fixed alert window.",
            )
        if state.fatal_error_kind is not None:
            return Finish(
                reason=RuntimeStopReason.FAILED,
                summary=state.fatal_error_message or "Archery MCP investigation failed.",
                requires_human=True,
            )
        return None

    def validate_finish(
        self,
        state: ArcheryHarnessState,
        observations: Sequence[HarnessObservation[dict[str, Any]]],
        finish: Finish,
    ) -> Finish | HostRejection:
        del observations
        if state.final_result is not None:
            return finish
        return HostRejection(
            code="archery_final_evidence_not_collected",
            message="The final bounded Archery history query has not completed.",
            repair_hint=(
                "Continue with an approved read-only probe or finish with an "
                "evidence-insufficient reason."
            ),
        )

    def _successful_transition(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        payload: Mapping[str, Any],
        *,
        artifact_ref: ArtifactRef | None,
    ) -> ScenarioTransition[ArcheryHarnessState, dict[str, Any]]:
        canonical = self.client._model_tool_result(payload)
        return ScenarioTransition(
            state=state,
            observation={"tool_name": call.tool_name, "payload": dict(payload)},
            message={"role": "user", "content": self._with_budget(state, canonical)},
            artifact_ref=artifact_ref,
        )

    def _with_budget(self, state: ArcheryHarnessState, canonical: str) -> str:
        return self.client._with_model_budget_status(
            canonical,
            model_calls_used=len(state.executed_model_calls),
            model_decisions_used=state.model_decision_count,
            max_model_decisions=(
                self.client.max_agent_steps * ARCHERY_MCP_MODEL_DECISION_MULTIPLIER
            ),
        )

    def _completion_issue(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        sql: str,
    ) -> str | None:
        issues: list[str] = []
        if self.client._target_key(call.effective_arguments) is None:
            issues.append("missing a positive instance_id or database name")
        issue = self.client._slow_log_query_completion_issue(
            sql,
            window_start=state.window_start,
            window_end=state.window_end,
        )
        if issue:
            issues.append(issue)
        return "; ".join(issues) if issues else None

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
            "model_decision_limit": (
                self.client.max_agent_steps * ARCHERY_MCP_MODEL_DECISION_MULTIPLIER
            ),
            "mcp_tool_call_count": len(state.executed_model_calls),
            "mcp_tool_call_limit": self.client.max_agent_steps,
            "mcp_roundtrip_count": state.mcp_roundtrip_count,
            "mcp_session_attempts": state.session_attempts,
            "alert_endpoint": state.alert_endpoint,
            "query_trace": deepcopy(state.query_trace),
            "metadata_resolution_stage": self.client._metadata_resolution_stage(
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

    @classmethod
    def _uses_legacy_slow_log_table(cls, sql: str) -> bool:
        return ARCHERY_SLOW_LOG_TABLE.casefold() in {
            part.casefold()
            for part in (
                cls._clean_reference(value)
                for value in cls._table_references(sql)
            )
        }

    @staticmethod
    def _table_references(sql: str) -> set[str]:
        from app.adapters.archery_mcp import ArcheryMCPClient

        return ArcheryMCPClient._sql_table_references(sql)

    @staticmethod
    def _clean_reference(value: str) -> str:
        from app.adapters.archery_mcp import ArcheryMCPClient

        return ArcheryMCPClient._clean_table_name(value)


async def execute_archery_harness(
    client: ArcheryMCPClient,
    occurred_at: datetime,
    *,
    alert_context: Mapping[str, Any],
    run_id: UUID | None = None,
    outer_dispatch_id: UUID | None = None,
    outer_dispatch_attempt: int | None = None,
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
    if (outer_dispatch_id is None) != (outer_dispatch_attempt is None):
        raise ValueError(
            "outer_dispatch_id and outer_dispatch_attempt must be provided together"
        )
    if outer_dispatch_attempt not in {None, 1, 2}:
        raise ValueError("outer_dispatch_attempt must be 1 or 2")
    window_start, window_end = client_window(client, occurred_at)
    state = ArcheryHarnessState(
        window_start=window_start,
        window_end=window_end,
        occurred_at=occurred_at,
        alert_context=dict(alert_context),
        alert_endpoint=client._alert_endpoint_from_context(alert_context),
    )
    registry = _PlannerCallRegistry()
    artifact_buffer = _ArcheryArtifactBuffer() if runtime_dependencies is not None else None
    scenario = ArcheryHarnessScenario(
        client,
        state,
        registry,
        artifact_buffer=artifact_buffer,
    )
    planner = ArcheryHarnessPlanner(client, state, registry)
    event_sink = InMemoryEventSink()
    invocation_store = None
    artifact_store = None
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
        assert artifact_buffer is not None
        artifact_store = RepositoryArcheryArtifactStore(
            repository,
            artifact_buffer,
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
                planner_requests=(
                    client.max_agent_steps * ARCHERY_MCP_MODEL_DECISION_MULTIPLIER * 2
                ),
                accepted_decisions=(
                    client.max_agent_steps * ARCHERY_MCP_MODEL_DECISION_MULTIPLIER
                ),
                remote_tool_calls=client.max_agent_steps,
                host_bootstrap_calls=ARCHERY_MCP_MAX_SESSION_ATTEMPTS,
                session_attempts=ARCHERY_MCP_MAX_SESSION_ATTEMPTS,
                wall_time_seconds=(
                    client.timeout_seconds
                    * (
                        client.max_agent_steps
                        + ARCHERY_MCP_MAX_SESSION_ATTEMPTS * 2
                    )
                ),
            )
        ),
        checkpoint_hook=checkpoint_store,
        invocation_store=invocation_store,
        artifact_store=artifact_store,
        planner_timeout_seconds=client.timeout_seconds,
        session_timeout_seconds=client.timeout_seconds,
    )
    checkpoint = (
        await checkpoint_store.load(effective_run_id)
        if checkpoint_store is not None
        else None
    )
    if outer_dispatch_attempt == 2 and checkpoint is None:
        raise ArcheryMCPConfigurationError(
            "Archery outer recovery attempt has no matching child checkpoint"
        )
    if checkpoint is None:
        result = await runtime.run(
            run_id=effective_run_id,
            initial_state=state,
        )
    else:
        restored_state = checkpoint.state
        if artifact_buffer is not None:
            artifact_buffer.restore(restored_state.pending_artifact_content)
        planner.state = restored_state
        scenario.state = restored_state
        result = await runtime.resume(
            checkpoint,
            restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
        )
        if checkpoint_store is not None and result.state.pending_artifact_content:
            artifacts_by_id = {
                str(invocation.artifact_ref.artifact_id): invocation.artifact_ref
                for invocation in result.invocations
                if invocation.artifact_ref is not None
            }
            for artifact_id, content in tuple(
                result.state.pending_artifact_content.items()
            ):
                reference = artifacts_by_id.get(artifact_id)
                if reference is None:
                    raise RuntimeError(
                        f"Archery pending artifact is not referenced: {artifact_id}"
                    )
                persisted = await runtime_dependencies.repository.get_agent_artifact(
                    artifact_id
                )
                if persisted != (reference, content):
                    raise RuntimeError(
                        f"Archery pending artifact was not durably persisted: {artifact_id}"
                    )
                result.state.pending_artifact_content.pop(artifact_id)
            await checkpoint_store(result)
    return _query_result(client, result)


def client_window(
    client: ArcheryMCPClient,
    occurred_at: datetime,
) -> tuple[datetime, datetime]:
    from app.adapters.archery_mcp import _slow_log_window

    return _slow_log_window(occurred_at, window_seconds=client.window_seconds)


def _query_result(
    client: ArcheryMCPClient,
    harness: MCPHarnessResult[ArcheryHarnessState, dict[str, Any]],
) -> ArcherySlowLogQueryResult:
    state = harness.state
    if state.final_result is not None:
        final_result = replace(
            state.final_result,
            model_tool_calls=tuple(state.final_result.model_tool_calls),
            model_request_ids=tuple(state.final_result.model_request_ids),
            metadata_resolution_tables=tuple(
                state.final_result.metadata_resolution_tables
            ),
        )
        diagnostics = dict(final_result.diagnostics or {})
        diagnostics["mcp_session_attempts"] = harness.budget.consumed.session_attempts
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
        f"; last query error: {_safe_error_detail(state.last_query_error)}"
        if state.last_query_error
        else ""
    )
    rejection_suffix = (
        f"; last Host rejection: {state.last_host_rejection}"
        if state.last_host_rejection
        else ""
    )
    probe_suffix = (
        f"; last successful slow-log probe was incomplete: {state.last_slow_log_probe_issue}"
        if state.last_slow_log_probe_issue
        else ""
    )
    partial = client._evidence_insufficient_result(
        window_start=state.window_start,
        window_end=state.window_end,
        target=state.last_query_target,
        attempted_model_calls=state.attempted_model_calls,
        model_calls=[],
        mcp_roundtrip_count=state.mcp_roundtrip_count,
        alert_endpoint=state.alert_endpoint,
        query_trace=state.query_trace,
        metadata_resolution_steps=state.metadata_resolution_steps,
        member_instance_ids=state.member_instance_ids,
        resolved_endpoints=state.resolved_endpoints,
        table_columns=state.table_columns,
        model_decision_limit=(
            client.max_agent_steps * ARCHERY_MCP_MODEL_DECISION_MULTIPLIER
        ),
        mcp_tool_call_limit=client.max_agent_steps,
        reason=f"{finish_reason}{error_suffix}{rejection_suffix}{probe_suffix}",
    )
    diagnostics = dict(partial.diagnostics or {})
    diagnostics.update(
        {
            "model_executed_tool_calls": list(state.executed_model_calls),
            "model_decision_count": state.model_decision_count,
            "mcp_tool_call_count": len(state.executed_model_calls),
            "mcp_session_attempts": harness.budget.consumed.session_attempts,
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
