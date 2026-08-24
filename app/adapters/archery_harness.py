"""Archery provider adapter for the shared, reconnectable MCP harness."""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4, uuid5

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client

from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_LOG_TS_COLUMN_TIMEZONE,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPClient,
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
from app.adapters.archery_sql import SQLTableReference, unquoted_words
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

ARCHERY_HARNESS_PROVIDER = "archery_mcp"
ARCHERY_HARNESS_POLICY_VERSION = "archery-discovered-tools-v3"
ARCHERY_HARNESS_SCHEMA_VERSION = "mcp-discovery-v3"
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
    # Per-id row accumulation for the truncation-recovery path: every per-id
    # retrieval query merges its rows here (id-keyed field union, later wins),
    # so the final result carries the complete window row set instead of only
    # the last query. New fields must keep defaults so old checkpoints load.
    history_id_rows: dict[int, dict[str, Any]] = field(default_factory=dict)
    history_merge_sources: list[dict[str, Any]] = field(default_factory=list)
    truncation_retry_hinted_sqls: set[str] = field(default_factory=set)
    truncation_projection_hinted_sqls: set[str] = field(default_factory=set)
    history_positional_rows: list[Any] = field(default_factory=list)
    history_positional_reference_columns: list[str] = field(default_factory=list)
    window_positional_hint_given: bool = False
    slow_query_explain_results: list[dict[str, Any]] = field(default_factory=list)
    slow_query_table_structure_results: list[dict[str, Any]] = field(default_factory=list)
    slow_query_index_results: list[dict[str, Any]] = field(default_factory=list)
    slow_query_analysis_failures: list[dict[str, Any]] = field(default_factory=list)
    analysis_instance_endpoints: dict[int, set[str]] = field(default_factory=dict)
    analysis_database_names: dict[int, set[str]] = field(default_factory=dict)
    history_result_target: tuple[int, str] | None = None
    history_recovery_ids: set[int] = field(default_factory=set)
    history_recovery_required: bool = False
    history_recovery_listing_completed: bool = False
    history_recovery_terminal_failure: bool = False
    # A projected sample remains a prefix even when its length marker is
    # missing or malformed. It is cleared only by a verified complete SELECT *
    # per-id row or an exact-width decoded SELECT * window row.
    history_sample_prefix_ids: set[int] = field(default_factory=set)
    history_full_row_ids: set[int] = field(default_factory=set)
    supplemental_analysis_started: bool = False


def _history_recovery_resolved_ids(state: ArcheryHarnessState) -> set[int]:
    """Return listed rows whose sample provenance is explicit and usable."""

    provenance_ids = set(state.history_full_row_ids) | set(
        state.history_sample_prefix_ids
    )
    return {
        row_id
        for row_id in provenance_ids
        if isinstance((row := state.history_id_rows.get(row_id)), Mapping)
        and isinstance(ArcheryMCPClient._casefolded_value(row, "sample"), str)
    }


def _history_recovery_missing_ids(state: ArcheryHarnessState) -> set[int]:
    return set(state.history_recovery_ids) - _history_recovery_resolved_ids(state)


def _history_recovery_unlisted_ids(state: ArcheryHarnessState) -> set[int]:
    if not state.history_recovery_listing_completed:
        return set()
    positional_ids: set[int] = set()
    for row in state.history_positional_rows:
        raw_id: Any = None
        if isinstance(row, Mapping):
            raw_id = ArcheryMCPClient._casefolded_value(row, "id")
        elif isinstance(row, (list, tuple)) and row:
            raw_id = row[0]
        row_id = ArcheryMCPClient._coerce_positive_integer(raw_id)
        if row_id is not None:
            positional_ids.add(row_id)
    return (set(state.history_id_rows) | positional_ids) - set(
        state.history_recovery_ids
    )


def _history_recovery_complete(state: ArcheryHarnessState) -> bool:
    if not state.history_recovery_required:
        return True
    return bool(
        state.history_recovery_listing_completed
        and not _history_recovery_missing_ids(state)
        and not _history_recovery_unlisted_ids(state)
        and not state.history_positional_rows
    )


def _history_payload_with_recovery_status(
    payload: Mapping[str, Any],
    state: ArcheryHarnessState,
) -> dict[str, Any]:
    projected = dict(payload)
    if _history_recovery_complete(state):
        return ArcheryMCPClient.with_result_completeness(projected)
    projected["rows_recovered_from_truncated_json"] = True
    projected["history_recovery_complete"] = False
    projected["history_recovery_id_listing_complete"] = (
        state.history_recovery_listing_completed
    )
    missing_ids = sorted(_history_recovery_missing_ids(state))
    if missing_ids:
        projected["history_recovery_missing_ids"] = missing_ids
    unlisted_ids = sorted(_history_recovery_unlisted_ids(state))
    if unlisted_ids:
        projected["history_recovery_unlisted_ids"] = unlisted_ids
    return ArcheryMCPClient.with_result_completeness(projected)


def _record_history_recovery_terminal_failure(
    state: ArcheryHarnessState,
    *,
    detail: str,
) -> None:
    if (
        not state.history_recovery_required
        or _history_recovery_complete(state)
        or state.history_recovery_terminal_failure
    ):
        return
    state.history_recovery_terminal_failure = True
    target: dict[str, Any] = {}
    if state.history_result_target is not None:
        target = {
            "instance_id": state.history_result_target[0],
            "db_name": state.history_result_target[1],
        }
    failure: dict[str, Any] = {
        "stage": "history_recovery",
        "target": target,
        "error_type": "incomplete_result",
        "reason_code": "history_recovery_incomplete",
        "detail": detail,
    }
    missing_ids = sorted(_history_recovery_missing_ids(state))
    if missing_ids:
        failure["missing_ids"] = missing_ids
    if not state.history_recovery_listing_completed:
        failure["id_listing_completed"] = False
    state.slow_query_analysis_failures.append(failure)


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
            _record_history_recovery_terminal_failure(
                self.state,
                detail=(
                    "Archery 内层 Agent 在 history 截断恢复完成前结束调查；"
                    "当前仅保留已恢复行并明确标记为不完整证据。"
                ),
            )
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
        self._allowed_non_sql_followup_tools = {
            ARCHERY_MCP_COLUMNS_TOOL_NAME,
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            ARCHERY_MCP_INSTANCES_TOOL_NAME,
            ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
            ARCHERY_MCP_TABLES_TOOL_NAME,
        }
        self._allowed_dynamic_auth_tools: set[str] = set()

    @property
    def current_state(self) -> ArcheryHarnessState:
        return self.state

    def restore_state(self, state: ArcheryHarnessState) -> None:
        legacy_accumulator = bool(
            getattr(state, "history_id_rows", {})
            or getattr(state, "history_merge_sources", [])
            or getattr(state, "history_positional_rows", [])
        )
        incomplete_final_result = bool(
            state.final_result is not None
            and self.client.is_result_incomplete(state.final_result.payload)
        )
        for field_name in (
            "slow_query_explain_results",
            "slow_query_table_structure_results",
            "slow_query_index_results",
            "slow_query_analysis_failures",
        ):
            if not hasattr(state, field_name):
                setattr(state, field_name, [])
        for field_name in (
            "analysis_instance_endpoints",
            "analysis_database_names",
        ):
            if not hasattr(state, field_name):
                setattr(state, field_name, {})
        if not hasattr(state, "history_result_target"):
            state.history_result_target = None
        if not hasattr(state, "history_recovery_ids"):
            state.history_recovery_ids = set()
        if not hasattr(state, "history_recovery_required"):
            state.history_recovery_required = (
                incomplete_final_result
                or bool(state.history_recovery_ids)
                or legacy_accumulator
            )
        elif (
            legacy_accumulator or incomplete_final_result
        ) and not state.history_recovery_required:
            # Accumulators and incomplete final results exist only on the
            # recovery path. A checkpoint claiming otherwise is inconsistent.
            state.history_recovery_required = True
            state.history_recovery_listing_completed = False
        if not hasattr(state, "history_recovery_listing_completed"):
            # Accumulated rows alone cannot prove that the id listing finished.
            # Older checkpoints did not retain enough provenance to infer it.
            state.history_recovery_listing_completed = bool(
                state.history_recovery_ids and not legacy_accumulator
            )
        if not hasattr(state, "history_recovery_terminal_failure"):
            state.history_recovery_terminal_failure = False
        if not hasattr(state, "history_positional_reference_columns"):
            state.history_positional_reference_columns = []
        if not hasattr(state, "history_sample_prefix_ids"):
            # Older checkpoints have no response-level provenance. Treat every
            # accumulated id as prefix/unknown until a new, currently verified
            # full per-id response proves otherwise.
            state.history_recovery_listing_completed = False
            prefix_ids: set[int] = {
                parsed_id
                for row_id in getattr(state, "history_id_rows", {})
                if (
                    parsed_id := self.client._coerce_positive_integer(row_id)
                )
                is not None
            }
            for source in getattr(state, "history_merge_sources", []):
                sql = source.get("full_sql") if isinstance(source, Mapping) else None
                retrieval = (
                    self.client.history_id_retrieval(sql)
                    if isinstance(sql, str)
                    else None
                )
                if retrieval is not None and retrieval[1] == "sample_prefix":
                    prefix_ids.add(retrieval[0])
            state.history_sample_prefix_ids = prefix_ids
        if not hasattr(state, "history_full_row_ids"):
            # Legacy checkpoints cannot prove actual-SQL verification, lack of
            # truncation, exact id cardinality, and presence of a full sample.
            state.history_full_row_ids = set()
        if not hasattr(state, "supplemental_analysis_started"):
            state.supplemental_analysis_started = False
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
        self._allowed_dynamic_auth_tools = {
            item.name
            for item in tools
            if item.annotations.get("readOnlyHint") is True
            and item.annotations.get("destructiveHint") is not True
            and re.search(r"(?i)(?:auth|login|session)", item.name)
        }
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

    def _is_allowed_non_sql_followup_tool(self, tool_name: str) -> bool:
        return tool_name in (
            self._allowed_non_sql_followup_tools | self._allowed_dynamic_auth_tools
        )

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

        sql = action.arguments.get("sql_content")
        if isinstance(sql, str):
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

        rejection, binding = self._post_history_call_decision(
            state,
            tool_name=action.tool_name,
            arguments=action.arguments,
        )
        if rejection is not None:
            metadata["local_rejection"] = rejection
        if binding is not None:
            metadata["analysis_binding"] = binding
        if (
            rejection is None
            and isinstance(sql, str)
            and self.client.has_slow_log_reference(sql)
            and self.client.is_history_recovery_query(sql)
        ):
            metadata["history_query_authorized"] = True
        if (
            rejection is None
            and isinstance(sql, str)
            and not self._has_history_context(state)
            and not self.client.has_slow_log_reference(sql)
            and self._is_safe_pre_history_select(
                state,
                sql,
                arguments=action.arguments,
            )
        ):
            metadata["pre_history_metadata_authorized"] = True

        return PreparedCall(
            tool_name=action.tool_name,
            objective=action.objective,
            hypothesis_ids=action.hypothesis_ids,
            model_arguments=dict(action.arguments),
            effective_arguments=deepcopy(action.arguments),
            timeout_seconds=self.client.timeout_seconds,
            metadata=metadata,
            local_result=(
                {"local_rejection": deepcopy(metadata["local_rejection"])}
                if "local_rejection" in metadata
                else None
            ),
        )

    def _post_history_call_decision(
        self,
        state: ArcheryHarnessState,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        sql = arguments.get("sql_content")
        has_history_context = self._has_history_context(state)
        if isinstance(sql, str) and tool_name != ARCHERY_MCP_QUERY_TOOL_NAME:
            if has_history_context:
                state.supplemental_analysis_started = True
            return self._local_rejection(
                stage="target_resolution",
                target=self._analysis_target_from_arguments(
                    self.client.target_key(arguments), arguments
                ),
                reason_code="sql_tool_forbidden",
                detail="SQL 只能通过已知 Archery SQL 查询工具发送。",
            ), None
        statement: str | None = None
        if isinstance(sql, str):
            target = self._analysis_target_from_arguments(
                self.client.target_key(arguments),
                arguments,
            )
            statement = self.client._single_sql_statement(sql)
            if statement is None:
                if has_history_context:
                    state.supplemental_analysis_started = True
                return self._local_rejection(
                    stage="explain" if has_history_context else "target_resolution",
                    target=target,
                    reason_code="multi_statement_forbidden",
                    detail="Archery SQL 调用必须只包含一个完整语句。",
                ), None
            if self.client.is_explain_analyze_query(statement):
                if has_history_context:
                    state.supplemental_analysis_started = True
                return self._local_rejection(
                    stage="explain",
                    target=target,
                    reason_code="explain_analyze_forbidden",
                    detail="EXPLAIN ANALYZE 会实际执行内层语句，已在发送到 MCP 前拒绝。",
                ), None
        if not has_history_context:
            if not isinstance(sql, str):
                if self._is_allowed_non_sql_followup_tool(tool_name):
                    return None, None
                return self._local_rejection(
                    stage="target_resolution",
                    target=self._analysis_target_from_arguments(
                        self.client.target_key(arguments),
                        arguments,
                    ),
                    reason_code="pre_history_tool_forbidden",
                    detail=(
                        "history 前仅允许已知只读导航工具、已验证认证工具，或包含字符串 "
                        "sql_content 的正式 Archery SQL 查询工具。"
                    ),
                ), None
            assert statement is not None
            if self.client.has_slow_log_reference(statement):
                if not self.client.is_history_recovery_query(statement):
                    return self._local_rejection(
                        stage="history_recovery",
                        target=target,
                        reason_code="history_recovery_query_forbidden",
                        detail=(
                            "任何 slow-log/history 数据源都必须使用封闭的单一 "
                            "history 查询形态。"
                        ),
                    ), None
                if self.client.is_history_id_only_projection(statement):
                    if not self._is_scoped_history_id_listing(state, statement):
                        return self._local_rejection(
                            stage="history_recovery",
                            target=target,
                            reason_code="history_recovery_query_forbidden",
                            detail="id 清单必须使用单一 history 数据源并严格保留告警窗口约束。",
                        ), None
                    if self._is_initial_history_target(
                        state,
                        arguments=arguments,
                        sql=statement,
                    ):
                        return None, None
                    return self._local_rejection(
                        stage="history_recovery",
                        target=target,
                        reason_code="history_target_mismatch",
                        detail="history 查询必须发送到已验证的 Archery 元数据库目标。",
                    ), None
                if self.client.is_history_id_retrieval_query(statement):
                    return self._local_rejection(
                        stage="history_recovery",
                        target=target,
                        reason_code="history_recovery_query_forbidden",
                        detail="单 id 恢复前必须先取得受约束 id 清单。",
                    ), None
                if not self._is_scoped_history_window_query(state, statement):
                    return self._local_rejection(
                        stage="history_recovery",
                        target=target,
                        reason_code="history_recovery_query_forbidden",
                        detail="首次 history 查询必须使用 SELECT *、单一数据源并严格绑定告警窗口。",
                    ), None
                if self._is_initial_history_target(
                    state,
                    arguments=arguments,
                    sql=statement,
                ):
                    return None, None
                return self._local_rejection(
                    stage="history_recovery",
                    target=target,
                    reason_code="history_target_mismatch",
                    detail="history 查询必须发送到已验证的 Archery 元数据库目标。",
                ), None
            if re.match(r"(?is)^\s*explain\b", statement):
                return self._local_rejection(
                    stage="explain",
                    target=target,
                    reason_code="unbound_explain_forbidden",
                    detail="只有与已验证 history sample 关联的普通 EXPLAIN 可以执行。",
                ), None
            if not self._is_safe_pre_history_select(
                state,
                statement,
                arguments=arguments,
            ):
                return self._local_rejection(
                    stage="target_resolution",
                    target=target,
                    reason_code="direct_statement_forbidden",
                    detail="history 之前仅允许封闭的单表直接投影元数据 SELECT。",
                ), None
            return None, None

        if not isinstance(sql, str):
            if self._history_recovery_blocks_supplemental(state):
                return self._history_recovery_pending_rejection(
                    state,
                    arguments=arguments,
                ), None
            state.supplemental_analysis_started = True
            return self._non_sql_followup_decision(
                state,
                tool_name=tool_name,
                arguments=arguments,
            )

        target = self._analysis_target_from_arguments(
            self.client.target_key(arguments),
            arguments,
        )
        assert statement is not None
        if self.client.has_slow_log_reference(statement):
            if self.client.is_history_recovery_query(
                statement
            ) and self._is_allowed_history_recovery(state, statement, arguments):
                return None, None
            return self._local_rejection(
                stage="history_recovery",
                target=target,
                reason_code="history_recovery_query_forbidden",
                detail="history 恢复只允许原 window 重试、id 清单或单 id 查询。",
            ), None

        canonical = self.client._canonical_sql(statement)
        samples = {
            self.client._canonical_sql(
                str(self.client._casefolded_value(row, "sample") or "")
            )
            for row in self.client._tabular_rows(self._history_payload(state))
            if self.client._casefolded_value(row, "sample") not in (None, "")
        }
        if canonical in samples:
            state.supplemental_analysis_started = True
            return self._local_rejection(
                stage="explain",
                target=target,
                reason_code="sample_execution_forbidden",
                detail="history sample 只能作为普通 EXPLAIN 的内层语句，禁止直接执行。",
            ), None

        if self._history_recovery_blocks_supplemental(state):
            return self._history_recovery_pending_rejection(
                state,
                arguments=arguments,
            ), None

        state.supplemental_analysis_started = True

        if re.match(r"(?is)^\s*explain\b", statement):
            if self.client.classify_plain_explain(statement) is None:
                return self._local_rejection(
                    stage="explain",
                    target=target,
                    reason_code="invalid_explain_statement",
                    detail="仅允许普通 EXPLAIN 包裹可解释的单语句。",
                ), None
            source_row = self.client.history_row_for_explain(
                statement,
                self._history_payload(state),
                sample_prefix_ids=state.history_sample_prefix_ids,
            )
            if source_row is None:
                return self._local_rejection(
                    stage="explain",
                    target=target,
                    error_type="sample_parse_failed",
                    reason_code="explain_sample_not_in_history",
                    detail="EXPLAIN 内层 SQL 无法与已取得的 history sample 关联。",
                ), None
            inner_sql = self.client.classify_plain_explain(statement) or ""
            tables = sorted(
                self.client.explainable_table_references(inner_sql),
                key=str.casefold,
            )
            rejection, binding = self._bind_supplemental_target(
                state,
                source_row=source_row,
                arguments=arguments,
                stage="explain",
                table_names=tables,
            )
            if rejection is not None or binding is None:
                return rejection, None
            if not self._table_structure_resolved(state, binding):
                return self._local_rejection(
                    stage="explain",
                    target=dict(binding["target"]),
                    error_type="prerequisite_missing",
                    reason_code="table_structure_required",
                    detail="普通 EXPLAIN 前必须先取得真实字段结构或记录该阶段失败。",
                    source_history_row=dict(binding["source_history_row"]),
                ), None
            return None, binding

        metadata_stage: str | None = None
        if self.client.is_information_schema_columns_query(statement):
            metadata_stage = "table_structure"
        elif self.client.is_information_schema_statistics_query(statement):
            metadata_stage = "indexes"
        if metadata_stage is not None:
            sql_target = self.client.information_schema_target(statement)
            db_name = sql_target.get("db_name")
            table_name = sql_target.get("table_name")
            if (
                not db_name
                or not table_name
                or not self.client.has_exact_information_schema_target_filters(statement)
            ):
                return self._local_rejection(
                    stage=metadata_stage,
                    target=target,
                    reason_code="metadata_target_filter_required",
                    detail="元数据查询必须同时按 TABLE_SCHEMA 和 TABLE_NAME 等值过滤。",
                ), None
            source_row = self._history_row_for_table(
                state,
                db_name=db_name,
                table_name=table_name,
            )
            if source_row is None:
                return self._local_rejection(
                    stage=metadata_stage,
                    target=target,
                    error_type="target_mismatch",
                    reason_code="metadata_table_not_in_sample",
                    detail="元数据目标无法与已选择的 history sample 引用表关联。",
                ), None
            return self._bind_supplemental_target(
                state,
                source_row=source_row,
                arguments=arguments,
                stage=metadata_stage,
                table_names=[table_name],
            )

        return self._local_rejection(
            stage="explain",
            target=target,
            reason_code="direct_statement_forbidden",
            detail="补充分析只允许受约束的 history 恢复、元数据查询和普通 EXPLAIN。",
        ), None

    def _is_safe_pre_history_select(
        self,
        state: ArcheryHarnessState,
        sql: str,
        *,
        arguments: Mapping[str, Any],
    ) -> bool:
        """Allow only the closed, single-table metadata-resolution shape."""

        if (
            not self._is_archery_metadata_target(arguments)
            or self.client.classify_explainable_statement(sql) != "select"
            or not self.client.is_simple_metadata_select(sql)
        ):
            return False
        references = self.client.explainable_physical_table_reference_sequence(sql)
        if references is None or len(references) != 1:
            return False
        reference = references[0]
        if not self._is_pre_history_metadata_reference(reference):
            return False
        target = self.client.target_key(arguments)
        assert target is not None
        words = unquoted_words(sql)
        if words is None or "or" in words:
            return False
        schema = reference.schema.casefold() if reference.schema is not None else None
        table = reference.table.casefold()
        if schema == "information_schema":
            return bool(
                (
                    self.client.is_information_schema_columns_query(sql)
                    or self.client.is_information_schema_statistics_query(sql)
                )
                and self.client.has_exact_information_schema_target_filters(sql)
            )
        columns = state.table_columns.get(target, {}).get(table, set())
        if table == "t_instance_member":
            return bool(
                self.client._member_query_selects_instance_id(sql, columns)
                and self.client.is_exact_member_endpoint_lookup(
                    sql,
                    alert_endpoint=state.alert_endpoint,
                    discovered_columns=columns,
                )
            )
        known_ids = state.member_instance_ids.get(target, set())
        return bool(
            table == "sql_instance"
            and known_ids
            and self.client.is_exact_sql_instance_lookup(
                sql,
                known_ids=known_ids,
                discovered_columns=columns,
            )
            and self.client._sql_instance_query_selects_endpoint(sql, columns)
        )

    def _is_archery_metadata_target(self, arguments: Mapping[str, Any]) -> bool:
        target = self.client.target_key(arguments)
        return target is not None and target[1] == "archery"

    def _is_initial_history_target(
        self,
        state: ArcheryHarnessState,
        *,
        arguments: Mapping[str, Any],
        sql: str,
    ) -> bool:
        if not self._is_archery_metadata_target(arguments):
            return False
        target = self.client.target_key(arguments)
        assert target is not None
        endpoint_match = re.search(
            r"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?hostname_max`?\s*=\s*'(?P<endpoint>(?:''|[^'])*)'",
            sql,
        )
        endpoint = (
            self.client._normalize_endpoint(
                endpoint_match.group("endpoint").replace("''", "'")
            )
            if endpoint_match is not None
            else None
        )
        return endpoint is not None and endpoint.casefold() in {
            item.casefold() for item in state.resolved_endpoints.get(target, set())
        }

    def _is_pre_history_metadata_reference(self, reference: SQLTableReference) -> bool:
        schema = reference.schema.casefold() if isinstance(reference.schema, str) else None
        table = reference.table.casefold()
        if schema is not None and schema not in {"archery", "information_schema"}:
            return False
        if schema == "information_schema":
            return table in {"columns", "statistics"}
        return table in {"t_instance_member", "sql_instance"}

    def _non_sql_followup_decision(
        self,
        state: ArcheryHarnessState,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if tool_name in {
            ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
            ARCHERY_MCP_INSTANCES_TOOL_NAME,
        }:
            return None, None
        if tool_name == ARCHERY_MCP_DATABASES_TOOL_NAME:
            return self._validate_database_discovery_target(state, arguments), None
        if not self._is_allowed_non_sql_followup_tool(tool_name):
            return self._local_rejection(
                stage="target_resolution",
                target=self._analysis_target_from_arguments(
                    self.client.target_key(arguments),
                    arguments,
                ),
                reason_code="followup_tool_forbidden",
                detail="history 后只允许只读认证、目标发现、字段发现和受约束 SQL 工具。",
            ), None
        if tool_name not in {ARCHERY_MCP_TABLES_TOOL_NAME, ARCHERY_MCP_COLUMNS_TOOL_NAME}:
            return None, None
        db_name = arguments.get("db_name")
        table_name = arguments.get("tb_name")
        if tool_name == ARCHERY_MCP_TABLES_TOOL_NAME:
            return self._bind_database_target(state, arguments)
        if not isinstance(db_name, str) or not isinstance(table_name, str):
            return self._local_rejection(
                stage="table_structure",
                target=self._analysis_target_from_arguments(
                    self.client.target_key(arguments),
                    arguments,
                ),
                reason_code="metadata_target_required",
                detail="字段发现必须提供真实 instance_id、db_name 和 tb_name。",
            ), None
        source_row = self._history_row_for_table(
            state,
            db_name=db_name,
            table_name=table_name,
        )
        if source_row is None:
            return self._local_rejection(
                stage="table_structure",
                target=self._analysis_target_from_arguments(
                    self.client.target_key(arguments),
                    arguments,
                    table_name=table_name,
                ),
                error_type="target_mismatch",
                reason_code="metadata_table_not_in_sample",
                detail="字段发现目标无法与已选择的 history sample 引用表关联。",
            ), None
        return self._bind_supplemental_target(
            state,
            source_row=source_row,
            arguments=arguments,
            stage="table_structure",
            table_names=[table_name],
        )

    def _is_allowed_history_recovery(
        self,
        state: ArcheryHarnessState,
        sql: str,
        arguments: Mapping[str, Any],
    ) -> bool:
        if (
            state.history_result_target is None
            or self.client.target_key(arguments) != state.history_result_target
        ):
            return False
        uncommented = self.client._sql_without_comments(sql) or ""
        if re.search(r"(?is)(?<![A-Za-z0-9_$])`?id`?\s+in\s*\(", uncommented):
            return False
        if self.client.is_history_id_only_projection(sql):
            if re.search(r"(?is)(?<![A-Za-z0-9_$])`?id`?\s*(?:=|\bin\b)", uncommented):
                return False
            return self._is_scoped_history_id_listing(state, uncommented)
        if (
            not state.supplemental_analysis_started
            and self._is_scoped_history_window_query(state, uncommented)
        ):
            return True
        retrieval = self.client.history_id_retrieval(sql)
        if retrieval is not None:
            row_id, _projection = retrieval
            max_result_chars = arguments.get("max_result_chars")
            return row_id in state.history_recovery_ids and max_result_chars in (
                None,
                24000,
            )
        permitted_sqls: list[str] = []
        if state.final_result is not None:
            permitted_sqls.extend(
                filter(
                    None,
                    (state.final_result.requested_sql, state.final_result.executed_sql),
                )
            )
        permitted_sqls.extend(
            str(source.get("full_sql") or "") for source in state.history_merge_sources
        )
        return any(self.client.sql_equivalent(item, sql) for item in permitted_sqls)

    @staticmethod
    def _history_recovery_blocks_supplemental(state: ArcheryHarnessState) -> bool:
        return bool(
            state.history_recovery_required
            and not state.history_recovery_terminal_failure
            and not _history_recovery_complete(state)
        )

    def _history_recovery_pending_rejection(
        self,
        state: ArcheryHarnessState,
        *,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        missing_ids = sorted(_history_recovery_missing_ids(state))
        if not state.history_recovery_listing_completed:
            detail = (
                "history 结果发生截断，必须先取得完整受约束 id 清单并恢复全部行，"
                "之后才能开始目标发现、元数据或 EXPLAIN。"
            )
        elif missing_ids:
            detail = (
                "history 截断恢复仍缺少 id："
                + ", ".join(str(row_id) for row_id in missing_ids)
                + "；恢复完成前禁止目标发现、元数据和 EXPLAIN。"
            )
        elif unlisted_ids := sorted(_history_recovery_unlisted_ids(state)):
            detail = (
                "history 已恢复行中存在未出现在完整 id 清单的 id："
                + ", ".join(str(row_id) for row_id in unlisted_ids)
                + "；清单与恢复结果一致前禁止目标发现、元数据和 EXPLAIN。"
            )
        else:
            detail = (
                "history 截断结果仍有无法按列名解码的位置行；"
                "完整恢复前禁止目标发现、元数据和 EXPLAIN。"
            )
        return self._local_rejection(
            stage="history_recovery",
            target=self._analysis_target_from_arguments(
                self.client.target_key(arguments),
                arguments,
            ),
            error_type="prerequisite_missing",
            reason_code="history_recovery_pending",
            detail=detail,
        )

    def _is_scoped_history_id_listing(
        self,
        state: ArcheryHarnessState,
        sql: str,
    ) -> bool:
        if (
            not self.client.is_history_id_only_projection(sql)
            or not self._has_simple_history_source(sql, projection="id")
        ):
            return False
        if not self._has_scoped_history_window_predicates(
            state,
            sql,
            require_ts_max=True,
        ):
            return False
        tail = re.search(r"(?is)\b(?:order\s+by|limit)\b.*$", sql)
        return tail is None or re.fullmatch(
            r"(?is)\s*(?:order\s+by\s+`?id`?(?:\s+(?:asc|desc))?\s*)?"
            r"(?:limit\s+\d+\s*)?;?\s*",
            tail.group(0),
        ) is not None

    def _is_scoped_history_window_query(
        self,
        state: ArcheryHarnessState,
        sql: str,
    ) -> bool:
        if (
            not self.client.is_history_result_query(sql)
            or not self._has_simple_history_source(sql, projection="*")
            or not self._has_scoped_history_window_predicates(
                state,
                sql,
                require_ts_max=False,
            )
        ):
            return False
        tail = re.search(r"(?is)\b(?:order\s+by|limit)\b.*$", sql)
        return tail is None or re.fullmatch(
            r"(?is)\s*(?:order\s+by\s+(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?[A-Za-z_][A-Za-z0-9_$]*`?(?:\s+(?:asc|desc))?\s*)?"
            r"(?:limit\s+\d+\s*)?;?\s*",
            tail.group(0),
        ) is not None

    def _has_simple_history_source(self, sql: str, *, projection: str) -> bool:
        """Match the fixed, single-source shape used by history recovery."""

        statement = self.client._single_sql_statement(sql)
        if statement is None:
            return False
        if projection == "*":
            projection_pattern = r"\*"
        elif projection == "id":
            projection_pattern = (
                r"(?:(?:`?[A-Za-z_][A-Za-z0-9_$]*`?)\s*\.\s*)?`?id`?"
            )
        else:
            return False
        return re.fullmatch(
            rf"(?is)\s*select\s+{projection_pattern}\s+from\s+"
            rf"`?{re.escape(ARCHERY_SLOW_QUERY_REVIEW_TABLE)}`?"
            r"(?:\s+(?:as\s+)?`?[A-Za-z_][A-Za-z0-9_$]*`?)?\s+"
            r"where\s+.+\s*",
            statement,
        ) is not None

    def _has_scoped_history_window_predicates(
        self,
        state: ArcheryHarnessState,
        sql: str,
        *,
        require_ts_max: bool,
    ) -> bool:
        endpoint_match = re.search(
            r"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?hostname_max`?\s*=\s*'(?P<endpoint>(?:''|[^'])*)'",
            sql,
        )
        if endpoint_match is None:
            return False
        endpoint = self.client._normalize_endpoint(
            endpoint_match.group("endpoint").replace("''", "'")
        )
        if endpoint is None:
            return False
        allowed_endpoints = {
            normalized.casefold()
            for row in self.client._tabular_rows(self._history_payload(state))
            if (
                normalized := self.client._normalize_endpoint(
                    self.client._casefolded_value(row, "hostname_max")
                )
            )
            is not None
        }
        allowed_endpoints.update(
            item.casefold()
            for endpoints in state.resolved_endpoints.values()
            for item in endpoints
        )
        if endpoint.casefold() not in allowed_endpoints:
            return False
        where_body = self.client._where_body(sql)
        if where_body is None:
            return False
        remainder = where_body
        literal = r"(?P<literal>from_unixtime\s*\(\s*\d+\s*\)|'(?:''|[^'])*')"
        hostname = re.compile(
            r"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?hostname_max`?\s*=\s*'(?:''|[^'])*'"
        )
        time_predicates = (
            (
                re.compile(
                    rf"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                    rf"`?ts_min`?\s*>=\s*{literal}"
                ),
                "lower",
                True,
            ),
            (
                re.compile(
                    rf"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                    rf"`?ts_min`?\s*<(?!=)\s*{literal}"
                ),
                "upper",
                True,
            ),
            (
                re.compile(
                    rf"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                    rf"`?ts_max`?\s*>=\s*{literal}"
                ),
                "ts_max",
                require_ts_max,
            ),
        )
        hostname_matches = list(hostname.finditer(remainder))
        if len(hostname_matches) != 1:
            return False
        match = hostname_matches[0]
        remainder = remainder[: match.start()] + " " + remainder[match.end() :]
        time_literals: dict[str, str] = {}
        for predicate, name, required in time_predicates:
            matches = list(predicate.finditer(remainder))
            if len(matches) > 1 or (required and len(matches) != 1):
                return False
            if not matches:
                continue
            match = matches[0]
            time_literals[name] = match.group("literal")
            remainder = remainder[: match.start()] + " " + remainder[match.end() :]
        if re.sub(r"(?is)\band\b|[\s()]", "", remainder):
            return False
        if not self._history_time_literal_matches(
            time_literals["upper"], state.window_end
        ):
            return False
        has_overlap_predicate = "ts_max" in time_literals
        if has_overlap_predicate and not self._history_time_literal_matches(
            time_literals["ts_max"], state.window_start
        ):
            return False
        expected_lower = (
            state.window_start - timedelta(hours=1)
            if has_overlap_predicate
            else state.window_start
        )
        return self._history_time_literal_matches(
            time_literals["lower"], expected_lower
        )

    @staticmethod
    def _history_time_literal_matches(literal: str, expected: datetime) -> bool:
        epoch = re.fullmatch(
            r"(?is)from_unixtime\s*\(\s*(?P<value>\d+)\s*\)",
            literal,
        )
        if epoch is not None:
            return int(epoch.group("value")) == int(expected.timestamp())
        quoted = re.fullmatch(r"'(?P<value>(?:''|[^'])*)'", literal)
        if quoted is None:
            return False
        expected_text = expected.astimezone(
            ARCHERY_SLOW_LOG_TS_COLUMN_TIMEZONE
        ).strftime("%Y-%m-%d %H:%M:%S")
        return quoted.group("value").replace("''", "'") == expected_text

    def _history_row_for_table(
        self,
        state: ArcheryHarnessState,
        *,
        db_name: str,
        table_name: str,
    ) -> dict[str, Any] | None:
        expected_db = db_name.strip()
        expected_table = self.client.clean_table_name(table_name)
        return next(
            (
                row
                for row in self.client.select_explainable_history_rows(
                    self._history_payload(state),
                    sample_prefix_ids=state.history_sample_prefix_ids,
                )
                if str(self.client._casefolded_value(row, "db_max") or "")
                .strip()
                == expected_db
                and expected_table
                in {
                    self.client.clean_table_name(item)
                    for item in self.client.explainable_table_references(
                        str(self.client._casefolded_value(row, "sample") or "")
                    )
                }
            ),
            None,
        )

    def _bind_supplemental_target(
        self,
        state: ArcheryHarnessState,
        *,
        source_row: Mapping[str, Any],
        arguments: Mapping[str, Any],
        stage: str,
        table_names: Sequence[str],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        source = self.client.slow_query_source_row(source_row)
        endpoint = self.client._normalize_endpoint(source.get("hostname_max"))
        expected_db_value = source.get("db_max")
        expected_db = (
            expected_db_value.strip()
            if isinstance(expected_db_value, str) and expected_db_value.strip()
            else None
        )
        target_key = self.client.target_key(arguments)
        target = self._analysis_target_from_arguments(
            target_key,
            arguments,
            table_name=(
                self.client.clean_table_name(table_names[0]) if len(table_names) == 1 else None
            ),
        )
        if endpoint is None or expected_db is None:
            return self._local_rejection(
                stage="target_resolution",
                target=target,
                error_type="target_unresolved",
                reason_code="history_target_incomplete",
                detail="history 行缺少可严格解析的 hostname_max 或 db_max。",
                source_history_row=source,
            ), None
        endpoint = endpoint.casefold()
        matching_ids = sorted(
            instance_id
            for instance_id, endpoints in state.analysis_instance_endpoints.items()
            if endpoint in {item.casefold() for item in endpoints}
        )
        if len(matching_ids) != 1:
            return self._local_rejection(
                stage="target_resolution",
                target=target,
                error_type="target_unresolved",
                reason_code=(
                    "instance_target_ambiguous"
                    if len(matching_ids) > 1
                    else "instance_not_allowlisted"
                ),
                detail=(
                    "history hostname_max 在 allowlist 中匹配到多个实例。"
                    if len(matching_ids) > 1
                    else "history hostname_max 未匹配到 allowlist 中的真实实例。"
                ),
                source_history_row=source,
            ), None
        expected_instance_id = matching_ids[0]
        if target_key is None or target_key[0] != expected_instance_id:
            return self._local_rejection(
                stage="target_resolution",
                target=target,
                error_type="target_mismatch",
                reason_code="instance_target_mismatch",
                detail="调用 instance_id 与 history hostname_max 绑定的 allowlist 实例不一致。",
                source_history_row=source,
            ), None
        requested_db = arguments.get("db_name")
        if not isinstance(requested_db, str) or requested_db.strip() != expected_db:
            return self._local_rejection(
                stage="target_resolution",
                target=target,
                error_type="target_mismatch",
                reason_code="database_target_mismatch",
                detail="调用 db_name 与 history db_max 不一致。",
                source_history_row=source,
            ), None
        databases = state.analysis_database_names.get(expected_instance_id, set())
        if expected_db not in databases:
            return self._local_rejection(
                stage="target_resolution",
                target=target,
                error_type="target_unresolved",
                reason_code="database_not_allowlisted",
                detail="history db_max 未出现在该实例真实返回的数据库列表中。",
                source_history_row=source,
            ), None
        sample = str(source.get("sample") or "")
        mismatched_schemas = sorted(
            {
                reference.schema
                for reference in self.client.explainable_physical_table_references(
                    sample
                )
                if reference.schema is not None and reference.schema != expected_db
            }
        )
        if mismatched_schemas:
            return self._local_rejection(
                stage=stage,
                target=target,
                error_type="target_mismatch",
                reason_code="sample_schema_mismatch",
                detail=(
                    "history sample 的显式 schema 与 db_max 不一致："
                    + ", ".join(mismatched_schemas)
                ),
                source_history_row=source,
            ), None
        clean_tables = [self.client.clean_table_name(item) for item in table_names]
        bound_target: dict[str, Any] = {
            "instance_id": expected_instance_id,
            "db_name": expected_db_value.strip(),
            "endpoint": endpoint,
        }
        if len(clean_tables) == 1:
            bound_target["table_name"] = clean_tables[0]
        return None, {
            "stage": stage,
            "source_history_row": source,
            "target": bound_target,
            "table_names": clean_tables,
        }

    def _validate_database_discovery_target(
        self,
        state: ArcheryHarnessState,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        requested_id = self.client._coerce_positive_integer(arguments.get("instance_id"))
        candidates = self.client.select_explainable_history_rows(
            self._history_payload(state),
            sample_prefix_ids=state.history_sample_prefix_ids,
        )
        valid_ids: set[int] = set()
        ambiguous = False
        for row in candidates:
            endpoint = self.client._normalize_endpoint(
                self.client._casefolded_value(row, "hostname_max")
            )
            if endpoint is None:
                continue
            matching = {
                instance_id
                for instance_id, endpoints in state.analysis_instance_endpoints.items()
                if endpoint.casefold() in {item.casefold() for item in endpoints}
            }
            if len(matching) == 1:
                valid_ids.update(matching)
            elif len(matching) > 1:
                ambiguous = True
        if requested_id is not None and requested_id in valid_ids:
            return None
        return self._local_rejection(
            stage="target_resolution",
            target=(
                {"instance_id": requested_id} if requested_id is not None else {}
            ),
            error_type="target_unresolved",
            reason_code=("instance_target_ambiguous" if ambiguous else "instance_not_allowlisted"),
            detail=(
                "history hostname_max 在 allowlist 中匹配到多个实例。"
                if ambiguous
                else "数据库发现只能使用与 history hostname_max 唯一匹配的 allowlist 实例。"
            ),
        )

    def _bind_database_target(
        self,
        state: ArcheryHarnessState,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        db_name = arguments.get("db_name")
        if not isinstance(db_name, str):
            return self._local_rejection(
                stage="target_resolution",
                target={},
                reason_code="database_target_required",
                detail="表发现必须提供已绑定的 instance_id 和 db_name。",
            ), None
        source_rows = [
            row
            for row in self.client.select_explainable_history_rows(
                self._history_payload(state),
                sample_prefix_ids=state.history_sample_prefix_ids,
            )
            if str(self.client._casefolded_value(row, "db_max") or "").strip()
            == db_name.strip()
        ]
        if not source_rows:
            return self._local_rejection(
                stage="target_resolution",
                target=self._analysis_target_from_arguments(
                    self.client.target_key(arguments),
                    arguments,
                ),
                error_type="target_mismatch",
                reason_code="database_target_mismatch",
                detail="表发现 db_name 无法与 history db_max 关联。",
            ), None
        first_rejection: dict[str, Any] | None = None
        for source_row in source_rows:
            rejection, binding = self._bind_supplemental_target(
                state,
                source_row=source_row,
                arguments=arguments,
                stage="target_resolution",
                table_names=[],
            )
            if binding is not None:
                return None, binding
            if first_rejection is None:
                first_rejection = rejection
        return first_rejection, None

    @staticmethod
    def _source_key(source: Mapping[str, Any]) -> tuple[str, str, str]:
        return (
            str(source.get("id") or ""),
            str(source.get("checksum") or "").casefold(),
            str(source.get("sample") or ""),
        )

    def _table_structure_resolved(
        self,
        state: ArcheryHarnessState,
        binding: Mapping[str, Any],
    ) -> bool:
        tables = {
            self.client.clean_table_name(str(item))
            for item in binding.get("table_names", [])
        }
        if not tables:
            return True
        source = binding.get("source_history_row")
        target = binding.get("target")
        if not isinstance(source, Mapping) or not isinstance(target, Mapping):
            return False
        expected_instance = target.get("instance_id")
        expected_db = str(target.get("db_name") or "")
        resolved: set[str] = set()
        for item in [
            *state.slow_query_table_structure_results,
            *state.slow_query_analysis_failures,
        ]:
            if not isinstance(item, Mapping):
                continue
            if item.get("stage") not in (None, "table_structure"):
                continue
            item_target = item.get("target")
            if not isinstance(item_target, Mapping):
                continue
            if item_target.get("instance_id") != expected_instance:
                continue
            if str(item_target.get("db_name") or "") != expected_db:
                continue
            table_name = item_target.get("table_name")
            if isinstance(table_name, str):
                resolved.add(self.client.clean_table_name(table_name))
        return tables <= resolved

    @staticmethod
    def _local_rejection(
        *,
        stage: str,
        target: Mapping[str, Any],
        reason_code: str,
        detail: str,
        error_type: str = "unsafe_statement",
        source_history_row: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        failure: dict[str, Any] = {
            "stage": stage,
            "target": dict(target),
            "error_type": error_type,
            "reason_code": reason_code,
            "detail": detail,
        }
        if source_history_row is not None:
            failure["source_history_row"] = dict(source_history_row)
        return failure

    def _response_mismatch(
        self,
        call: PreparedCall,
        payload: Mapping[str, Any],
        *,
        raw_payload: Mapping[str, Any] | None = None,
        supplemental_text: Sequence[str] = (),
        executed_sql: str | None,
        actual_sql_verified: bool,
    ) -> dict[str, Any] | None:
        binding = call.metadata.get("analysis_binding")
        source = (
            binding.get("source_history_row")
            if isinstance(binding, Mapping)
            else None
        )
        bound_target = binding.get("target") if isinstance(binding, Mapping) else None
        target = (
            dict(bound_target)
            if isinstance(bound_target, Mapping)
            else self._analysis_target(call)
        )
        requested_sql = call.effective_arguments.get("sql_content")
        stage = (
            str(binding.get("stage") or "target_resolution")
            if isinstance(binding, Mapping)
            else "history_recovery"
            if isinstance(requested_sql, str)
            and self.client.is_history_result_query(requested_sql)
            else "target_resolution"
        )
        if executed_sql is not None and isinstance(requested_sql, str) and not actual_sql_verified:
            return self._local_rejection(
                stage=stage,
                target=target,
                error_type="result_mismatch",
                reason_code="actual_sql_mismatch",
                detail="MCP 回显的实际执行 SQL 与已验证请求不一致，结果未投影。",
                source_history_row=source if isinstance(source, Mapping) else None,
            )
        reported_values = self.client.reported_execution_target_values(
            payload,
            supplemental_text=supplemental_text,
        )
        if raw_payload is not None and raw_payload is not payload:
            for field, values in self.client.reported_execution_target_values(
                raw_payload,
                supplemental_text=supplemental_text,
            ).items():
                reported_values.setdefault(field, set()).update(values)
        metadata_rows_are_physical_targets = isinstance(requested_sql, str) and (
            (
                stage == "table_structure"
                and self.client.is_information_schema_columns_query(requested_sql)
            )
            or (
                stage == "indexes"
                and self.client.is_information_schema_statistics_query(requested_sql)
            )
        )
        if metadata_rows_are_physical_targets:
            for field, values in self.client.reported_metadata_row_target_values(
                payload,
                supplemental_text=supplemental_text,
            ).items():
                reported_values.setdefault(field, set()).update(values)
            if raw_payload is not None and raw_payload is not payload:
                for field, values in self.client.reported_metadata_row_target_values(
                    raw_payload,
                    supplemental_text=supplemental_text,
                ).items():
                    reported_values.setdefault(field, set()).update(values)
        expected_values = {
            "instance_id": target.get("instance_id"),
            "db_name": (
                target.get("db_name")
                if isinstance(bound_target, Mapping)
                else call.effective_arguments.get("db_name")
            ),
            "endpoint": target.get("endpoint"),
            "table_name": (
                target.get("table_name")
                or call.effective_arguments.get("tb_name")
                or call.effective_arguments.get("table_name")
            ),
        }

        def normalized_target_value(field: str, value: Any) -> Any:
            if field == "instance_id":
                return self.client._coerce_positive_integer(value)
            if field == "endpoint":
                endpoint = self.client._normalize_endpoint(value)
                return endpoint.casefold() if endpoint is not None else None
            if field == "table_name" and isinstance(value, str):
                return self.client.clean_table_name(value)
            if field == "db_name" and isinstance(value, str):
                return value.strip().strip("`\"")
            if isinstance(value, str):
                return value.strip()
            return value

        mismatched_fields = {
            field
            for field, values in reported_values.items()
            if len({normalized_target_value(field, value) for value in values}) > 1
            or (
                expected_values.get(field) not in (None, "")
                and any(
                    normalized_target_value(field, value)
                    != normalized_target_value(field, expected_values[field])
                    for value in values
                )
            )
        }
        if not mismatched_fields:
            return None
        return self._local_rejection(
            stage=stage,
            target=target,
            error_type="result_mismatch",
            reason_code="actual_target_mismatch",
            detail=(
                "MCP 回显的实际目标与已绑定目标不一致，结果未投影："
                + ", ".join(sorted(mismatched_fields))
            ),
            source_history_row=source if isinstance(source, Mapping) else None,
        )

    def _supplemental_incomplete_result_failure(
        self,
        call: PreparedCall,
        payload: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Reject partial supplemental facts while retaining their raw artifact."""

        binding = call.metadata.get("analysis_binding")
        if not isinstance(binding, Mapping) or not self.client.is_result_incomplete(payload):
            return None
        target = binding.get("target")
        source = binding.get("source_history_row")
        reasons = self.client.result_incomplete_reasons(payload)
        return self._local_rejection(
            stage=str(binding.get("stage") or "target_resolution"),
            target=dict(target) if isinstance(target, Mapping) else {},
            error_type="incomplete_result",
            reason_code="supplemental_result_incomplete",
            detail=(
                "补充查询结果不完整，未投影为成功事实"
                + (f"：{', '.join(reasons)}" if reasons else "。")
            ),
            source_history_row=dict(source) if isinstance(source, Mapping) else None,
        )

    def _collect_table_columns_result(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        payload: Mapping[str, Any],
    ) -> None:
        binding = call.metadata.get("analysis_binding")
        if not isinstance(binding, Mapping):
            return
        source = binding.get("source_history_row")
        target = binding.get("target")
        if not isinstance(source, Mapping) or not isinstance(target, Mapping):
            return
        columns = self.client.table_columns_from_payload(payload)
        if not columns:
            state.slow_query_analysis_failures.append(
                self._local_rejection(
                    stage="table_structure",
                    target=target,
                    error_type="empty_result",
                    reason_code="empty_table_structure_result",
                    detail="字段发现成功返回，但没有可投影的真实字段。",
                    source_history_row=source,
                )
            )
            return
        state.slow_query_table_structure_results.append(
            {
                "stage": "table_structure",
                "source_history_row": dict(source),
                "target": dict(target),
                "source": "list_table_columns",
                "result": {
                    "columns": sorted(columns, key=str.casefold),
                    "rows": [],
                    "row_count": len(columns),
                },
            }
        )

    def _collect_slow_query_analysis_result(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        payload: Mapping[str, Any],
        *,
        result_sql: str,
    ) -> bool:
        binding = call.metadata.get("analysis_binding")
        if not isinstance(binding, Mapping):
            return False
        source = binding.get("source_history_row")
        target = binding.get("target")
        stage = binding.get("stage")
        if not isinstance(source, Mapping) or not isinstance(target, Mapping):
            return False
        projected_result = self.client.structured_sql_result(payload)

        if stage == "explain":
            source_row = self.client.history_row_for_explain(
                result_sql,
                self._history_payload(state),
                sample_prefix_ids=state.history_sample_prefix_ids,
            )
            if source_row is None or self._source_key(
                self.client.slow_query_source_row(source_row)
            ) != self._source_key(source):
                state.slow_query_analysis_failures.append(
                    self._local_rejection(
                        stage="explain",
                        target=target,
                        error_type="result_mismatch",
                        reason_code="actual_sql_sample_mismatch",
                        detail="MCP 实际执行 SQL 无法与已绑定的 history sample 关联。",
                        source_history_row=source,
                    )
                )
                return True
            inner_sql = self.client.classify_plain_explain(result_sql) or ""
            if projected_result["row_count"] == 0:
                state.slow_query_analysis_failures.append(
                    self._local_rejection(
                        stage="explain",
                        target=target,
                        error_type="empty_result",
                        reason_code="empty_explain_result",
                        detail="普通 EXPLAIN 成功返回，但没有可投影的执行计划行。",
                        source_history_row=source,
                    )
                )
                return True
            state.slow_query_explain_results.append(
                {
                    "stage": "explain",
                    "source_history_row": dict(source),
                    "target": dict(target),
                    "statement_type": self.client.classify_explainable_statement(inner_sql),
                    "result": projected_result,
                }
            )
            return True
        if stage == "table_structure" and self.client.is_information_schema_columns_query(
            result_sql
        ):
            if projected_result["row_count"] == 0:
                state.slow_query_analysis_failures.append(
                    self._local_rejection(
                        stage="table_structure",
                        target=target,
                        error_type="empty_result",
                        reason_code="empty_table_structure_result",
                        detail="字段结构查询成功返回，但没有可投影的字段。",
                        source_history_row=source,
                    )
                )
                return True
            state.slow_query_table_structure_results.append(
                {
                    "stage": "table_structure",
                    "source_history_row": dict(source),
                    "target": dict(target),
                    "source": "information_schema.COLUMNS",
                    "result": projected_result,
                }
            )
            return True
        if stage == "indexes" and self.client.is_information_schema_statistics_query(result_sql):
            state.slow_query_index_results.append(
                {
                    "stage": "indexes",
                    "source_history_row": dict(source),
                    "target": dict(target),
                    "source": "information_schema.STATISTICS",
                    "result": projected_result,
                }
            )
            return True
        return False

    def _slow_query_analysis_stage(self, call: PreparedCall) -> str | None:
        sql = call.effective_arguments.get("sql_content")
        if isinstance(sql, str):
            if re.match(r"(?is)^\s*explain\b", sql):
                return "explain"
            if self.client.is_information_schema_columns_query(sql):
                return "table_structure"
            if self.client.is_information_schema_statistics_query(sql):
                return "indexes"
        if call.tool_name == ARCHERY_MCP_COLUMNS_TOOL_NAME:
            return "table_structure"
        if call.tool_name in {
            ARCHERY_MCP_INSTANCES_TOOL_NAME,
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            ARCHERY_MCP_TABLES_TOOL_NAME,
        }:
            return "target_resolution"
        return None

    def _analysis_failure(
        self,
        call: PreparedCall,
        *,
        stage: str,
        error_type: str,
        detail: str,
    ) -> dict[str, Any]:
        normalized_detail = safe_error_detail(detail)
        folded = normalized_detail.casefold()
        if "allowlist" in folded or "白名单" in normalized_detail:
            classified_type = "permission_denied"
            reason_code = "instance_not_allowlisted"
        elif any(token in folded for token in ("permission", "forbidden", "denied", "403")) or (
            "权限" in normalized_detail
        ):
            classified_type = "permission_denied"
            reason_code = "permission_denied"
        elif any(token in folded for token in ("doesn't exist", "not found", "unknown table")) or (
            "表不存在" in normalized_detail
        ):
            classified_type = "table_not_found"
            reason_code = "table_not_found"
        elif stage == "explain" and any(
            token in folded
            for token in (
                "not supported",
                "unsupported",
                "syntax error",
                "you have an error in your sql syntax",
                "error 1064",
            )
        ):
            classified_type = "explain_not_supported"
            reason_code = "explain_not_supported_by_target"
        else:
            classified_type = error_type or "tool_error"
            reason_code = error_type or "tool_error"
        table_name = call.effective_arguments.get("tb_name")
        db_name: str | None = None
        sql = call.effective_arguments.get("sql_content")
        if isinstance(sql, str):
            sql_target = self.client.information_schema_target(sql)
            db_name = sql_target.get("db_name")
            table_name = sql_target.get("table_name") or table_name
            if stage == "explain":
                inner_sql = self.client.classify_plain_explain(sql)
                table_name = next(
                    iter(
                        sorted(
                            self.client.explainable_table_references(inner_sql or ""),
                            key=str.casefold,
                        )
                    ),
                    table_name,
                )
        binding = call.metadata.get("analysis_binding")
        bound_target = (
            binding.get("target") if isinstance(binding, Mapping) else None
        )
        failure: dict[str, Any] = {
            "stage": stage,
            "target": (
                dict(bound_target)
                if isinstance(bound_target, Mapping)
                else self._analysis_target(
                    call,
                    db_name=db_name,
                    table_name=table_name if isinstance(table_name, str) else None,
                )
            ),
            "error_type": classified_type,
            "reason_code": reason_code,
            "detail": normalized_detail,
        }
        bound_source = (
            binding.get("source_history_row")
            if isinstance(binding, Mapping)
            else None
        )
        if isinstance(bound_source, Mapping):
            failure["source_history_row"] = dict(bound_source)
        return failure

    def _analysis_target(
        self,
        call: PreparedCall,
        *,
        db_name: str | None = None,
        table_name: str | None = None,
    ) -> dict[str, Any]:
        return self._analysis_target_from_arguments(
            self.client.target_key(call.effective_arguments),
            call.effective_arguments,
            db_name=db_name,
            table_name=table_name,
        )

    @staticmethod
    def _analysis_target_from_arguments(
        target: tuple[int, str] | None,
        arguments: Mapping[str, Any],
        *,
        db_name: str | None = None,
        table_name: str | None = None,
    ) -> dict[str, Any]:
        projected: dict[str, Any] = {}
        if target is not None:
            projected["instance_id"] = target[0]
            projected["db_name"] = db_name or target[1]
        elif isinstance(arguments.get("instance_id"), int):
            projected["instance_id"] = arguments["instance_id"]
        if db_name:
            projected["db_name"] = db_name
        elif "db_name" not in projected and isinstance(arguments.get("db_name"), str):
            projected["db_name"] = arguments["db_name"]
        if table_name:
            projected["table_name"] = table_name
        return projected

    @staticmethod
    def _has_history_result(state: ArcheryHarnessState) -> bool:
        return state.final_result is not None or bool(
            state.history_merge_sources and state.history_id_rows
        )

    @classmethod
    def _has_history_context(cls, state: ArcheryHarnessState) -> bool:
        return cls._has_history_result(state) or state.history_result_target is not None

    def _history_payload(self, state: ArcheryHarnessState) -> dict[str, Any]:
        if state.history_merge_sources and state.history_id_rows:
            return _history_payload_with_recovery_status(
                self.client.merged_history_payload(
                    state.history_id_rows,
                    state.history_merge_sources,
                ),
                state,
            )
        return (
            _history_payload_with_recovery_status(state.final_result.payload, state)
            if state.final_result is not None
            else {}
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
        local_rejection = call.metadata.get("local_rejection")
        if isinstance(local_rejection, Mapping):
            failure = dict(local_rejection)
            if self._has_history_context(state) or state.supplemental_analysis_started:
                state.slow_query_analysis_failures.append(failure)
            trace = self._trace(state, call)
            if trace is not None:
                trace["outcome"] = "rejected_locally"
                trace["error_type"] = failure.get("error_type")
                trace["reason_code"] = failure.get("reason_code")
                trace["error_detail"] = failure.get("detail")
            return self._internal_only_transition(
                state,
                call,
                raw_result={"status": "rejected", **failure},
            )
        self._record_remote_call(state, call)
        payload = self.client.extract_tool_payload(result)
        text_blocks = self.client.tool_text_blocks(result)
        self.client.validate_business_success(
            payload,
            tool_name=call.tool_name,
            supplemental_text=text_blocks,
        )
        trace = self._trace(state, call)
        if trace is not None:
            trace["outcome"] = "ok"

        requested_sql = call.effective_arguments.get("sql_content")
        requested_sql = requested_sql if isinstance(requested_sql, str) else ""
        normalized_payload, executed_sql, actual_sql_verified = (
            self.client.normalize_query_payload(
                payload,
                requested_sql=requested_sql,
                supplemental_text=text_blocks,
            )
        )
        mismatch = self._response_mismatch(
            call,
            normalized_payload,
            raw_payload=payload,
            supplemental_text=text_blocks,
            executed_sql=executed_sql,
            actual_sql_verified=actual_sql_verified,
        )
        if mismatch is not None:
            if self._has_history_context(state) or state.supplemental_analysis_started:
                state.slow_query_analysis_failures.append(mismatch)
            if trace is not None:
                trace["outcome"] = "result_mismatch"
                trace["error_type"] = mismatch["error_type"]
                trace["reason_code"] = mismatch["reason_code"]
                trace["error_detail"] = mismatch["detail"]
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )

        incomplete_failure = self._supplemental_incomplete_result_failure(
            call,
            normalized_payload,
        )
        if incomplete_failure is not None:
            state.slow_query_analysis_failures.append(incomplete_failure)
            if trace is not None:
                trace["outcome"] = "incomplete_result"
                trace["error_type"] = incomplete_failure["error_type"]
                trace["reason_code"] = incomplete_failure["reason_code"]
                trace["error_detail"] = incomplete_failure["detail"]
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )

        if self._has_history_result(state) and call.tool_name == ARCHERY_MCP_INSTANCES_TOOL_NAME:
            for instance_id, endpoints in self.client.allowlisted_instance_endpoints(
                payload
            ).items():
                state.analysis_instance_endpoints.setdefault(instance_id, set()).update(
                    endpoints
                )

        if self._has_history_result(state) and call.tool_name == ARCHERY_MCP_DATABASES_TOOL_NAME:
            instance_id = self.client._coerce_positive_integer(
                call.effective_arguments.get("instance_id")
            )
            if instance_id is not None:
                reported_values = self.client.reported_execution_target_values(
                    payload,
                    supplemental_text=text_blocks,
                )
                reported_instances = reported_values.get("instance_id", set())
                reported_endpoints = {
                    str(item).casefold()
                    for item in reported_values.get("endpoint", set())
                }
                expected_endpoints = {
                    item.casefold()
                    for item in state.analysis_instance_endpoints.get(instance_id, set())
                }
                discovery_mismatch = any(
                    reported_instance != instance_id
                    for reported_instance in reported_instances
                ) or any(
                    reported_endpoint not in expected_endpoints
                    for reported_endpoint in reported_endpoints
                )
                if discovery_mismatch:
                    state.slow_query_analysis_failures.append(
                        self._local_rejection(
                            stage="target_resolution",
                            target={"instance_id": instance_id},
                            error_type="result_mismatch",
                            reason_code="actual_target_mismatch",
                            detail=(
                                "数据库发现结果回显的实际实例与已绑定请求不一致，"
                                "返回数据库未用于授权补充查询。"
                            ),
                        )
                    )
                else:
                    databases = self.client.allowlisted_database_names(payload)
                    if databases:
                        state.analysis_database_names.setdefault(instance_id, set()).update(
                            databases
                        )

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
        if call.tool_name == ARCHERY_MCP_COLUMNS_TOOL_NAME and self._has_history_result(state):
            self._collect_table_columns_result(state, call, normalized_payload)
        result_sql = executed_sql or requested_sql
        if not result_sql:
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )
        target = self.client.target_key(call.effective_arguments)
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
        if (
            is_final_history_result
            and call.metadata.get("history_query_authorized") is not True
        ):
            failure = self._local_rejection(
                stage="history_recovery",
                target=self._analysis_target_from_arguments(
                    target,
                    call.effective_arguments,
                ),
                error_type="authorization_missing",
                reason_code="history_query_not_authorized",
                detail="history 结果缺少当前策略生成的调用授权，结果未被采用。",
            )
            if trace is not None:
                trace["outcome"] = "result_mismatch"
                trace["error_type"] = failure["error_type"]
                trace["reason_code"] = failure["reason_code"]
                trace["error_detail"] = failure["detail"]
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )
        if not is_final_history_result:
            if self._has_history_result(state) and self._collect_slow_query_analysis_result(
                state,
                call,
                normalized_payload,
                result_sql=result_sql,
            ):
                return self._internal_only_transition(
                    state,
                    call,
                    raw_result=result,
                )
            target = self.client.target_key(call.effective_arguments)
            if (
                target is not None
                and call.metadata.get("pre_history_metadata_authorized") is True
            ):
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

        if state.history_result_target is None:
            state.history_result_target = target
        elif target != state.history_result_target:
            failure = self._local_rejection(
                stage="history_recovery",
                target=self._analysis_target_from_arguments(
                    target, call.effective_arguments
                ),
                error_type="result_mismatch",
                reason_code="history_target_mismatch",
                detail="history 结果目标与首次已验证的 history 目标不一致，结果未被采用。",
            )
            state.slow_query_analysis_failures.append(failure)
            if trace is not None:
                trace["outcome"] = "result_mismatch"
                trace["error_type"] = failure["error_type"]
                trace["error_detail"] = failure["detail"]
            return self._internal_only_transition(
                state,
                call,
                raw_result=result,
            )
        # Truncation-recovery navigation: an id listing or a per-id retrieval
        # query must never become the final slow-log result (run 2970f801 lost
        # 5 of 6 window rows because each history SELECT overwrote it).
        if self.client.is_history_id_only_projection(result_sql):
            if not self._is_scoped_history_id_listing(state, result_sql):
                failure = self._local_rejection(
                    stage="history_recovery",
                    target=self._analysis_target_from_arguments(
                        target, call.effective_arguments
                    ),
                    error_type="result_mismatch",
                    reason_code="history_recovery_query_forbidden",
                    detail="MCP 实际执行的 id 清单没有保留严格窗口约束，返回 id 未获授权。",
                )
                state.slow_query_analysis_failures.append(failure)
                return self._internal_only_transition(
                    state,
                    call,
                    raw_result=result,
                )
            listed_ids = self.client.history_row_ids(normalized_payload)
            listing_row_count = self.client.payload_row_count(normalized_payload)
            valid_id_listing = (
                listing_row_count is not None
                and len(listed_ids) == listing_row_count
            )
            state.history_recovery_required = True
            state.history_recovery_terminal_failure = False
            state.history_recovery_ids = listed_ids
            state.history_recovery_listing_completed = (
                valid_id_listing
                and not self.client.is_result_incomplete(normalized_payload)
            )
            self._resolve_deferred_positional_rows(state)
            return self._history_observation_transition(
                state,
                call,
                result,
                normalized_payload,
                result_sql=result_sql,
            )
        if self.client.is_history_id_retrieval_query(result_sql):
            retrieval = self.client.history_id_retrieval(result_sql)
            assert retrieval is not None
            row_id, projection = retrieval
            returned_ids = self.client.history_row_ids(normalized_payload)
            if returned_ids - {row_id}:
                failure = self._local_rejection(
                    stage="history_recovery",
                    target=self._analysis_target_from_arguments(
                        target, call.effective_arguments
                    ),
                    error_type="result_mismatch",
                    reason_code="history_row_id_mismatch",
                    detail="per-id 恢复结果包含请求 id 之外的行，结果未进入合并证据。",
                )
                state.slow_query_analysis_failures.append(failure)
                return self._internal_only_transition(
                    state,
                    call,
                    raw_result=result,
                )
            named_rows = self.client._tabular_rows(normalized_payload)
            trusted_full_row = (
                projection == "full"
                and actual_sql_verified
                and not self.client.is_result_incomplete(normalized_payload)
                and self.client.payload_row_count(normalized_payload) == 1
                and len(named_rows) == 1
                and returned_ids == {row_id}
                and self.client._coerce_positive_integer(
                    self.client._casefolded_value(named_rows[0], "id")
                )
                == row_id
                and any(str(key).casefold() == "sample" for key in named_rows[0])
                and isinstance(
                    self.client._casefolded_value(named_rows[0], "sample"), str
                )
            )
            if (
                projection == "sample_prefix"
                and returned_ids == {row_id}
                and len(named_rows) == 1
                and isinstance(
                    self.client._casefolded_value(named_rows[0], "sample"), str
                )
            ):
                if row_id not in state.history_full_row_ids:
                    state.history_sample_prefix_ids.add(row_id)
            elif projection == "full" and trusted_full_row:
                state.history_full_row_ids.add(row_id)
                state.history_sample_prefix_ids.discard(row_id)
                reference_columns = [str(column) for column in named_rows[0]]
                if (
                    reference_columns
                    and reference_columns[0].casefold() == "id"
                    and len({column.casefold() for column in reference_columns})
                    == len(reference_columns)
                ):
                    state.history_positional_reference_columns = reference_columns
            elif (
                projection == "full"
                and returned_ids == {row_id}
                and any(
                    str(key).casefold() == "sample"
                    for row in named_rows
                    for key in row
                )
            ):
                state.history_full_row_ids.discard(row_id)
                state.history_sample_prefix_ids.add(row_id)
            self.client.accumulate_history_rows(
                state.history_id_rows,
                state.history_merge_sources,
                normalized_payload,
                sql=result_sql,
                include_source=True,
                projection=(
                    "unverified_full"
                    if projection == "full" and not trusted_full_row
                    else projection
                ),
            )
            self._resolve_deferred_positional_rows(state)
            return self._history_observation_transition(
                state,
                call,
                result,
                normalized_payload,
                result_sql=result_sql,
            )
        window_note: str | None = None
        if self.client.is_result_incomplete(normalized_payload):
            # Truncated window query: recovered rows join the accumulation
            # while final_result keeps recording this query as the window
            # baseline; the merge itself happens in _query_result.
            state.history_id_rows.clear()
            state.history_merge_sources.clear()
            state.history_recovery_ids.clear()
            state.history_positional_rows = []
            state.history_positional_reference_columns = []
            state.history_sample_prefix_ids.clear()
            state.history_full_row_ids.clear()
            state.history_recovery_required = True
            state.history_recovery_listing_completed = False
            state.history_recovery_terminal_failure = False
            self.client.accumulate_history_rows(
                state.history_id_rows,
                state.history_merge_sources,
                normalized_payload,
                sql=result_sql,
                include_source=False,
            )
            if actual_sql_verified:
                state.history_full_row_ids.update(
                    row_id
                    for row in self.client._tabular_rows(normalized_payload)
                    if (
                        row_id := self.client._coerce_positive_integer(
                            self.client._casefolded_value(row, "id")
                        )
                    )
                    is not None
                    and isinstance(self.client._casefolded_value(row, "sample"), str)
                )
            recovered_rows = normalized_payload.get("rows")
            if isinstance(recovered_rows, list) and recovered_rows and any(
                not isinstance(row, Mapping) for row in recovered_rows
            ):
                # Archery places column_list after "rows", so a mid-rows
                # truncation leaves recovered rows positional. Defer them until
                # a structured row reveals the table column order.
                state.history_positional_rows = [
                    deepcopy(row)
                    for row in recovered_rows
                    if not isinstance(row, Mapping)
                ]
                declared_columns = normalized_payload.get(
                    "columns"
                ) or normalized_payload.get("column_list")
                if (
                    isinstance(declared_columns, list)
                    and declared_columns
                    and all(isinstance(column, str) for column in declared_columns)
                    and len({column.casefold() for column in declared_columns})
                    == len(declared_columns)
                ):
                    state.history_positional_reference_columns = list(declared_columns)
                self._resolve_deferred_positional_rows(state)
                if not state.window_positional_hint_given:
                    state.window_positional_hint_given = True
                    window_note = (
                        "\n\n【程序截断检测-列名缺失】window 查询被 MCP 截断：程序恢复了 "
                        + str(len(recovered_rows))
                        + " 行原始数据，但列名清单（column_list）位于截断点之后而丢失，这些行"
                        "暂时无法结构化进入最终合并结果（截断点所在行未被恢复）。请执行 id 清单"
                        "查询（SELECT id FROM "
                        + ARCHERY_SLOW_QUERY_REVIEW_TABLE
                        + " ...），并以下一条消息的程序合并检测提示为准，对缺失 id 逐一执行"
                        "per-id 查询。"
                    )
        else:
            # A fresh complete window query starts a new baseline: discard any
            # earlier accumulation so stale rows cannot leak into the result.
            state.history_id_rows.clear()
            state.history_merge_sources.clear()
            state.history_recovery_ids.clear()
            state.history_positional_rows = []
            state.history_positional_reference_columns = []
            state.history_sample_prefix_ids.clear()
            state.history_full_row_ids.clear()
            state.history_recovery_required = False
            state.history_recovery_listing_completed = False
            state.history_recovery_terminal_failure = False
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
                self._raw_model_tool_result(result) + (window_note or ""),
            ),
            status=(
                ToolInvocationStatus.NO_DATA
                if self.client.payload_row_count(normalized_payload) == 0
                else ToolInvocationStatus.SUCCEEDED
            ),
        )

    def _history_observation_transition(
        self,
        state: ArcheryHarnessState,
        call: PreparedCall,
        result: Any,
        normalized_payload: Mapping[str, Any],
        *,
        result_sql: str,
    ) -> ScenarioTransition[ArcheryHarnessState, dict[str, Any]]:
        """Return an id-listing / per-id retrieval result to the model only.

        The result still reaches the model unchanged and stays in the query
        trace; it simply never becomes the final slow-log result. When the MCP
        truncated the payload and complete rows were lost, a one-time program
        hint appended to the tool message asks the model to retry the same SQL
        once with an explicit ``max_result_chars`` so the truncated id is not
        silently dropped (run 92c9a017 lost id=24413640 this way: the model
        acknowledged the truncation but moved on without retrying).
        """

        content = self._raw_model_tool_result(result)
        if self.client.is_history_id_only_projection(result_sql):
            content = self._append_missing_id_hint(state, content, normalized_payload)
        shortfall = self.client.truncation_row_shortfall(normalized_payload)
        if shortfall is not None:
            hint_key = re.sub(r"\s+", " ", result_sql).strip().casefold()
            declared, recovered = shortfall
            limit_argument = call.effective_arguments.get("max_result_chars")
            carries_high_limit = isinstance(limit_argument, int) and limit_argument >= 24000
            if (
                not carries_high_limit
                and hint_key not in state.truncation_retry_hinted_sqls
            ):
                state.truncation_retry_hinted_sqls.add(hint_key)
                content = (
                    content
                    + "\n\n【程序截断检测】本次查询结果被 MCP 因内容过长截断：MCP 声明返回 "
                    + str(declared)
                    + " 行，程序仅恢复出 "
                    + str(recovered)
                    + " 行完整数据。请立即用相同的 SQL 重试一次本次查询，并在调用参数中"
                    "显式传 max_result_chars=24000；若重试后仍被截断，请继续其余调查"
                    "步骤，不要再次重试该 SQL。"
                )
            elif hint_key not in state.truncation_projection_hinted_sqls:
                state.truncation_retry_hinted_sqls.add(hint_key)
                state.truncation_projection_hinted_sqls.add(hint_key)
                content = (
                    content
                    + "\n\n【程序截断检测-字段级】提高 max_result_chars 后仍被截断：MCP 声明返回 "
                    + str(declared)
                    + " 行，程序仅恢复出 "
                    + str(recovered)
                    + " 行完整数据。该行包含超长字段（通常为 sample，完整长度可达数十万"
                    "字符），提高 max_result_chars 也无法完整取回。请改用列投影查询取回该行："
                    "保留常规列，用 LEFT(sample, '4000') AS sample 代替 sample 列（取前缀），并加 "
                    "LENGTH(sample) AS sample_full_length 记录完整长度，两者会随该行一起进入"
                    "最终证据供主 Agent 分析。注意：LEFT 的长度参数必须写成带引号的 '4000'，"
                    "Archery 的 SQL 解析层不接受函数参数中的裸数字，否则会报 1064 语法错误。"
                    "参考 SQL：\n"
                    + self._projection_retry_template(result_sql)
                )
        return ScenarioTransition(
            state=state,
            observation=self.client.trace_projection(
                call.tool_name,
                normalized_payload,
            ),
            message=self._tool_result_messages(call, content),
            status=(
                ToolInvocationStatus.NO_DATA
                if self.client.payload_row_count(normalized_payload) == 0
                else ToolInvocationStatus.SUCCEEDED
            ),
        )

    def _projection_retry_template(self, result_sql: str) -> str:
        """Build the column-projection SQL suggested after a fatal truncation."""

        match = re.search(r"(?i)\bid\s*=\s*(\d+)", result_sql)
        if match is None:
            return "无法生成字段级恢复 SQL：原查询缺少单一数字 id。"
        return self.client.history_sample_projection_sql(int(match.group(1)))

    def _resolve_deferred_positional_rows(self, state: ArcheryHarnessState) -> None:
        """Decode deferred rows only from a verified full-row column order."""

        if not state.history_positional_rows:
            return
        unresolved = self.client.merge_positional_rows_with_reference(
            state.history_id_rows,
            state.history_positional_rows,
            state.history_positional_reference_columns,
            allowed_ids=(
                set(state.history_recovery_ids)
                if state.history_recovery_listing_completed
                else set()
            ),
            trusted_full_row_ids=state.history_full_row_ids,
            sample_prefix_ids=state.history_sample_prefix_ids,
        )
        state.history_positional_rows = unresolved
        if not unresolved:
            state.history_positional_reference_columns = []

    def _append_missing_id_hint(
        self,
        state: ArcheryHarnessState,
        content: str,
        normalized_payload: Mapping[str, Any],
    ) -> str:
        """Tell the model which listed ids are still missing from the merge."""

        listed_ids = self.client.history_row_ids(normalized_payload)
        missing = sorted(listed_ids - set(state.history_id_rows.keys()))
        if not missing:
            return content
        return (
            content
            + "\n\n【程序合并检测】id 清单共 "
            + str(len(listed_ids))
            + " 个，其中 "
            + str(len(missing))
            + " 个尚未进入最终合并结果（window 查询截断恢复的行会因列名缺失暂缓合并）。"
            "请对下列 id 逐一执行 per-id 查询（SELECT * FROM "
            + ARCHERY_SLOW_QUERY_REVIEW_TABLE
            + " WHERE id = X）："
            + ", ".join(str(row_id) for row_id in missing)
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
        if self._has_history_result(state):
            stage = self._slow_query_analysis_stage(call)
            if stage is not None:
                state.slow_query_analysis_failures.append(
                    self._analysis_failure(
                        call,
                        stage=stage,
                        error_type=error.code,
                        detail=error.message,
                    )
                )

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
        # Persisting every reasoning delta as one durable event dominated the
        # planner wall time, so long slow-log summaries repeatedly exhausted
        # planner_timeout_seconds before the finish decision could return and
        # forced identical planner repairs. The complete reasoning is still
        # recorded once per decision through MODEL_DECISION / TRACE_REASONING,
        # so no audit evidence is lost.
        stream_planner_reasoning=False,
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
    _record_history_recovery_terminal_failure(
        state,
        detail=(
            "Archery 调查已终止，但 history 截断恢复尚未完成；"
            "当前仅保留已恢复行并明确标记为不完整证据。"
        ),
    )
    if (
        state.final_result is None
        and state.history_merge_sources
        and state.history_id_rows
    ):
        # Truncation recovery can also run without any successful full-column
        # window query: the model jumps straight from the id listing to per-id
        # retrievals (observed 2026-08-17: 14 rows recovered, yet no query ever
        # set final_result, so the main Agent received "no passthrough result"
        # and the whole evidence set was lost). Rebuild the final result from
        # the accumulated rows so the merged row set stays available.
        raw_target = state.history_result_target or state.last_query_target
        fallback_target = (
            (raw_target[0], raw_target[1])
            if isinstance(raw_target, (list, tuple))
            and len(raw_target) == 2
            and type(raw_target[0]) is int
            and isinstance(raw_target[1], str)
            else None
        )
        resolution_tables: tuple[str, ...] = ()
        if fallback_target is not None:
            resolution_steps = state.metadata_resolution_steps
            resolved_steps = resolution_steps.get(fallback_target)
            if resolved_steps is None:
                resolved_steps = next(
                    (
                        value
                        for key, value in resolution_steps.items()
                        if list(key) == list(fallback_target)
                    ),
                    None,
                )
            resolution_tables = tuple(resolved_steps or ())
        state.final_result = ArcherySlowLogQueryResult(
            payload=_history_payload_with_recovery_status(
                client.merged_history_payload(
                    state.history_id_rows,
                    state.history_merge_sources,
                ),
                state,
            ),
            requested_sql=str(state.history_merge_sources[0].get("full_sql") or ""),
            window_start=state.window_start,
            window_end=state.window_end,
            model_tool_calls=tuple(state.executed_model_calls),
            model_request_ids=tuple(state.model_request_ids),
            instance_id=(
                fallback_target[0] if fallback_target is not None else None
            ),
            db_name=(fallback_target[1] if fallback_target is not None else None),
            table_name=ARCHERY_SLOW_QUERY_REVIEW_TABLE,
            metadata_resolution_tables=resolution_tables,
            diagnostics={
                "final_result_source": "merged_per_id_queries_without_window_query"
            },
            query_completed=True,
        )
    if state.final_result is not None:
        final_result = replace(
            state.final_result,
            model_tool_calls=tuple(state.executed_model_calls),
            model_request_ids=tuple(state.model_request_ids),
            metadata_resolution_tables=tuple(
                state.final_result.metadata_resolution_tables
            ),
        )
        if state.history_merge_sources and state.history_id_rows:
            # The truncation-recovery path merged per-id retrieval rows; the
            # final result carries the complete row set instead of only the
            # last single query (run 2970f801 lost 5 of 6 rows without this).
            final_result = replace(
                final_result,
                payload=_history_payload_with_recovery_status(
                    client.merged_history_payload(
                        state.history_id_rows,
                        state.history_merge_sources,
                    ),
                    state,
                ),
            )
        else:
            final_result = replace(
                final_result,
                payload=_history_payload_with_recovery_status(
                    final_result.payload,
                    state,
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
        diagnostics["history_recovery_complete"] = _history_recovery_complete(state)
        diagnostics["history_recovery_id_listing_complete"] = (
            state.history_recovery_listing_completed
        )
        diagnostics["history_recovery_missing_ids"] = sorted(
            _history_recovery_missing_ids(state)
        )
        return replace(
            final_result,
            diagnostics=diagnostics,
            slow_query_analysis=_build_slow_query_analysis(client, state, final_result.payload),
        )

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


def _build_slow_query_analysis(
    client: ArcheryMCPClient,
    state: ArcheryHarnessState,
    history_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build supplemental facts without changing the final history contract."""

    explain_results = deepcopy(getattr(state, "slow_query_explain_results", []))
    table_results = deepcopy(getattr(state, "slow_query_table_structure_results", []))
    index_results = deepcopy(getattr(state, "slow_query_index_results", []))
    failures = deepcopy(getattr(state, "slow_query_analysis_failures", []))
    candidates = client.select_explainable_history_rows(
        history_payload,
        sample_prefix_ids=getattr(state, "history_sample_prefix_ids", set()),
    )
    source_history_row = (
        client.slow_query_source_row(candidates[0]) if candidates else None
    )

    def source_key(source: Mapping[str, Any]) -> tuple[str, str, str]:
        return (
            str(source.get("id") or ""),
            str(source.get("checksum") or "").casefold(),
            str(source.get("sample") or ""),
        )

    expected: list[dict[str, Any]] = []
    for row in candidates:
        source = client.slow_query_source_row(row)
        endpoint = client._normalize_endpoint(source.get("hostname_max"))
        matching_ids = (
            sorted(
                instance_id
                for instance_id, endpoints in state.analysis_instance_endpoints.items()
                if endpoint is not None
                and endpoint.casefold() in {item.casefold() for item in endpoints}
            )
            if endpoint is not None
            else []
        )
        instance_id = matching_ids[0] if len(matching_ids) == 1 else None
        db_name = source.get("db_max")
        db_is_allowlisted = bool(
            instance_id is not None
            and isinstance(db_name, str)
            and db_name.strip() in state.analysis_database_names.get(instance_id, set())
        )
        sample = str(source.get("sample") or "")
        expected.append(
            {
                "source": source,
                "source_key": source_key(source),
                "instance_id": instance_id,
                "db_name": db_name.strip() if isinstance(db_name, str) else None,
                "target_bound": instance_id is not None and db_is_allowlisted,
                "endpoint": endpoint.casefold() if endpoint is not None else None,
                "tables": {
                    client.clean_table_name(item)
                    for item in client.explainable_table_references(sample)
                },
            }
        )

    def matching_result(
        items: Sequence[Mapping[str, Any]],
        work: Mapping[str, Any],
        *,
        table_name: str | None = None,
        require_nonempty: bool = False,
        require_source: bool = False,
    ) -> bool:
        if not work.get("target_bound"):
            return False
        for item in items:
            item_source = item.get("source_history_row")
            item_target = item.get("target")
            result = item.get("result")
            if not isinstance(item_target, Mapping):
                continue
            if require_source and (
                not isinstance(item_source, Mapping)
                or source_key(item_source) != work["source_key"]
            ):
                continue
            if item_target.get("instance_id") != work["instance_id"]:
                continue
            if str(item_target.get("db_name") or "") != str(work.get("db_name") or ""):
                continue
            if table_name is not None and client.clean_table_name(
                str(item_target.get("table_name") or "")
            ).casefold() != client.clean_table_name(table_name).casefold():
                continue
            if require_nonempty and (
                not isinstance(result, Mapping) or not result.get("row_count")
            ):
                continue
            return True
        return False

    missing_stage_names: set[str] = set()
    completed_work = 0
    total_work = 0
    for work in expected:
        total_work += 1
        if matching_result(
            explain_results,
            work,
            require_nonempty=True,
            require_source=True,
        ):
            completed_work += 1
        else:
            missing_stage_names.add("explain")
        for table_name in work["tables"]:
            total_work += 1
            if matching_result(
                table_results,
                work,
                table_name=table_name,
                require_nonempty=True,
            ):
                completed_work += 1
            else:
                missing_stage_names.add("table_structure")
            total_work += 1
            if matching_result(index_results, work, table_name=table_name):
                completed_work += 1
            else:
                missing_stage_names.add("indexes")
    missing_stages = [
        stage
        for stage in ("explain", "table_structure", "indexes")
        if stage in missing_stage_names
    ]

    target: dict[str, Any] = {}
    if expected:
        primary = expected[0]
        if primary["instance_id"] is not None:
            target["instance_id"] = primary["instance_id"]
        if primary["db_name"] is not None:
            target["db_name"] = primary["db_name"]
        if primary["endpoint"] is not None:
            target["hostname"] = primary["endpoint"]

    if not candidates:
        status = "not_applicable"
        missing_stages = []
        if not any(
            item.get("reason_code") == "no_safe_explainable_sample"
            for item in failures
        ):
            failures.append(
                {
                    "stage": "explain",
                    "target": target,
                    "error_type": "sample_parse_failed",
                    "reason_code": "no_safe_explainable_sample",
                    "detail": "history 结果中没有可由普通 EXPLAIN 安全分析的单语句 sample。",
                }
            )
    elif total_work > 0 and completed_work == total_work and not failures:
        status = "succeeded"
    elif completed_work:
        status = "partial"
    else:
        status = "failed"
        if not failures:
            failures.append(
                {
                    "stage": "explain",
                    "target": target,
                    "error_type": "analysis_not_attempted",
                    "reason_code": "slow_query_analysis_not_attempted",
                    "detail": "history 查询成功，但未尝试 EXPLAIN、表结构或索引补充分析。",
                }
            )

    return sanitize(
        {
            "status": status,
            "source_history_row": source_history_row,
            "target": target,
            "explain_results": explain_results,
            "table_structure_results": table_results,
            "index_results": index_results,
            "missing_stages": missing_stages,
            "failures": failures,
        }
    )
