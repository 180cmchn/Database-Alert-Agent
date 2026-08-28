"""Prometheus transport, planning, and scenario adapter for the shared Harness."""

from __future__ import annotations

import inspect
import json
from collections import deque
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid4, uuid5

import httpx
from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

from app.adapters.prometheus_mcp import (
    _FINISH_TOOL_NAME,
    PROMETHEUS_ALERT_WINDOW_SECONDS,
    PROMETHEUS_MCP_PROMPT_VERSION,
    PROMETHEUS_MCP_SERVER_NAME,
    PrometheusMCPClient,
    PrometheusMCPConfigurationError,
    PrometheusMCPError,
    PrometheusMCPModelError,
    PrometheusMCPProtocolError,
    PrometheusMCPQueryResult,
    PrometheusMCPToolError,
)
from app.agent_runtime import (
    AgentEventKind,
    ArtifactRef,
    BudgetLedger,
    BudgetLimits,
    InMemoryEventSink,
    RepositoryEventSink,
    RepositoryInvocationStore,
    RuntimeStopReason,
    ToolInvocationStatus,
    ToolSpec,
)
from app.application.sanitization import sanitize, sanitize_text
from app.domain.models import InvestigationContext
from app.domain.ports import AlertRepository
from app.domain.tool_calling import MCPModelToolCall, ReasoningDeltaCallback
from app.mcp_runtime import (
    DiscoveredMCPTool,
    Finish,
    HarnessObservation,
    MCPAgentHarnessRuntime,
    PreparedCall,
    RepositoryMCPCheckpointStore,
    RetryDirective,
    ScenarioTransition,
    event_matches_dispatch_scope,
)


@dataclass(frozen=True, slots=True)
class PrometheusHarnessRuntimeDependencies:
    repository: AlertRepository


_PROMETHEUS_REMOTE_RESPONSE_ARTIFACT_CONTRACT = "prometheus-mcp-remote-response/v2"


class RepositoryPrometheusRemoteResponseStore:
    """Persist complete MCP responses after the Prometheus investigation ends."""

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
        contract: str = _PROMETHEUS_REMOTE_RESPONSE_ARTIFACT_CONTRACT,
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
            "contract": _PROMETHEUS_REMOTE_RESPONSE_ARTIFACT_CONTRACT,
            "provider": PROMETHEUS_MCP_SERVER_NAME,
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
            kind="prometheus_mcp_remote_response",
            media_type="application/json",
            uri=f"agent-artifact://{artifact_id}",
            metadata={
                "contract": _PROMETHEUS_REMOTE_RESPONSE_ARTIFACT_CONTRACT,
                "provider": PROMETHEUS_MCP_SERVER_NAME,
                "run_id": str(run_id),
                "tool_name": tool_name,
                "invocation_id": str(invocation_id),
                "outer_dispatch_id": (
                    str(self.outer_dispatch_id) if self.outer_dispatch_id is not None else None
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
            or artifact.kind != "prometheus_mcp_remote_response"
            or artifact.media_type != "application/json"
            or artifact.uri != f"agent-artifact://{artifact_id}"
            or metadata.get("contract") != _PROMETHEUS_REMOTE_RESPONSE_ARTIFACT_CONTRACT
            or metadata.get("provider") != PROMETHEUS_MCP_SERVER_NAME
            or metadata.get("run_id") != str(run_id)
            or metadata.get("tool_name") != tool_name
            or metadata.get("invocation_id") != str(invocation_id)
            or metadata.get("outer_dispatch_id") != expected_outer_dispatch_id
            or metadata.get("sanitized") is not False
            or metadata.get("raw_response_unmodified") is not True
            or metadata.get("internal_only") is not True
        ):
            raise RuntimeError(
                f"Prometheus remote-response artifact metadata is invalid: {artifact_id}"
            )
        if (
            content.get("contract") != _PROMETHEUS_REMOTE_RESPONSE_ARTIFACT_CONTRACT
            or content.get("provider") != PROMETHEUS_MCP_SERVER_NAME
            or content.get("run_id") != str(run_id)
            or content.get("invocation_id") != str(invocation_id)
            or content.get("outer_dispatch_id") != expected_outer_dispatch_id
            or content.get("tool_name") != tool_name
            or content.get("arguments") != sanitize(arguments)
            or "response" not in content
        ):
            raise RuntimeError(
                f"Prometheus remote-response artifact content is invalid: {artifact_id}"
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
                    f"Prometheus remote-response artifact content is invalid: {artifact_id}"
                ) from exc
        elif isinstance(content, str):
            try:
                content = json.loads(content)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Prometheus remote-response artifact content is invalid: {artifact_id}"
                ) from exc
        if not isinstance(content, dict):
            raise RuntimeError(
                f"Prometheus remote-response artifact content is invalid: {artifact_id}"
            )
        return content


@dataclass(slots=True)
class PrometheusHarnessState:
    window_start: datetime
    window_end: datetime
    responses: list[dict[str, Any]] = field(default_factory=list)
    tool_attempts: list[dict[str, Any]] = field(default_factory=list)
    executed_calls: list[MCPModelToolCall] = field(default_factory=list)
    consecutive_model_errors: list[dict[str, Any]] = field(default_factory=list)
    last_error_type: str | None = None
    last_error_detail: str | None = None
    monitoring_scope_status: str = "not_checked"
    monitoring_scope_reason: str | None = None
    monitored_database_engines: list[str] = field(default_factory=list)
    monitoring_target_identifiers: list[str] = field(default_factory=list)

    @property
    def has_monitoring_data(self) -> bool:
        return PrometheusMCPClient.responses_have_monitoring_data(self.responses)


_PROMETHEUS_MCP_TRANSPORT_ERROR_CODE = "prometheus_mcp_transport_error"


def _no_redirect_http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """Build an MCP transport client without forwarding credentials on redirects."""

    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=False,
    )


class _PrometheusMCPTransportError(PrometheusMCPProtocolError):
    code = _PROMETHEUS_MCP_TRANSPORT_ERROR_CODE
    retryable = True

    def __init__(self, *, operation: str, leaf: BaseException) -> None:
        detail = sanitize_text(str(leaf))[:500]
        suffix = f": {detail}" if detail else ""
        super().__init__(f"Prometheus MCP {operation} failed ({type(leaf).__name__}){suffix}")
        self.leaf_type = type(leaf).__name__


def _exception_leaves(error: BaseException) -> list[BaseException]:
    if isinstance(error, BaseExceptionGroup):
        return [leaf for nested in error.exceptions for leaf in _exception_leaves(nested)]
    return [error]


def _is_mcp_transport_error(error: BaseException) -> bool:
    if isinstance(
        error,
        (
            ConnectionError,
            TimeoutError,
            BrokenResourceError,
            ClosedResourceError,
            EndOfStream,
            httpx.TransportError,
        ),
    ):
        return True
    module = type(error).__module__
    return (
        module == "httpcore"
        or module.startswith("httpcore.")
        or module == "httpx_sse"
        or module.startswith("httpx_sse.")
    )


def _normalized_transport_exception(
    error: BaseException,
    *,
    operation: str,
) -> Exception | None:
    leaves = _exception_leaves(error)
    for leaf in leaves:
        if isinstance(leaf, PrometheusMCPError):
            return leaf
    for leaf in leaves:
        if _is_mcp_transport_error(leaf):
            return _PrometheusMCPTransportError(operation=operation, leaf=leaf)
    return None


class PrometheusMCPToolSession:
    """One initialized SDK session owned by an ``AsyncExitStack``."""

    def __init__(
        self,
        *,
        client: PrometheusMCPClient,
        stack: AsyncExitStack,
        session: Any,
        session_id: str,
    ) -> None:
        self.client = client
        self._stack = stack
        self._session = session
        self._session_id = session_id
        self._closed = False

    @property
    def session_id(self) -> str:
        return self._session_id

    async def list_tools(self) -> list[DiscoveredMCPTool]:
        try:
            raw_tools: list[Any] = []
            cursor: str | None = None
            seen_cursors: set[str] = set()
            first_page = True
            while True:
                response = (
                    await self._session.list_tools()
                    if first_page
                    else await self._session.list_tools(cursor=cursor)
                )
                first_page = False
                raw_tools.extend(response.tools)
                next_cursor = getattr(response, "nextCursor", None)
                if next_cursor is None:
                    next_cursor = getattr(response, "next_cursor", None)
                if not next_cursor:
                    break
                if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                    raise PrometheusMCPProtocolError(
                        "Prometheus MCP returned an invalid or repeated tool-list cursor"
                    )
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            if not raw_tools:
                raise PrometheusMCPProtocolError("Prometheus MCP returned no tools")
        except BaseException as exc:
            normalized = _normalized_transport_exception(exc, operation="tool discovery")
            if normalized is None or normalized is exc:
                raise
            raise normalized from exc
        return [self._convert_tool(tool) for tool in raw_tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            raw_result = await self._session.call_tool(name, arguments)
        except BaseException as exc:
            normalized = _normalized_transport_exception(exc, operation="tool call")
            if normalized is None or normalized is exc:
                raise
            raise normalized from exc
        return raw_result

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._stack.aclose()

    @staticmethod
    def _convert_tool(tool: Any) -> DiscoveredMCPTool:
        raw = tool.model_dump(mode="json") if hasattr(tool, "model_dump") else tool
        if not isinstance(raw, Mapping):
            raise PrometheusMCPProtocolError("Prometheus MCP tool schema is not an object")
        name = raw.get("name")
        schema = raw.get("inputSchema") or raw.get("input_schema") or {"type": "object"}
        if not isinstance(name, str) or not name or not isinstance(schema, dict):
            raise PrometheusMCPProtocolError("Prometheus MCP returned an invalid tool schema")
        return DiscoveredMCPTool(
            name=name,
            description=str(raw.get("description") or f"Prometheus MCP tool {name}"),
            input_schema=deepcopy(schema),
        )


class PrometheusMCPConnector:
    """Open one configured MCP session behind the provider-neutral connector API."""

    provider = PROMETHEUS_MCP_SERVER_NAME

    def __init__(self, client: PrometheusMCPClient) -> None:
        self.client = client

    async def open_session(self) -> PrometheusMCPToolSession:
        stack = AsyncExitStack()
        try:
            session_id = f"prometheus-mcp-{uuid4()}"
            get_session_id: Any = None
            if self.client.mcp_transport == "sse":
                read_stream, write_stream = await stack.enter_async_context(
                    sse_client(
                        self.client.mcp_url,
                        headers=self.client.headers,
                        timeout=self.client.timeout_seconds,
                        sse_read_timeout=self.client.sse_read_timeout_seconds,
                        httpx_client_factory=_no_redirect_http_client,
                    )
                )
            else:
                http_client = await stack.enter_async_context(
                    _no_redirect_http_client(
                        headers=dict(self.client.headers),
                        timeout=httpx.Timeout(self.client.timeout_seconds),
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
                        name="database-alert-agent", version="0.1.0"
                    ),
                )
            )
            await session.initialize()
            if get_session_id is not None:
                session_id = str(get_session_id() or session_id)
        except BaseException as exc:
            try:
                await stack.aclose()
            except BaseException:
                pass
            normalized = _normalized_transport_exception(exc, operation="session setup")
            if normalized is None or normalized is exc:
                raise
            raise normalized from exc
        return PrometheusMCPToolSession(
            client=self.client,
            stack=stack,
            session=session,
            session_id=session_id,
        )


class PrometheusHarnessPlanner:
    """Translate one provider function call into one strict harness action."""

    def __init__(
        self,
        *,
        client: PrometheusMCPClient,
        scenario: PrometheusHarnessScenario,
    ) -> None:
        self.client = client
        self.scenario = scenario
        self.last_reasoning_content: str | None = None

    @property
    def consecutive_errors(self) -> list[dict[str, Any]]:
        return self.scenario.current_state.consecutive_model_errors

    async def plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        reasoning_callback: ReasoningDeltaCallback | None = None,
    ) -> dict[str, Any]:
        return await self._plan(
            messages=messages,
            tools=tools,
            reasoning_callback=reasoning_callback,
        )

    async def _plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        reasoning_callback: ReasoningDeltaCallback | None = None,
    ) -> dict[str, Any]:
        state = self.scenario.current_state
        advertised_names = {tool.name for tool in tools}
        model_tool_list = [
            deepcopy(tool)
            for name, tool in sorted(self.scenario.model_tools.items())
            if name in advertised_names
        ]
        model_tools = self.client.model_tools_for_state(
            model_tool_list=model_tool_list,
        )
        model_messages = deepcopy(messages)
        model_messages.append(
            self.client.host_investigation_state_message(
                remote_calls_used=len(state.executed_calls),
                monitoring_scope_status=state.monitoring_scope_status,
                monitoring_scope_reason=state.monitoring_scope_reason,
            )
        )
        if messages and "Return exactly one valid Agent action" in str(
            messages[-1].get("content", "")
        ):
            model_messages.append(
                {
                    "role": "user",
                    "content": (
                        "上一轮没有形成有效的单工具调用。请严格从当前 functions 中选择"
                        "一个工具并按其 JSON Schema 生成参数，不要返回自然语言。"
                    ),
                }
            )
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
            diagnostic = {
                "error_type": type(exc).__name__,
                "error": sanitize_text(str(exc))[:500],
            }
            self.consecutive_errors.append(diagnostic)
            raise self._selection_error(model_tools, state) from exc

        self.consecutive_errors.clear()
        reasoning_content = call.reasoning_content
        self.last_reasoning_content = (
            reasoning_content
            if isinstance(reasoning_content, str) and reasoning_content.strip()
            else None
        )
        if call.name == _FINISH_TOOL_NAME:
            self.scenario.record_finish(call.arguments)
            reason = call.arguments.get("reason")
            return {
                "action": "finish",
                "reason": RuntimeStopReason.COMPLETED.value,
                "summary": (
                    sanitize_text(reason)
                    if isinstance(reason, str) and reason.strip()
                    else "Prometheus alert-window evidence collection is complete."
                ),
            }
        self.scenario.register_model_call(call)
        return {
            "action": "call_tool",
            "tool_name": call.name,
            "objective": "Collect Prometheus evidence relevant to the alert.",
            "hypothesis_ids": [],
            "arguments": deepcopy(call.arguments),
        }

    def _selection_error(
        self,
        model_tools: list[dict[str, Any]],
        state: PrometheusHarnessState,
    ) -> PrometheusMCPModelError:
        first = self.consecutive_errors[0]
        latest = self.consecutive_errors[-1]
        return PrometheusMCPModelError(
            "Model failed to select a Prometheus MCP tool: "
            f"first={first['error']}; latest={latest['error']}",
            diagnostic_data={
                "first_error_type": first["error_type"],
                "first_error": first["error"],
                "second_error_type": (
                    latest["error_type"] if len(self.consecutive_errors) > 1 else None
                ),
                "second_error": (latest["error"] if len(self.consecutive_errors) > 1 else None),
                "remote_calls_used": len(state.executed_calls),
                "available_tools": [
                    item.get("function", {}).get("name")
                    for item in model_tools
                    if isinstance(item, dict)
                ],
            },
        )


class PrometheusHarnessScenario:
    """Persist Prometheus calls and deterministic observations without policy gates."""

    provider = PROMETHEUS_MCP_SERVER_NAME

    def __init__(
        self,
        *,
        client: PrometheusMCPClient,
        context: InvestigationContext,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        self.client = client
        self.context = context
        self.window_start = window_start
        self.window_end = window_end
        self.model_tools: dict[str, dict[str, Any]] = {}
        self._pending_model_calls: list[MCPModelToolCall] = []
        self._state = PrometheusHarnessState(window_start, window_end)

    @property
    def current_state(self) -> PrometheusHarnessState:
        return self._state

    def register_model_call(self, call: MCPModelToolCall) -> None:
        self._pending_model_calls.append(call)

    def record_finish(self, arguments: Mapping[str, Any]) -> None:
        """Mechanically retain the model's local finish declaration."""

        status = arguments.get("monitoring_scope_status")
        reason = arguments.get("reason")
        engines = arguments.get("monitored_database_engines")
        targets = arguments.get("monitoring_target_identifiers")
        if isinstance(status, str) and status:
            self._state.monitoring_scope_status = status
        if isinstance(reason, str) and reason:
            self._state.monitoring_scope_reason = sanitize_text(reason)
        if isinstance(engines, list):
            self._state.monitored_database_engines = [
                sanitize_text(item) for item in engines if isinstance(item, str) and item.strip()
            ]
        if isinstance(targets, list):
            self._state.monitoring_target_identifiers = [
                sanitize_text(item) for item in targets if isinstance(item, str) and item.strip()
            ]

    def restore_state(self, state: PrometheusHarnessState) -> None:
        self._state = state

    def initial_state(self) -> PrometheusHarnessState:
        self._state = PrometheusHarnessState(self.window_start, self.window_end)
        return self._state

    def initial_messages(self, state: PrometheusHarnessState) -> list[dict[str, Any]]:
        self._state = state
        return self.client.agent_messages(
            self.context,
            state.window_start,
            state.window_end,
        )

    async def bootstrap(
        self,
        session: PrometheusMCPToolSession,
        state: PrometheusHarnessState,
    ) -> PrometheusHarnessState:
        del session
        self._state = state
        return state

    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]:
        converted = self.client.discovered_model_tools(tools)
        self.model_tools = {str(item["function"]["name"]): deepcopy(item) for item in converted}
        specs: list[ToolSpec] = []
        for name in sorted(self.model_tools):
            model_tool = self.model_tools[name]["function"]
            schema = deepcopy(model_tool["parameters"])
            specs.append(
                ToolSpec(
                    name=name,
                    provider=self.provider,
                    capability="prometheus.remote_tool",
                    input_schema=schema,
                    policy_version=PROMETHEUS_MCP_PROMPT_VERSION,
                    schema_version=self._schema_version(schema),
                    timeout=self.client.timeout_seconds,
                )
            )
        return specs

    def prepare_call(
        self,
        action: Any,
        *,
        state: PrometheusHarnessState,
    ) -> PreparedCall:
        self._state = state
        call = self._consume_model_call(action.tool_name, action.arguments)
        return PreparedCall(
            tool_name=action.tool_name,
            objective=action.objective,
            hypothesis_ids=list(action.hypothesis_ids),
            model_arguments=deepcopy(action.arguments),
            effective_arguments=deepcopy(action.arguments),
            timeout_seconds=self.client.timeout_seconds,
            metadata={
                "call_id": call.call_id,
                "request_id": call.request_id,
                "capability": "remote_tool",
                "provider_output_items": [deepcopy(item) for item in call.provider_output_items],
            },
        )

    def on_result(
        self,
        state: PrometheusHarnessState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[PrometheusHarnessState, dict[str, Any]]:
        updated = deepcopy(state)
        decoded = self.client.call_result(result)
        result = decoded.payload
        model_call = self._model_call_from_prepared(call)
        updated.executed_calls.append(model_call)
        trace_projection = self.client.project_alert_window_range(
            result,
            arguments=call.effective_arguments,
            alert=self.context.alert,
            window_start=updated.window_start,
            window_end=updated.window_end,
        )
        outcome = "no_data" if result is None else "result"
        qualified = trace_projection is not None
        response = {
            "tool_name": call.tool_name,
            "model_arguments": sanitize(call.model_arguments),
            "arguments": sanitize(call.effective_arguments),
            "capability": "remote_tool",
            "projection_kind": ("alert_window_range" if qualified else "auxiliary"),
            "has_monitoring_observation": qualified,
            "root_cause_eligible": qualified,
            "root_cause_ineligible_reason": "" if qualified else "auxiliary_response",
            "result": sanitize(result),
        }
        if trace_projection is not None:
            response["projection"] = deepcopy(trace_projection)
        if result is not None:
            updated.responses.append(response)
        status = ToolInvocationStatus.NO_DATA if result is None else ToolInvocationStatus.SUCCEEDED
        attempt = {
            "tool_name": call.tool_name,
            "model_arguments": sanitize(call.model_arguments),
            "arguments": sanitize(call.effective_arguments),
            "capability": "remote_tool",
            "outcome": outcome,
        }
        if status == ToolInvocationStatus.NO_DATA:
            attempt.update(
                {
                    "evidence_disposition": "MISSING",
                    "is_contradiction": False,
                }
            )
        updated.tool_attempts.append(attempt)
        self._state = updated
        observation = None
        if trace_projection is not None:
            observation = {
                "tool_name": call.tool_name,
                "outcome": outcome,
                "projection_kind": "alert_window_range",
                "projection": deepcopy(trace_projection),
            }
        return ScenarioTransition(
            state=updated,
            observation=observation,
            message=self.client.completed_tool_messages(
                model_call,
                decoded.raw_call_result,
                host_control=self.client.host_control_feedback(
                    remote_calls_used=len(updated.executed_calls),
                    outcome=outcome,
                    capability="remote_tool",
                    instruction="根据原始返回自主决定下一步，事实足够时调用结束工具。",
                ),
            ),
            status=status,
        )

    def result_error_directive(
        self,
        state: PrometheusHarnessState,
        call: PreparedCall,
        error: Exception,
    ) -> RetryDirective | None:
        leaf = self.client.first_exception_leaf(error)
        if not isinstance(leaf, PrometheusMCPToolError):
            return None
        return self.retry_directive(state, call, error)

    def on_failure(
        self,
        state: PrometheusHarnessState,
        call: PreparedCall,
        error: Any,
        status: ToolInvocationStatus,
    ) -> ScenarioTransition[PrometheusHarnessState, dict[str, Any]]:
        updated = deepcopy(state)
        model_call = self._model_call_from_prepared(call)
        updated.executed_calls.append(model_call)
        capability = str(call.metadata.get("capability") or "unknown")
        is_tool_error = error.code == PrometheusMCPToolError.__name__
        outcome = "tool_error" if is_tool_error else "transport_error"
        detail = sanitize_text(error.message)[:500]
        has_raw_call_result = "mcp_raw_response" in call.metadata
        raw_call_result = call.metadata.get("mcp_raw_response")
        updated.tool_attempts.append(
            {
                "tool_name": call.tool_name,
                "model_arguments": sanitize(call.model_arguments),
                "arguments": sanitize(call.effective_arguments),
                "capability": capability,
                "outcome": outcome,
                "error_type": error.code,
                "detail": detail,
                "evidence_disposition": "MISSING",
                "is_contradiction": False,
            }
        )
        if not is_tool_error:
            updated.last_error_type = error.code
            updated.last_error_detail = detail
        self._state = updated
        instruction = (
            "根据实际错误修改参数并选择下一步查询。"
            if is_tool_error
            else "连接已中断；Host 将在整次调查超时内重连。"
        )
        return ScenarioTransition(
            state=updated,
            observation={
                "tool_name": call.tool_name,
                "outcome": outcome,
                "error_type": error.code,
                "evidence_disposition": "MISSING",
                "is_contradiction": False,
            },
            message=self.client.completed_tool_messages(
                model_call,
                (
                    raw_call_result
                    if has_raw_call_result
                    else {"tool_error": error.code, "detail": detail}
                ),
                host_control=self.client.host_control_feedback(
                    remote_calls_used=len(updated.executed_calls),
                    outcome=outcome,
                    capability=capability,
                    instruction=instruction,
                ),
            ),
            status=status,
        )

    def retry_directive(
        self,
        state: PrometheusHarnessState,
        call: PreparedCall | None,
        error: Exception,
    ) -> RetryDirective:
        del state
        leaf = self.client.first_exception_leaf(error)
        if isinstance(leaf, PrometheusMCPConfigurationError):
            return RetryDirective(
                reason=sanitize_text(str(leaf))[:1000],
                continue_run=False,
            )
        if isinstance(leaf, PrometheusMCPToolError):
            return RetryDirective(
                reason=sanitize_text(str(leaf))[:1000],
                continue_run=True,
            )
        retryable_transport = isinstance(
            leaf,
            (
                _PrometheusMCPTransportError,
                ConnectionError,
                TimeoutError,
            ),
        ) or bool(getattr(leaf, "unknown_outcome", False))
        if not retryable_transport:
            return RetryDirective(
                reason=sanitize_text(str(leaf))[:1000] or type(leaf).__name__,
                continue_run=False,
            )
        if call is None:
            return RetryDirective(
                reason=sanitize_text(str(leaf))[:1000] or type(leaf).__name__,
                reconnect=True,
                continue_run=True,
            )
        return RetryDirective(
            reason=sanitize_text(str(leaf))[:1000] or type(leaf).__name__,
            reconnect=True,
            retry_call=True,
            continue_run=True,
            unknown_outcome=True,
            allow_unknown_outcome_retry=True,
        )

    def completion(
        self,
        state: PrometheusHarnessState,
        observations: Sequence[HarnessObservation[dict[str, Any]]],
    ) -> Finish | None:
        del observations
        del state
        return None

    def inconclusive_reason(self, state: PrometheusHarnessState) -> str | None:
        if state.has_monitoring_data:
            return None
        return state.monitoring_scope_reason

    def _consume_model_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> MCPModelToolCall:
        for index, call in enumerate(self._pending_model_calls):
            if call.name == tool_name and call.arguments == dict(arguments):
                return self._pending_model_calls.pop(index)
        return MCPModelToolCall(
            call_id=f"prometheus-harness-{uuid4()}",
            name=tool_name,
            arguments=deepcopy(dict(arguments)),
        )

    @staticmethod
    def _model_call_from_prepared(call: PreparedCall) -> MCPModelToolCall:
        call_id = call.metadata.get("call_id")
        request_id = call.metadata.get("request_id")
        provider_output_items = call.metadata.get("provider_output_items")
        return MCPModelToolCall(
            call_id=(
                call_id if isinstance(call_id, str) and call_id else f"prometheus-harness-{uuid4()}"
            ),
            name=call.tool_name,
            arguments=deepcopy(call.model_arguments),
            request_id=request_id if isinstance(request_id, str) else None,
            provider_output_items=tuple(
                deepcopy(item) for item in provider_output_items if isinstance(item, dict)
            )
            if isinstance(provider_output_items, list)
            else (),
        )

    @staticmethod
    def _schema_version(schema: Mapping[str, Any]) -> str:
        canonical = json.dumps(
            schema,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"


async def collect_prometheus_with_harness(
    client: PrometheusMCPClient,
    context: InvestigationContext,
) -> PrometheusMCPQueryResult:
    """Run one Prometheus MCP investigation and return the public result model."""

    occurred_at = context.alert.occurred_at
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise PrometheusMCPConfigurationError(
            "Alert occurred_at must include a timezone for Prometheus evidence"
        )
    window_end = occurred_at.astimezone(UTC)
    window_start = window_end - timedelta(seconds=PROMETHEUS_ALERT_WINDOW_SECONDS)
    scenario = PrometheusHarnessScenario(
        client=client,
        context=context,
        window_start=window_start,
        window_end=window_end,
    )
    planner = PrometheusHarnessPlanner(client=client, scenario=scenario)
    event_sink = InMemoryEventSink()
    invocation_store = None
    remote_response_store = None
    checkpoint_store = None
    runtime_dependencies = client.harness_runtime_dependencies
    if runtime_dependencies is not None:
        repository = runtime_dependencies.repository
        lease = {
            "lease_owner": context.lease_owner,
            "fencing_token": context.fencing_token,
        }
        event_sink = RepositoryEventSink(repository, **lease)
        invocation_store = RepositoryInvocationStore(repository, **lease)
        remote_response_store = RepositoryPrometheusRemoteResponseStore(
            repository,
            outer_dispatch_id=context.outer_dispatch_id,
            **lease,
        )
        manifest = await repository.get_run_manifest(str(context.run_id))
        if manifest is not None:
            checkpoint_store = RepositoryMCPCheckpointStore[
                PrometheusHarnessState,
                dict[str, Any],
            ](
                repository,
                provider=PROMETHEUS_MCP_SERVER_NAME,
                manifest_hash=manifest.digest(),
                dispatch_id=context.outer_dispatch_id,
                **lease,
            )
    budget = BudgetLedger(
        BudgetLimits(
            planner_requests=None,
            accepted_decisions=None,
            remote_tool_calls=None,
            host_bootstrap_calls=None,
            session_attempts=None,
            wall_time_seconds=client.timeout_seconds,
        )
    )
    runtime = MCPAgentHarnessRuntime[
        PrometheusHarnessState,
        dict[str, Any],
    ](
        connector=PrometheusMCPConnector(client),
        planner=planner,
        scenario=scenario,
        dispatch_scope_id=context.outer_dispatch_id,
        event_sink=event_sink,
        budget=budget,
        checkpoint_hook=checkpoint_store,
        invocation_store=invocation_store,
        remote_response_store=remote_response_store,
        planner_timeout_seconds=client.timeout_seconds,
        session_timeout_seconds=client.timeout_seconds,
        # Same rationale as Archery: durable reasoning deltas dominate
        # planner wall time inside the bounded client timeout, and the
        # MODEL_DECISION / TRACE_REASONING.
        stream_planner_reasoning=False,
    )
    checkpoint = (
        await checkpoint_store.load(context.run_id) if checkpoint_store is not None else None
    )
    if checkpoint is None:
        harness_result = await runtime.run(run_id=context.run_id)
    else:
        scenario.restore_state(checkpoint.state)
        harness_result = await runtime.resume(
            checkpoint,
            restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
        )
    state = harness_result.state
    finish = harness_result.finish
    assert finish is not None
    events = [
        event
        for event in await event_sink.read(harness_result.run_id)
        if event.payload.get("provider") == PROMETHEUS_MCP_SERVER_NAME
        and event_matches_dispatch_scope(event, context.outer_dispatch_id)
    ]
    state_attempts = deque(deepcopy(state.tool_attempts))
    attempts: list[dict[str, Any]] = []
    for event in events:
        if event.kind in {
            AgentEventKind.TOOL_INVOCATION_FAILED,
            AgentEventKind.TOOL_INVOCATION_NO_DATA,
            AgentEventKind.TOOL_INVOCATION_SUCCEEDED,
            AgentEventKind.TOOL_INVOCATION_TIMED_OUT,
            AgentEventKind.TOOL_INVOCATION_UNKNOWN_OUTCOME,
        }:
            if state_attempts:
                attempts.append(state_attempts.popleft())
    attempts.extend(state_attempts)

    has_monitoring_data = state.has_monitoring_data
    finished_by_model = finish.model_requested and finish.reason == RuntimeStopReason.COMPLETED
    if state.monitoring_scope_status == "out_of_scope":
        termination_reason = "database_not_monitored"
    elif state.monitoring_scope_status == "unknown" and not has_monitoring_data:
        termination_reason = "monitoring_scope_unknown"
    elif finished_by_model:
        termination_reason = "finished_by_model"
    elif finish.reason == RuntimeStopReason.BUDGET_EXHAUSTED:
        termination_reason = "budget_exhausted"
    elif finish.reason == RuntimeStopReason.DEADLINE_EXCEEDED:
        termination_reason = "deadline_exceeded"
    elif finish.reason == RuntimeStopReason.FAILED:
        termination_reason = (
            "protocol_error_after_partial_result"
            if has_monitoring_data
            else "protocol_error_no_result"
        )
    else:
        termination_reason = finish.reason.value.casefold()

    termination_error_type: str | None = None
    termination_error_detail: str | None = None
    if not finished_by_model:
        termination_error_type = state.last_error_type
        termination_error_detail = state.last_error_detail
        if termination_error_type is None and state.consecutive_model_errors:
            termination_error_type = PrometheusMCPModelError.__name__
            termination_error_detail = sanitize_text(state.consecutive_model_errors[-1]["error"])[
                :1000
            ]
        if termination_error_type is None:
            failed_sessions = [
                event for event in events if event.kind == AgentEventKind.MCP_SESSION_FAILED
            ]
            if failed_sessions:
                last_failure = failed_sessions[-1]
                termination_error_type = str(
                    last_failure.payload.get("error_code") or "MCPConnectionError"
                )
                termination_error_detail = sanitize_text(
                    str(last_failure.payload.get("message") or "")
                )[:1000]

    return PrometheusMCPQueryResult(
        responses=tuple(deepcopy(state.responses)),
        window_start=state.window_start,
        window_end=state.window_end,
        model_tool_calls=tuple(call.name for call in state.executed_calls),
        model_request_ids=tuple(
            call.request_id for call in state.executed_calls if call.request_id
        ),
        finished_by_model=finished_by_model,
        tool_attempts=tuple(attempts),
        termination_reason=termination_reason,
        partial=has_monitoring_data and not finished_by_model,
        termination_error_type=termination_error_type,
        termination_error_detail=termination_error_detail,
        mcp_session_attempts=harness_result.budget.consumed.session_attempts,
        reconnect_error_type=(
            PrometheusMCPProtocolError.__name__
            if harness_result.budget.consumed.session_attempts > 1
            else None
        ),
        inconclusive_reason=(
            scenario.inconclusive_reason(state)
            if finish.reason == RuntimeStopReason.NO_DISCRIMINATING_EVIDENCE
            else None
        ),
        monitoring_scope_status=state.monitoring_scope_status,
        monitoring_scope_reason=state.monitoring_scope_reason,
        monitored_database_engines=tuple(state.monitored_database_engines),
        monitoring_target_identifiers=tuple(state.monitoring_target_identifiers),
    )


__all__ = [
    "PrometheusHarnessPlanner",
    "PrometheusHarnessRuntimeDependencies",
    "PrometheusHarnessScenario",
    "PrometheusHarnessState",
    "PrometheusMCPConnector",
    "PrometheusMCPToolSession",
    "RepositoryPrometheusRemoteResponseStore",
    "collect_prometheus_with_harness",
]


def _accepts_keyword_argument(callable_object: Any, keyword: str) -> bool:
    try:
        parameters = inspect.signature(callable_object).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        or (
            parameter.name == keyword
            and parameter.kind
            in {
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            }
        )
        for parameter in parameters
    )
