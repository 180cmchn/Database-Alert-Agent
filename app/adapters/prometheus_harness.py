"""Prometheus transport, planning, and scenario adapter for the shared Harness.

Provider authorization and payload semantics come from the public policy/codec
surface on ``PrometheusMCPClient`` so there is only one Host contract.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import uuid4

import httpx
from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.sse import sse_client

from app.adapters.prometheus_mcp import (
    _FINISH_TOOL_NAME,
    _SCOPE_AUDIT_ARGUMENT_NAMES,
    PROMETHEUS_ALERT_WINDOW_SECONDS,
    PROMETHEUS_MCP_DECISION_LIMIT_MULTIPLIER,
    PROMETHEUS_MCP_MAX_EMPTY_RANGE_CALLS,
    PROMETHEUS_MCP_MAX_TARGET_MISMATCH_CALLS,
    PROMETHEUS_MCP_PROMPT_VERSION,
    PROMETHEUS_MCP_SERVER_NAME,
    PrometheusMCPClient,
    PrometheusMCPConfigurationError,
    PrometheusMCPError,
    PrometheusMCPModelError,
    PrometheusMCPProtocolError,
    PrometheusMCPQueryResult,
    PrometheusMCPToolError,
    PrometheusMCPToolPolicy,
    has_monitoring_observation,
)
from app.agent_runtime import (
    AgentEventKind,
    BudgetLedger,
    BudgetLimits,
    InMemoryEventSink,
    RepositoryEventSink,
    RepositoryInvocationStore,
    RetryPolicy,
    RuntimeStopReason,
    ToolInvocationStatus,
    ToolRisk,
    ToolSpec,
)
from app.application.sanitization import sanitize, sanitize_text
from app.domain.models import InvestigationContext
from app.domain.ports import AlertRepository
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    DiscoveredMCPTool,
    Finish,
    HarnessObservation,
    HostRejection,
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


_PROMETHEUS_SSE_TRANSPORT_ERROR_CODE = "prometheus_sse_transport_error"
_RETRYABLE_INVOCATION_ERROR_CODES = {
    _PROMETHEUS_SSE_TRANSPORT_ERROR_CODE,
    "ConnectionError",
    "TimeoutError",
    "recovered_unknown_outcome",
}


class _PrometheusSSETransportError(PrometheusMCPProtocolError):
    code = _PROMETHEUS_SSE_TRANSPORT_ERROR_CODE
    retryable = True

    def __init__(self, *, operation: str, leaf: BaseException) -> None:
        detail = sanitize_text(str(leaf))[:500]
        suffix = f": {detail}" if detail else ""
        super().__init__(
            f"Prometheus SSE MCP {operation} failed ({type(leaf).__name__}){suffix}"
        )
        self.leaf_type = type(leaf).__name__


def _exception_leaves(error: BaseException) -> list[BaseException]:
    if isinstance(error, BaseExceptionGroup):
        return [
            leaf
            for nested in error.exceptions
            for leaf in _exception_leaves(nested)
        ]
    return [error]


def _is_sse_transport_error(error: BaseException) -> bool:
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


def _normalized_sse_exception(
    error: BaseException,
    *,
    operation: str,
) -> Exception | None:
    leaves = _exception_leaves(error)
    for leaf in leaves:
        if isinstance(leaf, PrometheusMCPError):
            return leaf
    for leaf in leaves:
        if _is_sse_transport_error(leaf):
            return _PrometheusSSETransportError(operation=operation, leaf=leaf)
    return None


class PrometheusSSEMCPToolSession:
    """One initialized SDK session owned by an ``AsyncExitStack``."""

    def __init__(
        self,
        *,
        client: PrometheusMCPClient,
        stack: AsyncExitStack,
        session: Any,
    ) -> None:
        self.client = client
        self._stack = stack
        self._session = session
        self._session_id = f"prometheus-sse-{uuid4()}"
        self._closed = False

    @property
    def session_id(self) -> str:
        return self._session_id

    async def list_tools(self) -> list[DiscoveredMCPTool]:
        try:
            raw_tools: list[Any] = []
            cursor: str | None = None
            for _page in range(10):
                response = await self._session.list_tools(cursor=cursor)
                raw_tools.extend(response.tools)
                cursor = getattr(response, "nextCursor", None)
                if not cursor:
                    break
            if not raw_tools:
                raise PrometheusMCPProtocolError("Prometheus MCP returned no tools")
        except BaseException as exc:
            normalized = _normalized_sse_exception(exc, operation="tool discovery")
            if normalized is None or normalized is exc:
                raise
            raise normalized from exc
        return [self._convert_tool(tool) for tool in raw_tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            raw_result = await self._session.call_tool(name, arguments)
        except BaseException as exc:
            normalized = _normalized_sse_exception(exc, operation="tool call")
            if normalized is None or normalized is exc:
                raise
            raise normalized from exc
        return self.client.result_payload(raw_result)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._stack.aclose()

    @staticmethod
    def _convert_tool(tool: Any) -> DiscoveredMCPTool:
        raw = tool.model_dump(mode="json") if hasattr(tool, "model_dump") else tool
        if not isinstance(raw, Mapping):
            raise PrometheusMCPProtocolError(
                "Prometheus MCP tool schema is not an object"
            )
        name = raw.get("name")
        schema = raw.get("inputSchema") or raw.get("input_schema") or {"type": "object"}
        annotations = raw.get("annotations") or {}
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(schema, dict)
            or not isinstance(annotations, dict)
        ):
            raise PrometheusMCPProtocolError(
                "Prometheus MCP returned an invalid tool schema"
            )
        return DiscoveredMCPTool(
            name=name,
            description=str(raw.get("description") or f"Prometheus MCP tool {name}"),
            input_schema=deepcopy(schema),
            annotations=deepcopy(annotations),
        )


class PrometheusSSEMCPConnector:
    """Open one SSE MCP session behind the provider-neutral connector API."""

    provider = PROMETHEUS_MCP_SERVER_NAME

    def __init__(self, client: PrometheusMCPClient) -> None:
        self.client = client

    async def open_session(self) -> PrometheusSSEMCPToolSession:
        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(
                sse_client(
                    self.client.mcp_url,
                    headers=self.client.headers,
                    timeout=self.client.timeout_seconds,
                    sse_read_timeout=self.client.sse_read_timeout_seconds,
                )
            )
            session = await stack.enter_async_context(
                ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(
                        seconds=self.client.timeout_seconds
                    ),
                    client_info=mcp_types.Implementation(
                        name="database-alert-agent", version="0.1.0"
                    ),
                )
            )
            await session.initialize()
        except BaseException as exc:
            try:
                await stack.aclose()
            except BaseException:
                pass
            normalized = _normalized_sse_exception(exc, operation="session setup")
            if normalized is None or normalized is exc:
                raise
            raise normalized from exc
        return PrometheusSSEMCPToolSession(
            client=self.client,
            stack=stack,
            session=session,
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

    @property
    def consecutive_errors(self) -> list[dict[str, Any]]:
        return self.scenario.current_state.consecutive_model_errors

    async def plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> dict[str, Any]:
        return await self._plan(messages=messages, tools=tools)

    async def _plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
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
            authorized_policies=self.scenario.authorized_policies,
            calls=state.executed_calls,
            responses=state.responses,
            alert=self.scenario.context.alert,
            monitoring_scope_status=state.monitoring_scope_status,
        )
        model_messages = deepcopy(messages)
        model_messages.append(
            self.client.host_investigation_state_message(
                authorized_policies=self.scenario.authorized_policies,
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
        if len(self.consecutive_errors) >= 2:
            raise self._selection_error(model_tools, state)
        try:
            call = await self.client.model.request_mcp_tool_call(
                messages=model_messages,
                tools=model_tools,
            )
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
        if call.name == _FINISH_TOOL_NAME:
            if state.monitoring_scope_status == "investigating":
                scope_status = call.arguments.get("monitoring_scope_status")
                reason = call.arguments.get("reason")
                if scope_status not in {"out_of_scope", "unknown"}:
                    raise PrometheusMCPModelError(
                        "Prometheus scope finish must declare out_of_scope or unknown"
                    )
                if not isinstance(reason, str) or not reason.strip():
                    raise PrometheusMCPModelError(
                        "Prometheus scope conclusion must include a non-empty reason"
                    )
                state.monitoring_scope_status = scope_status
                state.monitoring_scope_reason = sanitize_text(reason)[:1000]
                state.monitored_database_engines = self._string_list(
                    call.arguments.get("monitored_database_engines"),
                    limit=20,
                )
                state.monitoring_target_identifiers = self._string_list(
                    call.arguments.get("monitoring_target_identifiers"),
                    limit=100,
                )
                return {
                    "action": "finish",
                    "reason": RuntimeStopReason.NO_DISCRIMINATING_EVIDENCE.value,
                    "summary": state.monitoring_scope_reason,
                }
            return {
                "action": "finish",
                "reason": RuntimeStopReason.COMPLETED.value,
                "summary": "Prometheus alert-window evidence collection is complete.",
            }
        policy = self.scenario.authorized_policies.get(call.name)
        if (
            state.monitoring_scope_status == "investigating"
            and policy is not None
            and policy.capability == "range_query"
        ):
            reason = call.arguments.get("monitoring_scope_reason")
            engines = self._string_list(
                call.arguments.get("monitored_database_engines"),
                limit=20,
            )
            identifiers = self._string_list(
                call.arguments.get("monitoring_target_identifiers"),
                limit=100,
            )
            if not isinstance(reason, str) or not reason.strip():
                raise PrometheusMCPModelError(
                    "Prometheus in-scope range query must include monitoring_scope_reason"
                )
            if not engines or not identifiers:
                raise PrometheusMCPModelError(
                    "Prometheus in-scope range query must include database engines "
                    "and target identifiers"
                )
            state.monitoring_scope_status = "in_scope"
            state.monitoring_scope_reason = sanitize_text(reason)[:1000]
            state.monitored_database_engines = engines
            state.monitoring_target_identifiers = identifiers
        self.scenario.register_model_call(call)
        capability = policy.capability if policy is not None else "unapproved"
        return {
            "action": "call_tool",
            "tool_name": call.name,
            "objective": (
                f"Collect read-only Prometheus {capability} evidence for the alert window."
            ),
            "hypothesis_ids": [],
            "arguments": deepcopy(call.arguments),
        }

    @staticmethod
    def _string_list(value: Any, *, limit: int) -> list[str]:
        if not isinstance(value, list):
            return []
        return list(
            dict.fromkeys(
                sanitize_text(item)[:500]
                for item in value[:limit]
                if isinstance(item, str) and item.strip()
            )
        )

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
                "second_error": (
                    latest["error"] if len(self.consecutive_errors) > 1 else None
                ),
                "remote_calls_used": len(state.executed_calls),
                "remote_call_limit": self.client.max_agent_steps,
                "remote_calls_remaining": max(
                    self.client.max_agent_steps - len(state.executed_calls), 0
                ),
                "available_tools": [
                    item.get("function", {}).get("name")
                    for item in model_tools
                    if isinstance(item, dict)
                ],
            },
        )


class PrometheusHarnessScenario:
    """Prometheus-specific Host policy and evidence semantics."""

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
        self.authorized_policies: dict[str, PrometheusMCPToolPolicy] = {}
        self.model_tools: dict[str, dict[str, Any]] = {}
        self._pending_model_calls: list[MCPModelToolCall] = []
        self._state = PrometheusHarnessState(window_start, window_end)

    @property
    def current_state(self) -> PrometheusHarnessState:
        return self._state

    def register_model_call(self, call: MCPModelToolCall) -> None:
        self._pending_model_calls.append(call)

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
        session: PrometheusSSEMCPToolSession,
        state: PrometheusHarnessState,
    ) -> PrometheusHarnessState:
        del session
        self._state = state
        return state

    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]:
        converted, authorized = self.client.authorized_model_tools(tools)
        self.authorized_policies = dict(authorized)
        self.model_tools = {
            str(item["function"]["name"]): deepcopy(item) for item in converted
        }
        specs: list[ToolSpec] = []
        for name, policy in sorted(authorized.items()):
            model_tool = self.model_tools[name]["function"]
            schema = deepcopy(model_tool["parameters"])
            specs.append(
                ToolSpec(
                    name=name,
                    provider=self.provider,
                    capability=f"prometheus.{policy.capability}",
                    input_schema=schema,
                    read_only=True,
                    risk=ToolRisk.LOW,
                    policy_version=self._policy_version(policy),
                    schema_version=self._schema_version(schema),
                    timeout=self.client.timeout_seconds,
                    retry=RetryPolicy(
                        max_attempts=2,
                        initial_backoff_seconds=0,
                        retryable_error_codes=set(_RETRYABLE_INVOCATION_ERROR_CODES),
                    ),
                )
            )
        return specs

    def prepare_call(
        self,
        action: Any,
        *,
        state: PrometheusHarnessState,
        catalog: dict[str, ToolSpec],
    ) -> PreparedCall | HostRejection:
        self._state = state
        call = self._consume_model_call(action.tool_name, action.arguments)
        policy = self.authorized_policies.get(action.tool_name)
        if policy is None or action.tool_name not in catalog:
            state.tool_attempts.append(
                {
                    "tool_name": action.tool_name,
                    "model_arguments": sanitize(action.arguments),
                    "outcome": "host_rejected_unauthorized",
                }
            )
            return HostRejection(
                code="tool_not_in_local_policy",
                message="Prometheus tool is not authorized by local read-only policy.",
                repair_hint="Choose one of the currently advertised Prometheus tools.",
            )
        effective_arguments = self.client.effective_arguments(
            action.arguments,
            policy=policy,
            window_start=state.window_start,
            window_end=state.window_end,
        )
        if policy.capability == "range_query":
            for argument_name in _SCOPE_AUDIT_ARGUMENT_NAMES:
                effective_arguments.pop(argument_name, None)
        return PreparedCall(
            tool_name=action.tool_name,
            objective=action.objective,
            hypothesis_ids=list(action.hypothesis_ids),
            model_arguments=deepcopy(action.arguments),
            effective_arguments=effective_arguments,
            timeout_seconds=self.client.timeout_seconds,
            metadata={
                "call_id": call.call_id,
                "request_id": call.request_id,
                "capability": policy.capability,
            },
        )

    def on_result(
        self,
        state: PrometheusHarnessState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[PrometheusHarnessState, dict[str, Any]]:
        updated = deepcopy(state)
        model_call = self._model_call_from_prepared(call)
        updated.executed_calls.append(model_call)
        policy = self.authorized_policies[call.tool_name]
        if policy.capability == "target_discovery":
            return self._on_target_discovery_result(
                updated,
                model_call,
                call,
                result,
            )
        has_observation = has_monitoring_observation(result)
        window_verification = self.client.window_verification(
            policy=policy,
            payload=result,
            window_start=updated.window_start,
            window_end=updated.window_end,
        )
        if policy.capability == "range_query":
            target_verification, target_mismatch_reasons = (
                self.client.target_verification(
                    self.context.alert,
                    result,
                )
            )
        else:
            target_verification, target_mismatch_reasons = "not_applicable", []
        target_mismatch = target_verification == "mismatch"
        usable_observation = (
            has_observation
            and window_verification == "exact"
            and not target_mismatch
        )
        no_data = result is None or (
            policy.capability == "range_query"
            and (not has_observation or target_mismatch)
        )
        if no_data:
            outcome = "target_mismatch" if target_mismatch else "no_data"
            model_payload = result
            if result is not None:
                updated.responses.append(
                    {
                        "tool_name": call.tool_name,
                        "model_arguments": sanitize(call.model_arguments),
                        "arguments": sanitize(call.effective_arguments),
                        "capability": policy.capability,
                        "has_monitoring_observation": has_observation,
                        "window_verification": window_verification,
                        "target_verification": target_verification,
                        "target_mismatch_reasons": target_mismatch_reasons,
                        "root_cause_eligible": False,
                        "root_cause_ineligible_reason": (
                            "target_mismatch" if target_mismatch else "no_observation"
                        ),
                        "result": self.client.evidence_visible_payload(result),
                    }
                )
            if target_mismatch:
                mismatch_count = 1 + sum(
                    attempt.get("outcome") == "target_mismatch" for attempt in updated.tool_attempts
                )
                model_payload = {
                    "tool_result": result,
                    "host_target_verification": target_verification,
                    "target_mismatch_reasons": target_mismatch_reasons,
                    "instruction": (
                        "该返回不属于required_target，不能作为告警证据；"
                        + (
                            "只允许修正指标或目标标签后重新执行range_query一次。"
                            if mismatch_count < PROMETHEUS_MCP_MAX_TARGET_MISMATCH_CALLS
                            else "已达到目标不匹配停止阈值，Host 将结束无效探测。"
                        )
                    ),
                }
                next_instruction = "返回目标与告警目标不一致；" + (
                    "只再修正一次指标或标签并执行 range_query。"
                    if mismatch_count < PROMETHEUS_MCP_MAX_TARGET_MISMATCH_CALLS
                    else "Host 将以无可区分证据结束。"
                )
            else:
                empty_count = 1 + sum(
                    attempt.get("outcome") == "no_data" for attempt in updated.tool_attempts
                )
                next_instruction = "该调用已完成但没有数据；" + (
                    "不要原样重试，只选择其它最相关的 range_query。"
                    if empty_count < PROMETHEUS_MCP_MAX_EMPTY_RANGE_CALLS
                    else "已达到空范围查询停止阈值，Host 将结束无效探测。"
                )
            status = ToolInvocationStatus.NO_DATA
        else:
            outcome = (
                "observation"
                if usable_observation
                else "unverified_window"
                if has_observation
                else "auxiliary_result"
            )
            response = {
                "tool_name": call.tool_name,
                "model_arguments": sanitize(call.model_arguments),
                "arguments": sanitize(call.effective_arguments),
                "capability": policy.capability,
                "has_monitoring_observation": has_observation,
                "window_verification": window_verification,
                "target_verification": target_verification,
                "target_mismatch_reasons": target_mismatch_reasons,
                "root_cause_eligible": usable_observation,
                "root_cause_ineligible_reason": (
                    ""
                    if usable_observation
                    else (
                        "unverified_window"
                        if has_observation
                        else "auxiliary_result"
                    )
                ),
                "result": self.client.evidence_visible_payload(result),
            }
            updated.responses.append(response)
            model_payload = result
            if has_observation and not usable_observation:
                model_payload = {
                    "tool_result": result,
                    "host_window_verification": window_verification,
                    "instruction": (
                        "该返回尚不能证明属于required_window；请改用带精确起止参数的"
                        "范围查询工具。"
                    ),
                }
            if usable_observation:
                next_instruction = (
                    "已取得合格的告警窗口观测；证据足够时结束调查，否则只再执行能区分"
                    "候选原因的范围查询。"
                )
            elif policy.capability == "catalog":
                next_instruction = (
                    "目录结果不能作为实时证据；下一步使用 range_query，不要继续枚举完整目录。"
                )
            elif has_observation:
                next_instruction = (
                    "返回包含观测但时间窗未通过验证；改用其它 range_query 或修正查询语义。"
                )
            else:
                next_instruction = (
                    "该范围查询没有样本；修改指标、标签或聚合语义后再查询。"
                )
            status = ToolInvocationStatus.SUCCEEDED
        attempt = {
            "tool_name": call.tool_name,
            "model_arguments": sanitize(call.model_arguments),
            "arguments": sanitize(call.effective_arguments),
            "capability": policy.capability,
            "outcome": outcome,
            "window_verification": window_verification,
            "target_verification": target_verification,
            "target_mismatch_reasons": target_mismatch_reasons,
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
        observation = {
            "tool_name": call.tool_name,
            "outcome": outcome,
            "has_monitoring_observation": has_observation,
            "window_verification": window_verification,
            "target_verification": target_verification,
            "target_mismatch_reasons": target_mismatch_reasons,
        }
        if status == ToolInvocationStatus.NO_DATA:
            observation.update(
                {
                    "evidence_disposition": "MISSING",
                    "is_contradiction": False,
                }
            )
        return ScenarioTransition(
            state=updated,
            observation=observation,
            message=self.client.completed_tool_messages(
                model_call,
                model_payload,
                host_control=self.client.host_control_feedback(
                    remote_calls_used=len(updated.executed_calls),
                    outcome=outcome,
                    capability=policy.capability,
                    instruction=next_instruction,
                ),
            ),
            status=status,
        )

    def _on_target_discovery_result(
        self,
        updated: PrometheusHarnessState,
        model_call: MCPModelToolCall,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[PrometheusHarnessState, dict[str, Any]]:
        updated.monitoring_scope_status = "investigating"
        updated.monitoring_scope_reason = None
        outcome = "monitoring_scope_evidence_collected"
        response = {
            "tool_name": call.tool_name,
            "model_arguments": sanitize(call.model_arguments),
            "arguments": sanitize(call.effective_arguments),
            "capability": "target_discovery",
            "has_monitoring_observation": False,
            "window_verification": "not_applicable",
            "target_verification": "not_applicable",
            "monitoring_scope_status": "investigating",
            "root_cause_eligible": False,
            "root_cause_ineligible_reason": "monitoring_scope_discovery",
            "result": self.client.evidence_visible_payload(result),
        }
        updated.responses.append(response)
        updated.tool_attempts.append(
            {
                "tool_name": call.tool_name,
                "model_arguments": sanitize(call.model_arguments),
                "arguments": sanitize(call.effective_arguments),
                "capability": "target_discovery",
                "outcome": outcome,
                "monitoring_scope_status": "investigating",
                "evidence_disposition": "MISSING",
                "is_contradiction": False,
            }
        )
        self._state = updated
        instruction = (
            "结合目标标签、服务发现 URL、抓取路径、job、指标目录和元数据判断数据库监控归属。"
            "证据支持范围内时，选择最相关的 range_query 并提交结构化范围依据；支持范围外或"
            "证据仍不足时，调用 finish_prometheus_investigation。筛选后的空结果不能单独证明"
            "数据库未受监控。"
        )
        invocation_status = (
            ToolInvocationStatus.SUCCEEDED
            if result is not None
            else ToolInvocationStatus.NO_DATA
        )
        observation = {
            "tool_name": call.tool_name,
            "outcome": outcome,
            "monitoring_scope_status": "investigating",
            "evidence_disposition": "MISSING",
            "is_contradiction": False,
        }
        return ScenarioTransition(
            state=updated,
            observation=observation,
            message=self.client.completed_tool_messages(
                model_call,
                result,
                host_control=self.client.host_control_feedback(
                    remote_calls_used=len(updated.executed_calls),
                    outcome=outcome,
                    capability="target_discovery",
                    instruction=instruction,
                ),
            ),
            status=invocation_status,
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
        elif capability == "target_discovery":
            updated.monitoring_scope_status = "unknown"
            updated.monitoring_scope_reason = (
                "Prometheus 目标发现工具执行失败，无法确认告警数据库是否受监控。"
            )
        self._state = updated
        instruction = (
            "根据实际错误修改参数，并选择最小的只读范围查询。"
            if is_tool_error
            else "连接已中断；Host 将重连并仅对只读调用执行受控重试。"
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
                {"tool_error": error.code, "detail": detail},
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
        retryable_transport = (
            isinstance(
                leaf,
                (
                    _PrometheusSSETransportError,
                    ConnectionError,
                    TimeoutError,
                ),
            )
            or bool(getattr(leaf, "unknown_outcome", False))
        )
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
        inconclusive_reason = self.inconclusive_reason(state)
        if inconclusive_reason is not None:
            return Finish(
                reason=RuntimeStopReason.NO_DISCRIMINATING_EVIDENCE,
                summary=inconclusive_reason,
                requires_human=True,
            )
        if len(state.executed_calls) >= self.client.max_agent_steps:
            return Finish(
                reason=RuntimeStopReason.BUDGET_EXHAUSTED,
                summary="Prometheus remote_tool_calls budget was exhausted.",
                requires_human=not state.has_monitoring_data,
            )
        return None

    def inconclusive_reason(self, state: PrometheusHarnessState) -> str | None:
        if state.has_monitoring_data:
            return None
        if state.monitoring_scope_status == "out_of_scope":
            return state.monitoring_scope_reason or (
                "告警数据库不在 Prometheus 当前配置的监控范围内，已跳过后续指标查询。"
            )
        if state.monitoring_scope_status == "unknown":
            return state.monitoring_scope_reason or (
                "无法确认告警数据库是否在 Prometheus 监控范围内，未继续执行指标查询。"
            )
        range_attempts = [
            attempt for attempt in state.tool_attempts if attempt.get("capability") == "range_query"
        ]
        target_mismatches = sum(
            attempt.get("outcome") == "target_mismatch" for attempt in range_attempts
        )
        if target_mismatches >= PROMETHEUS_MCP_MAX_TARGET_MISMATCH_CALLS:
            return (
                "Prometheus 已执行两次目标修正后的范围查询，但返回序列仍与告警目标不一致；"
                "继续探测不能提供可归属的实时证据。"
            )

        catalog_calls = sum(
            attempt.get("capability") == "catalog" for attempt in state.tool_attempts
        )
        missing_range_results = sum(
            attempt.get("outcome") in {"no_data", "target_mismatch"} for attempt in range_attempts
        )
        if (
            missing_range_results
            and catalog_calls >= self.client.catalog_call_limit()
            and self.client.catalog_metric_relevance(
                self.context.alert,
                state.responses,
            )
            == "irrelevant"
        ):
            return (
                "Prometheus 指标目录中未发现与当前告警信号语义相关的指标；"
                "继续查询仅共享数据库引擎前缀的指标不能区分候选原因。"
            )

        empty_ranges = sum(attempt.get("outcome") == "no_data" for attempt in range_attempts)
        if empty_ranges >= PROMETHEUS_MCP_MAX_EMPTY_RANGE_CALLS:
            return (
                f"Prometheus 已执行 {empty_ranges} 次不同的告警窗口范围查询且均无样本；"
                "继续猜测指标或标签不能提供可区分的实时证据。"
            )
        return None

    def validate_finish(
        self,
        state: PrometheusHarnessState,
        observations: Sequence[HarnessObservation[dict[str, Any]]],
        finish: Finish,
    ) -> Finish | HostRejection:
        del observations
        self._state = state
        if finish.reason in {
            RuntimeStopReason.HUMAN_INPUT_REQUIRED,
            RuntimeStopReason.AMBIGUOUS_TARGET,
            RuntimeStopReason.NO_SAFE_ACTION,
        }:
            return finish
        if (
            finish.reason == RuntimeStopReason.NO_DISCRIMINATING_EVIDENCE
            and state.monitoring_scope_status in {"out_of_scope", "unknown"}
            and any(
                attempt.get("capability") == "target_discovery"
                for attempt in state.tool_attempts
            )
        ):
            return finish
        if state.has_monitoring_data:
            return finish
        return HostRejection(
            code="finish_requires_exact_window_observation",
            message=(
                "Prometheus investigation cannot finish without an exact-window monitoring "
                "observation."
            ),
            repair_hint="Call an approved range_query tool for the Host-bound alert window.",
        )

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
        return MCPModelToolCall(
            call_id=(
                call_id
                if isinstance(call_id, str) and call_id
                else f"prometheus-harness-{uuid4()}"
            ),
            name=call.tool_name,
            arguments=deepcopy(call.model_arguments),
            request_id=request_id if isinstance(request_id, str) else None,
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

    @staticmethod
    def _policy_version(policy: PrometheusMCPToolPolicy) -> str:
        canonical = json.dumps(
            asdict(policy),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        digest = sha256(canonical.encode("utf-8")).hexdigest()[:24]
        return f"{PROMETHEUS_MCP_PROMPT_VERSION}:{digest}"


async def collect_prometheus_with_harness(
    client: PrometheusMCPClient,
    context: InvestigationContext,
) -> PrometheusMCPQueryResult:
    """Run one Prometheus child investigation and return the public result model."""

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
    decision_limit = (
        client.max_agent_steps * PROMETHEUS_MCP_DECISION_LIMIT_MULTIPLIER
    )
    budget = BudgetLedger(
        BudgetLimits(
            planner_requests=decision_limit * 2,
            accepted_decisions=decision_limit,
            remote_tool_calls=client.max_agent_steps,
            host_bootstrap_calls=0,
            session_attempts=2,
        )
    )
    runtime = MCPAgentHarnessRuntime[
        PrometheusHarnessState,
        dict[str, Any],
    ](
        connector=PrometheusSSEMCPConnector(client),
        planner=planner,
        scenario=scenario,
        dispatch_scope_id=context.outer_dispatch_id,
        event_sink=event_sink,
        budget=budget,
        checkpoint_hook=checkpoint_store,
        invocation_store=invocation_store,
        planner_timeout_seconds=client.timeout_seconds,
        session_timeout_seconds=client.timeout_seconds,
    )
    checkpoint = (
        await checkpoint_store.load(context.run_id)
        if checkpoint_store is not None
        else None
    )
    if context.outer_dispatch_attempt == 2 and checkpoint is None:
        raise PrometheusMCPConfigurationError(
            "Prometheus outer recovery attempt has no matching child checkpoint"
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
        if event.kind == AgentEventKind.HOST_REJECTED:
            code = str(event.payload.get("code") or "host_rejected")
            outcome = {
                "duplicate_call": "host_rejected_duplicate",
                "tool_not_approved": "host_rejected_unauthorized",
                "tool_not_in_local_policy": "host_rejected_unauthorized",
            }.get(code, f"host_rejected_{code}")
            if state_attempts and state_attempts[0].get("outcome") == outcome:
                attempts.append(state_attempts.popleft())
            else:
                attempts.append(
                    {
                        "outcome": outcome,
                        "detail": sanitize_text(
                            str(event.payload.get("message") or "")
                        )[:500],
                    }
                )
        elif event.kind in {
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
    finished_by_model = (
        finish.model_requested
        and finish.reason == RuntimeStopReason.COMPLETED
        and has_monitoring_data
    )
    model_failure = (
        finish.reason == RuntimeStopReason.HUMAN_INPUT_REQUIRED
        and bool(state.consecutive_model_errors)
    )
    call_limit_reached = (
        finish.reason == RuntimeStopReason.BUDGET_EXHAUSTED
        and "remote_tool_calls" in finish.summary
    )
    if state.monitoring_scope_status == "out_of_scope":
        termination_reason = "database_not_monitored"
    elif state.monitoring_scope_status == "unknown" and not has_monitoring_data:
        termination_reason = "monitoring_scope_unknown"
    elif finished_by_model:
        termination_reason = "finished_by_model"
    elif model_failure:
        termination_reason = (
            "model_error_after_partial_result"
            if has_monitoring_data
            else "model_error_no_result"
        )
    elif call_limit_reached:
        termination_reason = "call_limit_reached"
    elif finish.reason == RuntimeStopReason.BUDGET_EXHAUSTED:
        termination_reason = "decision_limit_reached"
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
    if model_failure:
        termination_error_type = PrometheusMCPModelError.__name__
        termination_error_detail = sanitize_text(finish.summary)[:1000]
        attempts.append(
            {
                "outcome": "model_selection_error",
                "error_type": termination_error_type,
                "detail": termination_error_detail,
                "remote_calls_used": len(state.executed_calls),
                "remote_calls_remaining": max(
                    client.max_agent_steps - len(state.executed_calls), 0
                ),
                "evidence_disposition": "MISSING",
                "is_contradiction": False,
                "diagnostics": sanitize(
                    {
                        "errors": state.consecutive_model_errors,
                        "first_error": (
                            state.consecutive_model_errors[0]["error"]
                            if state.consecutive_model_errors
                            else None
                        ),
                        "second_error": (
                            state.consecutive_model_errors[-1]["error"]
                            if len(state.consecutive_model_errors) > 1
                            else None
                        ),
                        "remote_calls_used": len(state.executed_calls),
                        "remote_calls_remaining": max(
                            client.max_agent_steps - len(state.executed_calls), 0
                        ),
                    }
                ),
            }
        )
    elif not finished_by_model:
        termination_error_type = state.last_error_type
        termination_error_detail = state.last_error_detail
        if termination_error_type is None:
            failed_sessions = [
                event
                for event in events
                if event.kind == AgentEventKind.MCP_SESSION_FAILED
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
        call_limit_reached=call_limit_reached,
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
    "PrometheusSSEMCPConnector",
    "PrometheusSSEMCPToolSession",
    "collect_prometheus_with_harness",
]
