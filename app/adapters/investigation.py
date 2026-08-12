from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from app.agent_runtime.contracts import RetryPolicy, ToolRisk, ToolSpec
from app.application.sanitization import sanitize
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.models import (
    EvidenceRecord,
    ExternalKnowledgeExcerpt,
    InvestigationContext,
    InvestigationStrategy,
    NormalizedAlert,
    RunbookExcerpt,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.ports import InvestigationTool
from app.domain.tool_calling import MCPServerSelectionModel


class InvestigationToolRegistry:
    def __init__(self, tools: list[InvestigationTool] | None = None) -> None:
        self._tools: dict[str, InvestigationTool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: InvestigationTool) -> None:
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def get(self, name: str) -> InvestigationTool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def available_names(self) -> list[str]:
        return sorted(
            name
            for name, tool in self._tools.items()
            if getattr(tool, "available", True)
        )

    def specs(self) -> list[ToolSpec]:
        """Return a stable, policy-bearing catalog for every registered tool."""

        return [self._spec_for(self._tools[name]) for name in sorted(self._tools)]

    def available_specs(self) -> list[ToolSpec]:
        """Return model-visible contracts for tools available in this runtime."""

        return [
            self._spec_for(self._tools[name])
            for name in sorted(self._tools)
            if getattr(self._tools[name], "available", True)
        ]

    def spec(self, name: str) -> ToolSpec | None:
        tool = self._tools.get(name)
        return self._spec_for(tool) if tool is not None else None

    @staticmethod
    def _spec_for(tool: InvestigationTool) -> ToolSpec:
        declared = getattr(tool, "tool_spec", None)
        if isinstance(declared, ToolSpec):
            return declared

        if not hasattr(tool, "read_only"):
            raise TypeError(
                f"Tool {tool.name} must explicitly declare read_only before registration"
            )
        read_only = tool.read_only
        if type(read_only) is not bool:
            raise TypeError(f"Tool {tool.name} read_only must be a boolean")

        schema = getattr(
            tool,
            "input_schema",
            {"type": "object", "additionalProperties": True},
        )
        if not isinstance(schema, dict):
            raise TypeError(f"Tool {tool.name} input_schema must be an object")
        canonical_schema = json.dumps(
            schema,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return ToolSpec(
            name=tool.name,
            provider=tool.source_system,
            capability=str(getattr(tool, "capability", tool.name)),
            input_schema=schema,
            read_only=read_only,
            risk=ToolRisk(str(getattr(tool, "risk", ToolRisk.LOW)).upper()),
            policy_version=str(getattr(tool, "policy_version", "legacy-read-only-v1")),
            schema_version=(
                "sha256:"
                + hashlib.sha256(canonical_schema.encode("utf-8")).hexdigest()[:16]
            ),
            timeout=float(getattr(tool, "default_timeout_seconds", 30)),
            retry=RetryPolicy(
                max_attempts=int(getattr(tool, "max_attempts", 1)),
            ),
        )


class ToolPolicyViolation(ValueError):
    """Raised before execution when a request violates its advertised contract."""


class InvestigationToolPolicy:
    """Provider-neutral safety and JSON Schema gate for outer investigation tools."""

    def __init__(self, registry: InvestigationToolRegistry) -> None:
        self.registry = registry

    def authorize(self, request: ToolExecutionRequest) -> ToolSpec:
        tool = self.registry.get(request.tool_name)
        spec = self.registry.spec(request.tool_name)
        if tool is None or spec is None:
            raise ToolPolicyViolation(f"Tool is not registered: {request.tool_name}")
        if not getattr(tool, "available", True):
            raise ToolPolicyViolation(f"Tool is not available: {request.tool_name}")
        if not spec.read_only:
            raise ToolPolicyViolation(
                f"Investigation tool is not declared read-only: {request.tool_name}"
            )
        try:
            Draft202012Validator.check_schema(spec.input_schema)
            Draft202012Validator(spec.input_schema).validate(request.parameters)
        except (SchemaError, ValidationError) as exc:
            raise ToolPolicyViolation(
                f"Tool arguments do not satisfy the registered schema: {request.tool_name}"
            ) from exc
        return spec


class ToolExecutor:
    def __init__(
        self,
        registry: InvestigationToolRegistry,
        *,
        policy: InvestigationToolPolicy | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy or InvestigationToolPolicy(registry)

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> EvidenceRecord:
        started_at = datetime.now(UTC)
        started = time.monotonic()
        tool = self.registry.get(request.tool_name)
        if tool is None:
            return self._record(
                request,
                context,
                source_system="unregistered",
                status=ToolStatus.SKIPPED,
                summary=f"未执行调查工具 {request.tool_name}：工具未注册或能力未启用。",
                structured_data={"reason_code": "tool_not_registered"},
                started_at=started_at,
                started=started,
            )

        try:
            self.policy.authorize(request)
        except ToolPolicyViolation as exc:
            return self._record(
                request,
                context,
                source_system=tool.source_system,
                status=ToolStatus.SKIPPED,
                summary=f"未执行调查工具 {request.tool_name}：调用未通过只读策略校验。",
                structured_data={
                    "reason_code": "tool_policy_rejected",
                    "policy_error": str(sanitize(exc)),
                },
                started_at=started_at,
                started=started,
            )

        try:
            async with asyncio.timeout(request.timeout_seconds):
                outcome = await tool.execute(request, context)
            if isinstance(outcome, ToolExecutionResult):
                status = outcome.status
                summary = outcome.summary
                structured_data = outcome.structured_data
            else:
                status = ToolStatus.SUCCESS
                summary, structured_data = outcome
            if status in {ToolStatus.FAILED, ToolStatus.TIMEOUT}:
                raise ValueError(
                    "Tools must raise an exception for FAILED/TIMEOUT outcomes"
                )
            safe_data = sanitize(structured_data)
            return self._record(
                request,
                context,
                source_system=tool.source_system,
                status=status,
                summary=str(sanitize(summary))[:2000],
                structured_data=safe_data,
                started_at=started_at,
                started=started,
            )

        except TimeoutError:
            return self._record(
                request,
                context,
                source_system=tool.source_system,
                status=ToolStatus.TIMEOUT,
                summary=f"调查工具 {request.tool_name} 执行超时。",
                error="Tool execution timed out",
                started_at=started_at,
                started=started,
            )
        except Exception as exc:
            failure_data = self._failure_data(exc)
            return self._record(
                request,
                context,
                source_system=tool.source_system,
                status=ToolStatus.FAILED,
                summary=f"调查工具 {request.tool_name} 执行失败。",
                structured_data=failure_data,
                error=f"{type(exc).__name__}: {sanitize(str(exc))}",
                started_at=started_at,
                started=started,
            )

    @staticmethod
    def _failure_data(exc: Exception) -> dict[str, Any]:
        status_code = getattr(exc, "status_code", None)
        vendor_error_code = getattr(exc, "code", None)
        reason_code = (
            "permission_denied"
            if status_code in {401, 403}
            else str(vendor_error_code or type(exc).__name__)
        )
        result: dict[str, Any] = {"reason_code": reason_code}
        if vendor_error_code:
            result["vendor_error_code"] = str(sanitize(vendor_error_code))
        if isinstance(status_code, int):
            result["http_status"] = status_code
        request_id = getattr(exc, "request_id", None)
        if request_id:
            result["request_id"] = str(sanitize(request_id))
        diagnostic_data = getattr(exc, "diagnostic_data", None)
        if isinstance(diagnostic_data, dict) and diagnostic_data:
            result["diagnostics"] = sanitize(diagnostic_data)
        return result

    @staticmethod
    def _record(
        request: ToolExecutionRequest,
        context: InvestigationContext,
        *,
        source_system: str,
        status: ToolStatus,
        summary: str,
        started_at: datetime,
        started: float,
        structured_data: dict[str, Any] | None = None,
        error: str | None = None,
        truncated: bool = False,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            run_id=context.run_id,
            tool_name=request.tool_name,
            source_system=source_system,
            status=status,
            request=sanitize(request.parameters),
            summary=summary,
            structured_data=structured_data or {},
            error=error,
            started_at=started_at,
            collected_at=datetime.now(UTC),
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            truncated=truncated,
        )


class AlertContextTool:
    name = "alert_context"
    source_system = "alert_platform"
    read_only = True
    max_attempts = 2

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        alert = context.alert
        return (
            "已采集告警平台随事件提供的指标和上下文；这些数据不等同于实时数据库诊断。",
            {
                "severity": alert.severity.value,
                "environment": alert.environment,
                "service_name": alert.service_name,
                "alert_type": alert.alert_type,
                "metric_name": alert.metric_name,
                "features": alert.features,
                "database": alert.database.model_dump(mode="json") if alert.database else None,
                "occurred_at": alert.occurred_at.isoformat(),
            },
        )


class UnavailableExternalTool:
    """Placeholder for a real log/APM/database-management platform adapter."""

    available = False
    read_only = True

    def __init__(self, name: str, source_system: str) -> None:
        self.name = name
        self.source_system = source_system

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> ToolExecutionResult:
        return ToolExecutionResult(
            status=ToolStatus.SKIPPED,
            summary=f"未执行调查工具 {self.name}：对应的 {self.source_system} 能力未配置。",
            structured_data={"reason_code": "adapter_not_configured"},
        )


@dataclass(frozen=True, slots=True)
class MCPToolBinding:
    """Map one secret-free catalog entry to its registered outer tool."""

    server_name: str
    tool_name: str
    role: str
    purpose: str
    timeout_seconds: float
    read_only: bool = True


class DefaultInvestigationStrategyProvider:
    """Let the configured model select zero or more relevant MCP servers.

    The name remains stable for callers that inject the default provider, but
    there are no alert-type or provider-specific strategy branches here.
    """

    def __init__(
        self,
        max_dynamic_turns: int = 0,
        *,
        model: MCPServerSelectionModel | None = None,
        mcp_bindings: list[MCPToolBinding] | None = None,
        available_tools: list[str] | None = None,
        **legacy_options: Any,
    ) -> None:
        # Legacy keyword arguments are accepted so rolling runtime updates do
        # not fail while API and worker processes run different code versions.
        del legacy_options
        self.max_dynamic_turns = max_dynamic_turns
        self.model = model
        available = set(available_tools or [])
        self.mcp_bindings = tuple(
            binding
            for binding in (mcp_bindings or [])
            if binding.tool_name in available and binding.read_only is True
        )

    async def select(
        self,
        alert: NormalizedAlert,
        runbooks: list[RunbookExcerpt] | None = None,
        external_knowledge: list[ExternalKnowledgeExcerpt] | None = None,
        knowledge_match_summary: str = "",
    ) -> InvestigationStrategy:
        runbooks = runbooks or []
        external_knowledge = external_knowledge or []
        selected_names: tuple[str, ...] = ()
        if self.mcp_bindings:
            if self.model is None:
                raise RuntimeError(
                    "Configured MCP servers require a model that supports relevance selection"
                )
            selection = await self.model.select_mcp_servers(
                alert=preprocess_normalized_alert(alert).model_dump(
                    mode="json", exclude={"raw_payload"}
                ),
                knowledge_matches=[
                    {
                        "source": "local_pdf",
                        "match": item.model_dump(mode="json"),
                    }
                    for item in runbooks
                ]
                + [
                    {
                        "source": "external_knowledge",
                        "match": item.model_dump(mode="json"),
                    }
                    for item in external_knowledge
                ],
                knowledge_match_summary=knowledge_match_summary,
                candidates=[
                    {
                        "name": binding.server_name,
                        "role": binding.role,
                        "purpose": binding.purpose,
                        "read_only": binding.read_only,
                    }
                    for binding in self.mcp_bindings
                ],
            )
            configured_names = {binding.server_name for binding in self.mcp_bindings}
            unknown = set(selection.server_names) - configured_names
            if unknown:
                raise ValueError(
                    "MCP selector returned servers outside the configured catalog: "
                    + ", ".join(sorted(unknown))
                )
            selected_names = tuple(dict.fromkeys(selection.server_names))

        by_name = {binding.server_name: binding for binding in self.mcp_bindings}
        tool_plan = [
            ToolExecutionRequest(
                tool_name=by_name[name].tool_name,
                objective=by_name[name].purpose,
                required=False,
                timeout_seconds=by_name[name].timeout_seconds,
            )
            for name in selected_names
        ]
        return InvestigationStrategy(
            strategy_id="agent-selected-mcp-v1",
            title="Agent 自主 MCP 调查",
            description="Agent 根据 MCP 角色和作用选择零个或多个相关只读 MCP。",
            tool_plan=tool_plan,
            max_dynamic_turns=0,
        )


def build_default_tool_registry() -> InvestigationToolRegistry:
    return InvestigationToolRegistry(
        [
            AlertContextTool(),
            UnavailableExternalTool("query_logs", "log_platform"),
            UnavailableExternalTool("query_metrics", "metrics_platform"),
            UnavailableExternalTool("query_trace", "trace_platform"),
            UnavailableExternalTool(
                "query_endpoint_errors", "log_and_trace_platform"
            ),
            UnavailableExternalTool(
                "query_database_diagnostics", "database_management_platform"
            ),
            UnavailableExternalTool("query_changes", "alert_platform"),
            UnavailableExternalTool("query_similar_incidents", "alert_platform"),
        ]
    )
