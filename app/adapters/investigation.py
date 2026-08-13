from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from app.agent_runtime.contracts import ToolSpec
from app.application.sanitization import sanitize
from app.domain.models import (
    EvidenceRecord,
    InvestigationContext,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.ports import InvestigationTool


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

        schema = getattr(
            tool,
            "input_schema",
            {"type": "object", "additionalProperties": True},
        )
        if not isinstance(schema, dict):
            raise TypeError(f"Tool {tool.name} input_schema must be an object")
        return ToolSpec(
            name=tool.name,
            provider=tool.source_system,
            capability=str(getattr(tool, "capability", tool.name)),
            role=str(getattr(tool, "role", "")),
            workflow=str(getattr(tool, "workflow", "")),
            safety=str(getattr(tool, "safety", "")),
            input_schema=schema,
            policy_version=str(getattr(tool, "policy_version", "mcp-server-key-v1")),
            schema_version=str(getattr(tool, "schema_version", "dynamic-mcp-schema-v1")),
            timeout=float(getattr(tool, "default_timeout_seconds", 30)),
        )


class ToolExecutor:
    def __init__(
        self,
        registry: InvestigationToolRegistry,
    ) -> None:
        self.registry = registry

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
