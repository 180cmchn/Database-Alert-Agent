from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any

from app.application.sanitization import sanitize
from app.domain.models import (
    EvidenceRecord,
    InvestigationContext,
    InvestigationStrategy,
    RunbookExcerpt,
    ToolExecutionRequest,
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

    def get(self, name: str) -> InvestigationTool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)


class ToolExecutor:
    def __init__(self, registry: InvestigationToolRegistry, max_result_chars: int = 12000) -> None:
        self.registry = registry
        self.max_result_chars = max_result_chars

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
                status=ToolStatus.FAILED,
                summary=f"调查工具 {request.tool_name} 尚未接入。",
                error="Tool is not registered",
                started_at=started_at,
                started=started,
            )

        try:
            async with asyncio.timeout(request.timeout_seconds):
                summary, structured_data = await tool.execute(request, context)
            safe_data = sanitize(structured_data)
            serialized = json.dumps(safe_data, ensure_ascii=False, default=str)
            truncated = len(serialized) > self.max_result_chars
            if truncated:
                safe_data = {
                    "truncated_preview": serialized[: self.max_result_chars],
                    "original_char_count": len(serialized),
                }
            return self._record(
                request,
                context,
                source_system=tool.source_system,
                status=ToolStatus.SUCCESS,
                summary=str(sanitize(summary))[:2000],
                structured_data=safe_data,
                truncated=truncated,
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
            return self._record(
                request,
                context,
                source_system=tool.source_system,
                status=ToolStatus.FAILED,
                summary=f"调查工具 {request.tool_name} 执行失败。",
                error=f"{type(exc).__name__}: {sanitize(str(exc))}",
                started_at=started_at,
                started=started,
            )

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

    def __init__(self, name: str, source_system: str) -> None:
        self.name = name
        self.source_system = source_system

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        raise RuntimeError(
            f"{self.name} adapter is not configured; connect the real {self.source_system} API"
        )


class DefaultInvestigationStrategyProvider:
    def __init__(self, max_dynamic_turns: int = 0) -> None:
        self.max_dynamic_turns = max_dynamic_turns

    async def select(
        self, alert, runbooks: list[RunbookExcerpt] | None = None
    ) -> InvestigationStrategy:  # type: ignore[no-untyped-def]
        if alert.alert_type.lower() in {"connection_exhausted", "too_many_connections"}:
            return InvestigationStrategy(
                strategy_id="database-connection-exhausted-v1",
                title="数据库连接数耗尽调查策略",
                description=(
                    "手册为首要依据；核对连接使用率和趋势，并通过只读诊断确认连接来源与长会话。"
                ),
                tool_plan=[
                    ToolExecutionRequest(
                        tool_name="alert_context", required=True, timeout_seconds=3
                    ),
                    ToolExecutionRequest(
                        tool_name="query_metrics",
                        parameters={
                            "metric_types": [
                                "current_connections",
                                "max_connections",
                                "connection_usage_trend",
                            ],
                            "environment": alert.environment,
                            "instance": alert.database.instance if alert.database else None,
                        },
                        required=True,
                        timeout_seconds=10,
                    ),
                    ToolExecutionRequest(
                        tool_name="query_database_diagnostics",
                        parameters={
                            "diagnostics": ["connection_sources", "long_sessions"],
                            "environment": alert.environment,
                            "instance": alert.database.instance if alert.database else None,
                        },
                        required=True,
                        timeout_seconds=15,
                    ),
                ],
                max_dynamic_turns=self.max_dynamic_turns,
            )
        tool_plan = [
            ToolExecutionRequest(tool_name="alert_context", required=True, timeout_seconds=3)
        ]
        seen_tools = {"alert_context"}
        for runbook in runbooks or []:
            for cause in runbook.causes:
                for probe in cause.probes:
                    if not probe.read_only or probe.tool_name in seen_tools:
                        continue
                    seen_tools.add(probe.tool_name)
                    tool_plan.append(
                        ToolExecutionRequest(
                            tool_name=probe.tool_name,
                            parameters={
                                "objective": probe.objective,
                                "runbook_id": runbook.runbook_id,
                                "section": runbook.section,
                            },
                            required=False,
                            timeout_seconds=10,
                        )
                    )
                    if len(tool_plan) >= 4:
                        break
                if len(tool_plan) >= 4:
                    break
            if len(tool_plan) >= 4:
                break
        return InvestigationStrategy(
            strategy_id="generic-alert-investigation-v1",
            title="通用告警调查策略",
            description="先采集告警上下文，再按命中手册的诊断图执行只读核查。",
            tool_plan=tool_plan,
            max_dynamic_turns=self.max_dynamic_turns,
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
        ]
    )
