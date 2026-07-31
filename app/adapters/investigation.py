from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import UTC, datetime
from typing import Any

from app.adapters.archery_mcp import (
    ARCHERY_SLOW_LOG_TOOL_NAME,
    is_slow_query_alert_title,
)
from app.application.sanitization import sanitize
from app.domain.models import (
    EvidenceRecord,
    InvestigationContext,
    InvestigationStrategy,
    NormalizedAlert,
    RunbookExcerpt,
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
                status=status,
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


class DefaultInvestigationStrategyProvider:
    def __init__(
        self,
        max_dynamic_turns: int = 0,
        *,
        alert_context_timeout_seconds: float = 15,
        external_tool_timeout_seconds: float = 45,
        available_tools: list[str] | None = None,
        metrics_ds_name: str = "",
        logs_ds_name: str = "",
        logs_ds_type: str = "loki",
    ) -> None:
        self.max_dynamic_turns = max_dynamic_turns
        self.alert_context_timeout_seconds = alert_context_timeout_seconds
        self.external_tool_timeout_seconds = external_tool_timeout_seconds
        self.available_tools = set(
            ["alert_context"] if available_tools is None else available_tools
        )
        self.metrics_ds_name = metrics_ds_name.strip()
        self.logs_ds_name = logs_ds_name.strip()
        self.logs_ds_type = logs_ds_type.strip()

    async def select(
        self, alert: NormalizedAlert, runbooks: list[RunbookExcerpt] | None = None
    ) -> InvestigationStrategy:
        runbooks = runbooks or []
        diagnostics = self._diagnostics_for_text(
            " ".join(
                [
                    alert.alert_type,
                    alert.alert_name,
                    alert.title,
                    alert.reason,
                    *[
                        probe.objective
                        for runbook in runbooks
                        for cause in runbook.causes
                        for probe in cause.probes
                        if probe.tool_name == "query_database_diagnostics"
                    ],
                ]
            )
        )
        tool_plan = self._base_tool_plan(alert, diagnostics)
        seen_tools = {item.tool_name for item in tool_plan}

        for runbook in runbooks or []:
            for cause in runbook.causes:
                for probe in cause.probes:
                    if (
                        not probe.read_only
                        or probe.tool_name in seen_tools
                        or probe.tool_name not in self.available_tools
                    ):
                        continue
                    parameters = self._parameters_for_tool(
                        probe.tool_name, alert, probe.objective
                    )
                    if parameters is None:
                        continue
                    seen_tools.add(probe.tool_name)
                    tool_plan.append(
                        ToolExecutionRequest(
                            tool_name=probe.tool_name,
                            parameters={
                                **parameters,
                                "objective": probe.objective,
                                "runbook_id": runbook.runbook_id,
                                "section": runbook.section,
                            },
                            required=False,
                            timeout_seconds=self.external_tool_timeout_seconds,
                        )
                    )
                    if len(tool_plan) >= 6:
                        break
                if len(tool_plan) >= 6:
                    break
            if len(tool_plan) >= 6:
                break

        connection_alert = alert.alert_type.casefold() in {
            "connection_exhausted",
            "too_many_connections",
        }
        slow_query_alert = is_slow_query_alert_title(alert.title)
        return InvestigationStrategy(
            strategy_id=(
                "database-connection-exhausted-v2"
                if connection_alert
                else (
                    "database-excessive-slow-query-v1"
                    if slow_query_alert
                    else "generic-alert-investigation-v2"
                )
            ),
            title=(
                "数据库连接数耗尽调查策略"
                if connection_alert
                else (
                    "慢查询过多实时取证策略"
                    if slow_query_alert
                    else "通用告警调查策略"
                )
            ),
            description=(
                "先采集告警上下文，再执行具备完整参数的基础只读探针；"
                "命中手册时补充其诊断图中的可执行探针。"
            ),
            tool_plan=tool_plan,
            max_dynamic_turns=self.max_dynamic_turns,
        )

    def _base_tool_plan(
        self, alert: NormalizedAlert, diagnostics: list[str]
    ) -> list[ToolExecutionRequest]:
        requests: list[ToolExecutionRequest] = []
        if "alert_context" in self.available_tools:
            requests.append(
                ToolExecutionRequest(
                    tool_name="alert_context",
                    required=True,
                    timeout_seconds=self.alert_context_timeout_seconds,
                )
            )

        if is_slow_query_alert_title(alert.title):
            requests.append(
                ToolExecutionRequest(
                    tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
                    required=True,
                    timeout_seconds=self.external_tool_timeout_seconds,
                )
            )

        for tool_name in (
            "query_metrics",
            "query_logs",
            "query_similar_incidents",
        ):
            if tool_name not in self.available_tools:
                continue
            parameters = self._parameters_for_tool(
                tool_name,
                alert,
                " ".join(diagnostics),
            )
            if parameters is None:
                continue
            requests.append(
                ToolExecutionRequest(
                    tool_name=tool_name,
                    parameters=parameters,
                    required=False,
                    timeout_seconds=self.external_tool_timeout_seconds,
                )
            )
        return requests

    def _parameters_for_tool(
        self, tool_name: str, alert: NormalizedAlert, objective: str
    ) -> dict[str, Any] | None:
        if tool_name == ARCHERY_SLOW_LOG_TOOL_NAME:
            if not is_slow_query_alert_title(alert.title):
                return None
            return {}

        if tool_name == "query_database_diagnostics":
            target_locator = (
                alert.attributes.get("flashduty_target_locator")
                or (alert.database.instance if alert.database else None)
                or (alert.database.host if alert.database else None)
            )
            if not isinstance(target_locator, str) or not target_locator.strip():
                return None
            parameters: dict[str, Any] = {
                "target_locator": target_locator.strip(),
                "diagnostics": self._diagnostics_for_text(objective),
                **self._alert_context_parameters(alert),
            }
            target_kind = alert.attributes.get("flashduty_target_kind")
            if isinstance(target_kind, str) and target_kind.strip():
                parameters["target_kind"] = target_kind.strip()
            return parameters

        if tool_name == "query_metrics":
            config = self._query_config(
                alert,
                "metrics",
                defaults={
                    "ds_type": "prometheus",
                    "ds_name": self.metrics_ds_name,
                },
            )
            expression = config.get("expr") or config.get("query_expr")
            if not expression and alert.metric_name and re.fullmatch(
                r"[A-Za-z_:][A-Za-z0-9_:]*", alert.metric_name
            ):
                expression = alert.metric_name
            if (
                not isinstance(expression, str)
                or not expression.strip()
                or not str(config.get("ds_name") or "").strip()
            ):
                return None
            return {
                **config,
                "ds_type": "prometheus",
                "expr": expression.strip(),
                **self._alert_context_parameters(alert),
            }

        if tool_name == "query_logs":
            config = self._query_config(
                alert,
                "logs",
                defaults={
                    "ds_type": self.logs_ds_type,
                    "ds_name": self.logs_ds_name,
                },
            )
            expression = config.get("expr") or config.get("query_expr")
            if (
                not isinstance(expression, str)
                or not expression.strip()
                or not str(config.get("ds_name") or "").strip()
            ):
                return None
            return {
                **config,
                "expr": expression.strip(),
                **self._alert_context_parameters(alert),
            }

        if tool_name in {"query_trace", "query_endpoint_errors"}:
            suffix = "trace" if tool_name == "query_trace" else "endpoint_errors"
            config = self._query_config(alert, suffix)
            expression = config.get("expr") or config.get("query_expr")
            if not all(
                isinstance(config.get(key), str) and str(config[key]).strip()
                for key in ("ds_type", "ds_name")
            ) or not isinstance(expression, str) or not expression.strip():
                return None
            return {
                **config,
                "expr": expression.strip(),
                **self._alert_context_parameters(alert),
            }

        if tool_name == "query_similar_incidents":
            incident_id = alert.attributes.get("flashduty_incident_id")
            return (
                self._alert_context_parameters(alert)
                if isinstance(incident_id, str) and incident_id
                else None
            )

        if tool_name == "query_changes":
            return {
                "window_seconds": 1800,
                "limit": 20,
                **self._alert_context_parameters(alert),
            }

        return {}

    @staticmethod
    def _query_config(
        alert: NormalizedAlert,
        suffix: str,
        *,
        defaults: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        config = dict(defaults or {})
        alert_config = alert.attributes.get(f"flashduty_{suffix}")
        if isinstance(alert_config, dict):
            config.update(alert_config)
        return config

    @staticmethod
    def _alert_context_parameters(alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "environment": alert.environment,
            "service_name": alert.service_name,
            "instance": alert.database.instance if alert.database else None,
        }

    @staticmethod
    def _diagnostics_for_text(value: str) -> list[str]:
        lowered = value.casefold()
        diagnostics: list[str] = []
        families = (
            (("connection", "连接", "session", "会话"), "connection_sources"),
            (("long", "慢查询", "长事务"), "long_sessions"),
            (("lock", "deadlock", "锁", "阻塞"), "locks"),
            (("replica", "replication", "slave", "lag", "复制", "同步"), "replication"),
        )
        for terms, diagnostic in families:
            if any(term in lowered for term in terms):
                diagnostics.append(diagnostic)
        return diagnostics or ["overview"]


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
            UnavailableExternalTool(
                ARCHERY_SLOW_LOG_TOOL_NAME, "archery_mcp"
            ),
            UnavailableExternalTool("query_changes", "alert_platform"),
            UnavailableExternalTool("query_similar_incidents", "alert_platform"),
        ]
    )
