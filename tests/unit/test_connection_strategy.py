from pathlib import Path

import pytest

from app.adapters.investigation import AlertContextTool, InvestigationToolRegistry
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import INCONCLUSIVE_ROOT_CAUSE_SUMMARY, AlertStatus


class RecordingTool:
    read_only = True

    def __init__(self, name: str, calls: list[tuple[str, dict]]) -> None:
        self.name = name
        self.source_system = "test_diagnostics"
        self.calls = calls

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append((self.name, request.parameters))
        if self.name == "query_metrics":
            return "连接使用率持续上升。", {
                "current_connections": 95,
                "max_connections": 100,
                "trend": "rising",
            }
        return "发现来自 orders-api 的长会话。", {
            "connection_sources": {"orders-api": 90},
            "long_sessions": 4,
        }


def make_settings(tmp_path: Path, name: str) -> Settings:
    runbooks = tmp_path / f"runbooks-{name}"
    runbooks.mkdir()
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / f'{name}.db'}",
        runbook_pdf_dir=runbooks,
        flashduty_metrics_ds_name="prod-prom",
    )


@pytest.mark.asyncio
async def test_connection_alert_does_not_trigger_hard_coded_tools(tmp_path: Path) -> None:
    calls: list[tuple[str, dict]] = []
    registry = InvestigationToolRegistry(
        [
            AlertContextTool(),
            RecordingTool("query_metrics", calls),
            RecordingTool("query_database_diagnostics", calls),
        ]
    )
    runtime = build_runtime(make_settings(tmp_path, "connected"), tool_registry=registry)
    await runtime.repository.initialize()
    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "connection-live-1",
            "severity": "WARNING",
            "title": "Connection usage 95%",
            "reason": "connection_exhausted",
            "environment": "prd",
            "service_name": "orders-api",
            "metric_name": "mysql_threads_connected",
            "database": {"engine": "postgresql", "instance": "orders-primary"},
            "features": {"connection_usage_percent": 95},
        },
    )

    # Registered non-MCP tools are not selected by alert-type branches. MCP
    # relevance selection is driven only by the declarative catalog bindings.
    assert result.status == AlertStatus.INCONCLUSIVE
    assert calls == []
    assert result.evidence_records == []
    assert all(item.passed for item in result.validations)
    assert all(not item.evidence_sufficient for item in result.validations)
    assert result.recommendation is not None
    assert result.recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.recommendation.root_causes == []
    assert result.recommendation.likely_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_missing_live_connection_evidence_is_inconclusive(tmp_path: Path) -> None:
    runtime = build_runtime(make_settings(tmp_path, "missing"))
    await runtime.repository.initialize()
    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "connection-missing-1",
            "severity": "WARNING",
            "title": "Connection usage 95%",
            "reason": "connection_exhausted",
        },
    )

    assert result.status == AlertStatus.INCONCLUSIVE
    assert all(item.passed for item in result.validations)
    assert all(not item.evidence_sufficient for item in result.validations)
    assert result.recommendation is not None
    assert result.recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.recommendation.root_causes == []
    assert result.recommendation.likely_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]
