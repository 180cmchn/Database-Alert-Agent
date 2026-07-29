from pathlib import Path

import pytest

from app.adapters.investigation import AlertContextTool, InvestigationToolRegistry
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import AlertStatus


class RecordingTool:
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
async def test_connection_strategy_collects_live_evidence(tmp_path: Path) -> None:
    calls: list[tuple[str, dict]] = []
    registry = InvestigationToolRegistry(
        [
            AlertContextTool(),
            RecordingTool("query_metrics", calls),
            RecordingTool("query_database_diagnostics", calls),
        ]
    )
    runtime = build_runtime(
        make_settings(tmp_path, "connected"), tool_registry=registry
    )
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

    assert result.status == AlertStatus.COMPLETED
    assert [name for name, _ in calls] == [
        "query_database_diagnostics",
        "query_metrics",
    ]
    assert all(parameters["environment"] == "production" for _, parameters in calls)
    parameters_by_tool = dict(calls)
    assert parameters_by_tool["query_database_diagnostics"]["target_locator"] == (
        "orders-primary"
    )
    assert parameters_by_tool["query_database_diagnostics"]["diagnostics"] == [
        "connection_sources"
    ]
    assert parameters_by_tool["query_metrics"]["ds_name"] == "prod-prom"
    assert parameters_by_tool["query_metrics"]["expr"] == "mysql_threads_connected"
    assert all(item.status.value == "SUCCESS" for item in result.evidence_records)
    assert all(item.passed for item in result.validations)
    assert all(item.evidence_sufficient for item in result.validations)
    assert result.recommendation is not None
    assert result.recommendation.root_causes[0].verified is True
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_missing_live_connection_evidence_requires_review(tmp_path: Path) -> None:
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

    assert result.status == AlertStatus.REVIEW_REQUIRED
    assert all(item.passed for item in result.validations)
    assert all(not item.evidence_sufficient for item in result.validations)
    assert result.recommendation is not None
    assert result.recommendation.root_causes[0].status.value == "UNKNOWN"
    assert result.recommendation.root_causes[0].next_probe
    await runtime.repository.close()  # type: ignore[attr-defined]
