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
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / f'{name}.db'}",
        runbook_dir=runbooks,
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
            "database": {"engine": "postgresql", "instance": "orders-primary"},
            "features": {"connection_usage_percent": 95},
        },
    )

    assert result.status == AlertStatus.COMPLETED
    assert [name for name, _ in calls] == [
        "query_metrics",
        "query_database_diagnostics",
    ]
    assert all(parameters["environment"] == "production" for _, parameters in calls)
    assert all(item.status.value == "SUCCESS" for item in result.evidence_records)
    assert result.recommendation is not None
    assert result.recommendation.root_causes[0].verified is True
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_missing_required_connection_tools_requires_review(tmp_path: Path) -> None:
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
    assert result.validations[0].passed is False
    assert "query_metrics" in result.validations[0].issues[-1]
    await runtime.repository.close()  # type: ignore[attr-defined]
