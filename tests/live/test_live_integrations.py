from __future__ import annotations

import json
import os
import re
from pathlib import Path
from uuid import uuid4

import pytest

from app.adapters.ai import OpenAICompatibleAdvisor
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.flashduty import (
    FlashDutyAlertContextTool,
    FlashDutyAlertSourceAdapter,
    FlashDutyClient,
)
from app.adapters.notification import LogManagementNotifier
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import (
    AlertStatus,
    InvestigationContext,
    InvestigationStrategy,
    ToolExecutionRequest,
    ToolStatus,
)

_LIVE_ENABLED = os.getenv("RUN_LIVE_TESTS", "").strip().casefold() in {
    "1",
    "true",
    "yes",
}
_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not _LIVE_ENABLED,
        reason="set RUN_LIVE_TESTS=1 to allow real external API calls",
    ),
]


@pytest.fixture(scope="module")
def live_settings() -> Settings:
    """Load the operator's real `.env` only for explicitly enabled live tests."""

    settings = Settings()
    missing: list[str] = []
    if settings.ai_provider != "openai_compatible":
        missing.append("AI_PROVIDER=openai_compatible")
    if not settings.ai_api_key.strip():
        missing.append("AI_API_KEY")
    if not settings.ai_model.strip():
        missing.append("AI_MODEL")
    if not settings.flashduty_enabled:
        missing.append("FLASHDUTY_ENABLED=true")
    if not settings.flashduty_app_key.strip():
        missing.append("FLASHDUTY_APP_KEY")
    if missing:
        pytest.fail("Live test configuration is incomplete: " + ", ".join(missing))
    return settings


@pytest.fixture(scope="module")
def flashduty_alert_id() -> str:
    alert_id = os.getenv("FLASHDUTY_TEST_ALERT_ID", "").strip()
    if not _OBJECT_ID.fullmatch(alert_id):
        pytest.fail("FLASHDUTY_TEST_ALERT_ID must be a real 24-character FlashDuty ObjectID")
    return alert_id


def _flashduty_client(settings: Settings) -> FlashDutyClient:
    return FlashDutyClient(
        settings.flashduty_app_key,
        base_url=settings.flashduty_base_url,
        timeout_seconds=settings.flashduty_timeout_seconds,
        max_retries=settings.flashduty_max_retries,
    )


@pytest.mark.asyncio
async def test_live_ai_provider_returns_valid_schema_and_request_id(
    live_settings: Settings,
) -> None:
    advisor = OpenAICompatibleAdvisor(
        api_key=live_settings.ai_api_key,
        base_url=live_settings.ai_base_url,
        model=live_settings.ai_model,
        timeout_seconds=live_settings.ai_timeout_seconds,
        max_retries=live_settings.ai_max_retries,
        json_mode=live_settings.ai_json_mode,
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": f"live-ai-{uuid4().hex}",
            "severity": "INFO",
            "title": "Live AI compatibility smoke test",
            "reason": "live_test_only",
            "environment": "test",
            "service_name": "database-alert-agent",
        }
    )

    recommendation, metadata = await advisor.advise(alert, [])

    assert metadata.provider == "openai_compatible"
    assert metadata.model == live_settings.ai_model
    assert metadata.request_id
    assert recommendation.summary.strip()
    assert recommendation.manual_matched is False
    assert recommendation.analysis_bases
    assert all(item.source.value == "AI" for item in recommendation.analysis_bases)


@pytest.mark.asyncio
async def test_live_flashduty_context_records_read_request_ids(
    live_settings: Settings,
    flashduty_alert_id: str,
) -> None:
    client = _flashduty_client(live_settings)
    initial = await client.alert_info(flashduty_alert_id)
    alert = FlashDutyAlertSourceAdapter(live_settings.environment_aliases).normalize(
        {"request_id": initial.request_id, "data": initial.data}
    )
    strategy = InvestigationStrategy(
        strategy_id="live-flashduty-context",
        title="Live FlashDuty read-only context test",
        description="Read alert and incident context without mutations.",
    )
    context = InvestigationContext(run_id=uuid4(), alert=alert, strategy=strategy)

    _, structured_data = await FlashDutyAlertContextTool(
        client, item_limit=min(live_settings.flashduty_context_item_limit, 5)
    ).execute(
        ToolExecutionRequest(
            tool_name="alert_context",
            required=True,
            timeout_seconds=live_settings.flashduty_timeout_seconds,
        ),
        context,
    )

    request_ids = structured_data["flashduty"]["request_ids"]
    assert {"alert_info", "alert_events", "alert_feed"} <= set(request_ids)
    assert all(value and value != "unknown" for value in request_ids.values())
    if alert.attributes.get("flashduty_incident_id"):
        assert {"incident_info", "incident_feed", "incident_alerts"} <= set(request_ids)
    assert live_settings.flashduty_app_key not in json.dumps(
        structured_data, ensure_ascii=False, default=str
    )


@pytest.mark.asyncio
async def test_live_full_flashduty_analysis_uses_real_ai_without_wecom(
    tmp_path: Path,
    live_settings: Settings,
    flashduty_alert_id: str,
) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = live_settings.model_copy(
        update={
            "app_env": "development",
            "database_url": f"sqlite+aiosqlite:///{tmp_path / 'live.db'}",
            "runtime_settings_path": tmp_path / "runtime-settings.json",
            "runbook_pdf_dir": runbooks,
            "http_scheduler": "manual",
            "kafka_enabled": False,
            "wecom_webhook_url": "",
            "shadow_enabled": True,
            "production_gate_approved": False,
            "react_enabled": False,
            "validation_enabled": True,
            "flashduty_context_item_limit": min(live_settings.flashduty_context_item_limit, 5),
            "tool_max_result_chars": 100_000,
        }
    )
    client = _flashduty_client(settings)
    initial = await client.alert_info(flashduty_alert_id)
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    try:
        result = await runtime.service.analyze(
            "flashduty", {"request_id": initial.request_id, "data": initial.data}
        )
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]

    assert isinstance(runtime.service.notifier, LogManagementNotifier)
    assert result.status == AlertStatus.REVIEW_REQUIRED
    assert result.error is None
    assert result.advisor_metadata is not None
    assert result.advisor_metadata.request_id
    assert result.recommendation is not None
    assert result.recommendation.analysis_mode == "shadow"
    context_evidence = next(
        item for item in result.evidence_records if item.tool_name == "alert_context"
    )
    assert context_evidence.status == ToolStatus.SUCCESS
    assert context_evidence.truncated is False
    request_ids = context_evidence.structured_data["flashduty"]["request_ids"]
    assert {"alert_info", "alert_events", "alert_feed"} <= set(request_ids)
    assert all(value and value != "unknown" for value in request_ids.values())
