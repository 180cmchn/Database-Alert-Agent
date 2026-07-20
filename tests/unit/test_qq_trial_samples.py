import json
from pathlib import Path

import pytest

from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import AlertStatus, NotificationPhase

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ROOT = PROJECT_ROOT / "examples" / "qq-trial"
@pytest.mark.asyncio
async def test_qq_trial_alerts_complete_without_local_runbooks(tmp_path: Path) -> None:
    manifest = json.loads((EXAMPLE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        ai_provider="fake",
        notifier_mode="log",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'qq-trial.db'}",
        runbook_dir=runbooks,
        notification_retry_backoff_seconds=0,
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()

    try:
        for case in manifest["cases"]:
            payload = json.loads((EXAMPLE_ROOT / case["file"]).read_text(encoding="utf-8"))
            result = await runtime.service.analyze("canonical", payload)

            assert result.status is AlertStatus.COMPLETED, case["name"]
            assert [item.runbook_id for item in result.manual_matches] == case[
                "expected_manual_matches"
            ], case["name"]
            assert result.recommendation is not None
            assert result.recommendation.manual_matched is bool(
                case["expected_manual_matches"]
            )
            phases = [item.phase for item in result.notifications]
            if case["expects_management_notification"]:
                assert phases == [NotificationPhase.ADVICE_READY]
            else:
                assert phases == []
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]
