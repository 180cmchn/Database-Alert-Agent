import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import (
    AlertRow,
    FeedbackRow,
    InvestigationRunRow,
    SQLAlchemyAlertRepository,
)
from app.application.scheduler import (
    SHANGHAI_TIME_ZONE,
    WeeklyAlertRetentionCleaner,
    next_weekly_retention_run,
)
from app.config import Settings
from app.domain.models import AlertStatus, InvestigationStage, RunStatus


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


async def _create_alert(repository: SQLAlchemyAlertRepository, external_id: str) -> str:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": external_id,
            "severity": "INFO",
            "title": f"Retention {external_id}",
            "reason": "retention-test",
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    return str(stored.alert.id)


@pytest.mark.asyncio
async def test_cleanup_removes_only_expired_terminal_alerts_without_feedback(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "retention.db"))
    await repository.initialize()
    old_completed = await _create_alert(repository, "old-completed")
    old_failed = await _create_alert(repository, "old-failed")
    old_reviewed = await _create_alert(repository, "old-reviewed")
    recent_completed = await _create_alert(repository, "recent-completed")
    old_review_required = await _create_alert(repository, "old-review-required")
    cutoff = datetime.now(UTC) - timedelta(days=7)
    old_time = cutoff - timedelta(seconds=1)

    async with repository.session_factory() as session:
        alert_ids = [
            old_completed,
            old_failed,
            old_reviewed,
            recent_completed,
            old_review_required,
        ]
        rows = {
            row.id: row
            for row in (
                await session.execute(select(AlertRow).where(AlertRow.id.in_(alert_ids)))
            )
            .scalars()
            .all()
        }
        for alert_id in (old_completed, old_reviewed, old_review_required, old_failed):
            rows[alert_id].created_at = old_time
        rows[old_completed].status = AlertStatus.COMPLETED.value
        rows[old_failed].status = AlertStatus.FAILED.value
        rows[old_reviewed].status = AlertStatus.COMPLETED.value
        rows[recent_completed].status = AlertStatus.COMPLETED.value
        rows[old_review_required].status = AlertStatus.REVIEW_REQUIRED.value

        reviewed_run_id = str(uuid4())
        session.add(
            InvestigationRunRow(
                id=reviewed_run_id,
                alert_id=old_reviewed,
                attempt=1,
                status=RunStatus.COMPLETED.value,
                current_stage=InvestigationStage.COMPLETED.value,
                created_at=old_time,
                updated_at=old_time,
            )
        )
        await session.flush()
        session.add(
            FeedbackRow(
                id=str(uuid4()),
                alert_id=old_reviewed,
                run_id=reviewed_run_id,
                idempotency_key="retain-human-feedback",
                verdict="CONFIRMED",
                reviewer="operator",
                created_at=old_time,
            )
        )
        await session.commit()

    reviewed_before_cleanup = await repository.get(old_reviewed)
    assert reviewed_before_cleanup is not None
    assert len(reviewed_before_cleanup.feedback) == 1
    assert await repository.cleanup_expired_alerts(cutoff) == 2
    assert await repository.get(old_completed) is None
    assert await repository.get(old_failed) is None
    assert await repository.get(recent_completed) is not None
    assert await repository.get(old_review_required) is not None

    retained = await repository.get(old_reviewed)
    assert retained is not None
    assert len(retained.feedback) == 1
    assert retained.feedback[0].idempotency_key == "retain-human-feedback"
    await repository.close()


def test_next_weekly_retention_run_is_friday_noon_shanghai_time() -> None:
    before_slot = datetime(2026, 8, 7, 11, 59, tzinfo=SHANGHAI_TIME_ZONE)
    exact_slot = datetime(2026, 8, 7, 12, 0, tzinfo=SHANGHAI_TIME_ZONE)

    assert next_weekly_retention_run(before_slot) == datetime(2026, 8, 7, 4, tzinfo=UTC)
    assert next_weekly_retention_run(exact_slot) == datetime(2026, 8, 14, 4, tzinfo=UTC)


@pytest.mark.asyncio
async def test_retention_cleaner_waits_on_startup_without_deleting() -> None:
    class RecordingRepository:
        def __init__(self) -> None:
            self.cutoffs: list[datetime] = []

        async def cleanup_expired_alerts(self, cutoff: datetime) -> int:
            self.cutoffs.append(cutoff)
            return 3

    settings = Settings(_env_file=None, ai_provider="fake")
    repository = RecordingRepository()
    cleaner = WeeklyAlertRetentionCleaner(settings, repository)

    await cleaner.start()
    await asyncio.sleep(0)
    assert repository.cutoffs == []

    now = datetime(2026, 8, 7, 4, tzinfo=UTC)
    assert await cleaner.run_once(now=now) == 3
    assert repository.cutoffs == [now - timedelta(days=7)]
    await cleaner.stop()