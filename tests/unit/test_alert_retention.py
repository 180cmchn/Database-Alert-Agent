import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import (
    AlertRow,
    SQLAlchemyAlertRepository,
)
from app.application.scheduler import (
    SHANGHAI_TIME_ZONE,
    WeeklyAlertRetentionCleaner,
    next_weekly_retention_run,
)
from app.config import Settings
from app.domain.models import AlertStatus


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
async def test_cleanup_removes_all_expired_terminal_alerts(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "retention.db"))
    await repository.initialize()
    old_completed = await _create_alert(repository, "old-completed")
    old_failed = await _create_alert(repository, "old-failed")
    old_active = await _create_alert(repository, "old-active")
    recent_completed = await _create_alert(repository, "recent-completed")
    old_inconclusive = await _create_alert(repository, "old-inconclusive")
    old_filtered = await _create_alert(repository, "old-filtered")
    cutoff = datetime.now(UTC) - timedelta(days=7)
    old_time = cutoff - timedelta(seconds=1)

    async with repository.session_factory() as session:
        alert_ids = [
            old_completed,
            old_failed,
            old_active,
            recent_completed,
            old_inconclusive,
            old_filtered,
        ]
        rows = {
            row.id: row
            for row in (await session.execute(select(AlertRow).where(AlertRow.id.in_(alert_ids))))
            .scalars()
            .all()
        }
        for alert_id in (old_completed, old_active, old_inconclusive, old_failed, old_filtered):
            rows[alert_id].created_at = old_time
        rows[old_completed].status = AlertStatus.COMPLETED.value
        rows[old_failed].status = AlertStatus.FAILED.value
        rows[old_active].status = AlertStatus.QUEUED.value
        rows[recent_completed].status = AlertStatus.COMPLETED.value
        rows[old_inconclusive].status = AlertStatus.INCONCLUSIVE.value
        rows[old_filtered].status = AlertStatus.FILTERED.value
        await session.commit()

    assert await repository.cleanup_expired_alerts(cutoff) == 4
    assert await repository.get(old_completed) is None
    assert await repository.get(old_failed) is None
    assert await repository.get(old_inconclusive) is None
    assert await repository.get(old_filtered) is None
    assert await repository.get(recent_completed) is not None
    assert await repository.get(old_active) is not None
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
