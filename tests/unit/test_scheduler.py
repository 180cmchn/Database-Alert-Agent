import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.adapters.flashduty import FlashDutyResponse
from app.application.factory import build_runtime
from app.application.scheduler import (
    FlashDutyAlertPoller,
    InMemoryAnalysisScheduler,
    KafkaAnalysisScheduler,
    ManualAnalysisScheduler,
)
from app.config import Settings
from app.domain.models import AlertStatus


def test_kafka_scheduler_construction_does_not_require_running_event_loop() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        kafka_bootstrap_servers="kafka:9092",
    )
    service = SimpleNamespace(repository=SimpleNamespace())

    scheduler = KafkaAnalysisScheduler(settings, service)  # type: ignore[arg-type]

    assert scheduler.producer is None


@pytest.mark.asyncio
async def test_in_memory_scheduler_runs_shared_investigation_pipeline(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'scheduler.db'}",
        runbook_pdf_dir=runbooks,
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    stored, created = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "scheduled-1",
            "severity": "WARNING",
            "title": "Latency",
            "reason": "latency",
        },
    )
    assert created is True
    assert stored.status == AlertStatus.QUEUED

    scheduler = InMemoryAnalysisScheduler(runtime.service)
    await scheduler.start()
    await scheduler.enqueue(str(stored.alert.id))
    await scheduler.join()
    result = await runtime.service.get(str(stored.alert.id))
    await scheduler.stop()

    assert result.status == AlertStatus.COMPLETED
    assert result.latest_run is not None
    assert result.progress[-1].stage.value == "COMPLETED"
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_in_memory_scheduler_retries_job_while_old_lease_is_active() -> None:
    finished = asyncio.Event()

    class EmptyRepository:
        async def list_by_status(self, statuses):  # type: ignore[no-untyped-def]
            return []

    class LeaseBusyService:
        repository = EmptyRepository()

        def __init__(self) -> None:
            self.calls = 0

        async def analyze_by_id(self, alert_id):  # type: ignore[no-untyped-def]
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(status=AlertStatus.ANALYZING)
            finished.set()
            return SimpleNamespace(status=AlertStatus.COMPLETED)

    service = LeaseBusyService()
    scheduler = InMemoryAnalysisScheduler(  # type: ignore[arg-type]
        service, lease_retry_delay_seconds=0.01
    )
    await scheduler.start()
    try:
        await scheduler.enqueue("alert-1")
        await asyncio.wait_for(finished.wait(), timeout=1)
    finally:
        await scheduler.stop()

    assert service.calls == 2


@pytest.mark.asyncio
async def test_flashduty_poller_recovers_missed_alert_and_deduplicates(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'poller.db'}",
        runbook_pdf_dir=runbooks,
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=True,
        flashduty_poll_interval_seconds=300,
        flashduty_poll_lookback_seconds=900,
        flashduty_poll_channel_ids=[7],
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    list_payloads: list[dict[str, object]] = []

    class RecordingClient:
        async def list_alerts(self, **payload):  # type: ignore[no-untyped-def]
            list_payloads.append(payload)
            return FlashDutyResponse(
                "req-list",
                {
                    "items": [
                        {"alert_id": "663a1b2c3d4e5f6789abcdef"}
                    ],
                    "has_next_page": False,
                },
            )

        async def alert_info(self, alert_id: str) -> FlashDutyResponse:
            assert alert_id == "663a1b2c3d4e5f6789abcdef"
            return FlashDutyResponse(
                "req-info",
                {
                    "alert_id": alert_id,
                    "title": "Database latency",
                    "description": "Latency is above threshold",
                    "alert_severity": "Warning",
                    "alert_status": "Warning",
                    "alert_key": "database-latency",
                    "start_time": 900,
                    "labels": {"env": "prod", "service": "orders-db"},
                },
            )

    scheduler = ManualAnalysisScheduler()
    poller = FlashDutyAlertPoller(
        settings,
        runtime.service,
        scheduler,
        RecordingClient(),  # type: ignore[arg-type]
    )

    assert await poller.run_once(now=1000) == 1
    assert await poller.run_once(now=1300) == 0
    assert len(scheduler.jobs) == 1
    assert list_payloads[0]["start_time"] == 100
    assert list_payloads[1]["start_time"] == 100
    assert list_payloads[0]["channel_ids"] == [7]
    assert list_payloads[0]["by_updated_at"] is True
    await runtime.repository.close()  # type: ignore[attr-defined]
