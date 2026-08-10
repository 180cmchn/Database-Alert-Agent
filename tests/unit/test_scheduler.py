import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.adapters.flashduty import FlashDutyResponse
from app.agent_runtime.leases import LeaseLostError
from app.application.factory import build_runtime
from app.application.scheduler import (
    FlashDutyAlertPoller,
    InMemoryAnalysisScheduler,
    KafkaAnalysisScheduler,
    ManualAnalysisScheduler,
    _remaining_poll_delay,
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

    assert result.status == AlertStatus.REVIEW_REQUIRED
    assert result.latest_run is not None
    # The investigation pipeline records REVIEW_REQUIRED, then the notification step
    # appends a REPORTING progress record for the WeCom delivery status.
    assert any(record.stage.value == "REVIEW_REQUIRED" for record in result.progress)
    assert result.progress[-1].stage.value == "REPORTING"
    assert "通知" in result.progress[-1].message
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
async def test_in_memory_scheduler_retries_after_worker_loses_lease() -> None:
    finished = asyncio.Event()

    class EmptyRepository:
        async def list_by_status(self, statuses):  # type: ignore[no-untyped-def]
            return []

    class LeaseLostService:
        repository = EmptyRepository()

        def __init__(self) -> None:
            self.calls = 0

        async def analyze_by_id(self, alert_id):  # type: ignore[no-untyped-def]
            self.calls += 1
            if self.calls == 1:
                raise LeaseLostError(
                    run_id="run-1",
                    lease_owner="worker-1",
                    fencing_token=1,
                    reason="simulated heartbeat loss",
                )
            finished.set()
            return SimpleNamespace(status=AlertStatus.COMPLETED)

    service = LeaseLostService()
    scheduler = InMemoryAnalysisScheduler(  # type: ignore[arg-type]
        service,
        lease_retry_delay_seconds=0,
    )
    await scheduler.start()
    try:
        await scheduler.enqueue("alert-lease-lost")
        await asyncio.wait_for(finished.wait(), timeout=1)
    finally:
        await scheduler.stop()

    assert service.calls == 2


@pytest.mark.asyncio
async def test_in_memory_scheduler_applies_runtime_worker_concurrency() -> None:
    first_started = asyncio.Event()
    two_started = asyncio.Event()
    release = asyncio.Event()

    class EmptyRepository:
        async def list_by_status(self, statuses):  # type: ignore[no-untyped-def]
            return []

    class BlockingService:
        repository = EmptyRepository()

        def __init__(self) -> None:
            self.active = 0
            self.max_active = 0
            self.started = 0

        async def analyze_by_id(self, alert_id):  # type: ignore[no-untyped-def]
            self.active += 1
            self.started += 1
            self.max_active = max(self.max_active, self.active)
            if self.started == 1:
                first_started.set()
            if self.started == 2:
                two_started.set()
            try:
                await release.wait()
                return SimpleNamespace(status=AlertStatus.COMPLETED)
            finally:
                self.active -= 1

    service = BlockingService()
    scheduler = InMemoryAnalysisScheduler(service, workers=1)  # type: ignore[arg-type]
    await scheduler.start()
    try:
        await scheduler.enqueue("alert-1")
        await scheduler.enqueue("alert-2")
        await asyncio.wait_for(first_started.wait(), timeout=1)
        assert service.started == 1

        await scheduler.sync_workers(2)
        await asyncio.wait_for(two_started.wait(), timeout=1)
        assert service.max_active == 2

        release.set()
        await scheduler.join()
    finally:
        release.set()
        await scheduler.stop()


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
                        {
                            "alert_id": "663a1b2c3d4e5f6789abcdef",
                            "title": "Database latency",
                            "description": "Latency is above threshold",
                            "alert_severity": "Warning",
                            "alert_status": "Warning",
                            "alert_key": "database-latency",
                            "start_time": 900,
                            "labels": {"env": "prod", "service": "orders-db"},
                        }
                    ],
                    "total": 1,
                    "has_next_page": False,
                },
            )

        async def alert_info(self, alert_id: str) -> FlashDutyResponse:
            raise AssertionError(f"polling must not call /alert/info for {alert_id}")

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
    assert list_payloads[1]["start_time"] == 400
    assert list_payloads[0]["channel_ids"] == [7]
    assert list_payloads[0]["by_updated_at"] is False
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_flashduty_poller_fetches_more_than_100_pages_without_truncation() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=True,
        flashduty_poll_interval_seconds=300,
        flashduty_poll_lookback_seconds=900,
        flashduty_poll_channel_ids=[7],
    )
    list_payloads: list[dict[str, object]] = []

    class ManyPageClient:
        async def list_alerts(self, **payload):  # type: ignore[no-untyped-def]
            list_payloads.append(payload)
            cursor = payload.get("search_after_ctx")
            page = 0 if cursor is None else int(str(cursor).removeprefix("cursor-"))
            has_next = page < 100
            return FlashDutyResponse(
                f"req-list-{page}",
                {
                    "items": [{"alert_id": f"{page:024x}"}],
                    "total": 101,
                    "has_next_page": has_next,
                    "search_after_ctx": f"cursor-{page + 1}" if has_next else "",
                },
            )

    class RecordingService:
        def __init__(self) -> None:
            self.alert_ids: list[str] = []

        async def ingest(self, source, payload):  # type: ignore[no-untyped-def]
            assert source == "flashduty"
            alert_id = payload["data"]["alert_id"]
            self.alert_ids.append(alert_id)
            return (
                SimpleNamespace(
                    status=AlertStatus.QUEUED,
                    alert=SimpleNamespace(id=alert_id),
                ),
                True,
            )

    service = RecordingService()
    scheduler = ManualAnalysisScheduler()
    poller = FlashDutyAlertPoller(
        settings,
        service,  # type: ignore[arg-type]
        scheduler,
        ManyPageClient(),  # type: ignore[arg-type]
    )

    assert await poller.run_once(now=1000) == 101
    assert len(list_payloads) == 101
    assert len(service.alert_ids) == 101
    assert len(scheduler.jobs) == 101
    assert all(payload["start_time"] == 100 for payload in list_payloads)
    assert all(payload["end_time"] == 1000 for payload in list_payloads)


@pytest.mark.asyncio
async def test_flashduty_poller_rejects_silently_incomplete_pagination() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=True,
        flashduty_poll_channel_ids=[7],
    )

    class IncompleteClient:
        async def list_alerts(self, **_payload):  # type: ignore[no-untyped-def]
            return FlashDutyResponse(
                "req-list",
                {
                    "items": [{"alert_id": "663a1b2c3d4e5f6789abcdef"}],
                    "total": 2,
                    "has_next_page": False,
                },
            )

    class ServiceThatMustNotRun:
        async def ingest(self, source, payload):  # type: ignore[no-untyped-def]
            raise AssertionError(f"unexpected ingest: {source} {payload}")

    poller = FlashDutyAlertPoller(
        settings,
        ServiceThatMustNotRun(),  # type: ignore[arg-type]
        ManualAnalysisScheduler(),
        IncompleteClient(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="pagination was incomplete"):
        await poller.run_once(now=1000)


def test_flashduty_poller_keeps_start_to_start_interval() -> None:
    assert _remaining_poll_delay(300, started_at=100.0, finished_at=125.0) == 275.0
    assert _remaining_poll_delay(300, started_at=100.0, finished_at=450.0) == 0.0
