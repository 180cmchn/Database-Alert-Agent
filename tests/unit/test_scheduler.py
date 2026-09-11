import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.adapters.flashduty import FlashDutyResponse
from app.agent_runtime.leases import LeaseLostError
from app.application.factory import build_runtime
from app.application.scheduler import (
    FlashDutyAlertPoller,
    InMemoryAnalysisScheduler,
    ManualAnalysisScheduler,
    RedisAnalysisScheduler,
    _remaining_poll_delay,
)
from app.config import Settings
from app.domain.models import (
    AlertStatus,
    FlashDutyPollStatus,
    ModelFailure,
    ModelFailureCategory,
)


class PollStateRepository:
    def __init__(self) -> None:
        self.started: list[dict[str, object]] = []
        self.completed: list[dict[str, object]] = []
        self.failed: list[dict[str, object]] = []

    async def record_flashduty_poll_started(self, **values: object) -> None:
        self.started.append(values)

    async def record_flashduty_poll_completed(self, **values: object) -> None:
        self.completed.append(values)

    async def record_flashduty_poll_failed(self, **values: object) -> None:
        self.failed.append(values)


def test_redis_scheduler_construction_does_not_require_running_event_loop() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        redis_url="redis://redis:6379/0",
    )
    service = SimpleNamespace(repository=SimpleNamespace())

    scheduler = RedisAnalysisScheduler(settings, service)  # type: ignore[arg-type]

    assert scheduler.client is None
    assert scheduler._started is False


@pytest.mark.asyncio
async def test_redis_scheduler_requeues_pending_alerts_on_start() -> None:
    class Repository:
        def __init__(self) -> None:
            self.statuses: set[AlertStatus] | None = None

        async def list_by_status(self, statuses):  # type: ignore[no-untyped-def]
            self.statuses = statuses
            return [SimpleNamespace(alert=SimpleNamespace(id="alert-1"))]

    class FakeRedis:
        def __init__(self) -> None:
            self.pings = 0
            self.entries: list[tuple[str, dict[str, str]]] = []
            self.closed = False

        async def ping(self) -> bool:
            self.pings += 1
            return True

        async def xadd(self, stream, fields):  # type: ignore[no-untyped-def]
            self.entries.append((stream, fields))
            return b"1-0"

        async def aclose(self) -> None:
            self.closed = True

    settings = Settings(_env_file=None, ai_provider="fake")
    repository = Repository()
    client = FakeRedis()

    class Service:
        def __init__(self, repository: Repository) -> None:
            self.repository = repository

        async def is_dispatch_enabled(self) -> bool:
            return True

    service = Service(repository)
    scheduler = RedisAnalysisScheduler(
        settings,
        service,  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
    )

    await scheduler.start()
    await scheduler.start()

    assert client.pings == 1
    assert repository.statuses == {
        AlertStatus.RECEIVED,
        AlertStatus.QUEUED,
        AlertStatus.ANALYZING,
    }
    assert len(client.entries) == 1
    stream, fields = client.entries[0]
    assert stream == settings.redis_stream_name
    assert json.loads(fields["envelope"]) == {
        "schema_version": 1,
        "job_type": "investigate",
        "alert_id": "alert-1",
    }

    await scheduler.stop()
    assert client.closed is True


@pytest.mark.asyncio
async def test_in_memory_scheduler_runs_shared_investigation_pipeline(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'scheduler.db'}",
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

    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.latest_run is not None
    assert any(record.stage.value == "INCONCLUSIVE" for record in result.progress)
    assert result.progress[-1].stage.value == "INCONCLUSIVE"
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

        async def is_dispatch_enabled(self) -> bool:
            return True

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

        async def is_dispatch_enabled(self) -> bool:
            return True

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

        async def is_dispatch_enabled(self) -> bool:
            return True

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
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'poller.db'}",
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
    poll_state = await runtime.repository.get_flashduty_poll_state()
    assert poll_state.status == FlashDutyPollStatus.SUCCESS
    assert poll_state.start_time == 400
    assert poll_state.end_time == 1300
    assert poll_state.fetched_count == 1
    assert poll_state.created_count == 0
    assert poll_state.deduplicated_count == 1
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_flashduty_poller_ingests_without_enqueue_while_dispatch_paused(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'paused-poller.db'}",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=True,
        flashduty_poll_interval_seconds=300,
        flashduty_poll_lookback_seconds=900,
        flashduty_poll_channel_ids=[7],
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    trigger, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "poll-pause-trigger",
            "severity": "CRITICAL",
            "title": "Pause trigger",
            "reason": "test",
        },
    )
    run = await runtime.repository.create_run(str(trigger.alert.id), "pause-worker", 300)
    assert run is not None
    await runtime.repository.pause_analysis_dispatch(
        ModelFailure(
            category=ModelFailureCategory.AUTHENTICATION,
            provider="fake",
            model="fake-model",
            pauses_dispatch=True,
            safe_detail="authentication rejected",
        ),
        trigger_run_id=str(run.id),
        settings_revision="a" * 64,
    )

    class RecordingClient:
        async def list_alerts(self, **_payload):  # type: ignore[no-untyped-def]
            return FlashDutyResponse(
                "req-list",
                {
                    "items": [
                        {
                            "alert_id": "763a1b2c3d4e5f6789abcdef",
                            "title": "Database latency",
                            "description": "Latency is above threshold",
                            "alert_severity": "Warning",
                            "alert_status": "Warning",
                            "alert_key": "database-latency-paused",
                            "start_time": 900,
                            "labels": {"env": "prod", "service": "orders-db"},
                        }
                    ],
                    "total": 1,
                    "has_next_page": False,
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
    assert scheduler.jobs == []
    queued = await runtime.service.list_alerts(
        page=1,
        page_size=10,
        statuses={AlertStatus.QUEUED},
    )
    assert [item.external_id for item in queued.items] == ["763a1b2c3d4e5f6789abcdef"]
    poll_state = await runtime.repository.get_flashduty_poll_state()
    assert poll_state.status == FlashDutyPollStatus.SUCCESS
    assert poll_state.created_count == 1
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
            self.repository = PollStateRepository()

        async def is_dispatch_enabled(self) -> bool:
            return True

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
    assert service.repository.started == [{"start_time": 100, "end_time": 1000}]
    assert service.repository.completed == [
        {
            "start_time": 100,
            "end_time": 1000,
            "fetched_count": 101,
            "created_count": 101,
            "deduplicated_count": 0,
        }
    ]


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
        repository = PollStateRepository()

        async def is_dispatch_enabled(self) -> bool:
            return True

        async def ingest(self, source, payload):  # type: ignore[no-untyped-def]
            raise AssertionError(f"unexpected ingest: {source} {payload}")

    service = ServiceThatMustNotRun()
    poller = FlashDutyAlertPoller(
        settings,
        service,  # type: ignore[arg-type]
        ManualAnalysisScheduler(),
        IncompleteClient(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="pagination was incomplete"):
        await poller.run_once(now=1000)
    assert len(service.repository.failed) == 1
    assert "pagination was incomplete" in str(service.repository.failed[0]["error"])


@pytest.mark.asyncio
async def test_flashduty_poller_runtime_switch_starts_and_stops_background_task() -> None:
    disabled = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=False,
        flashduty_poll_channel_ids=[7],
    )
    enabled = disabled.model_copy(update={"flashduty_polling_enabled": True})
    loop_started = asyncio.Event()
    loop_cancelled = asyncio.Event()

    class IdleClient:
        pass

    poller = FlashDutyAlertPoller(
        disabled,
        SimpleNamespace(),  # type: ignore[arg-type]
        ManualAnalysisScheduler(),
        IdleClient(),  # type: ignore[arg-type]
    )

    async def controlled_loop() -> None:
        loop_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            loop_cancelled.set()
            raise

    poller._loop = controlled_loop  # type: ignore[method-assign]

    await poller.start()
    assert poller._task is None

    await poller.sync_settings(enabled)
    await asyncio.wait_for(loop_started.wait(), timeout=1)
    assert poller.enabled is True
    assert poller._task is not None

    await poller.sync_settings(disabled)
    await asyncio.wait_for(loop_cancelled.wait(), timeout=1)
    assert poller.enabled is False
    assert poller._task is None


@pytest.mark.asyncio
async def test_flashduty_poller_disabled_switch_prevents_manual_loop_iteration() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=False,
        flashduty_poll_channel_ids=[7],
    )

    class ClientThatMustNotRun:
        async def list_alerts(self, **payload):  # type: ignore[no-untyped-def]
            raise AssertionError(f"disabled polling called FlashDuty with {payload}")

    poller = FlashDutyAlertPoller(
        settings,
        SimpleNamespace(),  # type: ignore[arg-type]
        ManualAnalysisScheduler(),
        ClientThatMustNotRun(),  # type: ignore[arg-type]
    )

    assert await poller.run_once(now=1000) == 0


def test_flashduty_poller_keeps_start_to_start_interval() -> None:
    assert _remaining_poll_delay(300, started_at=100.0, finished_at=125.0) == 275.0
    assert _remaining_poll_delay(300, started_at=100.0, finished_at=450.0) == 0.0
