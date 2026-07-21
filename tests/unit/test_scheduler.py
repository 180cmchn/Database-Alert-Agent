import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.application.factory import build_runtime
from app.application.scheduler import InMemoryAnalysisScheduler, KafkaAnalysisScheduler
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
