import asyncio
import json
from types import SimpleNamespace

import pytest

from app.application.admin import RuntimeSettingsManager
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.errors import InvestigationLeaseUnavailableError
from app.domain.models import AlertStatus
from app.workers.kafka import (
    KafkaAlertWorker,
    parse_envelope,
    process_envelope,
    process_with_retries,
)


class StubService:
    def __init__(
        self, failures: int = 0, status: AlertStatus = AlertStatus.COMPLETED
    ) -> None:
        self.failures = failures
        self.status = status
        self.calls = 0

    async def analyze(  # type: ignore[no-untyped-def]
        self, source, payload, *, retry_failed=False
    ):
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("temporary")
        return SimpleNamespace(status=self.status, alert=SimpleNamespace(id="alert-1"))

    async def analyze_by_id(self, alert_id):  # type: ignore[no-untyped-def]
        self.calls += 1
        return SimpleNamespace(status=self.status, alert=SimpleNamespace(id=alert_id))


def test_parse_envelope_validates_shape() -> None:
    assert parse_envelope(b'{"source":"canonical","payload":{"severity":"WARNING"}}')[
        "source"
    ] == "canonical"
    with pytest.raises(Exception, match="requires an object payload"):
        parse_envelope({"source": "canonical", "payload": "invalid"})


def test_parse_internal_investigation_job() -> None:
    parsed = parse_envelope(
        {"schema_version": 1, "job_type": "investigate", "alert_id": "alert-1"}
    )
    assert parsed == {
        "schema_version": 1,
        "job_type": "investigate",
        "alert_id": "alert-1",
    }


@pytest.mark.asyncio
async def test_retries_then_succeeds() -> None:
    service = StubService(failures=1)
    dead_letters = []

    async def send_dlq(payload):  # type: ignore[no-untyped-def]
        dead_letters.append(payload)

    result = await process_with_retries(
        service,  # type: ignore[arg-type]
        {"source": "canonical", "payload": {}},
        max_retries=2,
        dlq_sender=send_dlq,
    )
    assert result is not None
    assert service.calls == 2
    assert dead_letters == []


@pytest.mark.asyncio
async def test_exhausted_message_goes_to_sanitized_dlq() -> None:
    service = StubService(failures=5)
    dead_letters = []

    async def send_dlq(payload):  # type: ignore[no-untyped-def]
        dead_letters.append(payload)

    result = await process_with_retries(
        service,  # type: ignore[arg-type]
        {"source": "canonical", "payload": {"password": "secret"}},
        max_retries=2,
        dlq_sender=send_dlq,
    )
    assert result is None
    assert dead_letters[0]["original"]["payload"]["password"] == "***REDACTED***"


@pytest.mark.asyncio
async def test_active_lease_is_deferred_without_dlq_or_retry_budget() -> None:
    service = StubService(status=AlertStatus.ANALYZING)
    dead_letters = []

    async def send_dlq(payload):  # type: ignore[no-untyped-def]
        dead_letters.append(payload)

    envelope = {
        "schema_version": 1,
        "job_type": "investigate",
        "alert_id": "alert-1",
    }
    with pytest.raises(InvestigationLeaseUnavailableError):
        await process_with_retries(
            service,  # type: ignore[arg-type]
            envelope,
            max_retries=3,
            dlq_sender=send_dlq,
        )

    assert service.calls == 1
    assert dead_letters == []


@pytest.mark.asyncio
async def test_process_envelope_accepts_terminal_duplicate() -> None:
    service = StubService(status=AlertStatus.COMPLETED)
    result = await process_envelope(
        service,  # type: ignore[arg-type]
        {"job_type": "investigate", "alert_id": "alert-1"},
    )
    assert result.status == AlertStatus.COMPLETED


@pytest.mark.asyncio
async def test_kafka_worker_processes_configured_batch_concurrently() -> None:
    both_started = asyncio.Event()

    class ConcurrentService:
        def __init__(self) -> None:
            self.active = 0
            self.max_active = 0
            self.started = 0

        async def analyze_by_id(self, alert_id):  # type: ignore[no-untyped-def]
            self.active += 1
            self.started += 1
            self.max_active = max(self.max_active, self.active)
            if self.started == 2:
                both_started.set()
            try:
                await asyncio.wait_for(both_started.wait(), timeout=1)
                return SimpleNamespace(
                    status=AlertStatus.COMPLETED,
                    alert=SimpleNamespace(id=alert_id),
                )
            finally:
                self.active -= 1

    class FakeConsumer:
        def __init__(self) -> None:
            self.calls = 0
            self.commits = 0
            self.max_records: list[int] = []

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        async def getmany(self, *, timeout_ms, max_records):  # type: ignore[no-untyped-def]
            self.max_records.append(max_records)
            if self.calls:
                raise asyncio.CancelledError
            self.calls += 1
            return {
                "partition-0": [
                    SimpleNamespace(
                        value={"job_type": "investigate", "alert_id": "alert-1"}
                    ),
                    SimpleNamespace(
                        value={"job_type": "investigate", "alert_id": "alert-2"}
                    ),
                ]
            }

        async def commit(self) -> None:
            self.commits += 1

    class FakeProducer:
        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        scheduler_workers=2,
    )
    service = ConcurrentService()
    consumer = FakeConsumer()
    worker = KafkaAlertWorker.__new__(KafkaAlertWorker)
    worker.settings = settings
    worker.service = service  # type: ignore[assignment]
    worker.runtime = None
    worker.runtime_settings = None
    worker.consumer = consumer  # type: ignore[assignment]
    worker.producer = FakeProducer()  # type: ignore[assignment]

    with pytest.raises(asyncio.CancelledError):
        await worker.run()

    assert service.max_active == 2
    assert consumer.commits == 1
    assert consumer.max_records == [2, 2]


@pytest.mark.asyncio
async def test_kafka_worker_applies_startup_snapshot_and_reverts_deleted_override(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = Settings(
        _env_file=None,
        ai_provider="fake",
        runtime_settings_path=tmp_path / "runtime-settings.json",
        stream_main_agent_reasoning=False,
    )
    baseline.runtime_settings_path.write_text(
        json.dumps({"stream_main_agent_reasoning": True}),
        encoding="utf-8",
    )
    runtime = build_runtime(baseline, deployment_settings=baseline)
    manager = RuntimeSettingsManager(
        baseline.runtime_settings_path,
        deployment_baseline=baseline,
    )
    monkeypatch.setattr(
        "app.workers.kafka.AIOKafkaConsumer",
        lambda *args, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "app.workers.kafka.AIOKafkaProducer",
        lambda *args, **kwargs: SimpleNamespace(),
    )

    worker = KafkaAlertWorker(
        baseline,
        runtime.service,
        runtime=runtime,
        runtime_settings_manager=manager,
    )
    assert worker.settings.stream_main_agent_reasoning is True
    assert runtime.service.stream_main_agent_reasoning is True

    baseline.runtime_settings_path.write_text("{}\n", encoding="utf-8")
    await worker._refresh_runtime_settings()

    assert worker.settings.stream_main_agent_reasoning is False
    assert runtime.settings.stream_main_agent_reasoning is False
    assert runtime.service.stream_main_agent_reasoning is False
