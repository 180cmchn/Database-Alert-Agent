import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest
from redis.exceptions import ResponseError

from app.application.admin import RuntimeSettingsManager
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.errors import InvestigationLeaseUnavailableError
from app.domain.models import AlertStatus
from app.workers.redis import (
    RedisAlertWorker,
    parse_envelope,
    process_envelope,
    process_with_retries,
)


class StubService:
    def __init__(self, failures: int = 0, status: AlertStatus = AlertStatus.COMPLETED) -> None:
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


class FakeRedis:
    def __init__(self, *, read_batches: list[Any] | None = None) -> None:
        self.read_batches = list(read_batches or [])
        self.claim_responses: list[Any] = []
        self.eval_calls: list[tuple[str, int, tuple[Any, ...]]] = []
        self.group_calls: list[tuple[Any, ...]] = []
        self.read_counts: list[int] = []
        self.claim_counts: list[int] = []
        self.pings = 0
        self.closed = False
        self.fail_dead_letter = False

    async def ping(self) -> bool:
        self.pings += 1
        return True

    async def xgroup_create(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.group_calls.append((*args, kwargs))
        return True

    async def xautoclaim(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.claim_counts.append(kwargs["count"])
        if self.claim_responses:
            return self.claim_responses.pop(0)
        return [b"0-0", [], []]

    async def xreadgroup(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.read_counts.append(kwargs["count"])
        if self.read_batches:
            return self.read_batches.pop(0)
        raise asyncio.CancelledError

    async def eval(self, script, numkeys, *args):  # type: ignore[no-untyped-def]
        call = (script, numkeys, args)
        self.eval_calls.append(call)
        if numkeys == 2 and self.fail_dead_letter:
            raise RuntimeError("DLQ unavailable")
        return 1 if numkeys == 1 else [b"2-0", 1, 1]

    async def aclose(self) -> None:
        self.closed = True


def stream_fields(envelope: dict[str, Any]) -> dict[bytes, bytes]:
    return {b"envelope": json.dumps(envelope).encode()}


def make_worker(
    service: Any,
    client: FakeRedis | None = None,
    *,
    workers: int = 1,
) -> tuple[RedisAlertWorker, FakeRedis]:
    fake = client or FakeRedis()
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        scheduler_workers=workers,
    )
    worker = RedisAlertWorker(
        settings,
        service,
        client=fake,  # type: ignore[arg-type]
        consumer_name="test-consumer",
    )
    return worker, fake


def test_parse_envelope_validates_shape_and_encoding() -> None:
    assert (
        parse_envelope(b'{"source":"canonical","payload":{"severity":"WARNING"}}')["source"]
        == "canonical"
    )
    with pytest.raises(Exception, match="requires an object payload"):
        parse_envelope({"source": "canonical", "payload": "invalid"})
    with pytest.raises(Exception, match="not valid UTF-8"):
        parse_envelope(b"\xff")


def test_parse_internal_investigation_job() -> None:
    parsed = parse_envelope({"schema_version": 1, "job_type": "investigate", "alert_id": "alert-1"})
    assert parsed == {
        "schema_version": 1,
        "job_type": "investigate",
        "alert_id": "alert-1",
    }


@pytest.mark.asyncio
async def test_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("app.workers.redis.asyncio.sleep", no_sleep)
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
async def test_exhausted_message_goes_to_sanitized_dlq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("app.workers.redis.asyncio.sleep", no_sleep)
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
    assert dead_letters[0]["attempts"] == 2


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
@pytest.mark.parametrize("status", [AlertStatus.COMPLETED, AlertStatus.FILTERED])
async def test_process_envelope_accepts_terminal_duplicate(status: AlertStatus) -> None:
    service = StubService(status=status)
    result = await process_envelope(
        service,  # type: ignore[arg-type]
        {"job_type": "investigate", "alert_id": "alert-1"},
    )
    assert result.status == status


@pytest.mark.asyncio
async def test_successful_message_is_acknowledged_and_deleted() -> None:
    worker, client = make_worker(StubService())

    await worker._process_message(
        b"1-0",
        stream_fields({"job_type": "investigate", "alert_id": "alert-1"}),
    )

    assert len(client.eval_calls) == 1
    _script, numkeys, args = client.eval_calls[0]
    assert numkeys == 1
    assert args == (
        worker.settings.redis_stream_name,
        worker.settings.redis_consumer_group,
        b"1-0",
    )


@pytest.mark.asyncio
async def test_invalid_message_is_atomically_dead_lettered_and_sanitized() -> None:
    worker, client = make_worker(StubService())
    invalid = {"payload": {"password": "secret"}}

    await worker._process_message(b"1-0", stream_fields(invalid))

    assert len(client.eval_calls) == 1
    _script, numkeys, args = client.eval_calls[0]
    assert numkeys == 2
    dead_letter = json.loads(args[4])
    assert dead_letter["source_message_id"] == "1-0"
    assert dead_letter["failure"]["original"]["payload"]["password"] == "***REDACTED***"


@pytest.mark.asyncio
async def test_dead_letter_failure_leaves_original_message_pending() -> None:
    worker, client = make_worker(StubService())
    client.fail_dead_letter = True

    with pytest.raises(RuntimeError, match="DLQ unavailable"):
        await worker._process_message(b"1-0", {b"not-envelope": b"invalid"})

    assert len(client.eval_calls) == 1
    assert client.eval_calls[0][1] == 2
    assert not any(numkeys == 1 for _script, numkeys, _args in client.eval_calls)


@pytest.mark.asyncio
async def test_active_lease_message_is_not_acknowledged_or_dead_lettered() -> None:
    worker, client = make_worker(StubService(status=AlertStatus.ANALYZING))

    with pytest.raises(InvestigationLeaseUnavailableError):
        await worker._process_message(
            b"1-0",
            stream_fields({"job_type": "investigate", "alert_id": "alert-1"}),
        )

    assert client.eval_calls == []


@pytest.mark.asyncio
async def test_xautoclaim_advances_cursor_and_returns_stale_messages() -> None:
    client = FakeRedis()
    client.claim_responses.append(
        [
            b"9-0",
            [
                (
                    b"1-0",
                    stream_fields({"job_type": "investigate", "alert_id": "alert-1"}),
                )
            ],
            [],
        ]
    )
    worker, _client = make_worker(StubService(), client)

    messages = await worker._claim_stale(3)

    assert [message_id for message_id, _fields in messages] == [b"1-0"]
    assert worker._claim_cursor == b"9-0"
    assert client.claim_counts == [3]


@pytest.mark.asyncio
async def test_consumer_group_creation_is_idempotent() -> None:
    class BusyGroupRedis(FakeRedis):
        async def xgroup_create(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise ResponseError("BUSYGROUP Consumer Group name already exists")

    worker, _client = make_worker(StubService(), BusyGroupRedis())

    await worker._ensure_consumer_group()


@pytest.mark.asyncio
async def test_redis_worker_processes_configured_messages_concurrently() -> None:
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

    batch = [
        (
            b"1-0",
            stream_fields({"job_type": "investigate", "alert_id": "alert-1"}),
        ),
        (
            b"2-0",
            stream_fields({"job_type": "investigate", "alert_id": "alert-2"}),
        ),
    ]
    client = FakeRedis(read_batches=[[(b"jobs", batch)]])
    service = ConcurrentService()
    worker, _client = make_worker(service, client, workers=2)

    with pytest.raises(asyncio.CancelledError):
        await worker.run()

    assert service.max_active == 2
    assert [numkeys for _script, numkeys, _args in client.eval_calls] == [1, 1]
    assert client.read_counts == [2, 2]
    assert client.closed is True


@pytest.mark.asyncio
async def test_redis_worker_applies_startup_snapshot_and_reverts_deleted_override(
    tmp_path,
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
    worker = RedisAlertWorker(
        baseline,
        runtime.service,
        runtime=runtime,
        runtime_settings_manager=manager,
        client=FakeRedis(),  # type: ignore[arg-type]
        consumer_name="test-consumer",
    )
    assert worker.settings.stream_main_agent_reasoning is True
    assert runtime.service.stream_main_agent_reasoning is True

    baseline.runtime_settings_path.write_text("{}\n", encoding="utf-8")
    await worker._refresh_runtime_settings()

    assert worker.settings.stream_main_agent_reasoning is False
    assert runtime.settings.stream_main_agent_reasoning is False
    assert runtime.service.stream_main_agent_reasoning is False
