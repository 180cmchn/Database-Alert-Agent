from types import SimpleNamespace

import pytest

from app.domain.errors import InvestigationLeaseUnavailableError
from app.domain.models import AlertStatus
from app.workers.kafka import parse_envelope, process_envelope, process_with_retries


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
