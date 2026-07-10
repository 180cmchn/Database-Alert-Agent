from types import SimpleNamespace

import pytest

from app.domain.models import AlertStatus
from app.workers.kafka import parse_envelope, process_with_retries


class StubService:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.calls = 0

    async def analyze(  # type: ignore[no-untyped-def]
        self, source, payload, *, retry_failed=False
    ):
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("temporary")
        return SimpleNamespace(status=AlertStatus.COMPLETED)


def test_parse_envelope_validates_shape() -> None:
    assert parse_envelope(b'{"source":"canonical","payload":{"severity":"HIGH"}}')[
        "source"
    ] == "canonical"
    with pytest.raises(Exception, match="requires an object payload"):
        parse_envelope({"source": "canonical", "payload": "invalid"})


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
