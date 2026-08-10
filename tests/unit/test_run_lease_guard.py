from __future__ import annotations

import asyncio
from collections.abc import Awaitable

import pytest

from app.agent_runtime.leases import LeaseLostError, RunLeaseGuard


class StubLeaseManager:
    def __init__(self, results: list[bool | Exception] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[tuple[str, str, int, int]] = []
        self.renewed = asyncio.Event()

    async def renew(
        self,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool:
        self.calls.append((run_id, lease_owner, fencing_token, lease_seconds))
        self.renewed.set()
        result = self.results.pop(0) if self.results else True
        if isinstance(result, Exception):
            raise result
        return result


def _guard(
    manager: StubLeaseManager,
    *,
    interval: float = 0.005,
    cancellation_grace: float = 1.0,
) -> RunLeaseGuard:
    return RunLeaseGuard(
        manager,
        run_id="run-123",
        lease_owner="worker-a",
        fencing_token=7,
        lease_seconds=30,
        heartbeat_interval_seconds=interval,
        cancellation_grace_seconds=cancellation_grace,
    )


async def _with_timeout[T](awaitable: Awaitable[T]) -> T:
    async with asyncio.timeout(1):
        return await awaitable


@pytest.mark.asyncio
async def test_long_operation_renews_with_same_owner_and_fencing_token() -> None:
    manager = StubLeaseManager()
    release = asyncio.Event()

    async def operation() -> str:
        await manager.renewed.wait()
        release.set()
        return "complete"

    result = await _with_timeout(_guard(manager).run(operation()))

    assert result == "complete"
    assert manager.calls == [("run-123", "worker-a", 7, 30)]
    assert release.is_set()


@pytest.mark.asyncio
async def test_lost_lease_cancels_operation_and_raises_fenced_error() -> None:
    manager = StubLeaseManager([False])
    operation_cancelled = asyncio.Event()

    async def operation() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            operation_cancelled.set()
            raise

    with pytest.raises(LeaseLostError, match="owner or fencing token") as caught:
        await _with_timeout(_guard(manager).run(operation()))

    assert operation_cancelled.is_set()
    assert caught.value.run_id == "run-123"
    assert caught.value.lease_owner == "worker-a"
    assert caught.value.fencing_token == 7


@pytest.mark.asyncio
async def test_lost_lease_does_not_wait_forever_for_cancellation_resistant_operation(
) -> None:
    manager = StubLeaseManager([False])
    cancellation_seen = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()

    async def operation() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancellation_seen.set()
            await release.wait()
        finally:
            finished.set()

    started = asyncio.get_running_loop().time()
    with pytest.raises(LeaseLostError, match="owner or fencing token"):
        await _with_timeout(
            _guard(manager, cancellation_grace=0.01).run(operation())
        )
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 0.2
    assert cancellation_seen.is_set()
    assert not finished.is_set()
    release.set()
    await _with_timeout(finished.wait())
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_renewal_exception_is_fail_closed_and_preserves_cause() -> None:
    manager = StubLeaseManager([ConnectionError("database unavailable")])

    with pytest.raises(LeaseLostError, match="ConnectionError") as caught:
        await _with_timeout(_guard(manager).run(asyncio.Event().wait()))

    assert isinstance(caught.value.__cause__, ConnectionError)


@pytest.mark.asyncio
async def test_operation_exception_stops_heartbeat_and_propagates() -> None:
    manager = StubLeaseManager()

    async def operation() -> None:
        raise LookupError("operation failed")

    with pytest.raises(LookupError, match="operation failed"):
        await _with_timeout(_guard(manager).run(operation()))

    await asyncio.sleep(0.01)
    assert manager.calls == []


@pytest.mark.asyncio
async def test_cancelling_guard_cancels_operation_and_heartbeat() -> None:
    manager = StubLeaseManager()
    operation_started = asyncio.Event()
    operation_cancelled = asyncio.Event()

    async def operation() -> None:
        operation_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            operation_cancelled.set()
            raise

    task = asyncio.create_task(_guard(manager, interval=0.5).run(operation()))
    await operation_started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await _with_timeout(task)
    assert operation_cancelled.is_set()


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"lease_owner": ""}, ValueError),
        ({"lease_owner": "   "}, ValueError),
        ({"lease_owner": None}, TypeError),
        ({"fencing_token": 0}, ValueError),
        ({"fencing_token": -1}, ValueError),
        ({"fencing_token": True}, TypeError),
        ({"fencing_token": "7"}, TypeError),
    ],
)
def test_guard_rejects_invalid_owner_and_fencing_token(
    updates: dict[str, object],
    error: type[Exception],
) -> None:
    arguments: dict[str, object] = {
        "run_id": "run-123",
        "lease_owner": "worker-a",
        "fencing_token": 7,
        "lease_seconds": 30,
    }
    arguments.update(updates)

    with pytest.raises(error):
        RunLeaseGuard(StubLeaseManager(), **arguments)  # type: ignore[arg-type]


def test_default_heartbeat_interval_is_one_third_of_lease() -> None:
    guard = RunLeaseGuard(
        StubLeaseManager(),
        run_id="run-123",
        lease_owner="worker-a",
        fencing_token=7,
        lease_seconds=30,
    )

    assert guard.heartbeat_interval_seconds == 10
    assert guard.cancellation_grace_seconds == 1
