from __future__ import annotations

import asyncio

import pytest

from app.application.analysis_control import (
    ActiveAnalysisRegistry,
    wait_for_persisted_cancellation,
)


@pytest.mark.asyncio
async def test_registry_cancels_only_the_registered_analysis_task() -> None:
    registry = ActiveAnalysisRegistry()
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def operation() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    task = registry.start("run-1", operation())
    await started.wait()

    assert registry.cancel("run-1") is True
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
    assert registry.is_active("run-1") is False
    assert registry.cancel("missing") is False


@pytest.mark.asyncio
async def test_registry_identity_guard_does_not_remove_a_replacement_task() -> None:
    registry = ActiveAnalysisRegistry()
    first = registry.start("run-1", asyncio.sleep(0))
    await first
    replacement = registry.start("run-1", asyncio.Event().wait())

    await asyncio.sleep(0)
    assert registry.is_active("run-1") is True
    await registry.close()
    assert replacement.cancelled()


@pytest.mark.asyncio
async def test_persisted_cancellation_watcher_survives_transient_read_failure() -> None:
    class Repository:
        def __init__(self) -> None:
            self.calls = 0

        async def is_run_cancellation_requested(self, run_id: str) -> bool:
            assert run_id == "run-remote"
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("transient")
            return self.calls >= 3

    repository = Repository()
    async with asyncio.timeout(1):
        await wait_for_persisted_cancellation(
            repository,
            "run-remote",
            poll_interval_seconds=0.001,
        )

    assert repository.calls == 3
