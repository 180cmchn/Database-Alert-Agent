from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CancellationReader(Protocol):
    async def is_run_cancellation_requested(self, run_id: str) -> bool: ...


class ActiveAnalysisRegistry:
    """Own process-local analysis tasks while the database remains authoritative."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[Any]] = {}

    def start(
        self,
        run_id: str,
        operation: Awaitable[T],
        *,
        name: str | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> asyncio.Task[T]:
        existing = self._tasks.get(run_id)
        if existing is not None and not existing.done():
            if hasattr(operation, "close"):
                operation.close()  # type: ignore[attr-defined]
            raise RuntimeError(f"Analysis task is already active for run {run_id}")
        task = asyncio.create_task(operation, name=name or f"alert-analysis-{run_id}")
        self._tasks[run_id] = task

        def discard(completed: asyncio.Task[Any]) -> None:
            if self._tasks.get(run_id) is completed:
                self._tasks.pop(run_id, None)
            if on_error is None or completed.cancelled():
                return
            try:
                error = completed.exception()
            except asyncio.CancelledError:
                return
            if error is not None:
                on_error(error)

        task.add_done_callback(discard)
        return task

    def cancel(self, run_id: str) -> bool:
        task = self._tasks.get(run_id)
        if task is None or task.done():
            return False
        task.cancel()
        return True

    def is_active(self, run_id: str) -> bool:
        task = self._tasks.get(run_id)
        return task is not None and not task.done()

    async def close(self) -> None:
        tasks = [task for task in self._tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


async def wait_for_persisted_cancellation(
    repository: CancellationReader,
    run_id: str,
    *,
    poll_interval_seconds: float = 0.5,
) -> None:
    """Wait until another process persists a cancellation request for a run."""

    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be greater than zero")
    while True:
        try:
            if await repository.is_run_cancellation_requested(run_id):
                return
        except asyncio.CancelledError:
            raise
        except Exception:
            # Lease renewal remains the fail-closed database health boundary. A
            # transient watcher read must not turn into a false user cancellation.
            logger.warning(
                "Analysis cancellation watcher read failed run_id=%s",
                run_id,
                exc_info=True,
            )
        await asyncio.sleep(poll_interval_seconds)
