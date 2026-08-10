"""Lease heartbeat and fencing guard for long-running Agent operations."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable
from typing import Protocol, TypeVar

T = TypeVar("T")


class LeaseManager(Protocol):
    """Persistence boundary used to renew one fenced run lease."""

    async def renew(
        self,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool:
        """Renew the lease only when owner and fencing token still match."""

        ...


class LeaseLostError(RuntimeError):
    """Raised when an operation can no longer prove ownership of its run lease."""

    def __init__(
        self,
        *,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        reason: str,
    ) -> None:
        self.run_id = run_id
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token
        self.reason = reason
        super().__init__(f"Run lease lost for {run_id}: {reason}")


class RunLeaseGuard:
    """Keep a fenced lease alive while awaiting one long-running operation."""

    def __init__(
        self,
        lease_manager: LeaseManager,
        *,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
        heartbeat_interval_seconds: float | None = None,
        cancellation_grace_seconds: float = 1.0,
    ) -> None:
        self._validate_identity(
            run_id=run_id,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
            raise TypeError("lease_seconds must be an integer")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be greater than zero")

        interval = (
            lease_seconds / 3 if heartbeat_interval_seconds is None else heartbeat_interval_seconds
        )
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            raise TypeError("heartbeat_interval_seconds must be a number")
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("heartbeat_interval_seconds must be finite and greater than zero")
        if interval >= lease_seconds:
            raise ValueError("heartbeat_interval_seconds must be shorter than lease_seconds")
        if isinstance(cancellation_grace_seconds, bool) or not isinstance(
            cancellation_grace_seconds,
            (int, float),
        ):
            raise TypeError("cancellation_grace_seconds must be a number")
        if (
            not math.isfinite(cancellation_grace_seconds)
            or cancellation_grace_seconds <= 0
        ):
            raise ValueError(
                "cancellation_grace_seconds must be finite and greater than zero"
            )

        self._lease_manager = lease_manager
        self.run_id = run_id
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token
        self.lease_seconds = lease_seconds
        self.heartbeat_interval_seconds = float(interval)
        self.cancellation_grace_seconds = float(cancellation_grace_seconds)

    async def run(self, operation: Awaitable[T]) -> T:
        """Run an awaitable until it completes or its lease can no longer be renewed."""

        operation_task = asyncio.ensure_future(operation)
        heartbeat_task = asyncio.create_task(
            self._heartbeat(),
            name=f"run-lease-heartbeat-{self.run_id}",
        )
        try:
            done, _ = await asyncio.wait(
                {operation_task, heartbeat_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if heartbeat_task in done:
                try:
                    await heartbeat_task
                except LeaseLostError:
                    await self._cancel_and_wait(operation_task)
                    raise
                await self._cancel_and_wait(operation_task)
                raise RuntimeError("lease heartbeat stopped unexpectedly")

            await self._cancel_and_wait(heartbeat_task)
            return await operation_task
        except asyncio.CancelledError:
            await self._cancel_and_wait(operation_task)
            await self._cancel_and_wait(heartbeat_task)
            raise
        finally:
            await self._cancel_and_wait(heartbeat_task)

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval_seconds)
            try:
                renewed = await self._lease_manager.renew(
                    self.run_id,
                    self.lease_owner,
                    self.fencing_token,
                    self.lease_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                raise self._lease_lost(f"lease renewal failed: {type(exc).__name__}") from exc
            if renewed is not True:
                raise self._lease_lost("owner or fencing token no longer matches")

    def _lease_lost(self, reason: str) -> LeaseLostError:
        return LeaseLostError(
            run_id=self.run_id,
            lease_owner=self.lease_owner,
            fencing_token=self.fencing_token,
            reason=reason,
        )

    async def _cancel_and_wait(self, task: asyncio.Future[object]) -> None:
        if not task.done():
            task.cancel()
        try:
            async with asyncio.timeout(self.cancellation_grace_seconds):
                await asyncio.shield(task)
        except TimeoutError:
            self._detach(task)
        except asyncio.CancelledError:
            if not task.done():
                self._detach(task)
                raise
        except Exception:
            pass

    @staticmethod
    def _detach(task: asyncio.Future[object]) -> None:
        task.add_done_callback(RunLeaseGuard._consume_task_result)

    @staticmethod
    def _consume_task_result(task: asyncio.Future[object]) -> None:
        try:
            task.result()
        except BaseException:
            pass

    @staticmethod
    def _validate_identity(
        *,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        if not isinstance(run_id, str):
            raise TypeError("run_id must be a string")
        if not run_id.strip():
            raise ValueError("run_id must not be empty")
        if not isinstance(lease_owner, str):
            raise TypeError("lease_owner must be a string")
        if not lease_owner.strip():
            raise ValueError("lease_owner must not be empty")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int):
            raise TypeError("fencing_token must be an integer")
        if fencing_token <= 0:
            raise ValueError("fencing_token must be greater than zero")
