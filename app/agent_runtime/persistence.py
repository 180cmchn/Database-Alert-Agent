"""Repository-backed adapters for durable Agent harness state."""

from __future__ import annotations

import asyncio
from uuid import UUID

from app.agent_runtime.contracts import ToolInvocation, ToolInvocationStatus
from app.agent_runtime.events import AgentEvent, EventVersionConflictError
from app.domain.ports import AgentEventSequenceConflict, AlertRepository

_TERMINAL_INVOCATION_STATUSES = {
    ToolInvocationStatus.SUCCEEDED,
    ToolInvocationStatus.NO_DATA,
    ToolInvocationStatus.FAILED,
    ToolInvocationStatus.TIMED_OUT,
    ToolInvocationStatus.UNKNOWN_OUTCOME,
    ToolInvocationStatus.CANCELLED,
    ToolInvocationStatus.SKIPPED,
}


class RepositoryEventSink:
    """Assign event sequence numbers and append them to one repository stream."""

    def __init__(
        self,
        repository: AlertRepository,
        *,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> None:
        if (lease_owner is None) != (fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        self.repository = repository
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token
        self._lock = asyncio.Lock()

    async def append(
        self,
        event: AgentEvent,
        *,
        expected_version: int | None = None,
    ) -> AgentEvent:
        if event.sequence != 0 or event.version != 0:
            raise ValueError("uncommitted events must use sequence=0 and version=0")
        async with self._lock:
            actual_version = await self.current_version(event.run_id)
            if expected_version is not None and expected_version != actual_version:
                raise EventVersionConflictError(
                    run_id=event.run_id,
                    expected_version=expected_version,
                    actual_version=actual_version,
                )
            committed = AgentEvent.model_validate(
                {
                    **event.model_dump(mode="python"),
                    "sequence": actual_version + 1,
                    "version": actual_version + 1,
                }
            )
            try:
                await self.repository.append_agent_events(
                    str(event.run_id),
                    [committed],
                    expected_sequence=actual_version,
                    lease_owner=self.lease_owner,
                    fencing_token=self.fencing_token,
                )
            except AgentEventSequenceConflict as exc:
                raise EventVersionConflictError(
                    run_id=event.run_id,
                    expected_version=exc.expected,
                    actual_version=exc.actual,
                ) from exc
            stored = await self.repository.list_agent_events(
                str(event.run_id),
                after_sequence=actual_version,
            )
            matched = next(
                (item for item in stored if item.event_id == committed.event_id),
                None,
            )
            if matched is None:
                raise RuntimeError("repository did not return the appended Agent event")
            return matched

    async def current_version(self, run_id: UUID) -> int:
        return await self.repository.get_agent_event_sequence(str(run_id))

    async def read(
        self,
        run_id: UUID,
        *,
        after_sequence: int = 0,
    ) -> list[AgentEvent]:
        return await self.repository.list_agent_events(
            str(run_id),
            after_sequence=after_sequence,
        )


class RepositoryInvocationStore:
    """Map the generic MCP invocation lifecycle to repository persistence."""

    def __init__(
        self,
        repository: AlertRepository,
        *,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> None:
        if (lease_owner is None) != (fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        self.repository = repository
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token

    async def save(self, invocation: ToolInvocation) -> None:
        existing = await self.repository.get_tool_invocation(str(invocation.invocation_id))
        if existing is None:
            if invocation.status != ToolInvocationStatus.PENDING:
                raise RuntimeError("the first persisted invocation state must be PENDING")
            await self.repository.save_tool_invocation(
                invocation,
                lease_owner=self.lease_owner,
                fencing_token=self.fencing_token,
            )
            return
        if existing == invocation:
            return
        self._validate_transition(existing, invocation)
        await self.repository.update_tool_invocation(
            invocation,
            expected_status=existing.status,
            lease_owner=self.lease_owner,
            fencing_token=self.fencing_token,
        )

    async def load(self, invocation_id: UUID) -> ToolInvocation | None:
        return await self.repository.get_tool_invocation(str(invocation_id))

    @staticmethod
    def _validate_transition(
        existing: ToolInvocation,
        proposed: ToolInvocation,
    ) -> None:
        if existing.invocation_id != proposed.invocation_id:
            raise RuntimeError("invocation identity changed during persistence")
        if existing.status in _TERMINAL_INVOCATION_STATUSES:
            raise RuntimeError(
                f"terminal invocation cannot transition from {existing.status.value} "
                f"to {proposed.status.value}"
            )
        allowed = {
            ToolInvocationStatus.PENDING: {ToolInvocationStatus.STARTED},
            ToolInvocationStatus.STARTED: _TERMINAL_INVOCATION_STATUSES
            - {ToolInvocationStatus.SKIPPED},
        }
        if proposed.status not in allowed.get(existing.status, set()):
            raise RuntimeError(
                f"invalid invocation transition from {existing.status.value} "
                f"to {proposed.status.value}"
            )
