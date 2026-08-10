"""Append-only Agent event envelopes and an in-memory event sink."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.agent_runtime.contracts import utc_now


class AgentEventKind(StrEnum):
    RUN_STARTED = "RUN_STARTED"
    MODEL_DECISION = "MODEL_DECISION"
    PLANNER_REPAIR_REQUESTED = "PLANNER_REPAIR_REQUESTED"
    HOST_REJECTED = "HOST_REJECTED"
    MCP_SESSION_STARTED = "MCP_SESSION_STARTED"
    MCP_SESSION_FAILED = "MCP_SESSION_FAILED"
    MCP_TOOLS_DISCOVERED = "MCP_TOOLS_DISCOVERED"
    TOOL_INVOCATION_STARTED = "TOOL_INVOCATION_STARTED"
    TOOL_INVOCATION_SUCCEEDED = "TOOL_INVOCATION_SUCCEEDED"
    TOOL_INVOCATION_NO_DATA = "TOOL_INVOCATION_NO_DATA"
    TOOL_INVOCATION_FAILED = "TOOL_INVOCATION_FAILED"
    TOOL_INVOCATION_TIMED_OUT = "TOOL_INVOCATION_TIMED_OUT"
    TOOL_INVOCATION_UNKNOWN_OUTCOME = "TOOL_INVOCATION_UNKNOWN_OUTCOME"
    TOOL_INVOCATION_CANCELLED = "TOOL_INVOCATION_CANCELLED"
    TOOL_INVOCATION_SKIPPED = "TOOL_INVOCATION_SKIPPED"
    ARTIFACT_CREATED = "ARTIFACT_CREATED"
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    BUDGET_RESERVED = "BUDGET_RESERVED"
    BUDGET_DEBITED = "BUDGET_DEBITED"
    CHECKPOINT_SAVED = "CHECKPOINT_SAVED"
    RUN_PAUSED = "RUN_PAUSED"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_FAILED = "RUN_FAILED"


class AgentEvent(BaseModel):
    """One immutable envelope in a run-scoped event stream."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    parent_run_id: UUID | None = None
    invocation_id: UUID | None = None
    sequence: int = Field(default=0, ge=0)
    version: int = Field(default=0, ge=0)
    kind: AgentEventKind
    payload: dict[str, Any] = Field(default_factory=dict)
    causation_id: UUID | None = None
    correlation_id: UUID | None = None
    occurred_at: datetime = Field(default_factory=utc_now)

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("event occurred_at must be timezone-aware")
        return value


class EventVersionConflictError(RuntimeError):
    def __init__(self, *, run_id: UUID, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Event stream version conflict for run {run_id}: "
            f"expected={expected_version}, actual={actual_version}"
        )
        self.run_id = run_id
        self.expected_version = expected_version
        self.actual_version = actual_version


class DuplicateEventError(RuntimeError):
    pass


class EventSink(Protocol):
    async def append(
        self,
        event: AgentEvent,
        *,
        expected_version: int | None = None,
    ) -> AgentEvent: ...

    async def current_version(self, run_id: UUID) -> int: ...

    async def read(self, run_id: UUID, *, after_sequence: int = 0) -> list[AgentEvent]: ...


class InMemoryEventSink:
    """Deterministic sink for tests and local harness composition."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._events: dict[UUID, list[AgentEvent]] = {}
        self._event_ids: set[UUID] = set()

    async def append(
        self,
        event: AgentEvent,
        *,
        expected_version: int | None = None,
    ) -> AgentEvent:
        async with self._lock:
            stream = self._events.setdefault(event.run_id, [])
            actual_version = stream[-1].version if stream else 0
            if expected_version is not None and expected_version != actual_version:
                raise EventVersionConflictError(
                    run_id=event.run_id,
                    expected_version=expected_version,
                    actual_version=actual_version,
                )
            if event.event_id in self._event_ids:
                raise DuplicateEventError(f"Event {event.event_id} has already been appended")
            if event.sequence != 0 or event.version != 0:
                raise ValueError("uncommitted events must use sequence=0 and version=0")
            next_version = actual_version + 1
            committed = AgentEvent.model_validate(
                {
                    **event.model_dump(mode="python"),
                    "sequence": next_version,
                    "version": next_version,
                }
            )
            stream.append(committed)
            self._event_ids.add(committed.event_id)
            return committed

    async def current_version(self, run_id: UUID) -> int:
        async with self._lock:
            stream = self._events.get(run_id, [])
            return stream[-1].version if stream else 0

    async def read(self, run_id: UUID, *, after_sequence: int = 0) -> list[AgentEvent]:
        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        async with self._lock:
            return [
                event.model_copy(deep=True)
                for event in self._events.get(run_id, [])
                if event.sequence > after_sequence
            ]
