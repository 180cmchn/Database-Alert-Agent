"""Provider-neutral lifecycle wrapper for one tool invocation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_runtime.contracts import (
    ArtifactRef,
    InvocationError,
    ToolInvocation,
    ToolInvocationStatus,
)
from app.agent_runtime.events import AgentEvent, AgentEventKind, EventSink


class EvidenceDisposition(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"


class InvocationExecutionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: dict[str, Any] = Field(default_factory=dict)
    artifact_ref: ArtifactRef | None = None


class InvocationExecutionResult(BaseModel):
    """Outcome consumed by the hypothesis evaluator.

    A transport or tool failure is explicitly represented as missing evidence.
    It says nothing about whether a hypothesis is true or false.
    """

    model_config = ConfigDict(extra="forbid")

    invocation: ToolInvocation
    result: dict[str, Any] = Field(default_factory=dict)
    evidence_disposition: EvidenceDisposition
    is_contradiction: bool = False

    @model_validator(mode="after")
    def preserve_failure_semantics(self) -> InvocationExecutionResult:
        unavailable_statuses = {
            ToolInvocationStatus.FAILED,
            ToolInvocationStatus.TIMED_OUT,
            ToolInvocationStatus.UNKNOWN_OUTCOME,
            ToolInvocationStatus.CANCELLED,
            ToolInvocationStatus.SKIPPED,
        }
        if self.invocation.status in unavailable_statuses:
            if self.evidence_disposition != EvidenceDisposition.MISSING:
                raise ValueError("failed invocation must be represented as missing evidence")
            if self.is_contradiction:
                raise ValueError("failed invocation cannot be represented as contradiction")
        if self.is_contradiction and self.evidence_disposition != EvidenceDisposition.AVAILABLE:
            raise ValueError("only available evidence can contradict a hypothesis")
        return self


class InvocationHandler(Protocol):
    def __call__(
        self,
        invocation: ToolInvocation,
    ) -> Awaitable[InvocationExecutionOutput | ArtifactRef | dict[str, Any] | None]: ...


class InvalidInvocationTransitionError(ValueError):
    pass


ErrorMapper = Callable[[Exception], InvocationError]


class InvocationExecutor:
    def __init__(
        self,
        event_sink: EventSink,
        *,
        error_mapper: ErrorMapper | None = None,
    ) -> None:
        self.event_sink = event_sink
        self.error_mapper = error_mapper or self._default_error

    async def execute(
        self,
        invocation: ToolInvocation,
        handler: InvocationHandler,
        *,
        timeout_seconds: float | None = None,
    ) -> InvocationExecutionResult:
        if invocation.status != ToolInvocationStatus.PENDING:
            raise InvalidInvocationTransitionError(
                f"Only PENDING invocations can start, got {invocation.status}"
            )
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        started_at = datetime.now(UTC)
        started = self._transition(
            invocation,
            status=ToolInvocationStatus.STARTED,
            started_at=started_at,
        )
        await self._emit(
            started,
            AgentEventKind.TOOL_INVOCATION_STARTED,
            {
                "attempt": started.attempt,
                "fingerprint": started.fingerprint,
                "provider": started.provider,
                "tool_name": started.tool_name,
            },
        )

        effective_timeout = self._effective_timeout(started, timeout_seconds, started_at)
        if effective_timeout is not None and effective_timeout <= 0:
            return await self._failure_result(
                started,
                status=ToolInvocationStatus.TIMED_OUT,
                kind=AgentEventKind.TOOL_INVOCATION_TIMED_OUT,
                error=InvocationError(
                    code="invocation_deadline_exceeded",
                    message="Tool invocation deadline was reached before execution",
                    retryable=True,
                ),
            )
        try:
            if effective_timeout is None:
                raw_output = await handler(started)
            else:
                async with asyncio.timeout(effective_timeout):
                    raw_output = await handler(started)
            output = self._normalize_output(raw_output)
            completed = self._transition(
                started,
                status=ToolInvocationStatus.SUCCEEDED,
                completed_at=datetime.now(UTC),
                artifact_ref=output.artifact_ref,
            )
            result = InvocationExecutionResult(
                invocation=completed,
                result=output.result,
                evidence_disposition=EvidenceDisposition.AVAILABLE,
            )
            await self._emit(
                completed,
                AgentEventKind.TOOL_INVOCATION_SUCCEEDED,
                {
                    "artifact_ref": (
                        output.artifact_ref.model_dump(mode="json")
                        if output.artifact_ref is not None
                        else None
                    ),
                    "evidence_disposition": result.evidence_disposition.value,
                    "result": output.result,
                },
            )
            return result
        except TimeoutError:
            return await self._failure_result(
                started,
                status=ToolInvocationStatus.TIMED_OUT,
                kind=AgentEventKind.TOOL_INVOCATION_TIMED_OUT,
                error=InvocationError(
                    code="invocation_timeout",
                    message="Tool invocation timed out",
                    retryable=True,
                ),
            )
        except asyncio.CancelledError:
            cancelled = self._transition(
                started,
                status=ToolInvocationStatus.CANCELLED,
                completed_at=datetime.now(UTC),
                error=InvocationError(
                    code="invocation_cancelled",
                    message="Tool invocation was cancelled",
                    retryable=True,
                ),
            )
            await self._emit(
                cancelled,
                AgentEventKind.TOOL_INVOCATION_CANCELLED,
                {
                    "error": cancelled.error.model_dump(mode="json"),
                    "evidence_disposition": EvidenceDisposition.MISSING.value,
                    "is_contradiction": False,
                },
            )
            raise
        except Exception as exc:
            return await self._failure_result(
                started,
                status=ToolInvocationStatus.FAILED,
                kind=AgentEventKind.TOOL_INVOCATION_FAILED,
                error=self.error_mapper(exc),
            )

    async def _failure_result(
        self,
        invocation: ToolInvocation,
        *,
        status: ToolInvocationStatus,
        kind: AgentEventKind,
        error: InvocationError,
    ) -> InvocationExecutionResult:
        completed = self._transition(
            invocation,
            status=status,
            completed_at=datetime.now(UTC),
            error=error,
        )
        result = InvocationExecutionResult(
            invocation=completed,
            evidence_disposition=EvidenceDisposition.MISSING,
            is_contradiction=False,
        )
        await self._emit(
            completed,
            kind,
            {
                "error": error.model_dump(mode="json"),
                "evidence_disposition": result.evidence_disposition.value,
                "is_contradiction": False,
            },
        )
        return result

    async def _emit(
        self,
        invocation: ToolInvocation,
        kind: AgentEventKind,
        payload: dict[str, Any],
    ) -> AgentEvent:
        return await self.event_sink.append(
            AgentEvent(
                run_id=invocation.run_id,
                parent_run_id=invocation.parent_run_id,
                invocation_id=invocation.invocation_id,
                kind=kind,
                payload=payload,
                correlation_id=invocation.run_id,
            )
        )

    @staticmethod
    def _effective_timeout(
        invocation: ToolInvocation,
        timeout: float | None,
        now: datetime,
    ) -> float | None:
        candidates: list[float] = []
        if timeout is not None:
            candidates.append(timeout)
        if invocation.deadline is not None:
            candidates.append(max(0, (invocation.deadline - now).total_seconds()))
        return min(candidates) if candidates else None

    @staticmethod
    def _normalize_output(
        output: InvocationExecutionOutput | ArtifactRef | dict[str, Any] | None,
    ) -> InvocationExecutionOutput:
        if output is None:
            return InvocationExecutionOutput()
        if isinstance(output, InvocationExecutionOutput):
            return output
        if isinstance(output, ArtifactRef):
            return InvocationExecutionOutput(artifact_ref=output)
        if isinstance(output, dict):
            return InvocationExecutionOutput(result=output)
        raise TypeError(f"Unsupported invocation output: {type(output).__name__}")

    @staticmethod
    def _transition(invocation: ToolInvocation, **updates: Any) -> ToolInvocation:
        payload = invocation.model_dump(mode="python")
        payload.update(updates)
        return ToolInvocation.model_validate(payload)

    @staticmethod
    def _default_error(exc: Exception) -> InvocationError:
        return InvocationError(
            code=type(exc).__name__,
            message=str(exc) or type(exc).__name__,
            retryable=bool(getattr(exc, "retryable", False)),
        )
