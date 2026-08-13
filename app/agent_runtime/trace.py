"""Durable, append-only UI trace events emitted by the main Agent loop."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.agent_runtime.events import AgentEvent, AgentEventKind, EventSink


class AgentTraceKind(StrEnum):
    REASONING = "REASONING"
    ACTION = "ACTION"
    OBSERVATION = "OBSERVATION"


class AgentTraceScope(StrEnum):
    MAIN_AGENT = "main_agent"
    MCP_INTERNAL = "mcp_internal"


_EVENT_KIND = {
    AgentTraceKind.REASONING: AgentEventKind.TRACE_REASONING,
    AgentTraceKind.ACTION: AgentEventKind.TRACE_ACTION,
    AgentTraceKind.OBSERVATION: AgentEventKind.TRACE_OBSERVATION,
}
_TRACE_EVENT_KINDS = frozenset(_EVENT_KIND.values())


class AgentTraceEntry(BaseModel):
    """One exact provider/Agent trace item projected from an AgentEvent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    run_id: UUID
    sequence: int = Field(ge=1)
    kind: AgentTraceKind
    scope: AgentTraceScope
    actor: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1)
    stream_id: str | None = Field(default=None, min_length=1, max_length=512)
    delta_index: int | None = Field(default=None, ge=0)
    occurred_at: datetime

    @model_validator(mode="after")
    def require_complete_delta_identity(self) -> AgentTraceEntry:
        if (self.stream_id is None) != (self.delta_index is None):
            raise ValueError("stream_id and delta_index must be provided together")
        if self.stream_id is not None and self.kind != AgentTraceKind.REASONING:
            raise ValueError("only reasoning trace entries may be streamed deltas")
        return self


def trace_entry_from_event(event: AgentEvent) -> AgentTraceEntry | None:
    """Project valid UI trace events without letting corrupt history break the feed."""

    if event.kind not in _TRACE_EVENT_KINDS:
        return None
    kind = {
        AgentEventKind.TRACE_REASONING: AgentTraceKind.REASONING,
        AgentEventKind.TRACE_ACTION: AgentTraceKind.ACTION,
        AgentEventKind.TRACE_OBSERVATION: AgentTraceKind.OBSERVATION,
    }[event.kind]
    try:
        return AgentTraceEntry(
            event_id=event.event_id,
            run_id=event.run_id,
            sequence=event.sequence,
            kind=kind,
            scope=(
                event.payload["scope"]
                if "scope" in event.payload
                else _infer_legacy_scope(event)
            ),
            actor=event.payload.get("actor"),
            provider=event.payload.get("provider"),
            content=event.payload.get("content"),
            stream_id=event.payload.get("stream_id"),
            delta_index=event.payload.get("delta_index"),
            occurred_at=event.occurred_at,
        )
    except ValidationError:
        # Historical events predate the UI contract and a partially written or
        # malformed trace item must not make the entire incremental API fail.
        return None


class AgentTraceEmitter:
    """Hook for a ReAct loop to persist exact reasoning, actions, and observations."""

    def __init__(
        self,
        sink: EventSink,
        *,
        run_id: UUID,
        actor: str,
        provider: str,
        scope: AgentTraceScope | str | None = None,
    ) -> None:
        self.sink = sink
        self.run_id = run_id
        self.actor = self._label(actor, "actor")
        self.provider = self._label(provider, "provider")
        self.scope = (
            AgentTraceScope(scope)
            if scope is not None
            else _infer_scope_from_labels(actor=self.actor, trace_key=None)
        )

    async def emit_reasoning(
        self, content: str | None, *, trace_key: str | None = None
    ) -> AgentEvent | None:
        """Emit real reasoning only; unavailable reasoning deliberately emits nothing."""

        if content is None or not content.strip():
            return None
        return await self._emit(AgentTraceKind.REASONING, content, trace_key=trace_key)

    async def emit_reasoning_delta(
        self,
        content: str,
        *,
        stream_id: str,
        delta_index: int,
        trace_key: str | None = None,
    ) -> AgentEvent | None:
        """Persist one exact provider reasoning delta, including whitespace."""

        if not isinstance(content, str) or not content:
            return None
        if not isinstance(stream_id, str) or not stream_id.strip():
            raise ValueError("reasoning stream_id must be a non-empty string")
        if len(stream_id) > 512:
            raise ValueError("reasoning stream_id exceeds 512 characters")
        if not isinstance(delta_index, int) or isinstance(delta_index, bool) or delta_index < 0:
            raise ValueError("reasoning delta_index must be a non-negative integer")
        key = trace_key or f"{stream_id}:delta:{delta_index}"
        return await self._emit(
            AgentTraceKind.REASONING,
            content,
            trace_key=key,
            stream_id=stream_id,
            delta_index=delta_index,
            allow_whitespace=True,
        )

    async def next_reasoning_delta_index(self, stream_id: str) -> int:
        indexes = [
            event.payload.get("delta_index")
            for event in await self.sink.read(self.run_id)
            if event.kind == AgentEventKind.TRACE_REASONING
            and event.payload.get("stream_id") == stream_id
            and isinstance(event.payload.get("delta_index"), int)
        ]
        return max(indexes, default=-1) + 1

    async def emit_provider_reasoning(self, message: Any) -> AgentEvent | None:
        """Read the real provider ``reasoning_content``/``reasoning`` field."""

        return await self.emit_reasoning(provider_reasoning_text(message))

    async def emit_action(
        self, content: str, *, trace_key: str | None = None
    ) -> AgentEvent:
        return await self._emit(AgentTraceKind.ACTION, content, trace_key=trace_key)

    async def emit_observation(
        self,
        content: str,
        *,
        actor: str | None = None,
        provider: str | None = None,
        trace_key: str | None = None,
    ) -> AgentEvent:
        return await self._emit(
            AgentTraceKind.OBSERVATION,
            content,
            actor=actor,
            provider=provider,
            trace_key=trace_key,
        )

    async def _emit(
        self,
        kind: AgentTraceKind,
        content: str,
        *,
        actor: str | None = None,
        provider: str | None = None,
        trace_key: str | None = None,
        stream_id: str | None = None,
        delta_index: int | None = None,
        allow_whitespace: bool = False,
    ) -> AgentEvent:
        if not isinstance(content, str) or not content or (
            not allow_whitespace and not content.strip()
        ):
            raise ValueError("Agent trace content must be a non-empty string")
        safe_trace_key = trace_key.strip() if isinstance(trace_key, str) else None
        if safe_trace_key:
            for existing in await self.sink.read(self.run_id):
                if (
                    existing.kind == _EVENT_KIND[kind]
                    and existing.payload.get("trace_key") == safe_trace_key
                ):
                    if existing.payload.get("content") != content:
                        raise ValueError(
                            f"Agent trace key {safe_trace_key!r} was reused with new content"
                        )
                    existing_scope = existing.payload.get("scope")
                    if existing_scope is None:
                        existing_scope = _infer_legacy_scope(existing)
                    if existing_scope != self.scope:
                        raise ValueError(
                            f"Agent trace key {safe_trace_key!r} was reused across scopes"
                        )
                    return existing
        event = AgentEvent(
            event_id=(
                uuid5(self.run_id, f"agent-trace-v1:{kind.value}:{safe_trace_key}")
                if safe_trace_key
                else uuid5(
                    self.run_id,
                    "agent-trace-v1:"
                    f"{kind.value}:{await self.sink.current_version(self.run_id) + 1}",
                )
            ),
            run_id=self.run_id,
            kind=_EVENT_KIND[kind],
            payload={
                "actor": self._label(actor or self.actor, "actor"),
                "provider": self._label(provider or self.provider, "provider"),
                "scope": self.scope.value,
                # Preserve the provider text exactly. The persistence boundary
                # sanitizes secrets but neither this hook nor the API summarizes it.
                "content": content,
                **({"trace_key": safe_trace_key} if safe_trace_key else {}),
                **({"stream_id": stream_id} if stream_id is not None else {}),
                **({"delta_index": delta_index} if delta_index is not None else {}),
            },
        )
        return await self.sink.append(event)

    @staticmethod
    def _label(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Agent trace {field} must be a non-empty string")
        if len(value) > 128:
            raise ValueError(f"Agent trace {field} exceeds 128 characters")
        return value


def _infer_legacy_scope(event: AgentEvent) -> AgentTraceScope:
    """Classify trace events written before the explicit scope contract."""

    return _infer_scope_from_labels(
        actor=event.payload.get("actor"),
        trace_key=event.payload.get("trace_key"),
    )


def _infer_scope_from_labels(*, actor: Any, trace_key: Any) -> AgentTraceScope:
    if isinstance(trace_key, str):
        normalized_key = trace_key.strip().casefold()
        if normalized_key.startswith(("react:", "main-agent:", "main_agent:", "final:")):
            return AgentTraceScope.MAIN_AGENT
    if isinstance(actor, str):
        normalized_actor = actor.strip().casefold().replace("-", "_").replace(" ", "_")
        if normalized_actor == "main_agent":
            return AgentTraceScope.MAIN_AGENT
    # Unknown historical producers must not suppress the main-Agent reasoning fallback.
    return AgentTraceScope.MCP_INTERNAL


def provider_reasoning_text(message: Any) -> str | None:
    """Return an actual provider reasoning field without constructing a fallback."""

    candidates: list[Any] = []
    if isinstance(message, Mapping):
        candidates.extend((message.get("reasoning_content"), message.get("reasoning")))
        extra = message.get("model_extra")
    else:
        candidates.extend(
            (getattr(message, "reasoning_content", None), getattr(message, "reasoning", None))
        )
        extra = getattr(message, "model_extra", None)
    if isinstance(extra, Mapping):
        candidates.extend((extra.get("reasoning_content"), extra.get("reasoning")))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return None


def provider_reasoning_delta(message: Any) -> str | None:
    """Return one exact non-empty reasoning delta without treating content as thought."""

    candidates: list[Any] = []
    if isinstance(message, Mapping):
        candidates.extend((message.get("reasoning_content"), message.get("reasoning")))
        extra = message.get("model_extra")
    else:
        candidates.extend(
            (getattr(message, "reasoning_content", None), getattr(message, "reasoning", None))
        )
        extra = getattr(message, "model_extra", None)
    if isinstance(extra, Mapping):
        candidates.extend((extra.get("reasoning_content"), extra.get("reasoning")))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate:
            return candidate
    return None
