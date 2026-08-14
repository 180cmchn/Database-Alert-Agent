"""Contracts separating an MCP transport, Host profile, and Agent planner."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_runtime.budgets import BudgetSnapshot
from app.agent_runtime.contracts import (
    AgentAction,
    ArtifactRef,
    CallToolAction,
    InvocationError,
    RuntimeStopReason,
    ToolInvocation,
    ToolInvocationStatus,
    ToolSpec,
)


class MCPRuntimeContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DiscoveredMCPTool(MCPRuntimeContract):
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=20_000)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)


class PreparedCall(MCPRuntimeContract):
    """Arguments prepared for transport without Host-side policy enforcement."""

    tool_name: str = Field(min_length=1, max_length=256)
    objective: str = Field(min_length=1, max_length=4000)
    hypothesis_ids: list[str] = Field(default_factory=list)
    model_arguments: dict[str, Any] = Field(default_factory=dict)
    effective_arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float | None = Field(default=None, gt=0, le=3600)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finish(MCPRuntimeContract):
    reason: RuntimeStopReason
    summary: str = Field(min_length=1, max_length=10_000)
    requires_human: bool = False
    model_requested: bool = False


class RetryDirective(MCPRuntimeContract):
    reason: str = Field(min_length=1, max_length=4000)
    reconnect: bool = False
    retry_call: bool = False
    continue_run: bool = True
    unknown_outcome: bool = False
    allow_unknown_outcome_retry: bool = False

    @model_validator(mode="after")
    def prevent_unsafe_unknown_retry(self) -> RetryDirective:
        if (
            self.unknown_outcome
            and self.retry_call
            and not self.allow_unknown_outcome_retry
        ):
            raise ValueError(
                "an invocation with unknown outcome requires explicit retry authorization"
            )
        if self.allow_unknown_outcome_retry and not (
            self.unknown_outcome and self.retry_call
        ):
            raise ValueError(
                "allow_unknown_outcome_retry requires unknown_outcome=true and retry_call=true"
            )
        if self.retry_call and not self.continue_run:
            raise ValueError("retry_call requires continue_run=true")
        return self


class MCPToolSession(Protocol):
    @property
    def session_id(self) -> str: ...

    async def list_tools(self) -> list[DiscoveredMCPTool]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...

    async def close(self) -> None: ...


class MCPConnector(Protocol):
    @property
    def provider(self) -> str: ...

    async def open_session(self) -> MCPToolSession: ...


class MCPPlanner(Protocol):
    async def plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        reasoning_callback: Callable[[str, int], Awaitable[None]] | None = None,
    ) -> AgentAction | dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class HarnessObservation[ObservationT]:
    invocation_id: UUID
    fingerprint: str
    status: ToolInvocationStatus
    payload: ObservationT | None = None
    error: InvocationError | None = None


@dataclass(frozen=True, slots=True)
class RemoteResponseRecord:
    """A complete MCP transport response retained until the investigation ends."""

    invocation_id: UUID
    tool_name: str
    arguments: dict[str, Any]
    response: Any


@dataclass(frozen=True, slots=True)
class ScenarioTransition[StateT, ObservationT]:
    state: StateT
    observation: ObservationT | None = None
    message: dict[str, Any] | list[dict[str, Any]] | None = None
    status: ToolInvocationStatus = ToolInvocationStatus.SUCCEEDED
    artifact_ref: ArtifactRef | None = None


class MCPHarnessScenario[StateT, ObservationT](Protocol):
    @property
    def provider(self) -> str: ...

    def initial_state(self) -> StateT: ...

    def initial_messages(self, state: StateT) -> list[dict[str, Any]]: ...

    async def bootstrap(self, session: MCPToolSession, state: StateT) -> StateT:
        """Perform deterministic session setup; each call_tool is budgeted as bootstrap."""
        ...

    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]: ...

    def prepare_call(
        self,
        action: CallToolAction,
        *,
        state: StateT,
    ) -> PreparedCall: ...

    def on_result(
        self,
        state: StateT,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[StateT, ObservationT]: ...

    def result_error_directive(
        self,
        state: StateT,
        call: PreparedCall,
        error: Exception,
    ) -> RetryDirective | None:
        """Classify an expected remote tool error decoded from a transport result."""
        ...

    def on_failure(
        self,
        state: StateT,
        call: PreparedCall,
        error: InvocationError,
        status: ToolInvocationStatus,
    ) -> ScenarioTransition[StateT, ObservationT]: ...

    def retry_directive(
        self,
        state: StateT,
        call: PreparedCall | None,
        error: Exception,
    ) -> RetryDirective: ...

    def completion(
        self,
        state: StateT,
        observations: Sequence[HarnessObservation[ObservationT]],
    ) -> Finish | None: ...

@dataclass(frozen=True, slots=True)
class MCPHarnessSnapshot[StateT, ObservationT]:
    run_id: UUID
    parent_run_id: UUID | None
    state: StateT
    messages: tuple[dict[str, Any], ...]
    observations: tuple[HarnessObservation[ObservationT], ...]
    invocations: tuple[ToolInvocation, ...]
    tool_specs: tuple[ToolSpec, ...]
    fingerprints: frozenset[str]
    budget: BudgetSnapshot
    finish: Finish | None
    event_version: int
    deadline: datetime | None
    wall_time_deadline: datetime | None = None
    pending_retry: PreparedCall | None = None
    retry_not_before: datetime | None = None
    active_call: PreparedCall | None = None
    remote_responses: tuple[RemoteResponseRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class MCPHarnessResult[StateT, ObservationT](MCPHarnessSnapshot[StateT, ObservationT]):
    pass


class CheckpointHook[StateT, ObservationT](Protocol):
    async def __call__(
        self,
        snapshot: MCPHarnessSnapshot[StateT, ObservationT],
    ) -> None: ...


class InvocationStore(Protocol):
    """Idempotent persistence hook for every invocation lifecycle state."""

    async def save(self, invocation: ToolInvocation) -> None: ...

    async def load(self, invocation_id: UUID) -> ToolInvocation | None: ...


class ArtifactStore(Protocol):
    """Persist an artifact reference produced by a completed invocation."""

    async def save(
        self,
        *,
        run_id: UUID,
        invocation_id: UUID,
        artifact: ArtifactRef,
    ) -> None: ...


class RemoteResponseStore(Protocol):
    """Persist complete transport responses after an MCP investigation ends."""

    async def save(
        self,
        *,
        run_id: UUID,
        invocation_id: UUID,
        tool_name: str,
        arguments: dict[str, Any],
        response: Any,
    ) -> None: ...

    async def load(
        self,
        *,
        run_id: UUID,
        invocation_id: UUID,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any | None:
        """Return a retained response for recovery, or ``None`` when absent."""
        ...
