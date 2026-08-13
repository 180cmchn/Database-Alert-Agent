"""Versioned, persistence-friendly contracts used by the Agent harness."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictContract(BaseModel):
    """Base class for data written to an event stream or checkpoint."""

    model_config = ConfigDict(extra="forbid")


class ToolInvocationStatus(StrEnum):
    PENDING = "PENDING"
    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    NO_DATA = "NO_DATA"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


class RuntimeStopReason(StrEnum):
    COMPLETED = "COMPLETED"
    EVIDENCE_SUFFICIENT = "EVIDENCE_SUFFICIENT"
    HUMAN_INPUT_REQUIRED = "HUMAN_INPUT_REQUIRED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    NO_SAFE_ACTION = "NO_SAFE_ACTION"
    NO_DISCRIMINATING_EVIDENCE = "NO_DISCRIMINATING_EVIDENCE"
    AMBIGUOUS_TARGET = "AMBIGUOUS_TARGET"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ToolSpec(StrictContract):
    """A model-visible outer tool contract discovered by the runtime."""

    name: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=128)
    capability: str = Field(min_length=1, max_length=256)
    role: str = ""
    workflow: str = ""
    safety: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = Field(min_length=1, max_length=128)
    schema_version: str = Field(min_length=1, max_length=128)
    timeout: float = Field(default=30, gt=0, le=3600)


class ArtifactRef(StrictContract):
    artifact_id: UUID = Field(default_factory=uuid4)
    kind: str = Field(min_length=1, max_length=128)
    media_type: str = Field(default="application/json", min_length=1, max_length=256)
    uri: str = Field(min_length=1, max_length=4096)
    sha256: str | None = Field(default=None, min_length=1, max_length=128)
    size_bytes: int | None = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvocationError(StrictContract):
    code: str = Field(min_length=1, max_length=256)
    message: str = Field(min_length=1, max_length=4000)
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ToolInvocation(StrictContract):
    invocation_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    parent_run_id: UUID | None = None
    tool_name: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=128)
    objective: str = Field(min_length=1, max_length=4000)
    hypothesis_ids: list[str] = Field(default_factory=list)
    model_arguments: dict[str, Any] = Field(default_factory=dict)
    effective_arguments: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = Field(min_length=1, max_length=256)
    tool_policy_version: str = Field(default="", max_length=128)
    tool_schema_version: str = Field(default="", max_length=128)
    request_timeout_seconds: float | None = Field(default=None, gt=0, le=3600)
    execution_lease_owner: str | None = Field(default=None, min_length=1, max_length=256)
    execution_fencing_token: int | None = Field(default=None, ge=1)
    status: ToolInvocationStatus = ToolInvocationStatus.PENDING
    attempt: int = Field(default=1, ge=1)
    deadline: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: InvocationError | None = None
    artifact_ref: ArtifactRef | None = None

    @field_validator("deadline", "created_at", "started_at", "completed_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("invocation timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> ToolInvocation:
        terminal = {
            ToolInvocationStatus.SUCCEEDED,
            ToolInvocationStatus.NO_DATA,
            ToolInvocationStatus.FAILED,
            ToolInvocationStatus.TIMED_OUT,
            ToolInvocationStatus.UNKNOWN_OUTCOME,
            ToolInvocationStatus.CANCELLED,
            ToolInvocationStatus.SKIPPED,
        }
        if (self.execution_lease_owner is None) != (
            self.execution_fencing_token is None
        ):
            raise ValueError(
                "execution_lease_owner and execution_fencing_token must be set together"
            )
        if self.status == ToolInvocationStatus.PENDING and (
            self.execution_lease_owner is not None
            or self.execution_fencing_token is not None
        ):
            raise ValueError("PENDING invocation cannot have an execution lease claim")
        if self.status == ToolInvocationStatus.PENDING:
            if any(
                value is not None
                for value in (self.started_at, self.completed_at, self.error, self.artifact_ref)
            ):
                raise ValueError("PENDING invocation cannot contain lifecycle results")
        if self.status == ToolInvocationStatus.STARTED:
            if self.started_at is None:
                raise ValueError("STARTED invocation requires started_at")
            if self.completed_at is not None or self.error is not None:
                raise ValueError("STARTED invocation cannot contain a completion result")
        if self.status in terminal and self.completed_at is None:
            raise ValueError("terminal invocation requires completed_at")
        if self.status in terminal - {ToolInvocationStatus.SKIPPED} and self.started_at is None:
            raise ValueError("executed terminal invocation requires started_at")
        if self.status in {
            ToolInvocationStatus.FAILED,
            ToolInvocationStatus.TIMED_OUT,
            ToolInvocationStatus.UNKNOWN_OUTCOME,
            ToolInvocationStatus.CANCELLED,
        }:
            if self.error is None:
                raise ValueError("failed invocation requires error details")
        if self.status in {ToolInvocationStatus.SUCCEEDED, ToolInvocationStatus.NO_DATA}:
            if self.error is not None:
                raise ValueError("successful invocation cannot contain an error")
        if self.completed_at is not None and self.started_at is not None:
            if self.completed_at < self.started_at:
                raise ValueError("completed_at cannot precede started_at")
        if self.started_at is not None and self.started_at < self.created_at:
            raise ValueError("started_at cannot precede created_at")
        return self

    @staticmethod
    def build_fingerprint(
        *,
        tool_name: str,
        effective_arguments: dict[str, Any],
        objective: str = "",
    ) -> str:
        canonical = json.dumps(
            {
                "effective_arguments": effective_arguments,
                "objective": objective,
                "tool_name": tool_name,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RunManifest(StrictContract):
    run_id: UUID
    parent_run_id: UUID | None = None
    manifest_version: str = Field(default="1", min_length=1, max_length=64)
    agent_name: str = Field(min_length=1, max_length=256)
    code_version: str = Field(min_length=1, max_length=256)
    model_provider: str = Field(default="", max_length=128)
    model_name: str = Field(default="", max_length=256)
    prompt_version: str = Field(default="", max_length=256)
    tool_schema_versions: dict[str, str] = Field(default_factory=dict)
    tool_policy_versions: dict[str, str] = Field(default_factory=dict)
    knowledge_versions: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def require_created_at_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("manifest created_at must be timezone-aware")
        return value

    def digest(self) -> str:
        payload = self.model_dump(mode="json")
        canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RunCheckpoint(StrictContract):
    checkpoint_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    namespace: str = Field(default="agent", min_length=1, max_length=256)
    version: int = Field(ge=1)
    sequence: int = Field(ge=0)
    state: dict[str, Any] = Field(default_factory=dict)
    budget_snapshot: dict[str, Any] = Field(default_factory=dict)
    manifest_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    stop_reason: RuntimeStopReason | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def require_checkpoint_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("checkpoint created_at must be timezone-aware")
        return value


class CallToolAction(StrictContract):
    action: Literal["call_tool"] = "call_tool"
    tool_name: str = Field(min_length=1, max_length=256)
    objective: str = Field(min_length=1, max_length=4000)
    hypothesis_ids: list[str] = Field(default_factory=list)
    arguments: dict[str, Any] = Field(default_factory=dict)


class FinishAction(StrictContract):
    action: Literal["finish"] = "finish"
    reason: RuntimeStopReason
    summary: str = Field(min_length=1, max_length=10_000)


class RequestHumanInputAction(StrictContract):
    action: Literal["request_human_input"] = "request_human_input"
    reason: str = Field(min_length=1, max_length=4000)
    question: str = Field(min_length=1, max_length=4000)
    required_fields: list[str] = Field(default_factory=list)


AgentAction = Annotated[
    CallToolAction | FinishAction | RequestHumanInputAction,
    Field(discriminator="action"),
]
_AGENT_ACTION_ADAPTER = TypeAdapter(AgentAction)


def parse_agent_action(value: Any) -> AgentAction:
    """Validate untrusted planner output against the discriminated action schema."""

    return _AGENT_ACTION_ADAPTER.validate_python(value)
