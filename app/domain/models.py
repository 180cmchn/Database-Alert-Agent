from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class AlertStatus(StrEnum):
    RECEIVED = "RECEIVED"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class NotificationPhase(StrEnum):
    INITIAL_ALERT = "INITIAL_ALERT"
    ADVICE_READY = "ADVICE_READY"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"


class NotificationStatus(StrEnum):
    SENT = "SENT"
    FAILED = "FAILED"


class DatabaseTarget(BaseModel):
    model_config = ConfigDict(extra="allow")

    engine: str | None = None
    instance: str | None = None
    database: str | None = None
    host: str | None = None


class NormalizedAlert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    external_id: str
    source: str
    raw_severity: str
    severity: Severity
    title: str
    reason: str
    description: str = ""
    occurred_at: datetime = Field(default_factory=utc_now)
    database: DatabaseTarget | None = None
    features: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class RunbookExcerpt(BaseModel):
    runbook_id: str
    title: str
    section: str = "main"
    content: str
    score: float = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunbookReference(BaseModel):
    runbook_id: str
    section: str = "main"


class RecommendationStep(BaseModel):
    order: int = Field(ge=1)
    action: str
    expected_result: str | None = None
    caution: str | None = None
    source_ref: RunbookReference | None = None


class Recommendation(BaseModel):
    summary: str
    likely_causes: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    steps: list[RecommendationStep]
    risks: list[str] = Field(default_factory=list)
    requires_human: bool = True
    confidence: float = Field(ge=0, le=1)
    manual_matched: bool
    runbook_references: list[RunbookReference] = Field(default_factory=list)


class AdvisorMetadata(BaseModel):
    provider: str
    model: str
    prompt_version: str
    request_id: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)


class NotificationEvent(BaseModel):
    phase: NotificationPhase
    alert: NormalizedAlert
    recommendation: Recommendation | None = None
    message: str


class NotificationRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    phase: NotificationPhase
    status: NotificationStatus
    attempts: int = Field(ge=1)
    error: str | None = None
    external_delivery_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class StoredAlert(BaseModel):
    alert: NormalizedAlert
    status: AlertStatus
    recommendation: Recommendation | None = None
    manual_matches: list[RunbookExcerpt] = Field(default_factory=list)
    advisor_metadata: AdvisorMetadata | None = None
    error: str | None = None
    notifications: list[NotificationRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
