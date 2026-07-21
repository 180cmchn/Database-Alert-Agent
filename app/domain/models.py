from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class AlertStatus(StrEnum):
    RECEIVED = "RECEIVED"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAILED = "FAILED"


class InvestigationStage(StrEnum):
    RECEIVED = "RECEIVED"
    FINGERPRINTING = "FINGERPRINTING"
    KNOWLEDGE_MATCHING = "KNOWLEDGE_MATCHING"
    RUNBOOK_MATCHING = "RUNBOOK_MATCHING"
    INVESTIGATING = "INVESTIGATING"
    ADVISING = "ADVISING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAILED = "FAILED"


class RunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAILED = "FAILED"


class ToolStatus(StrEnum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ValidationKind(StrEnum):
    RULE = "RULE"
    AGENT = "AGENT"


class FeedbackVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    CORRECTED = "CORRECTED"
    REJECTED = "REJECTED"


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
    incident_fingerprint: str = ""
    fingerprint_version: str = "v1"
    environment: str = "unknown"
    service_name: str = "unknown"
    alert_type: str = "unknown"
    alert_name: str = "unknown"
    resource_type: str | None = None
    cluster: str | None = None
    alarm_type: str | None = None
    metric_name: str | None = None
    error_pattern: str | None = None
    error_summary: str | None = None
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


class RunbookDocument(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    section: str = Field(default="main", min_length=1, max_length=200)
    reasons: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    content: str = Field(min_length=1, max_length=1_000_000)
    metadata: dict[str, Any] = Field(default_factory=dict)
    version: int = Field(default=1, ge=1)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("severities", mode="before")
    @classmethod
    def validate_severities(cls, value: Any) -> Any:
        if isinstance(value, list):
            normalized = list(dict.fromkeys(str(item).upper() for item in value))
            valid = {item.value for item in Severity}
            if set(normalized) - valid:
                raise ValueError("severities must be CRITICAL, WARNING, or INFO")
            return normalized
        return value


class RunbookReference(BaseModel):
    runbook_id: str
    section: str = "main"


class AnalysisBasisSource(StrEnum):
    RUNBOOK = "RUNBOOK"
    AI = "AI"


class AnalysisBasis(BaseModel):
    source: AnalysisBasisSource
    statement: str = Field(min_length=1)
    source_ref: RunbookReference | None = None

    @model_validator(mode="after")
    def validate_source_reference(self) -> AnalysisBasis:
        if self.source == AnalysisBasisSource.RUNBOOK and self.source_ref is None:
            raise ValueError("RUNBOOK analysis basis requires source_ref")
        if self.source == AnalysisBasisSource.AI and self.source_ref is not None:
            raise ValueError("AI analysis basis must not contain source_ref")
        return self


class RecommendationStep(BaseModel):
    order: int = Field(ge=1)
    action: str
    expected_result: str | None = None
    caution: str | None = None
    source_ref: RunbookReference | None = None


class RootCauseAssessment(BaseModel):
    cause: str
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0, ge=0, le=1)
    verified: bool = False


class Recommendation(BaseModel):
    summary: str
    likely_causes: list[str] = Field(default_factory=list)
    analysis_bases: list[AnalysisBasis] = Field(default_factory=list)
    steps: list[RecommendationStep]
    risks: list[str] = Field(default_factory=list)
    requires_human: bool = True
    confidence: float = Field(ge=0, le=1)
    manual_matched: bool
    runbook_references: list[RunbookReference] = Field(default_factory=list)
    root_causes: list[RootCauseAssessment] = Field(default_factory=list)


class ToolExecutionRequest(BaseModel):
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=10, gt=0, le=120)
    required: bool = False


class InvestigationStrategy(BaseModel):
    strategy_id: str
    title: str
    description: str
    tool_plan: list[ToolExecutionRequest] = Field(default_factory=list)
    max_dynamic_turns: int = Field(default=0, ge=0, le=10)


class InvestigationContext(BaseModel):
    run_id: UUID
    alert: NormalizedAlert
    strategy: InvestigationStrategy


class EvidenceRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    tool_name: str
    source_system: str
    status: ToolStatus
    request: dict[str, Any] = Field(default_factory=dict)
    summary: str
    structured_data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    collected_at: datetime = Field(default_factory=utc_now)
    duration_ms: int = Field(default=0, ge=0)
    truncated: bool = False


class ProgressRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    sequence: int = Field(default=0, ge=0)
    stage: InvestigationStage
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ValidationRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    kind: ValidationKind
    passed: bool
    issues: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class InvestigationRun(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    attempt: int = Field(default=1, ge=1)
    status: RunStatus = RunStatus.RUNNING
    current_stage: InvestigationStage = InvestigationStage.RECEIVED
    strategy_id: str | None = None
    error: str | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class KnowledgeCase(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source_alert_id: UUID
    source_run_id: UUID
    incident_fingerprint: str
    fingerprint_version: str
    environment: str
    service_name: str
    alert_type: str
    database_engine: str | None = None
    final_root_cause: str
    actual_resolution: str
    recommendation: Recommendation | None = None
    confirmed_by: str
    confirmed_at: datetime = Field(default_factory=utc_now)
    created_at: datetime = Field(default_factory=utc_now)


class FeedbackRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    run_id: UUID
    idempotency_key: str
    verdict: FeedbackVerdict
    final_root_cause: str | None = None
    actual_resolution: str | None = None
    recovered: bool | None = None
    reviewer: str
    created_at: datetime = Field(default_factory=utc_now)


class InvestigationDecision(BaseModel):
    action: Literal["tool", "finish"]
    tool_name: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class AdvisorMetadata(BaseModel):
    provider: str
    model: str
    prompt_version: str
    request_id: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)


class AnalysisResultEvent(BaseModel):
    alert: NormalizedAlert
    recommendation: Recommendation
    status: AlertStatus
    message: str


class StoredAlert(BaseModel):
    alert: NormalizedAlert
    status: AlertStatus
    recommendation: Recommendation | None = None
    manual_matches: list[RunbookExcerpt] = Field(default_factory=list)
    advisor_metadata: AdvisorMetadata | None = None
    error: str | None = None
    latest_run: InvestigationRun | None = None
    progress: list[ProgressRecord] = Field(default_factory=list)
    evidence_records: list[EvidenceRecord] = Field(default_factory=list)
    validations: list[ValidationRecord] = Field(default_factory=list)
    feedback: list[FeedbackRecord] = Field(default_factory=list)
    knowledge_matches: list[KnowledgeCase] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AlertSummary(BaseModel):
    id: UUID
    external_id: str
    source: str
    severity: Severity
    status: AlertStatus
    title: str
    reason: str
    environment: str
    service_name: str
    occurred_at: datetime
    created_at: datetime
    updated_at: datetime
    current_stage: InvestigationStage | None = None
    manual_matched: bool = False
    requires_human: bool | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)


class AlertListResult(BaseModel):
    items: list[AlertSummary]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)


class DashboardSummary(BaseModel):
    total: int = Field(ge=0)
    active: int = Field(ge=0)
    critical_open: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    recent_alerts: list[AlertSummary] = Field(default_factory=list)
