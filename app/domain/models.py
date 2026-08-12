from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

INCONCLUSIVE_ROOT_CAUSE_SUMMARY = "现有结果无法得出根因"


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
    INCONCLUSIVE = "INCONCLUSIVE"
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
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"


class RunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"


class ToolStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NO_DATA = "NO_DATA"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ToolResultSourceSpan(BaseModel):
    """Exact character interval cited from one string-valued JSON Pointer."""

    model_config = ConfigDict(extra="forbid")

    path: str
    character_start: int = Field(ge=0)
    character_end: int = Field(gt=0)
    character_total: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_interval(self) -> ToolResultSourceSpan:
        if not self.path.startswith("/"):
            raise ValueError("tool result source span path must be a JSON Pointer")
        if self.character_end <= self.character_start:
            raise ValueError("tool result source span must have a non-empty interval")
        if self.character_end > self.character_total:
            raise ValueError("tool result source span exceeds the source string")
        return self


class ToolResultObservation(BaseModel):
    """One source-grounded fact extracted from a complete tool result."""

    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=4000)
    source_paths: list[str] = Field(min_length=1, max_length=50)
    source_spans: list[ToolResultSourceSpan] = Field(default_factory=list)

    @field_validator("source_paths")
    @classmethod
    def validate_json_pointers(cls, value: list[str]) -> list[str]:
        if any(not item.startswith("/") for item in value):
            raise ValueError("tool result source paths must be JSON Pointers")
        return value


class ToolResultAnalysis(BaseModel):
    """Traceable fact projection produced by an independent tool-result session.

    The child session never decides causality. ``source_coverage_complete`` is set
    by the host only after every lossless source partition has been processed.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=4000)
    observations: list[ToolResultObservation] = Field(default_factory=list)
    anomalies: list[ToolResultObservation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    analysis_usable: bool
    source_coverage_complete: bool
    source_artifact_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    request_id: str | None = Field(default=None, max_length=512)
    prompt_version: str = Field(min_length=1, max_length=128)
    usage: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_usability(self) -> ToolResultAnalysis:
        if self.analysis_usable and not (self.observations or self.anomalies):
            raise ValueError("a usable tool-result analysis requires facts or anomalies")
        return self


class ValidationKind(StrEnum):
    RULE = "RULE"
    AGENT = "AGENT"


class RunbookKnowledgeType(StrEnum):
    RUNBOOK = "runbook"
    INCIDENT_CASE = "incident_case"
    REFERENCE = "reference"
    INCOMPLETE = "incomplete"


class ExecutionClass(StrEnum):
    READ_ONLY = "read_only"
    CHANGE = "change"


class RootCauseStatus(StrEnum):
    # Retained only so recommendations written before the result-contract
    # migration remain deserializable. New analyses emit SUPPORTED.
    SUPPORT = "SUPPORT"
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


class DatabaseTarget(BaseModel):
    model_config = ConfigDict(extra="allow")

    engine: str | None = None
    instance: str | None = None
    database: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65_535)


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


class RunbookProbe(BaseModel):
    tool_name: str
    objective: str
    read_only: bool = True


class RunbookCause(BaseModel):
    cause_id: str
    hypothesis: str
    section_ids: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    probes: list[RunbookProbe] = Field(default_factory=list)


class RunbookAction(BaseModel):
    action: str
    cause_id: str | None = None
    section_ids: list[str] = Field(default_factory=list)
    execution_class: ExecutionClass = ExecutionClass.READ_ONLY
    expected_result: str | None = None
    approval_required: bool = False

    @model_validator(mode="after")
    def require_approval_for_changes(self) -> RunbookAction:
        if self.execution_class == ExecutionClass.CHANGE and not self.approval_required:
            raise ValueError("change runbook actions must require approval")
        return self


class RunbookSection(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    pages: list[int] = Field(default_factory=list)
    match_terms: list[str] = Field(default_factory=list)
    content: str = ""


class RunbookVisualEvidence(BaseModel):
    page: int = Field(ge=1)
    kind: str = Field(min_length=1, max_length=100)
    text: str = Field(min_length=1, max_length=10_000)
    keywords: list[str] = Field(default_factory=list)
    section_ids: list[str] = Field(default_factory=list)


class RunbookExcerpt(BaseModel):
    runbook_id: str
    title: str
    section: str = "main"
    content: str
    score: float = 0
    match_confidence: float = Field(default=0, ge=0, le=1)
    match_reasons: list[str] = Field(default_factory=list)
    page_refs: list[int] = Field(default_factory=list)
    knowledge_type: RunbookKnowledgeType = RunbookKnowledgeType.RUNBOOK
    causes: list[RunbookCause] = Field(default_factory=list)
    actions: list[RunbookAction] = Field(default_factory=list)
    visual_evidence: list[RunbookVisualEvidence] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExternalKnowledgeExcerpt(BaseModel):
    """Excerpt returned by the configured external knowledge service."""

    knowledge_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1, max_length=20_000)
    source_uri: str = Field(min_length=1, max_length=2048)
    score: float = Field(ge=0, le=1)
    raw_score: float = Field(ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunbookDocument(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    section: str = Field(default="main", min_length=1, max_length=200)
    reasons: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    knowledge_type: RunbookKnowledgeType = RunbookKnowledgeType.RUNBOOK
    deprecated: bool = False
    sections: list[RunbookSection] = Field(default_factory=list)
    causes: list[RunbookCause] = Field(default_factory=list)
    actions: list[RunbookAction] = Field(default_factory=list)
    visual_evidence: list[RunbookVisualEvidence] = Field(default_factory=list)
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


class ExternalKnowledgeReference(BaseModel):
    knowledge_id: str
    title: str
    source_uri: str


class AnalysisBasisSource(StrEnum):
    RUNBOOK = "RUNBOOK"
    EXTERNAL_KNOWLEDGE = "EXTERNAL_KNOWLEDGE"
    AI = "AI"


class AnalysisBasis(BaseModel):
    source: AnalysisBasisSource
    statement: str = Field(min_length=1)
    source_ref: RunbookReference | ExternalKnowledgeReference | None = None

    @model_validator(mode="after")
    def validate_source_reference(self) -> AnalysisBasis:
        if self.source == AnalysisBasisSource.RUNBOOK and not isinstance(
            self.source_ref, RunbookReference
        ):
            raise ValueError("RUNBOOK analysis basis requires a runbook source_ref")
        if self.source == AnalysisBasisSource.EXTERNAL_KNOWLEDGE and not isinstance(
            self.source_ref, ExternalKnowledgeReference
        ):
            raise ValueError("EXTERNAL_KNOWLEDGE analysis basis requires an external source_ref")
        if self.source == AnalysisBasisSource.AI and self.source_ref is not None:
            raise ValueError("AI analysis basis must not contain source_ref")
        return self


class RecommendationStep(BaseModel):
    order: int = Field(ge=1)
    action: str
    expected_result: str | None = None
    caution: str | None = None
    source_ref: RunbookReference | ExternalKnowledgeReference | None = None


class RootCauseAssessment(BaseModel):
    cause: str
    # Retained so recommendations persisted by the former hypothesis harness
    # remain readable. New analyses do not create or bind hypotheses.
    hypothesis_id: str | None = Field(default=None, min_length=1, max_length=200)
    cause_id: str | None = None
    status: RootCauseStatus = RootCauseStatus.UNKNOWN
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0, ge=0, le=1)
    verified: bool = False
    next_probe: str | None = None

    @model_validator(mode="after")
    def validate_verified_status(self) -> RootCauseAssessment:
        if self.verified and self.status == RootCauseStatus.CONTRADICTED:
            raise ValueError("verified root cause must have status=SUPPORTED")
        if self.verified and not self.evidence_refs:
            raise ValueError("verified root cause must reference evidence")
        return self


class Recommendation(BaseModel):
    summary: str
    knowledge_match_summary: str = ""
    likely_causes: list[str] = Field(default_factory=list)
    analysis_bases: list[AnalysisBasis] = Field(default_factory=list)
    steps: list[RecommendationStep]
    risks: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    manual_matched: bool
    runbook_references: list[RunbookReference] = Field(default_factory=list)
    external_knowledge_matches: list[ExternalKnowledgeExcerpt] = Field(default_factory=list)
    root_causes: list[RootCauseAssessment] = Field(default_factory=list)


class ToolExecutionRequest(BaseModel):
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    objective: str = ""
    hypothesis_ids: list[str] = Field(default_factory=list)
    # A bounded multi-step MCP investigation can legitimately outlive the
    # former single-request ceiling. This remains an internal strategy value;
    # API callers cannot supply tool plans directly.
    timeout_seconds: float = Field(default=10, gt=0, le=1200)
    required: bool = False


class ToolExecutionResult(BaseModel):
    """Explicit non-error outcome returned by an investigation tool."""

    status: ToolStatus = ToolStatus.SUCCESS
    summary: str
    structured_data: dict[str, Any] = Field(default_factory=dict)


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
    lease_owner: str | None = None
    fencing_token: int | None = Field(default=None, ge=1)
    # The outer dispatcher scopes durable child checkpoints to one logical tool
    # dispatch. Attempt 2 may only resume that same child run.
    outer_dispatch_id: UUID | None = None
    outer_dispatch_attempt: int | None = Field(default=None, ge=1, le=2)
    # Kept as a JSON-compatible projection so domain tool adapters do not depend
    # on the harness' richer checkpoint model.
    investigation_memory: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_complete_lease_identity(self) -> InvestigationContext:
        if (self.lease_owner is None) != (self.fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        if (self.outer_dispatch_id is None) != (self.outer_dispatch_attempt is None):
            raise ValueError(
                "outer_dispatch_id and outer_dispatch_attempt must be provided together"
            )
        return self


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

    def is_root_cause_support_eligible(self) -> bool:
        """Return whether this usable live record may decide a root cause.

        A legacy truncated record is usable only after a complete-data analysis
        explicitly marks it eligible. Providers can reject any record with
        ``partial=true`` or ``root_cause_eligible=false``.
        """

        return (
            self.status == ToolStatus.SUCCESS
            and self.source_system != "alert_platform"
            and self.structured_data.get("partial") is not True
            and (not self.truncated or self.structured_data.get("root_cause_eligible") is True)
            and self.structured_data.get("root_cause_eligible") is not False
        )


class ProgressRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    sequence: int = Field(default=0, ge=0)
    stage: InvestigationStage
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ConclusionValidationDecision(BaseModel):
    """Strict independent-validator output.

    ``analysis_contract_passed`` answers whether the recommendation is honest,
    traceable, and safe. ``evidence_sufficient`` separately answers whether the
    live evidence is strong enough to complete the RCA conclusively.
    """

    model_config = ConfigDict(extra="forbid")

    analysis_contract_passed: bool
    evidence_sufficient: bool
    issues: list[str] = Field(max_length=50)

    @model_validator(mode="after")
    def validate_decision_consistency(self) -> ConclusionValidationDecision:
        if self.analysis_contract_passed and self.issues:
            raise ValueError("a passed validation decision must not contain blocking issues")
        if not self.analysis_contract_passed and not self.issues:
            raise ValueError("a rejected validation decision must explain at least one issue")
        return self


class ValidationRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    kind: ValidationKind
    # ``passed`` is retained for API/storage compatibility and now means only
    # that the analysis contract is valid. Evidence sufficiency is independent.
    passed: bool
    evidence_sufficient: bool = False
    issues: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class AnalysisConfigSnapshot(BaseModel):
    """Snapshot of configuration used for an analysis run.

    This captures the key runtime settings at the time of analysis,
    allowing comparison across multiple re-analyses of the same alert.
    """

    knowledge_sources: list[str] = Field(default_factory=list)
    external_knowledge_enabled: bool = False
    external_knowledge_base_url: str = ""
    runbook_limit: int = 5
    runbook_match_min_score: float = 12
    runbook_match_min_confidence: float = 0.35
    external_knowledge_min_relevance: float = 0.60
    react_enabled: bool = False
    react_max_dynamic_turns: int = 0
    validation_enabled: bool = True
    ai_fallback_enabled: bool = True
    ai_model: str = ""
    ai_provider: str = "openai_compatible"
    ai_timeout_seconds: float = 300
    ai_max_retries: int = 2
    ai_max_tokens: int = 16_384
    prompt_version: str = ""
    code_version: str = ""
    archery_mcp_max_agent_steps: int = 0
    prometheus_mcp_max_agent_steps: int = 0
    tool_schema_versions: dict[str, str] = Field(default_factory=dict)
    tool_policy_versions: dict[str, str] = Field(default_factory=dict)


class InvestigationRun(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    attempt: int = Field(default=1, ge=1)
    fencing_token: int = Field(default=1, ge=1)
    status: RunStatus = RunStatus.RUNNING
    current_stage: InvestigationStage = InvestigationStage.RECEIVED
    strategy_id: str | None = None
    error: str | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    config_snapshot: AnalysisConfigSnapshot | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class InvestigationEvidenceAssessment(BaseModel):
    """Model-proposed semantic relation, enforced later by the evidence policy."""

    hypothesis_id: str = Field(min_length=1, max_length=200)
    evidence_id: str = Field(min_length=1, max_length=200)
    relation: Literal["SUPPORTS", "CONTRADICTS", "INCONCLUSIVE"]
    rationale: str = Field(default="", max_length=2_000)


class InvestigationDecision(BaseModel):
    action: Literal["tool", "finish"]
    tool_name: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    objective: str = ""
    hypothesis_ids: list[str] = Field(default_factory=list)
    evidence_assessments: list[InvestigationEvidenceAssessment] = Field(
        default_factory=list,
        max_length=200,
    )
    reason: str = ""

    @model_validator(mode="after")
    def validate_tool_decision(self) -> InvestigationDecision:
        if self.action == "tool" and not self.tool_name:
            raise ValueError("tool action requires tool_name")
        if self.action == "finish" and (self.tool_name or self.parameters):
            raise ValueError("finish action cannot contain a tool call")
        assessment_keys = [
            (item.hypothesis_id, item.evidence_id) for item in self.evidence_assessments
        ]
        if len(assessment_keys) != len(set(assessment_keys)):
            raise ValueError("evidence may be assessed only once per hypothesis")
        return self


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
    run_id: UUID | None = None


class StoredAlert(BaseModel):
    alert: NormalizedAlert
    status: AlertStatus
    recommendation: Recommendation | None = None
    manual_matches: list[RunbookExcerpt] = Field(default_factory=list)
    advisor_metadata: AdvisorMetadata | None = None
    error: str | None = None
    latest_run: InvestigationRun | None = None
    selected_run: InvestigationRun | None = None
    selected_run_result_available: bool = False
    all_runs: list[InvestigationRun] = Field(default_factory=list)
    progress: list[ProgressRecord] = Field(default_factory=list)
    evidence_records: list[EvidenceRecord] = Field(default_factory=list)
    validations: list[ValidationRecord] = Field(default_factory=list)
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
