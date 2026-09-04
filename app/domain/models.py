from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

INCONCLUSIVE_ROOT_CAUSE_SUMMARY = "现有结果无法得出根因"


def utc_now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"

    def is_higher_than(self, other: Severity) -> bool:
        if self is Severity.INFO:
            return False
        if self is Severity.WARNING:
            return other is Severity.INFO
        return other is not Severity.CRITICAL


class AlertStatus(StrEnum):
    RECEIVED = "RECEIVED"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    FILTERED = "FILTERED"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

AUTO_ANALYSIS_SCHEDULABLE_STATUSES = frozenset(
    {
        AlertStatus.RECEIVED,
        AlertStatus.QUEUED,
        AlertStatus.FAILED,
    }
)


class InvestigationStage(StrEnum):
    RECEIVED = "RECEIVED"
    FINGERPRINTING = "FINGERPRINTING"
    KNOWLEDGE_MATCHING = "KNOWLEDGE_MATCHING"
    INVESTIGATING = "INVESTIGATING"
    ADVISING = "ADVISING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ToolStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NO_DATA = "NO_DATA"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


EVIDENCE_RECORD_V1 = "evidence-record/v1"
EVIDENCE_RECORD_V2 = "evidence-record/v2"
EVIDENCE_UNIT_V2 = "evidence-unit/v2"


class EvidenceUnitKind(StrEnum):
    HISTORY = "HISTORY"
    SUPPLEMENTAL = "SUPPLEMENTAL"


class EvidenceUnitStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NO_DATA = "NO_DATA"
    RECOVERED = "RECOVERED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceUnit(BaseModel):
    """One independently qualified fact unit backed by a parent raw artifact."""

    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["evidence-unit/v2"] = EVIDENCE_UNIT_V2
    id: UUID
    parent_evidence_id: UUID
    unit_key: str = Field(min_length=1, max_length=256)
    kind: EvidenceUnitKind
    stage: str = Field(min_length=1, max_length=128)
    result_index: int | None = Field(default=None, ge=0)
    status: EvidenceUnitStatus
    summary: str = Field(min_length=1, max_length=4000)
    data: dict[str, Any] = Field(default_factory=dict)
    root_cause_eligible: bool = False
    root_cause_ineligible_reason: str | None = Field(default=None, max_length=256)
    source_artifact_id: UUID
    source_paths: list[str] = Field(min_length=1, max_length=50)

    @classmethod
    def build_id(cls, parent_evidence_id: UUID, unit_key: str) -> UUID:
        return uuid5(parent_evidence_id, f"{EVIDENCE_UNIT_V2}:{unit_key}")

    @field_validator("source_paths")
    @classmethod
    def validate_source_paths(cls, value: list[str]) -> list[str]:
        if any(not item.startswith("/") for item in value):
            raise ValueError("evidence unit source paths must be JSON Pointers")
        return value

    @model_validator(mode="after")
    def validate_identity_and_eligibility(self) -> EvidenceUnit:
        if self.id != self.build_id(self.parent_evidence_id, self.unit_key):
            raise ValueError("evidence unit id must be the stable UUID5 for its unit key")
        if self.root_cause_eligible and self.status != EvidenceUnitStatus.SUCCESS:
            raise ValueError("only a SUCCESS evidence unit may be root-cause eligible")
        if self.root_cause_eligible and self.root_cause_ineligible_reason is not None:
            raise ValueError("eligible evidence unit cannot have an ineligibility reason")
        if not self.root_cause_eligible and not self.root_cause_ineligible_reason:
            raise ValueError("ineligible evidence unit requires an ineligibility reason")
        return self

    def is_root_cause_support_eligible(self) -> bool:
        return self.status == EvidenceUnitStatus.SUCCESS and self.root_cause_eligible


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
    """Traceable fact projection produced by deterministic program processing.

    The projection never decides causality. ``source_coverage_complete`` records
    that the processor inspected the complete audited response before selecting
    bounded observations for the main Agent.
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
    # Format-conversion passthrough for providers (currently Archery) whose final
    # result must reach the main Agent unchanged. The program only converts the
    # text JSON into a JSON object and never judges causality.
    passthrough_payload: dict[str, Any] | None = Field(default=None)
    passthrough_parse_failed: bool = False
    # Archery's deterministic EXPLAIN/schema/index facts are supplemental and
    # never modify the unchanged final history passthrough above.
    slow_query_analysis: dict[str, Any] | None = Field(default=None)

    @model_validator(mode="after")
    def validate_usability(self) -> ToolResultAnalysis:
        if self.analysis_usable and not (self.observations or self.anomalies):
            raise ValueError("a usable tool-result analysis requires facts or anomalies")
        return self


class ValidationKind(StrEnum):
    RULE = "RULE"
    # Retained so historical runs with the removed model-based validator remain readable.
    AGENT = "AGENT"


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


class KnowledgeExcerpt(BaseModel):
    """A bounded match returned by any registered advisory knowledge source."""

    source: str = Field(min_length=1, max_length=128)
    knowledge_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1, max_length=20_000)
    source_uri: str = Field(min_length=1, max_length=2048)
    score: float = Field(ge=0, le=1)
    raw_score: float = Field(ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeReference(BaseModel):
    source: str = Field(min_length=1, max_length=128)
    knowledge_id: str
    title: str
    source_uri: str


class AnalysisBasisSource(StrEnum):
    KNOWLEDGE = "KNOWLEDGE"
    AI = "AI"


class AnalysisBasis(BaseModel):
    source: AnalysisBasisSource
    statement: str = Field(min_length=1)
    source_ref: KnowledgeReference | None = None


class RecommendationStep(BaseModel):
    order: int = Field(ge=1)
    action: str
    expected_result: str | None = None
    caution: str | None = None
    source_ref: KnowledgeReference | None = None


class RootCauseAnalysisStep(BaseModel):
    observation: str = Field(min_length=1, max_length=4_000)
    inference: str = Field(min_length=1, max_length=4_000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class RootCauseSqlEvidence(BaseModel):
    statement: str | None = Field(default=None, min_length=1, max_length=4_000)
    structure: str | None = Field(default=None, min_length=1, max_length=4_000)
    sample_id: str | None = Field(default=None, min_length=1, max_length=256)
    evidence_ref: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_representation(self) -> RootCauseSqlEvidence:
        if not any((self.statement, self.structure, self.sample_id)):
            raise ValueError("problem SQL requires a statement, structure, or sample id")
        return self


class RootCauseExplainEvidence(BaseModel):
    result: str = Field(min_length=1, max_length=8_000)
    interpretation: str = Field(min_length=1, max_length=4_000)
    evidence_ref: str = Field(min_length=1, max_length=256)


class RootCauseAssessment(BaseModel):
    cause: str
    analysis_process: list[RootCauseAnalysisStep] = Field(default_factory=list, max_length=20)
    problem_sql: RootCauseSqlEvidence | None = None
    explain_result: RootCauseExplainEvidence | None = None
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
    knowledge_matches: list[KnowledgeExcerpt] = Field(default_factory=list)
    root_causes: list[RootCauseAssessment] = Field(default_factory=list)


class ToolExecutionRequest(BaseModel):
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    objective: str = ""
    hypothesis_ids: list[str] = Field(default_factory=list)
    # A multi-step MCP investigation can legitimately outlive the former
    # single-request ceiling. API callers cannot supply Agent tool calls directly.
    timeout_seconds: float = Field(default=10, gt=0, le=1200)
    required: bool = False


class ToolExecutionResult(BaseModel):
    """Explicit non-error outcome returned by an investigation tool."""

    status: ToolStatus = ToolStatus.SUCCESS
    summary: str
    structured_data: dict[str, Any] = Field(default_factory=dict)


class InvestigationContext(BaseModel):
    run_id: UUID
    alert: NormalizedAlert
    lease_owner: str | None = None
    fencing_token: int | None = Field(default=None, ge=1)
    # The outer dispatcher scopes embedded MCP checkpoints to one logical tool
    # dispatch so recovery cannot attach state from another explicit Agent action.
    outer_dispatch_id: UUID | None = None

    @model_validator(mode="after")
    def require_complete_lease_identity(self) -> InvestigationContext:
        if (self.lease_owner is None) != (self.fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        return self


class EvidenceRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    contract_version: Literal["evidence-record/v1", "evidence-record/v2"] = EVIDENCE_RECORD_V1
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
    source_artifact_id: UUID | None = None
    evidence_units: list[EvidenceUnit] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_evidence_units(self) -> EvidenceRecord:
        if self.contract_version == EVIDENCE_RECORD_V1 and self.evidence_units:
            raise ValueError("v1 evidence records cannot contain v2 evidence units")
        if self.contract_version == EVIDENCE_RECORD_V2 and not self.evidence_units:
            raise ValueError("v2 evidence records require at least one evidence unit")
        if self.contract_version == EVIDENCE_RECORD_V2 and self.source_artifact_id is None:
            raise ValueError("v2 evidence records require a source artifact id")
        unit_ids = [item.id for item in self.evidence_units]
        unit_keys = [item.unit_key for item in self.evidence_units]
        if len(unit_ids) != len(set(unit_ids)) or len(unit_keys) != len(set(unit_keys)):
            raise ValueError("evidence unit identities must be unique within the parent")
        if any(item.parent_evidence_id != self.id for item in self.evidence_units):
            raise ValueError("evidence unit parent id must match its evidence record")
        if any(item.source_artifact_id != self.source_artifact_id for item in self.evidence_units):
            raise ValueError("evidence unit source artifact must match its parent record")
        if any(item.root_cause_eligible for item in self.evidence_units) and (
            self.status != ToolStatus.SUCCESS
            or self.source_system.casefold() == "alert_platform"
            or self.is_context_only()
        ):
            raise ValueError(
                "eligible evidence units require a successful non-context parent record"
            )
        return self

    def is_root_cause_support_eligible(self) -> bool:
        """Return whether this usable live record may decide a root cause.

        A legacy truncated record is usable only after a complete-data analysis
        explicitly marks it eligible. Providers can reject any record with
        ``partial=true`` or ``root_cause_eligible=false``.
        """

        if self.contract_version == EVIDENCE_RECORD_V2:
            return False
        return (
            self.status == ToolStatus.SUCCESS
            and self.source_system.casefold() != "alert_platform"
            and not self.is_context_only()
            and self.structured_data.get("partial") is not True
            and (not self.truncated or self.structured_data.get("root_cause_eligible") is True)
            and self.structured_data.get("root_cause_eligible") is not False
        )

    def is_context_only(self) -> bool:
        normalized_source = self.source_system.casefold()
        return normalized_source == "flashduty_similar" or (
            normalized_source
            in {
                "alert_platform",
                "flashduty",
                "flashduty_api",
                "flashduty_alert",
                "flashduty_alert_detail",
                "flashduty_monitors",
            }
            and self.tool_name.casefold()
            in {
                "query_similar_incidents",
                "flashduty_similar",
            }
        )

    def is_evidence_unit_root_cause_support_eligible(
        self,
        unit: EvidenceUnit,
    ) -> bool:
        """Qualify a v2 child together with its parent execution provenance."""

        return (
            self.contract_version == EVIDENCE_RECORD_V2
            and self.status == ToolStatus.SUCCESS
            and self.source_system.casefold() != "alert_platform"
            and not self.is_context_only()
            and unit.parent_evidence_id == self.id
            and self.source_artifact_id is not None
            and unit.source_artifact_id == self.source_artifact_id
            and any(item.id == unit.id for item in self.evidence_units)
            and unit.is_root_cause_support_eligible()
        )


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
    external_knowledge_min_relevance: float = 0.60
    react_max_rounds: int = Field(default=8, ge=1, le=100)
    analysis_timeout_seconds: int = Field(default=1800, ge=30, le=86_400)
    prometheus_mcp_timeout_seconds: float = 60
    prometheus_investigation_budget_seconds: float = 180
    prometheus_mcp_tool_timeout_seconds: float = 780
    # Retained in run snapshots so historical independent-validator settings deserialize.
    validation_enabled: bool = True
    ai_fallback_enabled: bool = True
    ai_model: str = ""
    ai_provider: str = "openai_compatible"
    # Role-specific model usage recorded per run for audit and re-analysis
    # comparison. Empty effort values mean "provider default" (parameter not sent).
    ai_react_model: str = ""
    ai_mcp_model: str = ""
    ai_react_reasoning_effort: str = ""
    ai_reasoning_effort: str = ""
    ai_mcp_reasoning_effort: str = ""
    # Whether the main Agent persisted one durable event per reasoning
    # delta at run time. Recorded per run so historical behavior stays
    # interpretable after the flag changes.
    stream_main_agent_reasoning: bool = True
    ai_timeout_seconds: float = 300
    # Historical compatibility only. New analyses always store zero because
    # provider retries are bounded by analysis timeout/cancellation, not a count.
    ai_max_retries: int = 0
    ai_max_tokens: int = 16_384
    prompt_version: str = ""
    code_version: str = ""
    tool_schema_versions: dict[str, str] = Field(default_factory=dict)
    tool_policy_versions: dict[str, str] = Field(default_factory=dict)


class InvestigationRun(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    attempt: int = Field(default=1, ge=1)
    fencing_token: int = Field(default=1, ge=1)
    status: RunStatus = RunStatus.RUNNING
    current_stage: InvestigationStage = InvestigationStage.RECEIVED
    error: str | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    cancel_requested_by: str | None = None
    cancelled_at: datetime | None = None
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
    reasoning_content: str | None = None


class InvestigationDecisionResult(BaseModel):
    """One main-Agent ReAct decision and the provider's actual reasoning field."""

    decision: InvestigationDecision
    metadata: AdvisorMetadata


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
