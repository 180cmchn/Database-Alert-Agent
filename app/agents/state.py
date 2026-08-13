"""LangGraph Agent State definition for alert investigation."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    EvidenceRecord,
    ExternalKnowledgeExcerpt,
    InvestigationDecision,
    InvestigationRun,
    InvestigationStage,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookExcerpt,
    RunStatus,
    StoredAlert,
    ToolExecutionRequest,
    ValidationRecord,
)


def merge_evidence(left: list[EvidenceRecord], right: list[EvidenceRecord]) -> list[EvidenceRecord]:
    """Merge evidence lists, appending new evidence to existing."""
    return left + right


def merge_progress(left: list[ProgressRecord], right: list[ProgressRecord]) -> list[ProgressRecord]:
    """Merge progress records, appending new records to existing."""
    return left + right


def merge_runbooks(left: list[RunbookExcerpt], right: list[RunbookExcerpt]) -> list[RunbookExcerpt]:
    """Merge runbook lists, replacing with new list if provided."""
    return right if right else left


class AgentState(BaseModel):
    """State for the alert investigation LangGraph agent.

    This state flows through all nodes in the investigation graph and accumulates
    evidence, progress, and results along the way.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Alert identification
    alert_id: str = ""

    # Core data
    alert: NormalizedAlert | None = None
    stored_alert: StoredAlert | None = None
    run: InvestigationRun | None = None

    # Investigation data
    runbooks: Annotated[list[RunbookExcerpt], merge_runbooks] = Field(default_factory=list)
    external_knowledge: list[ExternalKnowledgeExcerpt] = Field(default_factory=list)
    knowledge_match_summary: str = ""
    evidence: Annotated[list[EvidenceRecord], merge_evidence] = Field(default_factory=list)

    # Tool execution for dynamic investigation
    pending_tool_requests: list[ToolExecutionRequest] = Field(default_factory=list)
    react_decision: InvestigationDecision | None = None

    # Results
    recommendation: Recommendation | None = None
    advisor_metadata: AdvisorMetadata | None = None
    rule_validation: ValidationRecord | None = None

    # Progress tracking
    progress: Annotated[list[ProgressRecord], merge_progress] = Field(default_factory=list)
    current_stage: InvestigationStage = InvestigationStage.RECEIVED

    # Status
    status: AlertStatus = AlertStatus.QUEUED
    run_status: RunStatus = RunStatus.RUNNING

    # Error handling
    error: str | None = None
    advisor_degraded: bool = False
    primary_advisor_error: str | None = None

    # Control flow
    react_round: int = 0
    react_max_rounds: int = 8
    react_finished: bool = False

    # Validation flags
    validation_passed: bool = False
    evidence_sufficient: bool = False

    # Configuration
    ai_fallback_enabled: bool = True
    knowledge_sources: list[str] = Field(default_factory=lambda: ["local_pdf"])


def create_initial_state(
    alert_id: str,
    alert: NormalizedAlert,
    stored_alert: StoredAlert,
    run: InvestigationRun,
    *,
    react_max_rounds: int = 8,
    ai_fallback_enabled: bool = True,
    knowledge_sources: list[str] | None = None,
) -> AgentState:
    """Create the initial state for a new investigation.

    Args:
        alert_id: The alert ID to investigate
        alert: The normalized alert
        stored_alert: The stored alert from repository
        run: The investigation run
        react_max_rounds: Maximum main-Agent ReAct rounds
        ai_fallback_enabled: Whether AI fallback is enabled
        knowledge_sources: Which knowledge sources to use for matching

    Returns:
        Initial AgentState for the investigation
    """
    return AgentState(
        alert_id=alert_id,
        alert=alert,
        stored_alert=stored_alert,
        run=run,
        current_stage=InvestigationStage.RECEIVED,
        status=AlertStatus.QUEUED,
        run_status=RunStatus.RUNNING,
        react_max_rounds=react_max_rounds,
        ai_fallback_enabled=ai_fallback_enabled,
        knowledge_sources=(
            knowledge_sources if knowledge_sources is not None else ["local_pdf"]
        ),
    )
