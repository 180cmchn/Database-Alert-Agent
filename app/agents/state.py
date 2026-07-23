"""LangGraph Agent State definition for alert investigation."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    EvidenceRecord,
    InvestigationRun,
    InvestigationStage,
    KnowledgeCase,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookExcerpt,
    RunStatus,
    StoredAlert,
    ToolExecutionRequest,
    ToolStatus,
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
    
    # Alert identification
    alert_id: str = ""
    
    # Core data
    alert: NormalizedAlert | None = None
    stored_alert: StoredAlert | None = None
    run: InvestigationRun | None = None
    
    # Investigation data
    runbooks: Annotated[list[RunbookExcerpt], merge_runbooks] = Field(default_factory=list)
    knowledge_cases: list[KnowledgeCase] = Field(default_factory=list)
    evidence: Annotated[list[EvidenceRecord], merge_evidence] = Field(default_factory=list)
    
    # Tool execution for dynamic investigation
    pending_tool_requests: list[ToolExecutionRequest] = Field(default_factory=list)
    tool_execution_results: list[tuple[str, ToolStatus, dict[str, Any]]] = Field(default_factory=list)
    
    # Results
    recommendation: Recommendation | None = None
    advisor_metadata: AdvisorMetadata | None = None
    rule_validation: ValidationRecord | None = None
    agent_validation: ValidationRecord | None = None
    
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
    should_continue_investigation: bool = False
    dynamic_turns_remaining: int = 0
    max_dynamic_turns: int = 0
    
    # Validation flags
    validation_passed: bool = False
    unapproved_runbook: bool = False
    
    # Configuration
    validation_enabled: bool = True
    shadow_enabled: bool = False
    ai_fallback_enabled: bool = True

    class Config:
        arbitrary_types_allowed = True


def create_initial_state(
    alert_id: str,
    alert: NormalizedAlert,
    stored_alert: StoredAlert,
    run: InvestigationRun,
    *,
    max_dynamic_turns: int = 0,
    validation_enabled: bool = True,
    shadow_enabled: bool = False,
    ai_fallback_enabled: bool = True,
) -> AgentState:
    """Create the initial state for a new investigation.
    
    Args:
        alert_id: The alert ID to investigate
        alert: The normalized alert
        stored_alert: The stored alert from repository
        run: The investigation run
        max_dynamic_turns: Maximum dynamic tool selection turns
        validation_enabled: Whether to enable validation
        shadow_enabled: Whether shadow mode is enabled
        ai_fallback_enabled: Whether AI fallback is enabled
        
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
        max_dynamic_turns=max_dynamic_turns,
        dynamic_turns_remaining=max_dynamic_turns,
        validation_enabled=validation_enabled,
        shadow_enabled=shadow_enabled,
        ai_fallback_enabled=ai_fallback_enabled,
    )