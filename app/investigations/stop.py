"""Deterministic stop conditions for an alert investigation."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.domain.models import RootCauseStatus
from app.investigations.models import InvestigationMemory, is_qualified_live_evidence


class StopReason(StrEnum):
    CONTINUE = "CONTINUE"
    SUPPORTED_CAUSE = "SUPPORTED_CAUSE"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
    WINDOW_AMBIGUOUS = "WINDOW_AMBIGUOUS"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    NO_SAFE_PROBE = "NO_SAFE_PROBE"


class StopDecision(BaseModel):
    """Auditable result of evaluating harness-owned stop conditions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    should_stop: bool
    reason: StopReason
    requires_human: bool
    rationale: str = Field(min_length=1, max_length=2_000)
    supported_hypothesis_ids: list[str] = Field(default_factory=list)
    model_finish_requested: bool = False


class StopEvaluator:
    """Evaluate completion independently from a model's finish suggestion."""

    def evaluate(
        self,
        memory: InvestigationMemory,
        *,
        budget_exhausted: bool = False,
        deadline_exceeded: bool = False,
    ) -> StopDecision:
        model_finish_requested = memory.model_finish_requested

        if memory.target_ambiguous:
            return self._stop_for_human(
                StopReason.TARGET_AMBIGUOUS,
                "The affected database target is ambiguous.",
                model_finish_requested,
            )
        if memory.window_ambiguous:
            return self._stop_for_human(
                StopReason.WINDOW_AMBIGUOUS,
                "The alert investigation window is ambiguous.",
                model_finish_requested,
            )
        if memory.requires_human:
            return self._stop_for_human(
                StopReason.HUMAN_REQUIRED,
                memory.human_reason or "The investigation explicitly requires human review.",
                model_finish_requested,
            )

        supported_ids = self._supported_without_decisive_conflict(memory)
        unresolved_ids = [
            hypothesis.hypothesis_id
            for hypothesis in memory.hypotheses
            if hypothesis.status == RootCauseStatus.UNKNOWN
        ]
        if supported_ids and not unresolved_ids:
            return StopDecision(
                should_stop=True,
                reason=StopReason.SUPPORTED_CAUSE,
                requires_human=False,
                rationale=(
                    "At least one hypothesis has qualified live support and every "
                    "remaining hypothesis is decisive."
                ),
                supported_hypothesis_ids=supported_ids,
                model_finish_requested=model_finish_requested,
            )

        if deadline_exceeded:
            return self._stop_for_human(
                StopReason.DEADLINE_EXCEEDED,
                "The investigation deadline was reached before a cause was supported.",
                model_finish_requested,
            )
        if budget_exhausted:
            return self._stop_for_human(
                StopReason.BUDGET_EXHAUSTED,
                "The investigation budget was exhausted before a cause was supported.",
                model_finish_requested,
            )
        if not memory.safe_unattempted_probes():
            return self._stop_for_human(
                StopReason.NO_SAFE_PROBE,
                (
                    "No unattempted safe and available read-only probe can reduce the "
                    "remaining uncertainty."
                ),
                model_finish_requested,
            )

        rationale = "A safe probe remains available; continue the investigation."
        if model_finish_requested:
            rationale = "The model suggested finish, but a safe discriminating probe remains."
        return StopDecision(
            should_stop=False,
            reason=StopReason.CONTINUE,
            requires_human=False,
            rationale=rationale,
            model_finish_requested=model_finish_requested,
        )

    @staticmethod
    def _supported_without_decisive_conflict(memory: InvestigationMemory) -> list[str]:
        evidence = memory.evidence_by_id()
        supported: list[str] = []
        for hypothesis in sorted(
            memory.hypotheses,
            key=lambda item: (-item.priority, item.hypothesis_id),
        ):
            if not hypothesis.causal_candidate or hypothesis.status != RootCauseStatus.SUPPORTED:
                continue
            has_qualified_support = any(
                evidence_id in evidence and is_qualified_live_evidence(evidence[evidence_id])
                for evidence_id in hypothesis.supporting_evidence_ids
            )
            has_decisive_conflict = any(
                evidence_id in evidence and is_qualified_live_evidence(evidence[evidence_id])
                for evidence_id in hypothesis.contradicting_evidence_ids
            )
            if has_qualified_support and not has_decisive_conflict:
                supported.append(hypothesis.hypothesis_id)
        return supported

    @staticmethod
    def _stop_for_human(
        reason: StopReason,
        rationale: str,
        model_finish_requested: bool,
    ) -> StopDecision:
        return StopDecision(
            should_stop=True,
            reason=reason,
            requires_human=True,
            rationale=rationale,
            model_finish_requested=model_finish_requested,
        )
