"""Explicit, replayable memory for evidence-driven investigations.

The functions in this module deliberately do not perform semantic inference. A
planner or evaluator may describe how one evidence record relates to a
hypothesis, while these functions enforce whether that record is eligible to
change the hypothesis' tri-state assessment.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.models import EvidenceRecord, RootCauseStatus, ToolStatus

_TERMINAL_MISSING_TOOL_STATUSES = frozenset(
    {
        ToolStatus.FAILED,
        ToolStatus.NO_DATA,
        ToolStatus.SKIPPED,
        ToolStatus.TIMEOUT,
    }
)


class EvidenceRelation(StrEnum):
    """A semantic assessment of one record against one hypothesis."""

    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceNeed(BaseModel):
    """The smallest known probe that can discriminate a hypothesis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    need_id: str = Field(min_length=1, max_length=200)
    objective: str = Field(min_length=1, max_length=2_000)
    expected_observation: str = Field(min_length=1, max_length=2_000)
    contradicting_observation: str = Field(min_length=1, max_length=2_000)
    tool_name: str | None = Field(default=None, max_length=200)
    parameters: dict[str, object] = Field(default_factory=dict)
    read_only: bool = True
    safety_approved: bool = True
    available: bool = True
    unavailable_reason: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def require_unavailable_reason(self) -> EvidenceNeed:
        if not self.available and not self.unavailable_reason:
            raise ValueError("an unavailable evidence need must explain why it is unavailable")
        return self

    def is_safe_and_available(self) -> bool:
        """Return whether the harness may schedule this probe without approval."""

        return self.available and self.read_only and self.safety_approved


class Hypothesis(BaseModel):
    """A falsifiable causal mechanism and its current evidence assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str = Field(min_length=1, max_length=200)
    mechanism: str = Field(min_length=1, max_length=4_000)
    # Defaults to true so checkpoints created before this flag remain readable.
    # A false value marks a planning placeholder, not a falsifiable cause.
    causal_candidate: bool = True
    expected_observations: list[str] = Field(min_length=1, max_length=20)
    contradicting_observations: list[str] = Field(min_length=1, max_length=20)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    next_probe: EvidenceNeed | None = None
    # Higher values are investigated first. The harness, not the model, owns
    # ordering when priorities are equal.
    priority: int = Field(default=0, ge=0, le=100)
    status: RootCauseStatus = RootCauseStatus.UNKNOWN

    @model_validator(mode="before")
    @classmethod
    def protect_reserved_placeholder(cls, values: object) -> object:
        """Keep legacy checkpoints for the reserved placeholder fail-closed."""

        if isinstance(values, dict) and values.get("hypothesis_id") == "unresolved-cause":
            values = {
                **values,
                "causal_candidate": False,
                "supporting_evidence_ids": [],
                "contradicting_evidence_ids": [],
                "status": RootCauseStatus.UNKNOWN,
                "next_probe": values.get("next_probe")
                or {
                    "need_id": "unresolved-cause:legacy-review",
                    "objective": "由人工建立可证伪的候选机制并选择只读探针。",
                    "expected_observation": "实时观测支持明确的候选机制。",
                    "contradicting_observation": "实时观测反驳明确的候选机制。",
                    "available": False,
                    "unavailable_reason": "旧检查点仅包含非因果占位假设。",
                },
            }
        return values

    @model_validator(mode="after")
    def validate_assessment(self) -> Hypothesis:
        support_ids = self.supporting_evidence_ids
        contradiction_ids = self.contradicting_evidence_ids
        if len(support_ids) != len(set(support_ids)):
            raise ValueError("supporting evidence IDs must be unique")
        if len(contradiction_ids) != len(set(contradiction_ids)):
            raise ValueError("contradicting evidence IDs must be unique")
        if set(support_ids) & set(contradiction_ids):
            raise ValueError("one evidence record cannot both support and contradict a hypothesis")
        if not self.causal_candidate and (
            support_ids or contradiction_ids or self.status != RootCauseStatus.UNKNOWN
        ):
            raise ValueError(
                "a non-causal placeholder hypothesis must remain UNKNOWN without causal evidence"
            )
        if self.status == RootCauseStatus.SUPPORTED and not support_ids:
            raise ValueError("SUPPORTED hypothesis must reference supporting evidence")
        if self.status == RootCauseStatus.CONTRADICTED and not contradiction_ids:
            raise ValueError("CONTRADICTED hypothesis must reference contradicting evidence")
        if self.status == RootCauseStatus.UNKNOWN and self.next_probe is None:
            raise ValueError("UNKNOWN hypothesis must define a concrete next_probe")
        return self


class EvidenceAssessment(BaseModel):
    """Planner/evaluator interpretation retained separately from raw evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str = Field(min_length=1, max_length=200)
    evidence_id: str = Field(min_length=1, max_length=200)
    relation: EvidenceRelation
    rationale: str = Field(default="", max_length=2_000)


class InvestigationMemory(BaseModel):
    """Checkpointable investigation state independent from model messages."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=100)
    evidence_records: list[EvidenceRecord] = Field(default_factory=list, max_length=1_000)
    assessments: list[EvidenceAssessment] = Field(default_factory=list, max_length=2_000)
    model_finish_requested: bool = False
    target_ambiguous: bool = False
    window_ambiguous: bool = False
    requires_human: bool = False
    human_reason: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def validate_memory_references(self) -> InvestigationMemory:
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("hypothesis IDs must be unique")

        evidence_ids = [str(item.id) for item in self.evidence_records]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence record IDs must be unique")

        assessment_keys: set[tuple[str, str]] = set()
        for assessment in self.assessments:
            if assessment.hypothesis_id not in hypothesis_ids:
                raise ValueError("assessment references an unknown hypothesis")
            if assessment.evidence_id not in evidence_ids:
                raise ValueError("assessment references an unknown evidence record")
            key = (assessment.hypothesis_id, assessment.evidence_id)
            if key in assessment_keys:
                raise ValueError("evidence may be assessed only once per hypothesis")
            assessment_keys.add(key)

        if self.requires_human and not self.human_reason:
            raise ValueError("requires_human memory must explain why human review is needed")
        return self

    def evidence_by_id(self) -> dict[str, EvidenceRecord]:
        """Build a lookup without maintaining a second source of truth."""

        return {str(item.id): item for item in self.evidence_records}

    def safe_available_probes(self) -> list[EvidenceNeed]:
        """Return schedulable probes for hypotheses that remain unresolved."""

        return [
            hypothesis.next_probe
            for hypothesis in sorted(
                self.hypotheses,
                key=lambda item: (-item.priority, item.hypothesis_id),
            )
            if hypothesis.status == RootCauseStatus.UNKNOWN
            and hypothesis.next_probe is not None
            and hypothesis.next_probe.is_safe_and_available()
        ]

    def safe_unattempted_probes(self) -> list[EvidenceNeed]:
        """Return safe probes without a terminal attempt in this run.

        Missing outcomes close only the scheduling attempt. They remain
        ineligible to support or contradict a hypothesis.
        """

        terminal_attempts = [
            evidence for evidence in self.evidence_records if is_terminal_probe_attempt(evidence)
        ]
        return [
            probe
            for probe in self.safe_available_probes()
            if not any(
                evidence.tool_name == probe.tool_name and evidence.request == probe.parameters
                for evidence in terminal_attempts
            )
        ]


def is_terminal_probe_attempt(evidence: EvidenceRecord) -> bool:
    """Return whether outer ReAct must not repeat this request in one run."""

    return (
        evidence.status in _TERMINAL_MISSING_TOOL_STATUSES
        or evidence.status == ToolStatus.SUCCESS
        and (
            evidence.structured_data.get("partial") is not True
            or evidence.structured_data.get("allow_followup_dispatch") is False
        )
    )


def is_qualified_live_evidence(evidence: EvidenceRecord) -> bool:
    """Return whether a complete record may establish causal truth.

    Partial success is missing causal evidence even when a provider sets
    ``root_cause_eligible=true`` or disables another outer dispatch.
    """

    return evidence.is_root_cause_support_eligible()


def _effective_assessment(
    evidence: EvidenceRecord,
    assessment: EvidenceAssessment,
    hypothesis: Hypothesis | None = None,
) -> EvidenceAssessment:
    """Apply the Host's evidence gate to a model-proposed relation."""

    if assessment.relation == EvidenceRelation.INCONCLUSIVE:
        return assessment

    if hypothesis is not None and not hypothesis.causal_candidate:
        rationale = (
            "Host classified the target hypothesis as a non-causal planning "
            f"placeholder and overrode the proposed {assessment.relation.value} "
            f"relation to INCONCLUSIVE. {assessment.rationale}"
        )[:2_000]
        return assessment.model_copy(
            update={
                "relation": EvidenceRelation.INCONCLUSIVE,
                "rationale": rationale,
            }
        )

    if is_qualified_live_evidence(evidence):
        return assessment

    rationale = (
        "Host classified the record as missing causal evidence and overrode "
        f"the proposed {assessment.relation.value} relation to INCONCLUSIVE. "
        f"{assessment.rationale}"
    )[:2_000]
    return assessment.model_copy(
        update={
            "relation": EvidenceRelation.INCONCLUSIVE,
            "rationale": rationale,
        }
    )


def apply_evidence(
    hypothesis: Hypothesis,
    evidence: EvidenceRecord,
    assessment: EvidenceAssessment,
) -> Hypothesis:
    """Return a hypothesis updated by one eligible live evidence record.

    Failed, skipped, timed-out, empty, stale, alert-platform, or otherwise
    ineligible records are missing evidence. They never support or contradict a
    causal mechanism, irrespective of the supplied semantic relation.
    """

    if assessment.hypothesis_id != hypothesis.hypothesis_id:
        raise ValueError("assessment does not target this hypothesis")
    evidence_id = str(evidence.id)
    if assessment.evidence_id != evidence_id:
        raise ValueError("assessment evidence ID does not match the evidence record")
    if not hypothesis.causal_candidate:
        return hypothesis
    if assessment.relation == EvidenceRelation.INCONCLUSIVE:
        return hypothesis
    if not is_qualified_live_evidence(evidence):
        return hypothesis

    support_ids = list(hypothesis.supporting_evidence_ids)
    contradiction_ids = list(hypothesis.contradicting_evidence_ids)
    if assessment.relation == EvidenceRelation.SUPPORTS:
        if evidence_id not in support_ids and evidence_id not in contradiction_ids:
            support_ids.append(evidence_id)
    elif assessment.relation == EvidenceRelation.CONTRADICTS:
        if evidence_id not in contradiction_ids and evidence_id not in support_ids:
            contradiction_ids.append(evidence_id)

    # A contradiction is tied to a necessary prediction of the mechanism and
    # therefore takes precedence over positive correlation. Conflicting or
    # indirect observations should be classified INCONCLUSIVE by the evaluator.
    if contradiction_ids:
        status = RootCauseStatus.CONTRADICTED
    elif support_ids:
        status = RootCauseStatus.SUPPORTED
    else:
        status = RootCauseStatus.UNKNOWN

    values = hypothesis.model_dump()
    values.update(
        {
            "supporting_evidence_ids": support_ids,
            "contradicting_evidence_ids": contradiction_ids,
            "status": status,
            "next_probe": None if status != RootCauseStatus.UNKNOWN else hypothesis.next_probe,
        }
    )
    return Hypothesis.model_validate(values)


def update_memory(
    memory: InvestigationMemory,
    evidence: EvidenceRecord,
    assessments: Sequence[EvidenceAssessment] = (),
) -> InvestigationMemory:
    """Return memory with one evidence record and its assessments applied.

    Replaying an identical record and assessment is idempotent. Reusing an ID
    for different evidence, or changing an existing assessment, is rejected so
    checkpoint replay cannot silently rewrite investigation history.
    """

    evidence_id = str(evidence.id)
    existing_evidence = memory.evidence_by_id().get(evidence_id)
    if existing_evidence is not None and existing_evidence != evidence:
        raise ValueError("evidence ID is already associated with a different record")

    hypotheses = {item.hypothesis_id: item for item in memory.hypotheses}
    evidence_by_id = memory.evidence_by_id()
    normalized_existing_assessments = [
        _effective_assessment(
            evidence_by_id[item.evidence_id],
            item,
            hypotheses.get(item.hypothesis_id),
        )
        for item in memory.assessments
    ]
    existing_assessments = {
        (item.hypothesis_id, item.evidence_id): item for item in normalized_existing_assessments
    }
    new_assessments: list[EvidenceAssessment] = []
    for assessment in assessments:
        if assessment.evidence_id != evidence_id:
            raise ValueError("all assessments must reference the supplied evidence record")
        hypothesis = hypotheses.get(assessment.hypothesis_id)
        if hypothesis is None:
            raise ValueError("assessment references an unknown hypothesis")

        assessment = _effective_assessment(evidence, assessment, hypothesis)

        key = (assessment.hypothesis_id, evidence_id)
        existing_assessment = existing_assessments.get(key)
        if existing_assessment is not None:
            if existing_assessment != assessment:
                raise ValueError("an existing evidence assessment cannot be rewritten")
            continue

        hypotheses[assessment.hypothesis_id] = apply_evidence(
            hypothesis,
            evidence,
            assessment,
        )
        new_assessments.append(assessment)

    values = memory.model_dump()
    values.update(
        {
            "hypotheses": [hypotheses[item.hypothesis_id] for item in memory.hypotheses],
            "evidence_records": (
                memory.evidence_records
                if existing_evidence is not None
                else [*memory.evidence_records, evidence]
            ),
            "assessments": [*normalized_existing_assessments, *new_assessments],
        }
    )
    return InvestigationMemory.model_validate(values)
