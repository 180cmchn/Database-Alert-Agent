from uuid import uuid4

import pytest

from app.domain.models import (
    DatabaseTarget,
    EvidenceRecord,
    InvestigationStrategy,
    NormalizedAlert,
    RootCauseStatus,
    RunbookCause,
    RunbookExcerpt,
    RunbookProbe,
    Severity,
    ToolExecutionRequest,
    ToolStatus,
)
from app.investigations.models import (
    EvidenceAssessment,
    EvidenceNeed,
    EvidenceRelation,
    Hypothesis,
    InvestigationMemory,
    apply_evidence,
    is_qualified_live_evidence,
    update_memory,
)
from app.investigations.seeding import seed_investigation_memory
from app.investigations.stop import StopEvaluator, StopReason


def make_probe(
    *,
    read_only: bool = True,
    safety_approved: bool = True,
    available: bool = True,
) -> EvidenceNeed:
    return EvidenceNeed(
        need_id="connection-distribution",
        objective="Compare active connection ownership during the alert window.",
        expected_observation="One workload owns most long-lived connections.",
        contradicting_observation="Connection ages and owners remain evenly distributed.",
        tool_name="query_connection_sources",
        read_only=read_only,
        safety_approved=safety_approved,
        available=available,
        unavailable_reason=None if available else "The provider is disconnected.",
    )


def make_hypothesis(*, priority: int = 50) -> Hypothesis:
    return Hypothesis(
        hypothesis_id="pool-leak",
        mechanism="A pool leak retains sessions until the connection limit is reached.",
        expected_observations=["Connection age and ownership are concentrated."],
        contradicting_observations=["Connections remain short-lived and evenly distributed."],
        next_probe=make_probe(),
        priority=priority,
    )


def make_evidence(
    status: ToolStatus = ToolStatus.SUCCESS,
    *,
    source_system: str = "database_diagnostics",
    truncated: bool = False,
    root_cause_eligible: bool | None = None,
) -> EvidenceRecord:
    structured_data = {}
    if root_cause_eligible is not None:
        structured_data["root_cause_eligible"] = root_cause_eligible
    return EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_connection_sources",
        source_system=source_system,
        status=status,
        summary="Connection ownership and age distribution.",
        structured_data=structured_data,
        truncated=truncated,
    )


def assessment(
    hypothesis: Hypothesis,
    evidence: EvidenceRecord,
    relation: EvidenceRelation,
) -> EvidenceAssessment:
    return EvidenceAssessment(
        hypothesis_id=hypothesis.hypothesis_id,
        evidence_id=str(evidence.id),
        relation=relation,
        rationale="The observation directly tests a necessary prediction.",
    )


def test_successful_live_evidence_supports_a_hypothesis() -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence()

    result = apply_evidence(
        hypothesis,
        evidence,
        assessment(hypothesis, evidence, EvidenceRelation.SUPPORTS),
    )

    assert result.status == RootCauseStatus.SUPPORTED
    assert result.supporting_evidence_ids == [str(evidence.id)]
    assert result.contradicting_evidence_ids == []
    assert result.next_probe is None
    assert hypothesis.status == RootCauseStatus.UNKNOWN
    assert hypothesis.supporting_evidence_ids == []


@pytest.mark.parametrize(
    "relation",
    [EvidenceRelation.SUPPORTS, EvidenceRelation.CONTRADICTS],
)
def test_non_causal_placeholder_cannot_become_decisive(
    relation: EvidenceRelation,
) -> None:
    hypothesis = make_hypothesis().model_copy(update={"causal_candidate": False})
    evidence = make_evidence()

    memory = update_memory(
        InvestigationMemory(hypotheses=[hypothesis]),
        evidence,
        [assessment(hypothesis, evidence, relation)],
    )

    assert memory.assessments[0].relation == EvidenceRelation.INCONCLUSIVE
    assert memory.hypotheses[0].status == RootCauseStatus.UNKNOWN
    assert memory.hypotheses[0].supporting_evidence_ids == []
    assert memory.hypotheses[0].contradicting_evidence_ids == []
    decision = StopEvaluator().evaluate(memory)
    assert decision.reason == StopReason.NO_SAFE_PROBE
    assert decision.requires_human is True


def test_legacy_reserved_placeholder_defaults_to_non_causal() -> None:
    values = make_hypothesis().model_dump(exclude={"causal_candidate"})
    values.update(
        {
            "hypothesis_id": "unresolved-cause",
            "supporting_evidence_ids": ["legacy-evidence"],
            "status": RootCauseStatus.SUPPORTED,
            "next_probe": None,
        }
    )

    hypothesis = Hypothesis.model_validate(values)

    assert hypothesis.causal_candidate is False
    assert hypothesis.status == RootCauseStatus.UNKNOWN
    assert hypothesis.supporting_evidence_ids == []
    assert hypothesis.next_probe is not None
    assert hypothesis.next_probe.available is False


def test_successful_live_evidence_can_contradict_a_hypothesis() -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence()

    result = apply_evidence(
        hypothesis,
        evidence,
        assessment(hypothesis, evidence, EvidenceRelation.CONTRADICTS),
    )

    assert result.status == RootCauseStatus.CONTRADICTED
    assert result.contradicting_evidence_ids == [str(evidence.id)]
    assert result.supporting_evidence_ids == []
    assert result.next_probe is None


@pytest.mark.parametrize(
    "status",
    [ToolStatus.FAILED, ToolStatus.SKIPPED, ToolStatus.TIMEOUT, ToolStatus.NO_DATA],
)
def test_unavailable_evidence_cannot_contradict_a_hypothesis(status: ToolStatus) -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence(status)

    result = apply_evidence(
        hypothesis,
        evidence,
        assessment(hypothesis, evidence, EvidenceRelation.CONTRADICTS),
    )

    assert result == hypothesis
    assert result.status == RootCauseStatus.UNKNOWN
    assert result.contradicting_evidence_ids == []


def test_alert_platform_evidence_cannot_support_a_root_cause() -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence(source_system="alert_platform")

    result = apply_evidence(
        hypothesis,
        evidence,
        assessment(hypothesis, evidence, EvidenceRelation.SUPPORTS),
    )

    assert result == hypothesis
    assert result.status == RootCauseStatus.UNKNOWN


def test_truncated_success_requires_explicit_root_cause_eligibility() -> None:
    hypothesis = make_hypothesis()
    truncated = make_evidence(truncated=True)
    eligible = make_evidence(truncated=True, root_cause_eligible=True)

    unchanged = apply_evidence(
        hypothesis,
        truncated,
        assessment(hypothesis, truncated, EvidenceRelation.SUPPORTS),
    )
    supported = apply_evidence(
        hypothesis,
        eligible,
        assessment(hypothesis, eligible, EvidenceRelation.SUPPORTS),
    )

    assert unchanged.status == RootCauseStatus.UNKNOWN
    assert supported.status == RootCauseStatus.SUPPORTED


@pytest.mark.parametrize(
    "relation",
    [EvidenceRelation.SUPPORTS, EvidenceRelation.CONTRADICTS],
)
def test_partial_success_is_inconclusive_even_when_provider_marks_it_eligible(
    relation: EvidenceRelation,
) -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence(root_cause_eligible=True).model_copy(
        update={
            "structured_data": {
                "partial": True,
                "root_cause_eligible": True,
                "query_completed": True,
                "allow_followup_dispatch": False,
            }
        }
    )
    proposed = assessment(hypothesis, evidence, relation)

    result = update_memory(
        InvestigationMemory(hypotheses=[hypothesis]),
        evidence,
        [proposed],
    )
    decision = StopEvaluator().evaluate(result)

    assert evidence.is_root_cause_support_eligible() is False
    assert is_qualified_live_evidence(evidence) is False
    assert result.evidence_records == [evidence]
    assert result.assessments[0].relation == EvidenceRelation.INCONCLUSIVE
    assert "Host classified" in result.assessments[0].rationale
    assert result.hypotheses[0].status == RootCauseStatus.UNKNOWN
    assert result.hypotheses[0].supporting_evidence_ids == []
    assert result.hypotheses[0].contradicting_evidence_ids == []
    assert decision.should_stop is True
    assert decision.reason == StopReason.NO_SAFE_PROBE
    assert decision.requires_human is True


def test_update_memory_records_missing_evidence_without_changing_hypothesis() -> None:
    hypothesis = make_hypothesis()
    memory = InvestigationMemory(hypotheses=[hypothesis])
    evidence = make_evidence(ToolStatus.TIMEOUT)
    evidence_assessment = assessment(
        hypothesis,
        evidence,
        EvidenceRelation.CONTRADICTS,
    )

    result = update_memory(memory, evidence, [evidence_assessment])
    replayed = update_memory(result, evidence, [evidence_assessment])

    assert result.hypotheses[0].status == RootCauseStatus.UNKNOWN
    assert result.hypotheses[0].contradicting_evidence_ids == []
    assert result.evidence_records == [evidence]
    assert result.assessments[0].relation == EvidenceRelation.INCONCLUSIVE
    assert "Host classified" in result.assessments[0].rationale
    assert replayed == result
    assert memory.evidence_records == []


def test_update_memory_normalizes_legacy_ineligible_assessment_on_replay() -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence().model_copy(
        update={"structured_data": {"partial": True, "root_cause_eligible": True}}
    )
    legacy_assessment = assessment(
        hypothesis,
        evidence,
        EvidenceRelation.SUPPORTS,
    )
    legacy_memory = InvestigationMemory(
        hypotheses=[hypothesis],
        evidence_records=[evidence],
        assessments=[legacy_assessment],
    )

    result = update_memory(legacy_memory, evidence, [legacy_assessment])

    assert result.hypotheses == [hypothesis]
    assert result.assessments[0].relation == EvidenceRelation.INCONCLUSIVE
    assert update_memory(result, evidence, [legacy_assessment]) == result


@pytest.mark.parametrize(
    "status",
    [ToolStatus.FAILED, ToolStatus.SKIPPED, ToolStatus.TIMEOUT, ToolStatus.NO_DATA],
)
def test_terminal_missing_attempt_is_not_rescheduled(status: ToolStatus) -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence(status)
    memory = update_memory(
        InvestigationMemory(hypotheses=[hypothesis]),
        evidence,
        [assessment(hypothesis, evidence, EvidenceRelation.CONTRADICTS)],
    )

    decision = StopEvaluator().evaluate(memory)

    assert memory.safe_available_probes() == [hypothesis.next_probe]
    assert memory.safe_unattempted_probes() == []
    assert memory.hypotheses[0].status == RootCauseStatus.UNKNOWN
    assert memory.hypotheses[0].contradicting_evidence_ids == []
    assert decision.should_stop is True
    assert decision.reason == StopReason.NO_SAFE_PROBE
    assert decision.requires_human is True


def test_partial_success_probe_remains_schedulable() -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence().model_copy(update={"structured_data": {"partial": True}})
    memory = update_memory(InvestigationMemory(hypotheses=[hypothesis]), evidence)

    decision = StopEvaluator().evaluate(memory)

    assert memory.safe_unattempted_probes() == [hypothesis.next_probe]
    assert decision.should_stop is False
    assert decision.reason == StopReason.CONTINUE


def test_partial_success_without_followup_permission_is_terminal() -> None:
    hypothesis = make_hypothesis()
    evidence = make_evidence().model_copy(
        update={
            "structured_data": {
                "partial": True,
                "allow_followup_dispatch": False,
            }
        }
    )
    memory = update_memory(InvestigationMemory(hypotheses=[hypothesis]), evidence)

    decision = StopEvaluator().evaluate(memory)

    assert memory.safe_unattempted_probes() == []
    assert decision.should_stop is True
    assert decision.reason == StopReason.NO_SAFE_PROBE
    assert decision.requires_human is True


def test_same_tool_with_different_parameters_remains_schedulable() -> None:
    probe = make_probe().model_copy(update={"parameters": {"scope": "replica"}})
    hypothesis = make_hypothesis().model_copy(update={"next_probe": probe})
    evidence = make_evidence(ToolStatus.NO_DATA).model_copy(
        update={"request": {"scope": "primary"}}
    )
    memory = update_memory(InvestigationMemory(hypotheses=[hypothesis]), evidence)

    assert memory.safe_unattempted_probes() == [probe]
    assert StopEvaluator().evaluate(memory).reason == StopReason.CONTINUE


def test_supported_cause_is_a_deterministic_stop() -> None:
    hypothesis = make_hypothesis(priority=80)
    evidence = make_evidence()
    memory = update_memory(
        InvestigationMemory(hypotheses=[hypothesis]),
        evidence,
        [assessment(hypothesis, evidence, EvidenceRelation.SUPPORTS)],
    )

    decision = StopEvaluator().evaluate(memory)

    assert decision.should_stop is True
    assert decision.reason == StopReason.SUPPORTED_CAUSE
    assert decision.requires_human is False
    assert decision.supported_hypothesis_ids == [hypothesis.hypothesis_id]


def test_supported_cause_does_not_hide_an_unresolved_hypothesis() -> None:
    supported_hypothesis = make_hypothesis(priority=80)
    unresolved_hypothesis = make_hypothesis(priority=70).model_copy(
        update={
            "hypothesis_id": "hypothesis-2",
            "next_probe": make_probe().model_copy(update={"parameters": {"scope": "replica"}}),
        }
    )
    evidence = make_evidence()
    memory = update_memory(
        InvestigationMemory(hypotheses=[supported_hypothesis, unresolved_hypothesis]),
        evidence,
        [assessment(supported_hypothesis, evidence, EvidenceRelation.SUPPORTS)],
    )

    decision = StopEvaluator().evaluate(memory)

    assert decision.should_stop is False
    assert decision.reason == StopReason.CONTINUE
    assert decision.supported_hypothesis_ids == []


def test_supported_cause_with_unprobeable_unknown_requires_human() -> None:
    supported_hypothesis = make_hypothesis(priority=80)
    unresolved_hypothesis = make_hypothesis(priority=70).model_copy(
        update={
            "hypothesis_id": "hypothesis-2",
            "next_probe": make_probe(available=False),
        }
    )
    evidence = make_evidence()
    memory = update_memory(
        InvestigationMemory(hypotheses=[supported_hypothesis, unresolved_hypothesis]),
        evidence,
        [assessment(supported_hypothesis, evidence, EvidenceRelation.SUPPORTS)],
    )

    decision = StopEvaluator().evaluate(memory)

    assert decision.should_stop is True
    assert decision.reason == StopReason.NO_SAFE_PROBE
    assert decision.requires_human is True


def test_model_finish_is_only_a_suggestion_when_a_safe_probe_remains() -> None:
    memory = InvestigationMemory(
        hypotheses=[make_hypothesis()],
        model_finish_requested=True,
    )

    decision = StopEvaluator().evaluate(memory)

    assert decision.should_stop is False
    assert decision.reason == StopReason.CONTINUE
    assert decision.model_finish_requested is True


@pytest.mark.parametrize(
    ("probe", "reason"),
    [
        (make_probe(read_only=False), StopReason.NO_SAFE_PROBE),
        (make_probe(safety_approved=False), StopReason.NO_SAFE_PROBE),
        (make_probe(available=False), StopReason.NO_SAFE_PROBE),
    ],
)
def test_no_safe_available_probe_requires_human(
    probe: EvidenceNeed,
    reason: StopReason,
) -> None:
    hypothesis = make_hypothesis().model_copy(update={"next_probe": probe})
    memory = InvestigationMemory(hypotheses=[hypothesis])

    decision = StopEvaluator().evaluate(memory)

    assert decision.should_stop is True
    assert decision.reason == reason
    assert decision.requires_human is True


@pytest.mark.parametrize(
    ("evaluation_arguments", "reason"),
    [
        ({"budget_exhausted": True}, StopReason.BUDGET_EXHAUSTED),
        ({"deadline_exceeded": True}, StopReason.DEADLINE_EXCEEDED),
    ],
)
def test_exhaustion_requires_human(
    evaluation_arguments: dict[str, bool],
    reason: StopReason,
) -> None:
    decision = StopEvaluator().evaluate(
        InvestigationMemory(hypotheses=[make_hypothesis()]),
        **evaluation_arguments,
    )

    assert decision.should_stop is True
    assert decision.reason == reason
    assert decision.requires_human is True


@pytest.mark.parametrize(
    ("memory_update", "reason"),
    [
        ({"target_ambiguous": True}, StopReason.TARGET_AMBIGUOUS),
        ({"window_ambiguous": True}, StopReason.WINDOW_AMBIGUOUS),
        (
            {"requires_human": True, "human_reason": "Knowledge conflicts with live evidence."},
            StopReason.HUMAN_REQUIRED,
        ),
    ],
)
def test_ambiguity_and_explicit_human_review_preempt_model_finish(
    memory_update: dict[str, object],
    reason: StopReason,
) -> None:
    memory = InvestigationMemory(
        hypotheses=[make_hypothesis()],
        model_finish_requested=True,
        **memory_update,
    )

    decision = StopEvaluator().evaluate(memory)

    assert decision.should_stop is True
    assert decision.reason == reason
    assert decision.requires_human is True


def test_seed_memory_uses_structured_runbook_causes_as_unverified_hypotheses() -> None:
    alert = NormalizedAlert(
        external_id="seed-1",
        source="test",
        raw_severity="WARNING",
        severity=Severity.WARNING,
        title="Connection saturation",
        reason="connections exceeded threshold",
        database=DatabaseTarget(engine="mysql", instance="orders-primary"),
    )
    runbook = RunbookExcerpt(
        runbook_id="mysql-connections",
        title="MySQL connections",
        content="Read-only diagnostics",
        match_confidence=0.82,
        causes=[
            RunbookCause(
                cause_id="pool-leak",
                hypothesis="A pool leak retains sessions until the limit is reached.",
                supporting_evidence=["Long-lived sessions are concentrated by owner."],
                contradicting_evidence=["Sessions are short-lived and evenly distributed."],
                probes=[
                    RunbookProbe(
                        tool_name="query_database_diagnostics",
                        objective="Inspect active and idle session age by owner.",
                    )
                ],
            )
        ],
    )
    strategy = InvestigationStrategy(
        strategy_id="connection-v1",
        title="Connection investigation",
        description="Collect session evidence",
        tool_plan=[
            ToolExecutionRequest(
                tool_name="query_database_diagnostics",
                parameters={"diagnostics": ["connection_sources"]},
            )
        ],
    )

    memory = seed_investigation_memory(
        alert,
        [runbook],
        strategy,
        available_tools={"query_database_diagnostics"},
    )

    hypothesis = memory.hypotheses[0]
    assert hypothesis.status == RootCauseStatus.UNKNOWN
    assert hypothesis.supporting_evidence_ids == []
    assert hypothesis.hypothesis_id == "mysql-connections:pool-leak"
    assert hypothesis.priority == 82
    assert hypothesis.next_probe is not None
    assert hypothesis.next_probe.parameters == {"diagnostics": ["connection_sources"]}
    assert memory.target_ambiguous is False


def test_seed_memory_does_not_promote_alert_reason_to_a_root_cause() -> None:
    alert = NormalizedAlert(
        external_id="seed-2",
        source="test",
        raw_severity="WARNING",
        severity=Severity.WARNING,
        title="Database latency",
        reason="latency is high",
    )
    strategy = InvestigationStrategy(
        strategy_id="generic-v1",
        title="Generic investigation",
        description="No provider",
    )

    memory = seed_investigation_memory(alert, [], strategy, available_tools=set())

    hypothesis = memory.hypotheses[0]
    assert hypothesis.hypothesis_id == "unresolved-cause"
    assert alert.reason not in hypothesis.mechanism
    assert hypothesis.causal_candidate is False
    assert hypothesis.status == RootCauseStatus.UNKNOWN
    assert hypothesis.next_probe is not None
    assert hypothesis.next_probe.available is False
    assert memory.target_ambiguous is True
