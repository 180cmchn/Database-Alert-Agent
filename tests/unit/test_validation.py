from uuid import uuid4

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.application.validation import (
    RuleConclusionValidator,
    enforce_post_evidence_root_cause_policy,
)
from app.domain.models import (
    AnalysisBasis,
    AnalysisBasisSource,
    EvidenceRecord,
    InvestigationRun,
    Recommendation,
    RecommendationStep,
    RootCauseAssessment,
    RootCauseStatus,
    ToolStatus,
)
from app.investigations.models import (
    EvidenceAssessment,
    EvidenceNeed,
    EvidenceRelation,
    Hypothesis,
    InvestigationMemory,
    update_memory,
)


def make_alert():  # type: ignore[no-untyped-def]
    return CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "validation-1",
            "severity": "WARNING",
            "title": "Connections exhausted",
            "reason": "connection_exhausted",
        }
    )


def make_recommendation(
    *,
    root_causes: list[RootCauseAssessment] | None = None,
    action: str = "只读核对指标",
    requires_human: bool = True,
) -> Recommendation:
    return Recommendation(
        summary="candidate conclusion",
        analysis_bases=[
            AnalysisBasis(
                source=AnalysisBasisSource.AI,
                statement="AI analysis based on alert fields",
            )
        ],
        steps=[RecommendationStep(order=1, action=action)],
        requires_human=requires_human,
        confidence=0.5,
        manual_matched=False,
        root_causes=root_causes or [],
    )


def make_hypothesis(
    hypothesis_id: str,
    mechanism: str,
    *,
    causal_candidate: bool = True,
) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=hypothesis_id,
        mechanism=mechanism,
        causal_candidate=causal_candidate,
        expected_observations=["实时观测符合该机制的必要预测。"],
        contradicting_observations=["实时观测与该机制的必要预测冲突。"],
        next_probe=EvidenceNeed(
            need_id=f"{hypothesis_id}:probe",
            objective=f"只读核验 {mechanism}",
            expected_observation="出现必要预测。",
            contradicting_observation="必要预测未出现。",
            tool_name="query_database_diagnostics",
        ),
    )


def assessed_memory(
    hypotheses: list[Hypothesis],
    evidence: EvidenceRecord,
    *,
    hypothesis_id: str,
    relation: EvidenceRelation,
) -> InvestigationMemory:
    return update_memory(
        InvestigationMemory(hypotheses=hypotheses),
        evidence,
        [
            EvidenceAssessment(
                hypothesis_id=hypothesis_id,
                evidence_id=str(evidence.id),
                relation=relation,
                rationale="该观测用于检验指定机制。",
            )
        ],
    )


def test_post_evidence_policy_drops_contradicted_hypotheses() -> None:
    live_evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="连接来源分布与平台采集 SQL 假设不符",
    )
    contradicted_evidence_id = str(live_evidence.id)
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="连接泄漏",
                status=RootCauseStatus.UNKNOWN,
                next_probe="查询连接来源分布。",
            ),
            RootCauseAssessment(
                cause="数据库管理平台采集 SQL 导致告警",
                status=RootCauseStatus.CONTRADICTED,
                evidence_refs=[contradicted_evidence_id],
            ),
        ]
    ).model_copy(update={"likely_causes": ["连接泄漏", "数据库管理平台采集 SQL 导致告警"]})

    result = enforce_post_evidence_root_cause_policy(recommendation, [live_evidence])

    assert [item.cause for item in result.root_causes] == ["连接泄漏"]
    assert result.likely_causes == ["连接泄漏"]
    assert not hasattr(result, "excluded_causes")


def test_post_evidence_policy_requires_review_when_all_causes_are_removed() -> None:
    live_evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="连接来源分布与平台采集 SQL 假设不符",
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="数据库管理平台采集 SQL 导致告警",
                status=RootCauseStatus.CONTRADICTED,
                evidence_refs=[str(live_evidence.id)],
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [live_evidence])

    assert result.root_causes == []
    assert result.likely_causes == []
    assert result.requires_human is True


def test_post_evidence_policy_drops_management_sql_cause_filtered_by_alert() -> None:
    filter_note = "（已排除640个数据库管理平台采集数据用sql）"
    alert = make_alert().model_copy(
        update={"raw_payload": {"description": f"五分钟内慢查询触发值为646个{filter_note}"}}
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="本次告警完全由数据库管理平台采集 SQL 造成",
                status=RootCauseStatus.UNKNOWN,
                next_probe="复核 SQL 来源。",
            ),
            RootCauseAssessment(
                cause="业务 SQL 执行频次异常增加",
                status=RootCauseStatus.UNKNOWN,
                next_probe="按指纹核对慢查询执行次数。",
            ),
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [], alert)

    assert [item.cause for item in result.root_causes] == ["业务 SQL 执行频次异常增加"]
    assert result.likely_causes == ["业务 SQL 执行频次异常增加"]
    assert result.requires_human is True


@pytest.mark.parametrize(
    "status",
    [ToolStatus.FAILED, ToolStatus.TIMEOUT, ToolStatus.NO_DATA, ToolStatus.SKIPPED],
)
def test_post_evidence_policy_keeps_cause_unknown_without_live_success(
    status: ToolStatus,
) -> None:
    unavailable_evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=status,
        summary="实时证据不可用",
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="数据库管理平台采集 SQL 导致告警",
                status=RootCauseStatus.CONTRADICTED,
                evidence_refs=[str(unavailable_evidence.id)],
                confidence=0.9,
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [unavailable_evidence])

    assert len(result.root_causes) == 1
    assert result.root_causes[0].status == RootCauseStatus.UNKNOWN
    assert result.root_causes[0].evidence_refs == []
    assert result.root_causes[0].confidence == 0.45
    assert result.root_causes[0].next_probe
    assert result.likely_causes == ["数据库管理平台采集 SQL 导致告警"]
    assert result.requires_human is True


@pytest.mark.parametrize(
    ("status", "verified"),
    [
        (RootCauseStatus.SUPPORTED, True),
        (RootCauseStatus.CONTRADICTED, False),
    ],
)
def test_post_evidence_policy_treats_partial_success_as_unknown(
    status: RootCauseStatus,
    verified: bool,
) -> None:
    partial_evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_archery_slow_logs",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="已采集部分慢日志。",
        structured_data={
            "partial": True,
            "query_completed": True,
            "root_cause_eligible": True,
            "allow_followup_dispatch": False,
        },
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="慢查询突增",
                status=status,
                evidence_refs=[str(partial_evidence.id)],
                confidence=0.9,
                verified=verified,
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(
        recommendation,
        [partial_evidence],
    )

    assert result.root_causes[0].status == RootCauseStatus.UNKNOWN
    assert result.root_causes[0].verified is False
    assert result.root_causes[0].evidence_refs == []
    assert result.root_causes[0].next_probe
    assert result.requires_human is True


def test_post_evidence_policy_canonicalizes_cause_to_bound_hypothesis() -> None:
    evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_database_diagnostics",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="长连接集中在同一应用连接池。",
    )
    hypothesis = make_hypothesis(
        "pool-leak",
        "连接池泄漏导致长连接持续占用连接槽位。",
    )
    memory = assessed_memory(
        [hypothesis],
        evidence,
        hypothesis_id=hypothesis.hypothesis_id,
        relation=EvidenceRelation.SUPPORTS,
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                hypothesis_id=hypothesis.hypothesis_id,
                cause="不相关的磁盘容量不足",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(
        recommendation,
        [evidence],
        investigation_memory=memory,
    )

    assert len(result.root_causes) == 1
    assert result.root_causes[0].hypothesis_id == hypothesis.hypothesis_id
    assert result.root_causes[0].cause == hypothesis.mechanism
    assert result.root_causes[0].status == RootCauseStatus.SUPPORTED
    assert result.root_causes[0].evidence_refs == [str(evidence.id)]
    assert result.root_causes[0].verified is True
    assert result.requires_human is True


def test_post_evidence_policy_replaces_cross_hypothesis_evidence_refs() -> None:
    evidence_a = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="长连接集中在应用 A。",
    )
    evidence_b = EvidenceRecord(
        run_id=evidence_a.run_id,
        tool_name="query_disk_latency",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="磁盘延迟显著升高。",
    )
    hypothesis_a = make_hypothesis("pool-leak", "连接池泄漏导致连接耗尽。")
    hypothesis_b = make_hypothesis("disk-stall", "磁盘阻塞导致请求堆积。")
    memory = assessed_memory(
        [hypothesis_a, hypothesis_b],
        evidence_a,
        hypothesis_id=hypothesis_a.hypothesis_id,
        relation=EvidenceRelation.SUPPORTS,
    )
    memory = update_memory(
        memory,
        evidence_b,
        [
            EvidenceAssessment(
                hypothesis_id=hypothesis_b.hypothesis_id,
                evidence_id=str(evidence_b.id),
                relation=EvidenceRelation.SUPPORTS,
                rationale="磁盘观测支持磁盘阻塞机制。",
            )
        ],
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                hypothesis_id=hypothesis_a.hypothesis_id,
                cause=hypothesis_a.mechanism,
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence_b.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(
        recommendation,
        [evidence_a, evidence_b],
        investigation_memory=memory,
    )

    assert result.root_causes[0].evidence_refs == [str(evidence_a.id)]
    assert result.requires_human is True


def test_post_evidence_policy_drops_unbound_new_model_cause() -> None:
    hypothesis = make_hypothesis("pool-leak", "连接池泄漏导致连接耗尽。")
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="模型临时生成但未进入调查记忆的原因",
                status=RootCauseStatus.UNKNOWN,
                next_probe="执行只读核验。",
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(
        recommendation,
        [],
        investigation_memory=InvestigationMemory(hypotheses=[hypothesis]),
    )

    assert result.root_causes == []
    assert result.likely_causes == []
    assert result.requires_human is True


def test_post_evidence_policy_cannot_promote_partial_memory_assessment() -> None:
    partial = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_archery_slow_logs",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="仅返回部分慢日志。",
        structured_data={"partial": True, "root_cause_eligible": True},
    )
    hypothesis = make_hypothesis("sql-burst", "业务 SQL 调用频率突增。")
    memory = assessed_memory(
        [hypothesis],
        partial,
        hypothesis_id=hypothesis.hypothesis_id,
        relation=EvidenceRelation.SUPPORTS,
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                hypothesis_id=hypothesis.hypothesis_id,
                cause=hypothesis.mechanism,
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(partial.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = enforce_post_evidence_root_cause_policy(
        recommendation,
        [partial],
        investigation_memory=memory,
    )

    assert memory.assessments[0].relation == EvidenceRelation.INCONCLUSIVE
    assert result.root_causes[0].status == RootCauseStatus.UNKNOWN
    assert result.root_causes[0].verified is False
    assert result.root_causes[0].next_probe == hypothesis.next_probe.objective
    assert result.requires_human is True


def test_legacy_root_cause_json_without_hypothesis_id_remains_readable() -> None:
    root_cause = RootCauseAssessment.model_validate(
        {
            "cause": "旧版持久化根因",
            "status": "UNKNOWN",
            "confidence": 0.3,
            "verified": False,
            "next_probe": "补充只读证据。",
        }
    )

    assert root_cause.hypothesis_id is None


@pytest.mark.asyncio
async def test_rule_validator_rejects_missing_and_failed_evidence() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    failed_evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_metrics",
        source_system="metrics",
        status=ToolStatus.FAILED,
        summary="metrics unavailable",
    )
    missing_id = uuid4()
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="connection leak",
                evidence_refs=[str(failed_evidence.id), str(missing_id)],
                confidence=0.9,
                verified=True,
            )
        ]
    )

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [failed_evidence], []
    )

    assert result.passed is False
    assert any("不是 SUCCESS" in issue for issue in result.issues)
    assert any("不存在的证据" in issue for issue in result.issues)
    assert any("必须至少引用一条 SUCCESS 证据" in issue for issue in result.issues)
    assert result.evidence_sufficient is False


@pytest.mark.asyncio
async def test_rule_validator_accepts_honest_unknown_but_marks_evidence_insufficient() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="connection leak",
                status=RootCauseStatus.UNKNOWN,
                confidence=0.3,
                verified=False,
                next_probe="查询连接来源和长会话分布。",
            )
        ]
    )

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [], [])

    assert result.passed is True
    assert result.evidence_sufficient is False
    assert result.issues == []


@pytest.mark.asyncio
async def test_rule_validator_accepts_empty_cause_assessment_with_human_review() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(requires_human=True)

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [], [])

    assert result.passed is True
    assert result.evidence_sufficient is False
    assert result.issues == []


@pytest.mark.asyncio
async def test_rule_validator_marks_supported_live_evidence_sufficient() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    live_evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_database_diagnostics",
        source_system="flashduty_monitors",
        status=ToolStatus.SUCCESS,
        summary="connection sources confirm one leaking client",
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="connection leak",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(live_evidence.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [live_evidence], []
    )

    assert result.passed is True
    assert result.evidence_sufficient is True
    assert result.issues == []


@pytest.mark.asyncio
async def test_rule_validator_rejects_cross_hypothesis_cause_binding() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="连接池 A 持有大量长连接。",
    )
    hypothesis = make_hypothesis("pool-leak", "连接池泄漏导致连接耗尽。")
    memory = assessed_memory(
        [hypothesis],
        evidence,
        hypothesis_id=hypothesis.hypothesis_id,
        relation=EvidenceRelation.SUPPORTS,
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                hypothesis_id=hypothesis.hypothesis_id,
                cause="磁盘容量不足",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [evidence],
        [],
        memory,
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("mechanism 不一致" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_rejects_live_evidence_marked_root_cause_ineligible() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    unscoped_evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_archery_slow_logs",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="unscoped slow-log snapshot",
        structured_data={"root_cause_eligible": False},
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="excessive slow queries on the alerted instance",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(unscoped_evidence.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [unscoped_evidence], []
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("明确标记为不能支持根因" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_rejects_partial_success_as_causal_evidence() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    partial_evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_prometheus_metrics",
        source_system="prometheus_mcp",
        status=ToolStatus.SUCCESS,
        summary="已采集部分监控样本。",
        structured_data={
            "partial": True,
            "query_completed": True,
            "root_cause_eligible": True,
            "allow_followup_dispatch": False,
        },
    )
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="数据库 CPU 饱和",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(partial_evidence.id)],
                confidence=0.9,
                verified=True,
            )
        ],
        requires_human=False,
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [partial_evidence],
        [],
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("partial=true 的部分证据" in issue for issue in result.issues)
    assert any("部分结果只能作为描述性上下文" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_rejects_dangerous_action() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(action="立即重启数据库实例恢复服务")

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [], [])

    assert result.passed is False
    assert any("禁止的危险动作" in issue and "重启" in issue for issue in result.issues)
