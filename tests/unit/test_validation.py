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
    ExcludedCauseAssessment,
    InvestigationRun,
    Recommendation,
    RecommendationStep,
    RootCauseAssessment,
    RootCauseStatus,
    ToolStatus,
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


def test_post_evidence_policy_moves_contradicted_hypotheses_out_of_root_causes() -> None:
    contradicted_evidence_id = str(uuid4())
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
    ).model_copy(
        update={
            "likely_causes": ["连接泄漏", "数据库管理平台采集 SQL 导致告警"]
        }
    )

    result = enforce_post_evidence_root_cause_policy(recommendation)

    assert [item.cause for item in result.root_causes] == ["连接泄漏"]
    assert result.likely_causes == ["连接泄漏"]
    assert len(result.excluded_causes) == 1
    assert result.excluded_causes[0].cause == "数据库管理平台采集 SQL 导致告警"
    assert result.excluded_causes[0].evidence_refs == [contradicted_evidence_id]


def test_post_evidence_policy_removes_cause_already_explicitly_excluded() -> None:
    recommendation = make_recommendation(
        root_causes=[
            RootCauseAssessment(
                cause="数据库管理平台采集 SQL 导致告警",
                status=RootCauseStatus.UNKNOWN,
                next_probe="复核 SQL 来源。",
            )
        ],
        requires_human=False,
    ).model_copy(
        update={
            "excluded_causes": [
                ExcludedCauseAssessment(
                    cause="数据库管理平台采集 SQL 导致告警",
                    evidence_refs=[str(uuid4())],
                    reason="实时证据已排除该来源。",
                )
            ]
        }
    )

    result = enforce_post_evidence_root_cause_policy(recommendation)

    assert result.root_causes == []
    assert result.likely_causes == []
    assert result.requires_human is True


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

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [], []
    )

    assert result.passed is True
    assert result.evidence_sufficient is False
    assert result.issues == []


@pytest.mark.asyncio
async def test_rule_validator_rejects_empty_cause_assessment() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(requires_human=True)

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [], []
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("至少形成一个可能根因" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_accepts_only_excluded_hypotheses_with_human_review() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    live_evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=ToolStatus.SUCCESS,
        summary="连接来源分布与平台采集 SQL 假设不符",
    )
    recommendation = make_recommendation(requires_human=True).model_copy(
        update={
            "excluded_causes": [
                ExcludedCauseAssessment(
                    cause="数据库管理平台采集 SQL 导致告警",
                    evidence_refs=[str(live_evidence.id)],
                    reason="实时连接来源和耗时分布未出现该平台采集 SQL。",
                )
            ]
        }
    )

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [live_evidence], []
    )

    assert result.passed is True
    assert result.evidence_sufficient is False
    assert result.issues == []
    assert result.metadata["checked_root_causes"] == 0
    assert result.metadata["checked_excluded_causes"] == 1


@pytest.mark.asyncio
async def test_rule_validator_rejects_exclusion_without_successful_live_evidence() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    failed_evidence = EvidenceRecord(
        run_id=run.id,
        tool_name="query_connection_sources",
        source_system="database_diagnostics",
        status=ToolStatus.FAILED,
        summary="实时查询失败",
    )
    recommendation = make_recommendation(requires_human=True).model_copy(
        update={
            "excluded_causes": [
                ExcludedCauseAssessment(
                    cause="数据库管理平台采集 SQL 导致告警",
                    evidence_refs=[str(failed_evidence.id)],
                    reason="工具没有返回该 SQL。",
                )
            ]
        }
    )

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [failed_evidence], []
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("不能作为实时反证" in issue for issue in result.issues)
    assert any("缺少可用的实时 SUCCESS 反证" in issue for issue in result.issues)


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
async def test_rule_validator_rejects_dangerous_action() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(action="立即重启数据库实例恢复服务")

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [], [])

    assert result.passed is False
    assert any("禁止的危险动作" in issue and "重启" in issue for issue in result.issues)
