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
    ).model_copy(
        update={
            "likely_causes": ["连接泄漏", "数据库管理平台采集 SQL 导致告警"]
        }
    )

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
        update={
            "raw_payload": {
                "description": f"五分钟内慢查询触发值为646个{filter_note}"
            }
        }
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

    result = enforce_post_evidence_root_cause_policy(
        recommendation, [], alert
    )

    assert [item.cause for item in result.root_causes] == [
        "业务 SQL 执行频次异常增加"
    ]
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

    result = enforce_post_evidence_root_cause_policy(
        recommendation, [unavailable_evidence]
    )

    assert len(result.root_causes) == 1
    assert result.root_causes[0].status == RootCauseStatus.UNKNOWN
    assert result.root_causes[0].evidence_refs == []
    assert result.root_causes[0].confidence == 0.45
    assert result.root_causes[0].next_probe
    assert result.likely_causes == ["数据库管理平台采集 SQL 导致告警"]
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
async def test_rule_validator_accepts_empty_cause_assessment_with_human_review() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(requires_human=True)

    result = await RuleConclusionValidator().validate(
        run, alert, recommendation, [], []
    )

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
