from uuid import uuid4

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.application.validation import (
    RuleConclusionValidator,
    enforce_post_evidence_root_cause_policy,
)
from app.domain.models import (
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
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
    summary: str = INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
    root_causes: list[RootCauseAssessment] | None = None,
    likely_causes: list[str] | None = None,
    action: str = "只读核对指标",
) -> Recommendation:
    causes = root_causes or []
    return Recommendation(
        summary=summary,
        likely_causes=(
            [item.cause for item in causes] if likely_causes is None else likely_causes
        ),
        analysis_bases=[
            AnalysisBasis(
                source=AnalysisBasisSource.AI,
                statement="AI 已审阅告警、知识与实时证据。",
            )
        ],
        steps=[RecommendationStep(order=1, action=action)],
        confidence=0.5,
        root_causes=causes,
    )


def make_live_evidence(
    *,
    status: ToolStatus = ToolStatus.SUCCESS,
    source_system: str = "database_diagnostics",
    structured_data: dict | None = None,
    truncated: bool = False,
) -> EvidenceRecord:
    return EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_database_diagnostics",
        source_system=source_system,
        status=status,
        summary="已采集当前告警窗口内的数据库诊断事实。",
        structured_data=structured_data or {},
        truncated=truncated,
    )


def test_post_evidence_policy_keeps_only_supported_with_eligible_live_evidence() -> None:
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="实时证据表明长事务持续占用连接槽位。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务持续占用连接槽位，导致可用连接耗尽。",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id), str(evidence.id)],
                confidence=0.9,
                verified=False,
                next_probe="旧模型不应保留此字段。",
            ),
            RootCauseAssessment(
                cause="连接池泄漏。",
                status=RootCauseStatus.UNKNOWN,
                next_probe="查询连接来源。",
            ),
        ],
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [evidence])

    assert [item.cause for item in result.root_causes] == [
        "长事务持续占用连接槽位，导致可用连接耗尽。"
    ]
    assert result.root_causes[0].status == RootCauseStatus.SUPPORTED
    assert result.root_causes[0].verified is True
    assert result.root_causes[0].evidence_refs == [str(evidence.id)]
    assert result.root_causes[0].hypothesis_id is None
    assert result.root_causes[0].next_probe is None
    assert result.likely_causes == [result.root_causes[0].cause]


@pytest.mark.parametrize(
    "status",
    [
        RootCauseStatus.SUPPORT,
        RootCauseStatus.UNKNOWN,
        RootCauseStatus.CONTRADICTED,
    ],
)
def test_post_evidence_policy_rejects_historical_statuses_for_new_results(
    status: RootCauseStatus,
) -> None:
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="旧三态输出。",
        root_causes=[
            RootCauseAssessment(
                cause="连接池泄漏。",
                status=status,
                evidence_refs=[str(evidence.id)],
                verified=status == RootCauseStatus.SUPPORT,
                next_probe=("查询连接来源。" if status == RootCauseStatus.UNKNOWN else None),
            )
        ],
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [evidence])

    assert result.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.root_causes == []
    assert result.likely_causes == []
    assert result.confidence == 0


@pytest.mark.parametrize(
    ("status", "structured_data", "source_system", "truncated"),
    [
        (ToolStatus.FAILED, {}, "database_diagnostics", False),
        (ToolStatus.TIMEOUT, {}, "database_diagnostics", False),
        (ToolStatus.NO_DATA, {}, "database_diagnostics", False),
        (ToolStatus.SKIPPED, {}, "database_diagnostics", False),
        (ToolStatus.SUCCESS, {"partial": True}, "database_diagnostics", False),
        (
            ToolStatus.SUCCESS,
            {"root_cause_eligible": False},
            "database_diagnostics",
            False,
        ),
        (ToolStatus.SUCCESS, {}, "alert_platform", False),
    ],
)
def test_post_evidence_policy_returns_fixed_no_cause_for_ineligible_evidence(
    status: ToolStatus,
    structured_data: dict,
    source_system: str,
    truncated: bool,
) -> None:
    evidence = make_live_evidence(
        status=status,
        structured_data=structured_data,
        source_system=source_system,
        truncated=truncated,
    )
    recommendation = make_recommendation(
        summary="模型尝试给出根因。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务导致连接耗尽。",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                verified=True,
            )
        ],
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [evidence])

    assert result.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.root_causes == []
    assert result.likely_causes == []


def test_post_evidence_policy_accepts_truncated_record_after_complete_fact_projection() -> None:
    evidence = make_live_evidence(
        truncated=True,
        structured_data={"root_cause_eligible": True, "analyzed_from_complete_raw": True},
    )
    recommendation = make_recommendation(
        summary="完整分析结果表明长事务导致连接耗尽。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务持续占用连接槽位，导致可用连接耗尽。",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                verified=True,
            )
        ],
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [evidence])

    assert result.root_causes[0].status == RootCauseStatus.SUPPORTED
    assert result.summary != INCONCLUSIVE_ROOT_CAUSE_SUMMARY


def test_program_projection_usability_does_not_create_a_root_cause() -> None:
    evidence = make_live_evidence(
        structured_data={"root_cause_eligible": True, "analyzed_from_complete_raw": True}
    )
    recommendation = make_recommendation(summary="程序事实投影仅返回结构化事实。")

    result = enforce_post_evidence_root_cause_policy(recommendation, [evidence])

    assert result.root_causes == []
    assert result.likely_causes == []
    assert result.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY


def test_verified_unknown_status_is_not_silently_promoted() -> None:
    evidence = make_live_evidence()
    cause = RootCauseAssessment(
        cause="旧模型返回未决原因。",
        status=RootCauseStatus.UNKNOWN,
        evidence_refs=[str(evidence.id)],
        verified=True,
    )

    assert cause.status == RootCauseStatus.UNKNOWN


def test_post_evidence_policy_does_not_promote_alert_reason_to_root_cause() -> None:
    alert = make_alert()
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="模型复述了告警。",
        root_causes=[
            RootCauseAssessment(
                cause=alert.reason,
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                verified=True,
            )
        ],
    )

    result = enforce_post_evidence_root_cause_policy(
        recommendation,
        [evidence],
        alert,
    )

    assert result.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.root_causes == []


def test_post_evidence_policy_drops_filtered_management_sql_cause() -> None:
    alert = make_alert().model_copy(
        update={
            "raw_payload": {
                "description": (
                    "五分钟内慢查询触发值为646个"
                    "（已排除640个数据库管理平台采集数据用sql）"
                )
            }
        }
    )
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="模型错误使用过滤说明。",
        root_causes=[
            RootCauseAssessment(
                cause="本次告警完全由数据库管理平台采集 SQL 造成",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                verified=True,
            )
        ],
    )

    result = enforce_post_evidence_root_cause_policy(recommendation, [evidence], alert)

    assert result.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.root_causes == []


def test_legacy_root_cause_json_remains_readable() -> None:
    cause = RootCauseAssessment.model_validate(
        {
            "cause": "历史候选原因",
            "status": "UNKNOWN",
            "confidence": 0.3,
            "verified": False,
            "next_probe": "补充实时证据。",
        }
    )

    assert cause.status == RootCauseStatus.UNKNOWN
    assert cause.hypothesis_id is None


@pytest.mark.asyncio
async def test_rule_validator_accepts_fixed_no_cause_as_evidence_insufficient() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation()

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [])

    assert result.passed is True
    assert result.evidence_sufficient is False
    assert result.issues == []


@pytest.mark.asyncio
async def test_rule_validator_rejects_empty_cause_with_noncanonical_summary() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(summary="可能是连接池问题。")

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [])

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("summary 必须固定" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_accepts_supported_with_live_evidence() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="长事务持续占用连接槽位，最终触发连接耗尽。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务持续占用连接槽位，导致可用连接耗尽。",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                confidence=0.9,
                verified=True,
            )
        ],
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [evidence],
    )

    assert result.passed is True
    assert result.evidence_sufficient is True
    assert result.issues == []


@pytest.mark.asyncio
async def test_unrelated_no_data_does_not_invalidate_supported_relevant_evidence() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    relevant = make_live_evidence()
    target_not_configured = make_live_evidence(
        status=ToolStatus.NO_DATA,
        source_system="prometheus_mcp",
        structured_data={
            "reason_code": "target_not_configured",
            "target_configured": False,
        },
    )
    recommendation = make_recommendation(
        summary="慢查询证据确认长事务持续占用连接槽位。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务持续占用连接槽位，导致可用连接耗尽。",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(relevant.id)],
                confidence=0.9,
                verified=True,
            )
        ],
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [relevant, target_not_configured],
    )

    assert result.passed is True
    assert result.evidence_sufficient is True
    assert result.issues == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        RootCauseStatus.SUPPORT,
        RootCauseStatus.UNKNOWN,
        RootCauseStatus.CONTRADICTED,
    ],
)
async def test_rule_validator_rejects_historical_status_in_new_result(
    status: RootCauseStatus,
) -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="旧状态结果。",
        root_causes=[
            RootCauseAssessment(
                cause="连接池泄漏。",
                status=status,
                evidence_refs=[str(evidence.id)],
                verified=status == RootCauseStatus.SUPPORT,
                next_probe=("查询连接来源。" if status == RootCauseStatus.UNKNOWN else None),
            )
        ],
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [evidence],
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("状态必须为 SUPPORTED" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_rejects_missing_partial_or_ineligible_support() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    partial = make_live_evidence(structured_data={"partial": True})
    recommendation = make_recommendation(
        summary="模型尝试使用部分证据。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务导致连接耗尽。",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(partial.id)],
                verified=True,
            )
        ],
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [partial],
    )

    assert result.passed is False
    assert result.evidence_sufficient is False
    assert any("partial=true" in issue for issue in result.issues)
    assert any("缺少合格实时 SUCCESS 证据" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_rejects_hypothesis_binding_in_new_result() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    evidence = make_live_evidence()
    recommendation = make_recommendation(
        summary="旧假设绑定结果。",
        root_causes=[
            RootCauseAssessment(
                cause="长事务导致连接耗尽。",
                hypothesis_id="legacy-hypothesis",
                status=RootCauseStatus.SUPPORTED,
                evidence_refs=[str(evidence.id)],
                verified=True,
            )
        ],
    )

    result = await RuleConclusionValidator().validate(
        run,
        alert,
        recommendation,
        [evidence],
    )

    assert result.passed is False
    assert any("不得绑定采证前假设" in issue for issue in result.issues)


@pytest.mark.asyncio
async def test_rule_validator_does_not_enforce_action_permissions() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(action="立即重启数据库实例恢复服务")

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [])

    assert result.passed is True
    assert result.issues == []
