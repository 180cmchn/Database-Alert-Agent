from uuid import uuid4

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.application.validation import RuleConclusionValidator
from app.domain.models import (
    AnalysisBasis,
    AnalysisBasisSource,
    EvidenceRecord,
    InvestigationRun,
    Recommendation,
    RecommendationStep,
    RootCauseAssessment,
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
    *, root_causes: list[RootCauseAssessment] | None = None, action: str = "只读核对指标"
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
        requires_human=True,
        confidence=0.5,
        manual_matched=False,
        root_causes=root_causes or [],
    )


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


@pytest.mark.asyncio
async def test_rule_validator_rejects_dangerous_action() -> None:
    alert = make_alert()
    run = InvestigationRun(alert_id=alert.id)
    recommendation = make_recommendation(action="立即重启数据库实例恢复服务")

    result = await RuleConclusionValidator().validate(run, alert, recommendation, [], [])

    assert result.passed is False
    assert any("禁止的危险动作" in issue and "重启" in issue for issue in result.issues)
