import pytest

from app.adapters.ai import FakeAIAdvisor, _validate_manual_policy
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.config import DEFAULT_SEVERITY_MAPPING
from app.domain.errors import AdvisorError
from app.domain.models import Recommendation, RecommendationStep, RunbookExcerpt


def make_alert():
    return CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Unknown issue", "reason": "unknown_reason"}
    )


@pytest.mark.asyncio
async def test_no_runbook_forces_low_confidence() -> None:
    recommendation, _ = await FakeAIAdvisor().advise(make_alert(), [])
    assert recommendation.manual_matched is False
    assert recommendation.confidence <= 0.45
    assert recommendation.runbook_references == []


def test_matched_runbook_requires_real_citations() -> None:
    recommendation = Recommendation(
        summary="test",
        steps=[RecommendationStep(order=1, action="check")],
        requires_human=True,
        confidence=0.9,
        manual_matched=True,
    )
    runbooks = [RunbookExcerpt(runbook_id="rb-1", title="RB", content="approved")]
    with pytest.raises(AdvisorError, match="references"):
        _validate_manual_policy(recommendation, runbooks)
