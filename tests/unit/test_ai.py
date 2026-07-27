import pytest

import app.adapters.ai as ai_module
from app.adapters.ai import FakeAIAdvisor, _validate_manual_policy
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.domain.models import (
    AnalysisBasis,
    AnalysisBasisSource,
    Recommendation,
    RecommendationStep,
    RunbookExcerpt,
    RunbookReference,
)


def make_alert():
    return CanonicalAlertSourceAdapter().normalize(
        {"severity": "WARNING", "title": "Unclassified issue", "reason": "unclassified_reason"}
    )


@pytest.mark.asyncio
async def test_no_runbook_forces_low_confidence() -> None:
    recommendation, _ = await FakeAIAdvisor().advise(make_alert(), [])
    assert recommendation.manual_matched is False
    assert recommendation.confidence <= 0.45
    assert recommendation.runbook_references == []
    assert [item.source for item in recommendation.analysis_bases] == [
        AnalysisBasisSource.AI
    ]


@pytest.mark.asyncio
async def test_matched_runbook_bases_are_ordered_before_ai() -> None:
    runbook = RunbookExcerpt(
        runbook_id="rb-1", title="RB", section="triage", content="approved"
    )

    recommendation, _ = await FakeAIAdvisor().advise(make_alert(), [runbook])

    assert [item.source for item in recommendation.analysis_bases] == [
        AnalysisBasisSource.RUNBOOK,
        AnalysisBasisSource.AI,
    ]
    assert recommendation.analysis_bases[0].source_ref == RunbookReference(
        runbook_id="rb-1", section="triage"
    )


def test_matched_runbook_auto_repairs_invalid_citations() -> None:
    """manual_matched=True with invalid/missing citations must auto-repair:
    drop invalid RUNBOOK bases, keep AI bases, drop steps without valid source_ref,
    clear invalid runbook_references, and force requires_human=True rather than
    raising AdvisorError."""
    recommendation = Recommendation(
        summary="test",
        analysis_bases=[
            AnalysisBasis(
                source=AnalysisBasisSource.AI,
                statement="AI basis",
            )
        ],
        steps=[RecommendationStep(order=1, action="check")],
        requires_human=True,
        confidence=0.9,
        manual_matched=True,
        runbook_references=[
            RunbookReference(runbook_id="unknown-rb", section="PDF")
        ],
    )
    runbooks = [RunbookExcerpt(runbook_id="rb-1", title="RB", section="PDF", content="approved")]
    result = _validate_manual_policy(recommendation, runbooks)

    # Invalid runbook reference dropped, valid references kept.
    assert result.runbook_references == []

    # AI basis preserved; no RUNBOOK basis (none were valid), but one AI basis
    # ensures the ordering invariant.
    assert [basis.source for basis in result.analysis_bases] == [
        AnalysisBasisSource.AI
    ]

    # Step without valid source_ref dropped.
    assert result.steps == []

    # Repair triggered human review.
    assert result.requires_human is True

    # No AdvisorError raised — that is the new behavior.


def test_unmatched_runbook_with_candidates_degrades_instead_of_raising() -> None:
    """When retrieval returns candidates but the model judges them irrelevant
    (manual_matched=False), policy should NOT raise; it should clear citations,
    force human review, and cap confidence."""
    reference = RunbookReference(runbook_id="rb-1", section="triage")
    recommendation = Recommendation(
        summary="候选手册与本次告警无关",
        analysis_bases=[
            AnalysisBasis(
                source=AnalysisBasisSource.RUNBOOK,
                statement="手册候选",
                source_ref=reference,
            ),
            AnalysisBasis(
                source=AnalysisBasisSource.AI,
                statement="AI basis",
            ),
        ],
        steps=[
            RecommendationStep(
                order=1,
                action="check",
                source_ref=reference,
            )
        ],
        requires_human=False,
        confidence=0.9,
        manual_matched=False,
        runbook_references=[reference],
    )
    runbooks = [RunbookExcerpt(runbook_id="rb-1", title="RB", section="triage", content="approved")]
    result = _validate_manual_policy(recommendation, runbooks)
    assert result.manual_matched is False
    assert result.runbook_references == []
    assert result.requires_human is True
    assert result.confidence <= 0.45
    assert all(step.source_ref is None for step in result.steps)
    runbook_bases = [b for b in result.analysis_bases if b.source == AnalysisBasisSource.RUNBOOK]
    assert all(basis.source_ref is None for basis in runbook_bases)


def test_system_trust_http_client_keeps_tls_verification_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ssl_context = object()
    client = object()
    captured: dict[str, object] = {}

    monkeypatch.setattr(ai_module.ssl, "create_default_context", lambda: ssl_context)

    def build_client(**kwargs: object) -> object:
        captured.update(kwargs)
        return client

    monkeypatch.setattr(ai_module.httpx, "AsyncClient", build_client)

    assert ai_module._system_trust_http_client(17) is client
    assert captured["verify"] is ssl_context
    assert captured["trust_env"] is True
    assert captured["timeout"].connect == 17  # type: ignore[union-attr]


def test_real_ai_clients_use_system_trust_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http_client = object()
    constructed: list[dict[str, object]] = []
    timeout_values: list[float] = []

    def build_http_client(timeout_seconds: float) -> object:
        timeout_values.append(timeout_seconds)
        return http_client

    class CapturingAsyncOpenAI:
        def __init__(self, **kwargs: object) -> None:
            constructed.append(kwargs)

    monkeypatch.setattr(ai_module, "_system_trust_http_client", build_http_client)
    monkeypatch.setattr(ai_module, "AsyncOpenAI", CapturingAsyncOpenAI)

    ai_module.OpenAICompatibleAdvisor(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="test-model",
        timeout_seconds=19,
        max_retries=2,
        json_mode=True,
    )
    ai_module.OpenAICompatibleConclusionValidator(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="test-model",
        timeout_seconds=23,
        max_retries=2,
    )

    assert timeout_values == [19, 23]
    assert [item["http_client"] for item in constructed] == [http_client, http_client]
    assert [item["default_headers"] for item in constructed] == [
        {"User-Agent": ai_module.AI_HTTP_USER_AGENT},
        {"User-Agent": ai_module.AI_HTTP_USER_AGENT},
    ]


@pytest.mark.asyncio
async def test_real_ai_adapters_close_their_owned_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []
    constructed: list[str] = []

    class ClosingAsyncOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.kind = "advisor" if not constructed else "validator"
            constructed.append(self.kind)

        async def close(self) -> None:
            closed.append(self.kind)

    monkeypatch.setattr(ai_module, "_system_trust_http_client", lambda _: object())
    monkeypatch.setattr(ai_module, "AsyncOpenAI", ClosingAsyncOpenAI)

    advisor = ai_module.OpenAICompatibleAdvisor(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="test-model",
        timeout_seconds=19,
        max_retries=2,
        json_mode=True,
    )
    validator = ai_module.OpenAICompatibleConclusionValidator(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="test-model",
        timeout_seconds=19,
        max_retries=2,
    )

    await advisor.aclose()
    await validator.aclose()

    assert closed == ["advisor", "validator"]