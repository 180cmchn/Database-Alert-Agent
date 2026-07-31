import json
from types import SimpleNamespace

import pytest

import app.adapters.ai as ai_module
from app.adapters.ai import FakeAIAdvisor, _validate_manual_policy
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.domain.errors import AdvisorError
from app.domain.models import (
    AnalysisBasis,
    AnalysisBasisSource,
    ExternalKnowledgeExcerpt,
    ExternalKnowledgeReference,
    InvestigationRun,
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


def test_external_knowledge_reference_metadata_is_restored_from_retrieval() -> None:
    external = ExternalKnowledgeExcerpt(
        knowledge_id="external-1",
        title="Replica guide",
        content="Check replica apply rate.",
        source_uri="file://replica.md",
        score=0.9,
        raw_score=0.1,
    )
    recommendation = Recommendation(
        summary="test",
        analysis_bases=[
            AnalysisBasis(
                source=AnalysisBasisSource.EXTERNAL_KNOWLEDGE,
                statement="External basis",
                source_ref=ExternalKnowledgeReference(
                    knowledge_id="external-1",
                    title="altered title",
                    source_uri="https://untrusted.invalid",
                ),
            ),
            AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI basis"),
        ],
        steps=[
            RecommendationStep(
                order=1,
                action="check",
                source_ref=ExternalKnowledgeReference(
                    knowledge_id="external-1",
                    title="altered title",
                    source_uri="https://untrusted.invalid",
                ),
            )
        ],
        requires_human=False,
        confidence=0.8,
        manual_matched=False,
    )

    result = _validate_manual_policy(recommendation, [], [external])

    exact = ExternalKnowledgeReference(
        knowledge_id=external.knowledge_id,
        title=external.title,
        source_uri=external.source_uri,
    )
    assert result.analysis_bases[0].source_ref == exact
    assert result.steps[0].source_ref == exact
    assert result.requires_human is True
    assert result.confidence == 0.8


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
        max_tokens=16_384,
        timeout_seconds=19,
        max_retries=2,
        json_mode=True,
    )
    ai_module.OpenAICompatibleConclusionValidator(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="test-model",
        max_tokens=16_384,
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
        max_tokens=16_384,
        timeout_seconds=19,
        max_retries=2,
        json_mode=True,
    )
    validator = ai_module.OpenAICompatibleConclusionValidator(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="test-model",
        max_tokens=16_384,
        timeout_seconds=19,
        max_retries=2,
    )

    await advisor.aclose()
    await validator.aclose()

    assert closed == ["advisor", "validator"]


@pytest.mark.asyncio
async def test_advisor_empty_content_error_contains_only_safe_response_metadata() -> None:
    prompt_secret = "prompt-secret-that-must-not-be-logged"
    reasoning_secret = "reasoning-secret-that-must-not-be-logged"
    calls: list[dict[str, object]] = []

    class EmptyCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(
                id="empty-request-1",
                choices=[
                    SimpleNamespace(
                        finish_reason="length",
                        message=SimpleNamespace(
                            content="",
                            reasoning_content=reasoning_secret,
                            model_extra={
                                "reasoning_content": reasoning_secret,
                                "provider_trace": "trace-secret-that-must-not-be-logged",
                            },
                        ),
                    )
                ],
                usage=SimpleNamespace(
                    model_dump=lambda: {
                        "prompt_tokens": 321,
                        "completion_tokens": 654,
                        "total_tokens": 975,
                    }
                ),
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._model = "shared-analysis-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = False
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=EmptyCompletions())
    )
    messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": prompt_secret},
    ]

    with pytest.raises(AdvisorError) as caught:
        await advisor._complete(messages)

    error = str(caught.value)
    assert calls[0]["max_tokens"] == 16_384
    assert "AI provider returned empty content" in error
    assert "request_id=empty-request-1" in error
    assert "finish_reason=length" in error
    assert f"input_chars={len('system') + len(prompt_secret)}" in error
    assert f"reasoning_chars={len(reasoning_secret)}" in error
    assert "extra_keys=['provider_trace', 'reasoning_content']" in error
    assert "max_tokens=16384" in error
    assert "json_mode=False" in error
    assert "'prompt_tokens': 321" in error
    assert prompt_secret not in error
    assert reasoning_secret not in error
    assert "trace-secret-that-must-not-be-logged" not in error


@pytest.mark.asyncio
async def test_advisor_requests_one_forced_mcp_tool_call() -> None:
    calls: list[dict[str, object]] = []

    class ToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(
                id="model-tool-request-1",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            tool_calls=[
                                SimpleNamespace(
                                    id="tool-call-1",
                                    function=SimpleNamespace(
                                        name="ensure_login_gymJPA",
                                        arguments="{}",
                                    ),
                                )
                            ]
                        )
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=ToolCompletions())
    )
    tool = {
        "type": "function",
        "function": {
            "name": "ensure_login_gymJPA",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    }

    result = await advisor.request_mcp_tool_call(
        messages=[{"role": "user", "content": "confirm login"}],
        tool=tool,
    )

    assert result.name == "ensure_login_gymJPA"
    assert result.arguments == {}
    assert result.call_id == "tool-call-1"
    assert result.request_id == "model-tool-request-1"
    assert calls[0]["tools"] == [tool]
    assert calls[0]["tool_choice"] == {
        "type": "function",
        "function": {"name": "ensure_login_gymJPA"},
    }
    assert "response_format" not in calls[0]


@pytest.mark.asyncio
async def test_advisor_no_choices_error_contains_request_shape() -> None:
    class NoChoiceCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(id="no-choice-request-1", choices=[], usage=None)

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._model = "shared-analysis-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = True
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=NoChoiceCompletions())
    )

    with pytest.raises(AdvisorError) as caught:
        await advisor._complete([{"role": "user", "content": "hello"}])

    assert str(caught.value) == (
        "AI provider returned no choices "
        "(request_id=no-choice-request-1, input_chars=5, "
        "max_tokens=16384, json_mode=True)"
    )


@pytest.mark.asyncio
async def test_conclusion_validator_uses_same_model_and_strict_output_schema() -> None:
    calls: list[dict[str, object]] = []

    class CapturingCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            content = json.dumps(
                {
                    "analysis_contract_passed": True,
                    "evidence_sufficient": False,
                    "issues": [],
                }
            )
            return SimpleNamespace(
                id="validation-request-1",
                choices=[
                    SimpleNamespace(message=SimpleNamespace(content=content))
                ],
                usage=None,
            )

    validator = object.__new__(ai_module.OpenAICompatibleConclusionValidator)
    validator._model = "shared-analysis-model"
    validator._max_tokens = 16_384
    validator._json_mode = True
    validator._client = SimpleNamespace(
        chat=SimpleNamespace(completions=CapturingCompletions())
    )
    alert = make_alert()
    recommendation, _ = await FakeAIAdvisor().advise(alert, [])
    run = InvestigationRun(alert_id=alert.id)

    result = await validator.validate(run, alert, recommendation, [], [])

    assert result.passed is True
    assert result.evidence_sufficient is False
    assert result.issues == []
    assert result.metadata["model"] == "shared-analysis-model"
    assert result.metadata["prompt_version"].endswith("validation-v2")
    assert len(calls) == 1
    assert calls[0]["model"] == "shared-analysis-model"
    assert calls[0]["temperature"] == 0
    assert calls[0]["max_tokens"] == 16_384
    response_format = calls[0]["response_format"]
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"
    json_schema = response_format["json_schema"]
    assert isinstance(json_schema, dict)
    assert json_schema["strict"] is True
    schema = json_schema["schema"]
    assert isinstance(schema, dict)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "analysis_contract_passed",
        "evidence_sufficient",
        "issues",
    }
