import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

import app.adapters.ai as ai_module
from app.adapters.ai import (
    ConservativeFallbackAdvisor,
    FakeAIAdvisor,
    _validate_manual_policy,
)
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.domain.errors import AdvisorError
from app.domain.models import (
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
    AnalysisBasis,
    AnalysisBasisSource,
    EvidenceRecord,
    ExternalKnowledgeExcerpt,
    ExternalKnowledgeReference,
    InvestigationRun,
    Recommendation,
    RecommendationStep,
    RunbookExcerpt,
    RunbookReference,
    RunbookVisualEvidence,
    ToolStatus,
)


def make_alert():
    return CanonicalAlertSourceAdapter().normalize(
        {"severity": "WARNING", "title": "Unclassified issue", "reason": "unclassified_reason"}
    )


def test_prompts_use_successful_archery_logs_without_endpoint_comparison() -> None:
    assert "结果包含可解析日志" in ai_module.SYSTEM_PROMPT
    assert "partial 不为 true" in ai_module.SYSTEM_PROMPT
    assert "不得比较告警标题端点与 hostname_max" in ai_module.SYSTEM_PROMPT
    assert "不得输出 instance_id 归属核验" in ai_module.SYSTEM_PROMPT
    assert "instance_identity_verification.status=MATCHED" not in (ai_module.SYSTEM_PROMPT)
    assert "不得比较告警标题端点与 hostname_max" in ai_module.VALIDATION_PROMPT
    assert "analysis_contract_passed 必须为 false" in ai_module.VALIDATION_PROMPT
    assert "target_verification=mismatch" in ai_module.SYSTEM_PROMPT
    assert "target_verification=mismatch" in ai_module.VALIDATION_PROMPT


def test_system_prompt_requires_chinese_user_facing_recommendations() -> None:
    assert "最终面向用户的自然语言必须使用简体中文" in ai_module.SYSTEM_PROMPT
    assert "不得输出英文推理过程、计算草稿" in ai_module.SYSTEM_PROMPT
    assert "指标名" in ai_module.SYSTEM_PROMPT
    assert "数据库对象名" in ai_module.SYSTEM_PROMPT


def test_prompts_form_final_causes_only_after_reviewing_live_evidence() -> None:
    assert "知识匹配和全部实时证据采集已经结束后工作" in ai_module.SYSTEM_PROMPT
    assert "必须一次性完整审阅这些输入之后才分析根因" in ai_module.SYSTEM_PROMPT
    assert "不得构造或展示待验证原因、假设" in ai_module.SYSTEM_PROMPT
    assert "status 必须为 SUPPORTED" in ai_module.SYSTEM_PROMPT
    assert "现有结果无法得出根因" in ai_module.SYSTEM_PROMPT
    assert "不得为新结果使用 SUPPORT、UNKNOWN 或 CONTRADICTED" in (
        ai_module.SYSTEM_PROMPT
    )
    assert not hasattr(ai_module.OpenAICompatibleAdvisor, "choose_next_tool")
    assert "合法结果只有两种" in ai_module.VALIDATION_PROMPT


def test_prompts_treat_partial_success_as_descriptive_missing_evidence() -> None:
    assert "NO_DATA 或部分结果只是证据缺失" in ai_module.SYSTEM_PROMPT
    assert "只能把完整原始返回转换为可追溯的结构化事实、异常与限制" in (
        ai_module.SYSTEM_PROMPT
    )
    assert "不得提出、选择或判断根因" in ai_module.SYSTEM_PROMPT
    assert "只有你这个主 Agent" in ai_module.SYSTEM_PROMPT
    assert "宿主依据状态、完整性、来源绑定和可追溯性设置的机械接纳门禁" in (
        ai_module.SYSTEM_PROMPT
    )
    assert "structured_data.partial 不为 true" in ai_module.SYSTEM_PROMPT
    assert "partial" in ai_module.VALIDATION_PROMPT
    assert "大结果子 Agent 只能提供可追溯的结构化事实、异常与限制" in (
        ai_module.VALIDATION_PROMPT
    )
    assert "不是因果结论" in ai_module.VALIDATION_PROMPT
    assert "analysis_contract_passed 必须为 false" in ai_module.VALIDATION_PROMPT


@pytest.mark.asyncio
async def test_fake_advisor_returns_fixed_no_cause_for_partial_success() -> None:
    evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_archery_slow_logs",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="已返回部分慢日志，可用于描述当前监控上下文。",
        structured_data={
            "partial": True,
            "query_completed": True,
            "root_cause_eligible": True,
            "allow_followup_dispatch": False,
        },
    )

    recommendation, _ = await FakeAIAdvisor().advise(
        make_alert(),
        [],
        evidence=[evidence],
    )

    assert recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert recommendation.root_causes == []
    assert recommendation.likely_causes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("advisor", [FakeAIAdvisor(), ConservativeFallbackAdvisor()])
async def test_deterministic_advisors_ignore_legacy_investigation_memory(
    advisor: FakeAIAdvisor,
) -> None:
    recommendation, _ = await advisor.advise(
        make_alert(),
        [],
        investigation_memory=None,
    )

    assert recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert recommendation.root_causes == []
    assert recommendation.likely_causes == []


@pytest.mark.asyncio
async def test_no_runbook_forces_low_confidence() -> None:
    recommendation, _ = await FakeAIAdvisor().advise(make_alert(), [])
    assert recommendation.manual_matched is False
    assert recommendation.confidence <= 0.45
    assert recommendation.runbook_references == []
    assert [item.source for item in recommendation.analysis_bases] == [AnalysisBasisSource.AI]


@pytest.mark.asyncio
async def test_real_advisor_preserves_application_knowledge_match_summary() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    model_response = Recommendation(
        summary="Model analysis",
        knowledge_match_summary="model-overwritten-value",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI basis")],
        steps=[RecommendationStep(order=1, action="check read-only metrics")],
        confidence=0.3,
        manual_matched=False,
    )

    async def complete(messages):  # type: ignore[no-untyped-def]
        return model_response.model_dump_json(), object()

    advisor._complete = complete
    expected = "匹配本地pdf失败，pdf中没有该类型告警的处理方法"

    recommendation, _ = await advisor.advise(
        make_alert(),
        [],
        knowledge_match_summary=expected,
    )

    assert recommendation.knowledge_match_summary == expected


@pytest.mark.asyncio
async def test_advisor_removes_slow_query_filter_note_from_model_payload() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    captured_payload: dict[str, object] = {}
    signal = "五分钟内慢查询触发值为646个"
    raw_text = f"{signal}（已排除640个数据库管理平台采集数据用sql）"
    alert = make_alert().model_copy(
        update={
            "title": "MySQL slow_query threshold",
            "reason": raw_text,
            "description": raw_text,
            "labels": {"check": raw_text},
            "raw_payload": {"reason": raw_text},
        }
    )
    evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="alert_context",
        source_system="alert_platform",
        status=ToolStatus.SUCCESS,
        summary=raw_text,
        structured_data={"flashduty": {"alert": {"description": raw_text}}},
    )
    model_response = Recommendation(
        summary="证据不足，需继续核查。",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI 分析依据")],
        steps=[RecommendationStep(order=1, action="执行只读核查")],
        confidence=0.3,
        manual_matched=False,
    )

    async def complete(messages):  # type: ignore[no-untyped-def]
        captured_payload.update(json.loads(messages[1]["content"]))
        return model_response.model_dump_json(), object()

    advisor._complete = complete

    await advisor.advise(alert, [], evidence=[evidence])

    serialized = json.dumps(captured_payload, ensure_ascii=False)
    assert "数据库管理平台采集数据用" not in serialized
    assert captured_payload["alert"]["reason"] == signal  # type: ignore[index]
    assert captured_payload["tool_evidence"][0]["summary"] == signal  # type: ignore[index]


@pytest.mark.asyncio
async def test_fake_advisor_does_not_copy_slow_query_filter_note_into_cause() -> None:
    signal = "五分钟内慢查询触发值为646个"
    raw_text = f"{signal}（已排除640个数据库管理平台采集数据用sql）"
    alert = make_alert().model_copy(update={"reason": raw_text})

    recommendation, _ = await FakeAIAdvisor().advise(alert, [])

    assert recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert recommendation.root_causes == []
    assert recommendation.likely_causes == []


@pytest.mark.asyncio
async def test_advisor_repair_repeats_chinese_output_requirement() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    repair_prompt = ""
    valid_response = Recommendation(
        summary="中文分析结果",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI 分析依据")],
        steps=[RecommendationStep(order=1, action="执行只读核查")],
        confidence=0.3,
        manual_matched=False,
    )
    calls = 0

    async def complete(messages):  # type: ignore[no-untyped-def]
        nonlocal calls, repair_prompt
        calls += 1
        if calls == 1:
            return "not-json", object()
        repair_prompt = messages[-1]["content"]
        return valid_response.model_dump_json(), object()

    advisor._complete = complete

    await advisor.advise(make_alert(), [])

    assert "中文最终输出规则" in repair_prompt
    assert "所有面向用户的自然语言字段使用简体中文" in repair_prompt


@pytest.mark.asyncio
async def test_advisor_repairs_archery_endpoint_comparison() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    invalid = Recommendation(
        summary=(
            "Archery 慢日志查询因实例 IP 定位偏差（查询了 100.84.97.139:3306 "
            "而非告警目标实例）未能获取有效慢日志证据。"
        ),
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI 分析依据")],
        steps=[RecommendationStep(order=1, action="执行只读核查")],
        confidence=0.3,
        manual_matched=False,
    )
    repaired = invalid.model_copy(update={"summary": "Archery 慢日志证据不足，需继续只读核查。"})
    calls = 0
    repair_prompt = ""

    async def complete(messages):  # type: ignore[no-untyped-def]
        nonlocal calls, repair_prompt
        calls += 1
        if calls == 1:
            return invalid.model_dump_json(), object()
        repair_prompt = messages[-1]["content"]
        return repaired.model_dump_json(), object()

    advisor._complete = complete

    recommendation, _ = await advisor.advise(make_alert(), [])

    assert recommendation.summary == repaired.summary
    assert "must not compare Archery query endpoints" in repair_prompt


@pytest.mark.asyncio
async def test_advisor_rejects_archery_endpoint_comparison_after_repair() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    invalid = Recommendation(
        summary="Archery 查询的实例与告警目标不一致，因此慢日志无效。",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI 分析依据")],
        steps=[RecommendationStep(order=1, action="执行只读核查")],
        confidence=0.3,
        manual_matched=False,
    )

    async def complete(messages):  # type: ignore[no-untyped-def]
        del messages
        return invalid.model_dump_json(), object()

    advisor._complete = complete

    with pytest.raises(AdvisorError, match="invalid after repair"):
        await advisor.advise(make_alert(), [])


@pytest.mark.asyncio
async def test_advisor_payload_omits_runbook_quality_and_review_states() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    captured_payload: dict[str, object] = {}
    model_response = Recommendation(
        summary="No semantic match",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI basis")],
        steps=[RecommendationStep(order=1, action="check read-only metrics")],
        confidence=0.3,
        manual_matched=False,
    )

    async def complete(messages):  # type: ignore[no-untyped-def]
        captured_payload.update(json.loads(messages[1]["content"]))
        return model_response.model_dump_json(), object()

    advisor._complete = complete
    runbook = RunbookExcerpt(
        runbook_id="rb-1",
        title="Replica guide",
        section="triage",
        content="Check replica apply rate.",
        visual_evidence=[
            RunbookVisualEvidence(
                page=1,
                kind="screenshot",
                text="Replica apply rate chart",
            )
        ],
    )

    await advisor.advise(make_alert(), [runbook])

    excerpt = captured_payload["runbook_excerpts"][0]  # type: ignore[index]
    assert "quality_status" not in excerpt
    assert "review_status" not in excerpt["visual_evidence"][0]


@pytest.mark.asyncio
async def test_matched_runbook_bases_are_ordered_before_ai() -> None:
    runbook = RunbookExcerpt(
        runbook_id="rb-1",
        title="RB",
        section="triage",
        content="diagnostic guidance",
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
    clear invalid runbook_references, and lower confidence rather than raising
    AdvisorError."""
    recommendation = Recommendation(
        summary="test",
        analysis_bases=[
            AnalysisBasis(
                source=AnalysisBasisSource.AI,
                statement="AI basis",
            )
        ],
        steps=[RecommendationStep(order=1, action="check")],
        confidence=0.9,
        manual_matched=True,
        runbook_references=[RunbookReference(runbook_id="unknown-rb", section="PDF")],
    )
    runbooks = [
        RunbookExcerpt(
            runbook_id="rb-1",
            title="RB",
            section="PDF",
            content="diagnostic guidance",
        )
    ]
    result = _validate_manual_policy(recommendation, runbooks)

    # Invalid runbook reference dropped, valid references kept.
    assert result.runbook_references == []

    # AI basis preserved; no RUNBOOK basis (none were valid), but one AI basis
    # ensures the ordering invariant.
    assert [basis.source for basis in result.analysis_bases] == [AnalysisBasisSource.AI]

    # Step without valid source_ref dropped.
    assert result.steps == []

    # No AdvisorError raised — that is the new behavior.


def test_unmatched_runbook_with_candidates_degrades_instead_of_raising() -> None:
    """When retrieval returns candidates but the model judges them irrelevant
    (manual_matched=False), policy should NOT raise; it should clear citations,
    and cap confidence."""
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
        confidence=0.9,
        manual_matched=False,
        runbook_references=[reference],
    )
    runbooks = [
        RunbookExcerpt(
            runbook_id="rb-1",
            title="RB",
            section="triage",
            content="diagnostic guidance",
        )
    ]
    result = _validate_manual_policy(recommendation, runbooks)
    assert result.manual_matched is False
    assert result.runbook_references == []
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
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=EmptyCompletions()))
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
async def test_advisor_requests_one_selected_mcp_tool_call() -> None:
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
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=ToolCompletions()))
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
    discovery_tool = {
        "type": "function",
        "function": {
            "name": "list_instances_gymJPA",
            "parameters": {
                "type": "object",
                "properties": {"instance_ref": {"type": "string"}},
            },
        },
    }
    tools = [tool, discovery_tool]

    result = await advisor.request_mcp_tool_call(
        messages=[{"role": "user", "content": "confirm login"}],
        tools=tools,
    )

    assert result.name == "ensure_login_gymJPA"
    assert result.arguments == {}
    assert result.call_id == "tool-call-1"
    assert result.request_id == "model-tool-request-1"
    assert calls[0]["tools"] == tools
    assert calls[0]["tool_choice"] == "required"
    assert calls[0]["parallel_tool_calls"] is False
    assert "response_format" not in calls[0]


@pytest.mark.asyncio
async def test_advisor_accepts_one_harness_call_tool_action_from_text_content() -> None:
    action = {
        "action": "call_tool",
        "tool_name": "sql_query_gymJPA",
        "objective": "Collect read-only Archery evidence for the fixed alert window",
        "hypothesis_ids": ["slow_query_evidence"],
        "arguments": {
            "db_name": "archery",
            "instance_id": 17,
            "limit_num": 10,
            "sql_content": (
                "SELECT id, instance_name, host, port FROM sql_instance "
                "WHERE id = 3 LIMIT 10"
            ),
        },
    }

    class TextActionCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="text-action-request-1",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(
                            content=json.dumps(action),
                            tool_calls=[],
                        ),
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=TextActionCompletions())
    )
    tool = {
        "type": "function",
        "function": {
            "name": "sql_query_gymJPA",
            "parameters": {"type": "object"},
        },
    }

    first = await advisor.request_mcp_tool_call(messages=[], tools=[tool])
    second = await advisor.request_mcp_tool_call(messages=[], tools=[tool])

    assert first.name == "sql_query_gymJPA"
    assert first.arguments == action["arguments"]
    assert first.request_id == "text-action-request-1"
    assert first.call_id.startswith("agent-action-")
    assert second.call_id == first.call_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        json.dumps(
            {
                "action": "finish",
                "reason": "COMPLETED",
                "summary": "No more evidence is required.",
            }
        ),
        json.dumps(
            {
                "action": "call_tool",
                "tool_name": "monitoring_query",
                "objective": "Collect evidence",
                "hypothesis_ids": [],
                "arguments": [],
            }
        ),
        'result: {"action":"call_tool"}',
    ],
)
async def test_advisor_rejects_non_call_tool_text_actions(content: str) -> None:
    class InvalidTextActionCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="invalid-text-action-request",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(content=content, tool_calls=[]),
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=InvalidTextActionCompletions())
    )

    with pytest.raises(AdvisorError, match="exactly one MCP tool call"):
        await advisor.request_mcp_tool_call(
            messages=[],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "monitoring_query",
                        "parameters": {"type": "object"},
                    },
                }
            ],
        )


@pytest.mark.asyncio
async def test_advisor_rejects_unavailable_tool_in_text_action() -> None:
    content = json.dumps(
        {
            "action": "call_tool",
            "tool_name": "write_database",
            "objective": "Change the database",
            "hypothesis_ids": [],
            "arguments": {},
        }
    )

    class UnknownToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="unknown-text-tool-request",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(content=content, tool_calls=[]),
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=UnknownToolCompletions())
    )

    with pytest.raises(AdvisorError, match="selected an unavailable MCP tool"):
        await advisor.request_mcp_tool_call(
            messages=[],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "monitoring_query",
                        "parameters": {"type": "object"},
                    },
                }
            ],
        )


@pytest.mark.asyncio
async def test_advisor_does_not_use_text_fallback_for_multiple_native_tool_calls() -> None:
    content = json.dumps(
        {
            "action": "call_tool",
            "tool_name": "monitoring_query",
            "objective": "Collect evidence",
            "hypothesis_ids": [],
            "arguments": {},
        }
    )
    raw_call = SimpleNamespace(
        id="native-call",
        function=SimpleNamespace(name="monitoring_query", arguments="{}"),
    )

    class MultipleToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="multiple-tool-request",
                choices=[
                    SimpleNamespace(
                        finish_reason="tool_calls",
                        message=SimpleNamespace(
                            content=content,
                            tool_calls=[raw_call, raw_call],
                        ),
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=MultipleToolCompletions())
    )

    with pytest.raises(AdvisorError, match="count=2"):
        await advisor.request_mcp_tool_call(
            messages=[],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "monitoring_query",
                        "parameters": {"type": "object"},
                    },
                }
            ],
        )


@pytest.mark.asyncio
async def test_advisor_mcp_tool_error_exposes_safe_upstream_diagnostics() -> None:
    secret = "provider-secret-that-must-not-appear"

    class APIStatusError(Exception):
        status_code = 422
        request_id = "gateway-request-123"
        code = "unsupported_tools"
        body = {
            "error": {
                "message": f"tools are unsupported; token={secret}",
                "api_key": secret,
            }
        }

    class FailingCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            raise APIStatusError(f"Authorization: Bearer {secret}")

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=FailingCompletions()))
    tool = {
        "type": "function",
        "function": {"name": "monitoring_query", "parameters": {"type": "object"}},
    }

    with pytest.raises(AdvisorError) as caught:
        await advisor.request_mcp_tool_call(
            messages=[{"role": "user", "content": "never expose this prompt"}],
            tools=[tool],
        )

    error = str(caught.value)
    assert "AI provider MCP tool request failed" in error
    assert "type=APIStatusError" in error
    assert "status_code=422" in error
    assert "request_id=gateway-request-123" in error
    assert "code=unsupported_tools" in error
    assert "***REDACTED***" in error
    assert secret not in error
    assert "never expose this prompt" not in error


@pytest.mark.asyncio
async def test_advisor_mcp_missing_tool_call_preserves_safe_response_shape() -> None:
    secret = "provider-response-secret"

    class TextOnlyCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="text-only-tool-request",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(
                            content=f"工具预算已经用完。token={secret}",
                            tool_calls=[],
                            model_extra={"reasoning_content": "internal reasoning"},
                        ),
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=TextOnlyCompletions()))

    with pytest.raises(AdvisorError) as caught:
        await advisor.request_mcp_tool_call(
            messages=[{"role": "user", "content": "select one tool"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "monitoring_query",
                        "parameters": {"type": "object"},
                    },
                }
            ],
        )

    error = str(caught.value)
    assert "request_id=text-only-tool-request" in error
    assert "count=0" in error
    assert "finish_reason=stop" in error
    assert "content_chars=" in error
    assert "工具预算已经用完" in error
    assert "reasoning_chars=18" in error
    assert "***REDACTED***" in error
    assert secret not in error


@pytest.mark.asyncio
async def test_advisor_no_choices_error_contains_request_shape() -> None:
    class NoChoiceCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(id="no-choice-request-1", choices=[], usage=None)

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._model = "shared-analysis-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = True
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=NoChoiceCompletions()))

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
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                usage=None,
            )

    validator = object.__new__(ai_module.OpenAICompatibleConclusionValidator)
    validator._model = "shared-analysis-model"
    validator._max_tokens = 16_384
    validator._json_mode = True
    validator._client = SimpleNamespace(chat=SimpleNamespace(completions=CapturingCompletions()))
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
