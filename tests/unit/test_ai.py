import asyncio
import json
from types import SimpleNamespace
from uuid import uuid4

import httpx
import openai
import pytest

import app.adapters.ai as ai_module
from app.adapters.ai import (
    FakeAIAdvisor,
    _validate_knowledge_policy,
)
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.tool_result_analysis import DeterministicToolResultProcessor
from app.agent_runtime.contracts import ArtifactRef
from app.domain.errors import AdvisorError
from app.domain.models import (
    EVIDENCE_RECORD_V2,
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
    AnalysisBasis,
    AnalysisBasisSource,
    EvidenceRecord,
    EvidenceUnit,
    EvidenceUnitKind,
    EvidenceUnitStatus,
    KnowledgeExcerpt,
    KnowledgeReference,
    Recommendation,
    RecommendationStep,
    ToolStatus,
)


def test_v2_model_evidence_dto_exposes_units_without_internal_artifact_identity() -> None:
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery projection",
        structured_data={
            "root_cause_eligible": False,
            "tool_result_analysis": {
                "summary": "Projection",
                "observations": [],
                "anomalies": [],
                "limitations": [],
                "analysis_usable": True,
                "source_coverage_complete": True,
                "provider": "deterministic_host",
                "model": "none",
                "prompt_version": "test-v1",
                "passthrough_payload": {"rows": [{"id": 41}]},
                "slow_query_analysis": {"status": "failed"},
            },
        },
    )
    artifact_id = uuid4()
    history = EvidenceUnit(
        id=EvidenceUnit.build_id(parent.id, "history"),
        parent_evidence_id=parent.id,
        unit_key="history",
        kind=EvidenceUnitKind.HISTORY,
        stage="history",
        status=EvidenceUnitStatus.SUCCESS,
        summary="History complete",
        data={"rows": [{"id": 41}]},
        root_cause_eligible=True,
        source_artifact_id=artifact_id,
        source_paths=["/structured_data/final_result_payload"],
    )
    parent = parent.model_copy(
        update={
            "contract_version": EVIDENCE_RECORD_V2,
            "source_artifact_id": artifact_id,
            "evidence_units": [history],
        }
    )

    payload = ai_module._model_evidence_payload(parent)

    assert payload["contract_version"] == EVIDENCE_RECORD_V2
    assert payload["evidence_units"][0]["id"] == str(history.id)
    assert payload["evidence_units"][0]["parent_evidence_id"] == str(parent.id)
    assert payload["evidence_units"][0]["data"] == {"rows": [{"id": 41}]}
    analysis = payload["structured_data"]["tool_result_analysis"]
    assert "passthrough_payload" not in analysis
    assert "slow_query_analysis" not in analysis
    assert str(artifact_id) not in json.dumps(payload)


@pytest.mark.asyncio
async def test_prometheus_model_evidence_dto_preserves_public_metric_identity_only() -> None:
    artifact_id = uuid4()
    artifact = ArtifactRef(
        artifact_id=artifact_id,
        kind="raw_tool_result",
        uri=f"agent-artifact://{artifact_id}",
        sha256="b" * 64,
        size_bytes=10_000,
    )
    secret = "raw-prometheus-secret"
    window_end = "2026-08-13T08:00:00+00:00"
    analysis = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "schema_version": "prometheus-evidence-v5",
                "window_start": "2026-08-13T07:55:00+00:00",
                "window_end": window_end,
                "required_target": {
                    "database_engine": "mysql",
                    "host": "mysql-17",
                    "port": 3306,
                },
                "monitoring_results": [
                    {
                        "tool_name": "query_range",
                        "projection_kind": "alert_window_range",
                        "projection": {
                            "projection_kind": "alert_window_range",
                            "window": {
                                "start": "2026-08-13T07:55:00+00:00",
                                "end": window_end,
                            },
                            "target_match": {
                                "matched": True,
                                "authoritative_fields": [
                                    "database.host",
                                    "database.endpoint",
                                ],
                            },
                            "timeseries": {
                                "has_numeric_samples": True,
                                "series_count": 1,
                                "sample_count": 2,
                                "series": [
                                    {
                                        "metric": {
                                            "__name__": "mysql:all_server_status:all",
                                            "metric": "threads_connected",
                                            "artifact_uri": f"agent-artifact://{secret}",
                                        },
                                        "value_semantics": "raw",
                                        "sample_count": 2,
                                        "min": 3,
                                        "max": 5,
                                        "avg": 4,
                                        "latest": 5,
                                        "delta": 2,
                                    }
                                ],
                                "omitted_series_count": 0,
                                "excluded_metric_identity_missing_count": 0,
                                "excluded_metric_identity_collision_count": 0,
                            },
                        },
                    },
                    {
                        "tool_name": "list_targets",
                        "projection_kind": "auxiliary",
                        "raw_response": {"authorization": secret},
                    },
                ],
                "range_query_success_count": 1,
                "range_query_empty_count": 0,
            },
        },
        artifact=artifact,
    )
    evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        status=ToolStatus.SUCCESS,
        summary=analysis.summary,
        structured_data={
            "root_cause_eligible": True,
            "tool_result_analysis": analysis.model_dump(
                mode="json",
                exclude={"source_artifact_id", "source_sha256"},
            ),
        },
    )

    payload = ai_module._model_evidence_payload(evidence)
    tool_analysis = payload["structured_data"]["tool_result_analysis"]
    metric_statement = next(
        item["statement"]
        for item in tool_analysis["observations"]
        if "时序聚合" in item["statement"]
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert '"__name__":"mysql:all_server_status:all"' in metric_statement
    assert '"metric":"threads_connected"' in metric_statement
    assert '"value_semantics":"raw"' in metric_statement
    assert secret not in serialized
    assert "agent-artifact://" not in serialized
    assert str(artifact_id) not in serialized


def make_alert():
    return CanonicalAlertSourceAdapter().normalize(
        {"severity": "WARNING", "title": "Unclassified issue", "reason": "unclassified_reason"}
    )


def test_prompts_use_successful_archery_logs_without_endpoint_comparison() -> None:
    assert "程序只把 result 文本内嵌 JSON 按" in ai_module.SYSTEM_PROMPT
    assert "column_list 更改格式为 JSON" in ai_module.SYSTEM_PROMPT
    assert "不删改内容、不过滤、不聚合、不排序、不设大小限制" in ai_module.SYSTEM_PROMPT
    assert "后续只按完整时序项做机械限量" in ai_module.SYSTEM_PROMPT
    assert "不得输出 instance_id 归属核验" in ai_module.SYSTEM_PROMPT
    prompt = ai_module.SYSTEM_PROMPT.replace("\n", "")
    assert "证据与告警实例的归属已由程序保障" in prompt
    assert "与 hostname_max 不同属于预期现象" in prompt
    assert "不得把一致与否作为采纳、降级或拒绝任何证据的条件" in prompt
    assert "instance_identity_verification.status=MATCHED" not in (ai_module.SYSTEM_PROMPT)
    assert "target_verification" not in ai_module.SYSTEM_PROMPT


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
    assert "不得为新结果使用 SUPPORT、UNKNOWN 或 CONTRADICTED" in (ai_module.SYSTEM_PROMPT)


def test_final_recommendations_are_actionable_without_repeating_mcp_checks() -> None:
    prompt = ai_module.SYSTEM_PROMPT.replace("\n", "")
    assert "steps 必须给出能够直接消除根因、恢复服务或降低影响的实际处置动作" in prompt
    assert "允许在证据支持时建议终止指定查询或会话" in prompt
    assert "不得把 tool_evidence 已完成的指标、日志、实例或数据库核查再次交给 DBA" in prompt
    assert "root_causes=[]、likely_causes=[]、steps=[]" in prompt
    assert "steps 仅允许只读核查" not in prompt
    assert "所有工具调用都必须保持只读" in ai_module.REACT_PROMPT
    assert not hasattr(ai_module.OpenAICompatibleAdvisor, "choose_next_tool")


def test_final_conclusion_requires_auditable_sql_and_explain_details() -> None:
    prompt = ai_module.SYSTEM_PROMPT.replace("\n", "")

    assert ai_module.PROMPT_VERSION == "database-alert-advisor-v27"
    assert "root_causes 是前端“AI 分析结论”的唯一正文" in prompt
    assert "analysis_process 至少包含一项" in prompt
    assert "事实 → 推导" in prompt
    assert "完整原始 SQL 不超过 4000 字符" in prompt
    assert "sample_id 和/或 structure" in prompt
    assert "该问题 SQL 对应的普通 EXPLAIN 已成功" in prompt
    assert "关键原始字段和值" in prompt
    assert "后续只按完整时序项做机械限量" in prompt
    assert "expression 或 unknown不得被擅自解释为速率、窗口增量或计数器类型" in prompt

    root_cause_schema = Recommendation.model_json_schema()["$defs"]["RootCauseAssessment"]
    assert {
        "analysis_process",
        "problem_sql",
        "explain_result",
    } <= root_cause_schema["properties"].keys()


def test_prompts_treat_program_projection_as_non_causal_evidence() -> None:
    prompt = ai_module.SYSTEM_PROMPT.replace("\n", "")
    assert (
        "NO_DATA、UNAVAILABLE、NOT_APPLICABLE、RECOVERED、JSON 无法解析或没有可用事实的"
        "程序输出只是证据缺失" in prompt
    )
    assert "RECOVERED 只表示一次失败尝试随后已由最终成功结果取代" in prompt
    assert "只陈述事实、异常、限制和来源" in prompt
    assert "不提出、选择或判断根因" in prompt
    assert "只有你这个主 Agent" in prompt
    assert "MCP 原始响应只保存在内部审计 artifact" in prompt
    assert "子 Agent" not in prompt
    assert "宿主完整性门禁" not in prompt
    assert "call_limit_reached" not in prompt


def test_ai_adapter_exposes_no_model_based_conclusion_validator() -> None:
    assert not hasattr(ai_module, "VALIDATION_PROMPT")
    assert not hasattr(ai_module, "OpenAICompatibleConclusionValidator")
    assert not hasattr(ai_module, "FakeConclusionValidator")


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
    assert recommendation.steps == []


@pytest.mark.asyncio
async def test_no_knowledge_remains_a_valid_optional_input() -> None:
    recommendation, _ = await FakeAIAdvisor().advise(make_alert(), [])
    assert recommendation.knowledge_matches == []
    assert recommendation.steps == []
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
        steps=[
            RecommendationStep(order=1, action="terminate the evidence-identified blocking session")
        ],
        confidence=0.3,
    )

    async def complete(messages):  # type: ignore[no-untyped-def]
        return model_response.model_dump_json(), object()

    advisor._complete = complete
    expected = "所选知识来源均未命中。"

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
        steps=[RecommendationStep(order=1, action="终止证据标识的阻塞会话")],
        confidence=0.3,
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
async def test_main_agent_payloads_use_bounded_evidence_dto_without_provenance() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    captured_payloads: list[dict[str, object]] = []
    digest = "d" * 64
    business_checksum = "0123456789abcdef0123456789abcdef"
    artifact_uri = "agent-artifact://internal-only"
    program_evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_archery_slow_logs",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="已投影慢查询事实。",
        request={
            "objective": "查询慢日志",
            "raw_parameters": {"token": "must-not-reach-model"},
            "artifact_uri": artifact_uri,
        },
        structured_data={
            "processing_status": "completed",
            "root_cause_eligible": True,
            "source_artifact": {
                "artifact_id": str(uuid4()),
                "uri": artifact_uri,
                "metadata": {"internal_only": True},
            },
            "raw_mcp_call_results": [{"result": "raw-secret"}],
            "provider_private": "must-not-reach-model",
            "tool_result_analysis": {
                "summary": "已完成程序事实投影。",
                "observations": [
                    {
                        "statement": ("慢查询数量升高；业务 checksum=" + business_checksum),
                        "source_paths": [
                            "/structured_data/rows/0",
                            "/structured_data/raw_mcp_call_results/0",
                        ],
                        "source_spans": [],
                        "raw_result": "must-not-reach-model",
                    }
                ],
                "anomalies": [],
                "limitations": [
                    "完整内容位于 " + artifact_uri,
                    "片段...[sha256:" + digest[:16] + ",total_chars:9000]",
                ],
                "analysis_usable": True,
                "source_coverage_complete": True,
                "provider": "deterministic_host",
                "model": "none",
                "prompt_version": "program-fact-projection-v3",
                "slow_query_analysis": {
                    "status": "partial",
                    "source_history_row": {
                        "checksum": business_checksum,
                        "sample": "UPDATE orders SET status='done' WHERE id=1",
                    },
                    "target": {"instance_id": 3, "db_name": "orders_prod"},
                    "explain_results": [{"result": {"rows": [{"type": "range"}]}}],
                    "table_structure_results": [],
                    "index_results": [],
                    "missing_stages": ["table_structure", "indexes"],
                    "failures": [
                        {
                            "stage": "indexes",
                            "reason_code": "permission_denied",
                            "artifact_uri": artifact_uri,
                            "request_id": "supplemental-internal-request",
                            "raw_response": "supplemental-secret",
                        }
                    ],
                },
                "source_artifact_id": str(uuid4()),
                "source_sha256": digest,
                "request_id": "projection-request-id",
                "usage": {"input_tokens": 100},
            },
        },
    )
    alert_detail_evidence = EvidenceRecord(
        run_id=program_evidence.run_id,
        tool_name="flashduty_alert_info",
        source_system="flashduty_alert_detail",
        status=ToolStatus.SUCCESS,
        summary="已获取权威 FlashDuty 告警详情。",
        request={"operation": "alert_info"},
        structured_data={
            "partial": False,
            "authoritative_source": "/alert/info",
            "alert_detail": {
                "title": "MySQL 慢查询告警",
                "database": {"host": "db-prod-1", "port": 3306},
                "nested": {
                    "raw_payload": {"secret": "raw-alert-secret"},
                    "artifact_id": "internal-artifact-id",
                    "source_sha256": digest,
                    "sha256": digest,
                    "hash": digest,
                    "content_hash": digest,
                    "audit": {
                        "uri": artifact_uri,
                        "request_id": "nested-request-id",
                        "usage": {"tokens": 20},
                    },
                },
            },
            "flashduty_alert_info": {
                "alarm_host": "db-prod-1",
                "alarm_port": 3306,
                "raw_response": "raw-flashduty-secret",
            },
        },
    )
    original_program = program_evidence.model_copy(deep=True)
    original_alert_detail = alert_detail_evidence.model_copy(deep=True)
    recommendation = Recommendation(
        summary=INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI basis")],
        steps=[],
        confidence=0.3,
    )
    calls = 0

    async def complete(messages):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        captured_payloads.append(json.loads(messages[1]["content"]))
        if calls == 1:
            return recommendation.model_dump_json(), object()
        return '{"action":"finish","reason":"done"}', ai_module.AdvisorMetadata(
            provider="test",
            model="test-model",
            prompt_version="test",
        )

    advisor._complete = complete

    evidence = [program_evidence, alert_detail_evidence]
    await advisor.advise(make_alert(), [], evidence=evidence)
    await advisor.decide_investigation(
        alert=make_alert(),
        knowledge=[],
        knowledge_match_summary="",
        evidence=evidence,
        available_tools=[],
        react_round=1,
        react_max_rounds=8,
    )

    assert program_evidence == original_program
    assert alert_detail_evidence == original_alert_detail
    for payload, evidence_key in zip(
        captured_payloads,
        ("tool_evidence", "evidence"),
        strict=True,
    ):
        model_evidence = payload[evidence_key]  # type: ignore[index]
        program_payload = model_evidence[0]
        detail_payload = model_evidence[1]

        assert set(program_payload) == {
            "id",
            "tool_name",
            "source_system",
            "status",
            "request",
            "summary",
            "error",
            "started_at",
            "collected_at",
            "duration_ms",
            "truncated",
            "structured_data",
        }
        assert program_payload["request"] == {"objective": "查询慢日志"}
        assert program_payload["structured_data"]["processing_status"] == "completed"
        assert program_payload["structured_data"]["root_cause_eligible"] is True
        analysis = program_payload["structured_data"]["tool_result_analysis"]
        assert set(analysis) == {
            "summary",
            "observations",
            "anomalies",
            "limitations",
            "analysis_usable",
            "source_coverage_complete",
            "provider",
            "model",
            "prompt_version",
            "slow_query_analysis",
        }
        assert analysis["observations"][0]["source_paths"] == ["/structured_data/rows/0"]
        assert business_checksum in analysis["observations"][0]["statement"]
        assert analysis["limitations"][1].endswith("[total_chars:9000]")
        assert analysis["slow_query_analysis"]["status"] == "partial"
        assert analysis["slow_query_analysis"]["failures"][0] == {
            "stage": "indexes",
            "reason_code": "permission_denied",
        }

        assert detail_payload["structured_data"] == {
            "partial": False,
            "authoritative_source": "/alert/info",
            "alert_detail": {
                "title": "MySQL 慢查询告警",
                "database": {"host": "db-prod-1", "port": 3306},
                "nested": {"audit": {}},
            },
            "flashduty_alert_info": {
                "alarm_host": "db-prod-1",
                "alarm_port": 3306,
            },
        }

        serialized = json.dumps(model_evidence, ensure_ascii=False, sort_keys=True)
        for forbidden in (
            "raw_mcp_call_results",
            "raw_parameters",
            "raw_payload",
            "raw_response",
            "raw-secret",
            "raw-alert-secret",
            "raw-flashduty-secret",
            "provider_private",
            "source_artifact",
            "artifact_id",
            "artifact_uri",
            "agent-artifact://",
            "source_sha256",
            "sha256",
            "content_hash",
            '"hash"',
            digest,
            "request_id",
            "projection-request-id",
            "nested-request-id",
            "usage",
        ):
            assert forbidden not in serialized


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
        steps=[RecommendationStep(order=1, action="终止证据标识的阻塞会话")],
        confidence=0.3,
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
async def test_advisor_does_not_apply_archery_endpoint_output_gate() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    model_response = Recommendation(
        summary=(
            "Archery 慢日志查询因实例 IP 定位偏差（查询了 100.84.97.139:3306 "
            "而非告警目标实例）未能获取有效慢日志证据。"
        ),
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI 分析依据")],
        steps=[RecommendationStep(order=1, action="终止证据标识的阻塞会话")],
        confidence=0.3,
    )
    calls = 0

    async def complete(messages):  # type: ignore[no-untyped-def]
        nonlocal calls
        del messages
        calls += 1
        return model_response.model_dump_json(), object()

    advisor._complete = complete

    recommendation, _ = await advisor.advise(make_alert(), [])

    assert calls == 1
    assert recommendation.summary == model_response.summary


@pytest.mark.asyncio
async def test_advisor_accepts_schema_valid_archery_endpoint_statement_once() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    model_response = Recommendation(
        summary="Archery 查询的实例与告警目标不一致，因此慢日志无效。",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI 分析依据")],
        steps=[RecommendationStep(order=1, action="终止证据标识的阻塞会话")],
        confidence=0.3,
    )

    calls = 0

    async def complete(messages):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        assert len(messages) == 2
        return model_response.model_dump_json(), object()

    advisor._complete = complete

    recommendation, _ = await advisor.advise(make_alert(), [])

    assert calls == 1
    assert recommendation.summary == model_response.summary


@pytest.mark.asyncio
async def test_react_decision_keeps_repairing_until_schema_is_valid() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    calls = 0
    emitted_reasoning: list[tuple[str, int, str]] = []

    async def complete(messages):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        assert len(messages) <= 4
        metadata = ai_module.AdvisorMetadata(
            provider="test",
            model="test-model",
            prompt_version="test",
            reasoning_content=f"repair reasoning {calls}",
        )
        if calls <= 4:
            return '{"action":"tool","tool_name":"unknown"}', metadata
        return '{"action":"finish","reason":"done"}', metadata

    async def capture_reasoning(
        content: str,
        stream_id: str,
        delta_index: int,
    ) -> None:
        emitted_reasoning.append((stream_id, delta_index, content))

    advisor._complete = complete

    result = await advisor.decide_investigation(
        alert=make_alert(),
        knowledge=[],
        knowledge_match_summary="",
        evidence=[],
        available_tools=[],
        react_round=1,
        react_max_rounds=8,
        reasoning_callback=capture_reasoning,
    )

    assert calls == 5
    assert result.decision.action == "finish"
    assert emitted_reasoning == [
        ("react:1:attempt:0", 0, "repair reasoning 1"),
        ("react:1:attempt:1", 0, "repair reasoning 2"),
        ("react:1:attempt:2", 0, "repair reasoning 3"),
        ("react:1:attempt:3", 0, "repair reasoning 4"),
        ("react:1:attempt:4", 0, "repair reasoning 5"),
    ]


@pytest.mark.asyncio
async def test_advisor_payload_uses_unified_knowledge_contract() -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "test-model"
    captured_payload: dict[str, object] = {}
    model_response = Recommendation(
        summary="No semantic match",
        analysis_bases=[AnalysisBasis(source=AnalysisBasisSource.AI, statement="AI basis")],
        steps=[
            RecommendationStep(order=1, action="terminate the evidence-identified blocking session")
        ],
        confidence=0.3,
    )

    async def complete(messages):  # type: ignore[no-untyped-def]
        captured_payload.update(json.loads(messages[1]["content"]))
        return model_response.model_dump_json(), object()

    advisor._complete = complete
    knowledge = KnowledgeExcerpt(
        source="incident_library",
        knowledge_id="knowledge-1",
        title="Replica guide",
        content="Check replica apply rate.",
        source_uri="https://knowledge.test/replica",
        score=0.9,
        raw_score=0.1,
    )

    await advisor.advise(make_alert(), [knowledge])

    excerpt = captured_payload["knowledge_matches"][0]  # type: ignore[index]
    assert excerpt["source"] == "incident_library"
    assert excerpt["knowledge_id"] == "knowledge-1"


@pytest.mark.asyncio
async def test_matched_knowledge_bases_are_ordered_before_ai() -> None:
    knowledge = KnowledgeExcerpt(
        source="incident_library",
        knowledge_id="knowledge-1",
        title="Replica guide",
        content="diagnostic guidance",
        source_uri="https://knowledge.test/replica",
        score=0.9,
        raw_score=0.1,
    )

    recommendation, _ = await FakeAIAdvisor().advise(make_alert(), [knowledge])

    assert [item.source for item in recommendation.analysis_bases] == [
        AnalysisBasisSource.KNOWLEDGE,
        AnalysisBasisSource.AI,
    ]
    assert recommendation.analysis_bases[0].source_ref == KnowledgeReference(
        source="incident_library",
        knowledge_id="knowledge-1",
        title="Replica guide",
        source_uri="https://knowledge.test/replica",
    )


def test_knowledge_reference_metadata_is_restored_from_retrieval() -> None:
    knowledge = KnowledgeExcerpt(
        source="incident_library",
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
                source=AnalysisBasisSource.KNOWLEDGE,
                statement="Knowledge basis",
                source_ref=KnowledgeReference(
                    source="incident_library",
                    knowledge_id="external-1",
                    title="altered title",
                    source_uri="https://untrusted.invalid",
                ),
            ),
            AnalysisBasis(
                source=AnalysisBasisSource.AI,
                statement="AI basis",
                source_ref=KnowledgeReference(
                    source="incident_library",
                    knowledge_id="fabricated",
                    title="fabricated title",
                    source_uri="https://untrusted.invalid/fabricated",
                ),
            ),
        ],
        steps=[
            RecommendationStep(
                order=1,
                action="check",
                source_ref=KnowledgeReference(
                    source="incident_library",
                    knowledge_id="external-1",
                    title="altered title",
                    source_uri="https://untrusted.invalid",
                ),
            )
        ],
        confidence=0.8,
    )

    result = _validate_knowledge_policy(recommendation, [knowledge])

    exact = KnowledgeReference(
        source=knowledge.source,
        knowledge_id=knowledge.knowledge_id,
        title=knowledge.title,
        source_uri=knowledge.source_uri,
    )
    assert result.analysis_bases[0].source_ref == exact
    assert result.analysis_bases[1].source_ref is None
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


def test_real_ai_client_uses_system_trust_http_client(
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
        json_mode=True,
    )
    assert timeout_values == [19]
    assert [item["http_client"] for item in constructed] == [http_client]
    assert [item["default_headers"] for item in constructed] == [
        {"User-Agent": ai_module.AI_HTTP_USER_AGENT},
    ]
    assert [item["max_retries"] for item in constructed] == [0]


@pytest.mark.asyncio
async def test_provider_retries_recoverable_failures_past_legacy_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    attempts = 0
    delays: list[float] = []
    request = httpx.Request("POST", "https://models.example.test/v1/chat/completions")

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts <= 4:
            raise ai_module.APIConnectionError(request=request)
        return "ok"

    async def no_wait(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(ai_module.asyncio, "sleep", no_wait)

    result = await advisor._request_provider(operation, operation="test")

    assert result == "ok"
    assert attempts == 5
    assert delays == [0.5, 1.0, 2.0, 4.0]


@pytest.mark.asyncio
async def test_provider_does_not_retry_permanent_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    attempts = 0
    sleeps = 0
    request = httpx.Request("POST", "https://models.example.test/v1/chat/completions")
    response = httpx.Response(400, request=request)

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        raise openai.APIStatusError("invalid request", response=response, body=None)

    async def no_wait(_delay: float) -> None:
        nonlocal sleeps
        sleeps += 1

    monkeypatch.setattr(ai_module.asyncio, "sleep", no_wait)

    with pytest.raises(openai.APIStatusError):
        await advisor._request_provider(operation, operation="test")

    assert attempts == 1
    assert sleeps == 0


@pytest.mark.asyncio
async def test_provider_retry_wait_is_cancellable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    retry_wait_started = asyncio.Event()
    request = httpx.Request("POST", "https://models.example.test/v1/chat/completions")

    async def operation() -> str:
        raise ai_module.APIConnectionError(request=request)

    async def wait_until_cancelled(_delay: float) -> None:
        retry_wait_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(ai_module.asyncio, "sleep", wait_until_cancelled)
    task = asyncio.create_task(advisor._request_provider(operation, operation="test"))
    await retry_wait_started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_provider_retries_end_when_outer_analysis_timeout_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    attempts = 0
    block_until_timeout = asyncio.Event()
    request = httpx.Request("POST", "https://models.example.test/v1/chat/completions")

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts >= 3:
            await block_until_timeout.wait()
        raise ai_module.APIConnectionError(request=request)

    original_sleep = asyncio.sleep

    async def cooperative_retry_wait(_delay: float) -> None:
        await original_sleep(0)

    monkeypatch.setattr(ai_module.asyncio, "sleep", cooperative_retry_wait)

    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.05):
            await advisor._request_provider(operation, operation="test")

    assert attempts == 3


@pytest.mark.asyncio
async def test_real_ai_adapters_close_their_owned_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []
    constructed: list[str] = []

    class ClosingAsyncOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.kind = "advisor"
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
        json_mode=True,
    )
    await advisor.aclose()

    assert constructed == ["advisor"]
    assert closed == ["advisor"]


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
async def test_advisor_complete_reads_top_level_provider_reasoning() -> None:
    class ReasoningCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="top-level-reasoning-request",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(
                            content='{"action":"finish","reason":"done"}',
                            reasoning="top-level provider reasoning",
                            model_extra={},
                        ),
                    )
                ],
                usage=None,
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._model = "reasoning-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = False
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=ReasoningCompletions()))

    _, metadata = await advisor._complete([{"role": "user", "content": "decide"}])

    assert metadata.reasoning_content == "top-level provider reasoning"


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
async def test_advisor_mcp_tool_call_reads_top_level_provider_reasoning() -> None:
    class ReasoningToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="top-level-tool-reasoning-request",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            reasoning="top-level MCP planning reasoning",
                            tool_calls=[
                                SimpleNamespace(
                                    id="reasoning-tool-call",
                                    function=SimpleNamespace(
                                        name="monitoring_query",
                                        arguments="{}",
                                    ),
                                )
                            ],
                        )
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=ReasoningToolCompletions()))

    result = await advisor.request_mcp_tool_call(
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

    assert result.reasoning_content == "top-level MCP planning reasoning"


@pytest.mark.asyncio
async def test_advisor_forwards_mcp_tool_definitions_without_host_validation() -> None:
    tools = [
        {"type": "function", "function": {"parameters": {"type": "object"}}},
        {"type": "function", "function": {"name": "duplicate"}},
        {"type": "function", "function": {"name": "duplicate"}},
    ]
    calls: list[dict[str, object]] = []

    class ToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(
                id="unvalidated-tool-definitions",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            tool_calls=[
                                SimpleNamespace(
                                    id="returned-call",
                                    function=SimpleNamespace(name="duplicate", arguments="{}"),
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

    result = await advisor.request_mcp_tool_call(messages=[], tools=tools)

    assert calls[0]["tools"] is tools
    assert result.name == "duplicate"


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
                "SELECT id, instance_name, host, port FROM sql_instance WHERE id = 3 LIMIT 10"
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
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=TextActionCompletions()))
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
async def test_advisor_rejects_unlisted_tool_in_text_action() -> None:
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
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=UnknownToolCompletions()))

    with pytest.raises(AdvisorError, match="not advertised"):
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
async def test_advisor_rejects_markup_polluted_native_tool_name() -> None:
    polluted_name = 'initially_advertised_tool</function>\n<parameter name="datasource">mcdchina'

    class UnknownNativeToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="unknown-native-tool-request",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[
                                SimpleNamespace(
                                    id="unknown-native-tool-call",
                                    function=SimpleNamespace(
                                        name=polluted_name,
                                        arguments='{"opaque":true}',
                                    ),
                                )
                            ],
                        )
                    )
                ],
            )

    advisor = object.__new__(ai_module.OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=UnknownNativeToolCompletions())
    )

    with pytest.raises(AdvisorError, match="not advertised"):
        await advisor.request_mcp_tool_call(
            messages=[],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "initially_advertised_tool",
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
    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=MultipleToolCompletions()))

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
async def test_responses_completion_maps_request_and_actual_reasoning() -> None:
    calls: list[dict[str, object]] = []

    class Responses:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(
                id="resp-completion-1",
                status="completed",
                error=None,
                incomplete_details=None,
                output=[
                    {
                        "id": "rs_1",
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "provider reasoning"}],
                        "encrypted_content": "opaque-replay-state",
                    },
                    {
                        "id": "msg_1",
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            {
                                "type": "output_text",
                                "text": '{"action":"finish","reason":"done"}',
                            }
                        ],
                    },
                ],
                usage={"input_tokens": 12, "output_tokens": 8, "total_tokens": 20},
            )

    advisor = object.__new__(ai_module.OpenAIResponsesAdvisor)
    advisor._model = "responses-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = True
    advisor._client = SimpleNamespace(responses=Responses())

    content, metadata = await advisor._complete(
        [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "return JSON"},
        ]
    )

    assert content == '{"action":"finish","reason":"done"}'
    assert metadata.provider == "openai_responses"
    assert metadata.request_id == "resp-completion-1"
    assert metadata.reasoning_content == "provider reasoning"
    assert metadata.usage == {"input_tokens": 12, "output_tokens": 8, "total_tokens": 20}
    assert calls == [
        {
            "model": "responses-model",
            "input": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "return JSON"},
            ],
            "max_output_tokens": 16_384,
            "store": False,
            "include": ["reasoning.encrypted_content"],
            "stream": True,
            "text": {"format": {"type": "json_object"}},
        }
    ]
    assert "reasoning" not in calls[0]
    assert "temperature" not in calls[0]
    assert "messages" not in calls[0]
    assert "max_tokens" not in calls[0]
    assert "response_format" not in calls[0]


@pytest.mark.asyncio
async def test_responses_streams_reasoning_and_preserves_native_tool_replay() -> None:
    calls: list[dict[str, object]] = []
    reasoning_deltas: list[tuple[str, int]] = []
    terminal_response = SimpleNamespace(
        id="resp-stream-1",
        status="completed",
        error=None,
        incomplete_details=None,
        output=[
            {
                "id": "rs_stream",
                "type": "reasoning",
                "summary": [
                    {"type": "summary_text", "text": "inspect target"},
                    {"type": "summary_text", "text": " then query"},
                ],
                "encrypted_content": "encrypted-provider-state",
            },
            {
                "id": "fc_stream",
                "type": "function_call",
                "call_id": "call-stream-1",
                "name": "monitoring_query",
                "arguments": '{"host":"db.example"}',
                "status": "completed",
            },
        ],
        usage={"input_tokens": 30, "output_tokens": 9, "total_tokens": 39},
    )
    events = [
        SimpleNamespace(
            type="response.created",
            response=SimpleNamespace(id="resp-stream-1"),
        ),
        SimpleNamespace(
            type="response.reasoning_summary_text.delta",
            response_id="resp-stream-1",
            delta="inspect target",
        ),
        SimpleNamespace(
            type="response.reasoning_text.delta",
            response_id="resp-stream-1",
            delta=" then query",
        ),
        SimpleNamespace(
            type="response.output_item.added",
            response_id="resp-stream-1",
            output_index=1,
            item={
                "type": "function_call",
                "call_id": "call-stream-1",
                "name": "monitoring_query",
                "arguments": "",
            },
        ),
        SimpleNamespace(
            type="response.function_call_arguments.delta",
            response_id="resp-stream-1",
            output_index=1,
            delta='{"host":',
        ),
        SimpleNamespace(
            type="response.function_call_arguments.delta",
            response_id="resp-stream-1",
            output_index=1,
            delta='"db.example"}',
        ),
        SimpleNamespace(
            type="response.function_call_arguments.done",
            response_id="resp-stream-1",
            output_index=1,
            name="monitoring_query",
            arguments='{"host":"db.example"}',
        ),
        SimpleNamespace(
            type="response.output_item.done",
            response_id="resp-stream-1",
            output_index=1,
            item=terminal_response.output[1],
        ),
        SimpleNamespace(type="response.completed", response=terminal_response),
    ]

    class Stream:
        def __aiter__(self):
            async def iterate():
                for event in events:
                    yield event

            return iterate()

    class Responses:
        async def create(self, **kwargs: object) -> Stream:
            calls.append(kwargs)
            return Stream()

    async def capture_reasoning(content: str, index: int) -> None:
        reasoning_deltas.append((content, index))

    advisor = object.__new__(ai_module.OpenAIResponsesAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "responses-tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(responses=Responses())
    previous_reasoning = {
        "id": "rs_previous",
        "type": "reasoning",
        "summary": [],
        "encrypted_content": "previous-encrypted-state",
    }
    previous_call = {
        "id": "fc_previous",
        "type": "function_call",
        "call_id": "call-previous",
        "name": "list_targets",
        "arguments": "{}",
    }
    previous_output = {
        "type": "function_call_output",
        "call_id": "call-previous",
        "output": '{"targets":["db.example"]}',
    }
    synthetic_action = {
        "role": "assistant",
        "content": '{"action":"call_tool","tool_name":"list_targets"}',
    }
    tool = {
        "type": "function",
        "function": {
            "name": "monitoring_query",
            "description": "Query one monitoring target",
            "parameters": {
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
        },
    }

    result = await advisor.request_mcp_tool_call(
        messages=[
            {"role": "system", "content": "read only"},
            synthetic_action,
            previous_reasoning,
            previous_call,
            previous_output,
            {"role": "user", "content": "choose the next query"},
        ],
        tools=[tool],
        reasoning_callback=capture_reasoning,
    )

    assert result.call_id == "call-stream-1"
    assert result.name == "monitoring_query"
    assert result.arguments == {"host": "db.example"}
    assert result.request_id == "resp-stream-1"
    assert result.reasoning_content == "inspect target then query"
    assert reasoning_deltas == [("inspect target", 0), (" then query", 1)]
    assert result.provider_output_items == tuple(terminal_response.output)
    request = calls[0]
    assert request["input"] == [
        {"role": "system", "content": "read only"},
        previous_reasoning,
        previous_call,
        previous_output,
        {"role": "user", "content": "choose the next query"},
    ]
    assert synthetic_action not in request["input"]
    assert request["tools"] == [
        {
            "type": "function",
            "name": "monitoring_query",
            "description": "Query one monitoring target",
            "parameters": tool["function"]["parameters"],
            "strict": False,
        }
    ]
    assert request["tool_choice"] == "required"
    assert request["parallel_tool_calls"] is False
    assert request["store"] is False
    assert request["include"] == ["reasoning.encrypted_content"]
    assert "reasoning" not in request
    assert "temperature" not in request


@pytest.mark.asyncio
async def test_responses_recovers_reasoning_from_done_item_without_deltas() -> None:
    reasoning_item = {
        "id": "rs_done",
        "type": "reasoning",
        "summary": [{"type": "summary_text", "text": "done-only reasoning"}],
        "encrypted_content": "done-only-encrypted-state",
    }
    function_item = {
        "id": "fc_done",
        "type": "function_call",
        "call_id": "call-done-only",
        "name": "monitoring_query",
        "arguments": "{}",
        "status": "completed",
    }
    events = [
        SimpleNamespace(
            type="response.created",
            response=SimpleNamespace(id="resp-done-only"),
        ),
        SimpleNamespace(
            type="response.output_item.done",
            response_id="resp-done-only",
            output_index=0,
            item=reasoning_item,
        ),
        SimpleNamespace(
            type="response.output_item.done",
            response_id="resp-done-only",
            output_index=1,
            item=function_item,
        ),
    ]

    class Stream:
        def __aiter__(self):
            async def iterate():
                for event in events:
                    yield event

            return iterate()

    class Responses:
        async def create(self, **kwargs: object) -> Stream:
            del kwargs
            return Stream()

    reasoning_deltas: list[tuple[str, int]] = []

    async def capture_reasoning(content: str, index: int) -> None:
        reasoning_deltas.append((content, index))

    advisor = object.__new__(ai_module.OpenAIResponsesAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "responses-tool-model"
    advisor._max_tokens = 16_384
    advisor._client = SimpleNamespace(responses=Responses())

    result = await advisor.request_mcp_tool_call(
        messages=[{"role": "user", "content": "choose a tool"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "monitoring_query",
                    "parameters": {"type": "object"},
                },
            }
        ],
        reasoning_callback=capture_reasoning,
    )

    assert result.request_id == "resp-done-only"
    assert result.call_id == "call-done-only"
    assert result.reasoning_content == "done-only reasoning"
    assert reasoning_deltas == [("done-only reasoning", 0)]
    assert result.provider_output_items == (reasoning_item, function_item)


@pytest.mark.asyncio
async def test_responses_reads_legacy_reasoning_summary_shape() -> None:
    class Responses:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="resp-legacy-reasoning",
                status="completed",
                error=None,
                incomplete_details=None,
                output=[
                    {
                        "id": "legacy-rs",
                        "type": "reasoning",
                        "summary": [],
                        "content": [
                            {
                                "type": "reasoning_summary",
                                "summary": "legacy provider reasoning",
                            }
                        ],
                    },
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": '{"status":"ok"}'}],
                    },
                ],
                usage=None,
            )

    advisor = object.__new__(ai_module.OpenAIResponsesAdvisor)
    advisor._model = "legacy-responses-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = False
    advisor._client = SimpleNamespace(responses=Responses())

    _, metadata = await advisor._complete([{"role": "user", "content": "inspect"}])

    assert metadata.reasoning_content == "legacy provider reasoning"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error", "incomplete_details", "expected"),
    [
        (
            "failed",
            {
                "type": "invalid_request_error",
                "code": "unsupported_parameter",
                "message": "token=provider-secret-must-not-leak",
            },
            None,
            "code=unsupported_parameter",
        ),
        (
            "incomplete",
            None,
            {"reason": "max_output_tokens"},
            "reason=max_output_tokens",
        ),
    ],
)
async def test_responses_terminal_failures_are_safe_and_not_accepted(
    status: str,
    error: dict[str, str] | None,
    incomplete_details: dict[str, str] | None,
    expected: str,
) -> None:
    class Responses:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                id="resp-terminal-error",
                status=status,
                error=error,
                incomplete_details=incomplete_details,
                output=[],
                usage=None,
            )

    advisor = object.__new__(ai_module.OpenAIResponsesAdvisor)
    advisor._model = "responses-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = False
    advisor._client = SimpleNamespace(responses=Responses())

    with pytest.raises(AdvisorError) as caught:
        await advisor._complete([{"role": "user", "content": "inspect"}])

    rendered = str(caught.value)
    assert "OpenAI Responses request failed" in rendered
    assert "request_id=resp-terminal-error" in rendered
    assert f"status={status}" in rendered
    assert expected in rendered
    assert "provider-secret-must-not-leak" not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (
            SimpleNamespace(
                type="response.failed",
                response=SimpleNamespace(
                    id="resp-stream-failed",
                    status="failed",
                    error={
                        "type": "server_error",
                        "code": "stream_failed",
                        "message": "token=stream-secret-must-not-leak",
                    },
                    incomplete_details=None,
                    output=[],
                ),
            ),
            "code=stream_failed",
        ),
        (
            SimpleNamespace(
                type="response.incomplete",
                response=SimpleNamespace(
                    id="resp-stream-incomplete",
                    status="incomplete",
                    error=None,
                    incomplete_details={"reason": "max_output_tokens"},
                    output=[],
                ),
            ),
            "reason=max_output_tokens",
        ),
        (
            SimpleNamespace(
                type="response.error",
                response_id="resp-stream-error",
                error={
                    "type": "invalid_request_error",
                    "code": "bad_stream_request",
                    "message": "token=stream-secret-must-not-leak",
                },
            ),
            "code=bad_stream_request",
        ),
    ],
)
async def test_responses_stream_terminal_errors_are_safe(
    event: SimpleNamespace,
    expected: str,
) -> None:
    class Stream:
        def __aiter__(self):
            async def iterate():
                yield event

            return iterate()

    class Responses:
        async def create(self, **kwargs: object) -> Stream:
            del kwargs
            return Stream()

    advisor = object.__new__(ai_module.OpenAIResponsesAdvisor)
    advisor._model = "responses-model"
    advisor._max_tokens = 16_384
    advisor._json_mode = False
    advisor._client = SimpleNamespace(responses=Responses())

    with pytest.raises(AdvisorError) as caught:
        await advisor._complete([{"role": "user", "content": "inspect"}])

    rendered = str(caught.value)
    assert "OpenAI Responses request failed" in rendered
    assert expected in rendered
    assert "stream-secret-must-not-leak" not in rendered
