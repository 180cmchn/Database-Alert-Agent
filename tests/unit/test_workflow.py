import asyncio
import json
from pathlib import Path
from uuid import uuid5

import pytest

from app.adapters.ai import FakeAIAdvisor, OpenAICompatibleAdvisor
from app.adapters.investigation import InvestigationToolRegistry
from app.adapters.knowledge import KnowledgeSourceRegistry
from app.adapters.notification import LogManagementNotifier
from app.agent_runtime.events import AgentEvent, AgentEventKind
from app.agent_runtime.persistence import RepositoryEventSink
from app.agents.nodes import enrich_alert_node, react_decide_node
from app.agents.state import AgentState
from app.application.evidence_context import model_evidence_payload
from app.application.factory import apply_runtime_settings, build_runtime
from app.application.validation import enforce_post_evidence_root_cause_policy
from app.config import Settings
from app.domain.errors import AdvisorError, AnalysisFailedError
from app.domain.models import (
    EVIDENCE_RECORD_V2,
    AdvisorMetadata,
    AlertStatus,
    AnalysisBasis,
    AnalysisBasisSource,
    DatabaseTarget,
    EvidenceUnitStatus,
    InvestigationDecision,
    InvestigationDecisionResult,
    InvestigationStage,
    Recommendation,
    RecommendationStep,
    RootCauseAnalysisStep,
    RootCauseAssessment,
    RootCauseSqlEvidence,
    RootCauseStatus,
    RunStatus,
    Severity,
    ToolExecutionRequest,
    ToolResultAnalysis,
    ToolResultObservation,
    ToolStatus,
    ValidationKind,
)


@pytest.mark.asyncio
async def test_flashduty_detail_precedes_knowledge_and_mcp_selection(tmp_path: Path) -> None:
    events: list[str] = []
    seen_hosts: list[str | None] = []

    class DetailEnricher:
        read_only = True

        async def enrich(self, alert):  # type: ignore[no-untyped-def]
            events.append("DETAIL")
            return alert.model_copy(
                update={
                    "database": DatabaseTarget(
                        engine="mysql",
                        instance="orders-primary",
                        host="detail-host",
                        port=3306,
                    ),
                    "raw_payload": {
                        "flashduty_alert_info": {
                            "alert_id": alert.external_id,
                            "alarm_host": "detail-host",
                            "alarm_port": 3306,
                        },
                        "flashduty_ingested_alert": alert.raw_payload,
                    },
                }
            )

    class RecordingKnowledgeSource:
        name = "recording"

        async def search(self, alert):  # type: ignore[no-untyped-def]
            events.append("KNOWLEDGE")
            seen_hosts.append(alert.database.host if alert.database else None)
            return []

    class RecordingTool:
        name = "detail_probe"
        source_system = "test_mcp"
        read_only = True
        input_schema = {"type": "object", "additionalProperties": False}

        async def execute(self, request, context):  # type: ignore[no-untyped-def]
            events.append("MCP_CALL")
            seen_hosts.append(context.alert.database.host if context.alert.database else None)
            return "detail endpoint observed", {"root_cause_eligible": False}

    advisor = ScriptedReActAdvisor(
        [
            InvestigationDecision(
                action="tool",
                tool_name="detail_probe",
                objective="Read facts for the authoritative FlashDuty target.",
            ),
            InvestigationDecision(action="finish", reason="Detail probe completed."),
        ],
        events=events,
    )
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"knowledge_sources": ["recording"]}),
        advisor=advisor,
        knowledge_registry=KnowledgeSourceRegistry([RecordingKnowledgeSource()]),
        tool_registry=InvestigationToolRegistry([RecordingTool()]),
    )
    runtime.service.agent.ctx.alert_detail_enricher = DetailEnricher()
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "flashduty",
        {
            "request_id": "req-list",
            "data": {
                "alert_id": "663a1b2c3d4e5f6789abcdef",
                "title": "MySQL/mysql_slow_query/title-host:3307",
                "alert_severity": "Warning",
                "alert_key": "slow_query",
                "start_time": 1712650000,
                "labels": {
                    "engine": "mysql",
                    "alarm_host": "list-host",
                    "alarm_port": "3307",
                },
            },
        },
    )

    assert events == [
        "DETAIL",
        "KNOWLEDGE",
        "REACT:1",
        "MCP_CALL",
        "REACT:2",
        "ADVISOR",
    ]
    assert seen_hosts == ["detail-host", "detail-host"]
    assert advisor.alert_hosts == ["detail-host", "detail-host"]
    assert result.alert.database is not None
    assert result.alert.database.host == "detail-host"
    assert result.alert.database.port == 3306
    assert result.latest_run is not None
    detail_evidence = next(
        item for item in result.evidence_records if item.tool_name == "flashduty_alert_info"
    )
    assert detail_evidence.id == uuid5(
        result.latest_run.id,
        "flashduty-alert-info-evidence-v1:663a1b2c3d4e5f6789abcdef",
    )
    assert detail_evidence.source_system == "flashduty_alert_detail"
    assert detail_evidence.status == ToolStatus.SUCCESS
    assert detail_evidence.structured_data["partial"] is False
    assert detail_evidence.structured_data["flashduty_alert_info"] is not None
    assert detail_evidence.structured_data["alert_detail"]["database"] == {
        "engine": "mysql",
        "instance": "orders-primary",
        "database": None,
        "host": "detail-host",
        "port": 3306,
    }
    assert detail_evidence.is_root_cause_support_eligible() is True

    detail_progress_count = sum(
        item.details.get("flashduty_detail_status") == "loaded" for item in result.progress
    )
    replay = await enrich_alert_node(
        AgentState(
            alert_id=str(result.alert.id),
            alert=result.alert.model_copy(
                update={
                    "database": result.alert.database.model_copy(
                        update={"host": None, "port": None}
                    )
                }
            ),
            stored_alert=result,
            run=result.latest_run,
        ),
        runtime.service.agent.ctx,
    )
    assert events.count("DETAIL") == 1
    assert replay["evidence"] == [detail_evidence]
    assert replay["alert"].database.host == "detail-host"
    assert replay["alert"].database.port == 3306
    assert replay["alert"].raw_payload["flashduty_alert_info"] == {
        "alert_id": "663a1b2c3d4e5f6789abcdef",
        "alarm_host": "detail-host",
        "alarm_port": 3306,
    }
    after_replay = await runtime.repository.get(
        str(result.alert.id), run_id=str(result.latest_run.id)
    )
    assert after_replay is not None
    assert after_replay.evidence_records == result.evidence_records
    assert (
        sum(
            item.details.get("flashduty_detail_status") == "loaded"
            for item in after_replay.progress
        )
        == detail_progress_count
    )
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_knowledge_failure_does_not_block_detail_evidence_root_cause(
    tmp_path: Path,
) -> None:
    class DetailEnricher:
        read_only = True

        async def enrich(self, alert):  # type: ignore[no-untyped-def]
            return alert.model_copy(
                update={
                    "database": DatabaseTarget(
                        engine="mysql",
                        instance="orders-primary",
                        host="detail-host",
                        port=3306,
                    ),
                    "features": {
                        **alert.features,
                        "observed_value": 100,
                        "threshold": 80,
                    },
                }
            )

    class DetailEvidenceAdvisor:
        async def decide_investigation(self, **kwargs):  # type: ignore[no-untyped-def]
            alert = kwargs["alert"]
            assert alert.database is not None
            assert alert.database.host == "detail-host"
            return InvestigationDecisionResult(
                decision=InvestigationDecision(
                    action="finish",
                    reason="The authoritative detail is sufficient for final synthesis.",
                ),
                metadata=AdvisorMetadata(
                    provider="test",
                    model="detail-evidence-advisor",
                    prompt_version="test-v1",
                ),
            )

        async def advise(
            self,
            alert,
            knowledge,
            evidence=None,
            knowledge_match_summary="",
        ):  # type: ignore[no-untyped-def]
            assert knowledge == []
            assert "recording 查询失败（RuntimeError），已忽略" in knowledge_match_summary
            detail = next(
                item for item in evidence or [] if item.tool_name == "flashduty_alert_info"
            )
            assert detail.structured_data["alert_detail"]["reason"] == alert.reason
            cause = "连接需求突增使当前连接数超过配置容量"
            assert cause != alert.reason
            return (
                Recommendation(
                    summary=cause,
                    knowledge_match_summary=knowledge_match_summary,
                    likely_causes=[cause],
                    analysis_bases=[
                        AnalysisBasis(
                            source=AnalysisBasisSource.AI,
                            statement="结合权威告警详情中的当前值和阈值判断。",
                        )
                    ],
                    steps=[
                        RecommendationStep(
                            order=1,
                            action="提高连接容量或扩容数据库连接资源，并限制突发连接流量。",
                        )
                    ],
                    risks=[],
                    confidence=0.9,
                    root_causes=[
                        RootCauseAssessment(
                            cause=cause,
                            analysis_process=[
                                RootCauseAnalysisStep(
                                    observation="权威告警详情显示当前连接数 100，阈值为 80。",
                                    inference="连接需求已超过配置容量并触发高连接告警。",
                                    evidence_refs=[str(detail.id)],
                                )
                            ],
                            status=RootCauseStatus.SUPPORTED,
                            evidence_refs=[str(detail.id)],
                            confidence=0.9,
                            verified=True,
                        )
                    ],
                ),
                AdvisorMetadata(
                    provider="test",
                    model="detail-evidence-advisor",
                    prompt_version="test-v1",
                ),
            )

    class FailingKnowledgeSource:
        name = "recording"

        async def search(self, alert):  # type: ignore[no-untyped-def]
            del alert
            raise RuntimeError("knowledge service unavailable")

    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"knowledge_sources": ["recording"]}),
        advisor=DetailEvidenceAdvisor(),
        knowledge_registry=KnowledgeSourceRegistry([FailingKnowledgeSource()]),
    )
    runtime.service.agent.ctx.alert_detail_enricher = DetailEnricher()
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "flashduty",
        {
            "request_id": "req-zero-mcp",
            "data": {
                "alert_id": "773a1b2c3d4e5f6789abcdef",
                "title": "MySQL connections high",
                "alert_severity": "Warning",
                "alert_key": "connections_high",
                "start_time": 1712650000,
                "labels": {"engine": "mysql"},
            },
        },
    )

    assert result.status == AlertStatus.COMPLETED
    assert result.recommendation is not None
    assert result.recommendation.knowledge_matches == []
    assert "recording 查询失败（RuntimeError），已忽略" in (
        result.recommendation.knowledge_match_summary
    )
    assert result.recommendation.root_causes[0].cause != result.alert.reason
    assert len(result.validations) == 1
    assert result.validations[0].kind == ValidationKind.RULE
    assert result.validations[0].evidence_sufficient is True
    assert [item.tool_name for item in result.evidence_records] == ["flashduty_alert_info"]
    detail_evidence = result.evidence_records[0]
    reason_only = result.recommendation.model_copy(
        update={
            "summary": result.alert.reason,
            "likely_causes": [result.alert.reason],
            "root_causes": [
                RootCauseAssessment(
                    cause=result.alert.reason,
                    status=RootCauseStatus.SUPPORTED,
                    evidence_refs=[str(detail_evidence.id)],
                    confidence=0.9,
                    verified=True,
                )
            ],
        }
    )
    rejected = enforce_post_evidence_root_cause_policy(
        reason_only,
        [detail_evidence],
        result.alert,
    )
    assert rejected.root_causes == []
    assert rejected.likely_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_flashduty_detail_failure_closes_before_knowledge_and_mcp(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class UnusableDetailEnricher:
        read_only = True

        async def enrich(self, _alert):  # type: ignore[no-untyped-def]
            calls.append("DETAIL")
            raise RuntimeError("detail unavailable")

    class RecordingKnowledgeSource:
        name = "recording"

        async def search(self, _alert):  # type: ignore[no-untyped-def]
            calls.append("KNOWLEDGE")
            return []

    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"knowledge_sources": ["recording"]}),
        knowledge_registry=KnowledgeSourceRegistry([RecordingKnowledgeSource()]),
    )
    runtime.service.agent.ctx.alert_detail_enricher = UnusableDetailEnricher()  # type: ignore[assignment]
    await runtime.repository.initialize()

    with pytest.raises(AnalysisFailedError, match="FlashDuty alert detail"):
        await runtime.service.analyze(
            "flashduty",
            {
                "request_id": "req-list",
                "data": {
                    "alert_id": "663a1b2c3d4e5f6789abcdef",
                    "title": "MySQL/mysql_slow_query/list-host:3307",
                    "alert_severity": "Warning",
                    "alert_key": "slow_query",
                    "start_time": 1712650000,
                    "labels": {
                        "engine": "mysql",
                        "alarm_host": "list-host",
                        "alarm_port": "3307",
                    },
                },
            },
        )

    assert calls == ["DETAIL"]
    await runtime.repository.close()  # type: ignore[attr-defined]


class RecordingNotifier(LogManagementNotifier):
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self.events = events
        self.fail = fail

    async def send(self, event):  # type: ignore[no-untyped-def]
        self.events.append(f"RESULT:{event.alert.severity.value}")
        if self.fail:
            raise RuntimeError("wecom unavailable")
        return "recorded"


class RecordingAdvisor(FakeAIAdvisor):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0
        self.evidence_tool_names: list[str] = []

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        knowledge,
        evidence=None,
        knowledge_match_summary="",
        reasoning_callback=None,
    ):
        self.events.append("ADVISOR")
        self.calls += 1
        self.evidence_tool_names = [item.tool_name for item in evidence or []]
        return await super().advise(
            alert,
            knowledge,
            evidence=evidence,
            knowledge_match_summary=knowledge_match_summary,
            reasoning_callback=reasoning_callback,
        )


class ScriptedReActAdvisor(RecordingAdvisor):
    def __init__(
        self,
        decisions: list[InvestigationDecision],
        *,
        events: list[str] | None = None,
        reasoning: list[str | None] | None = None,
        final_reasoning: str | None = None,
    ) -> None:
        super().__init__(events if events is not None else [])
        self.decisions = list(decisions)
        self.reasoning = list(reasoning or [None] * len(decisions))
        self.final_reasoning = final_reasoning
        self.decision_evidence: list[list[tuple[str, ToolStatus]]] = []
        self.alert_hosts: list[str | None] = []
        self.available_tool_names: list[list[str]] = []

    async def decide_investigation(self, **kwargs):  # type: ignore[no-untyped-def]
        index = len(self.decision_evidence)
        if index >= len(self.decisions):
            raise AssertionError("main Agent requested an unexpected ReAct decision")
        alert = kwargs["alert"]
        evidence = kwargs["evidence"]
        available_tools = kwargs["available_tools"]
        self.events.append(f"REACT:{kwargs['react_round']}")
        self.alert_hosts.append(alert.database.host if alert.database else None)
        self.decision_evidence.append([(item.tool_name, item.status) for item in evidence])
        self.available_tool_names.append([item.name for item in available_tools])
        return InvestigationDecisionResult(
            decision=self.decisions[index],
            metadata=AdvisorMetadata(
                provider=self.provider,
                model=self.model,
                prompt_version=self.prompt_version,
                request_id=f"react-{index + 1}",
                reasoning_content=self.reasoning[index],
            ),
        )

    async def advise(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        recommendation, metadata = await super().advise(*args, **kwargs)
        return recommendation, metadata.model_copy(
            update={"reasoning_content": self.final_reasoning}
        )


class FailingAdvisor:
    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        knowledge,
        evidence=None,
        knowledge_match_summary="",
    ):
        del alert, knowledge, evidence, knowledge_match_summary
        raise AdvisorError("provider unavailable")


class FlakyAdvisor(FakeAIAdvisor):
    def __init__(self) -> None:
        self.calls = 0

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        knowledge,
        evidence=None,
        knowledge_match_summary="",
    ):
        self.calls += 1
        if self.calls == 1:
            raise AdvisorError("temporary failure")
        return await super().advise(
            alert,
            knowledge,
            evidence=evidence,
            knowledge_match_summary=knowledge_match_summary,
        )


class RecordingMCPStyleTool:
    name = "mcp_style_probe"
    source_system = "test_mcp"
    read_only = True

    def __init__(self, events: list[str] | None = None) -> None:
        self.calls: list[ToolExecutionRequest] = []
        self.events = events

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        if self.events is not None:
            self.events.append(f"TOOL:{request.parameters['phase']}")
        return "MCP evidence collected.", {"phase": request.parameters["phase"]}


class StaticOutcomeTool(RecordingMCPStyleTool):
    def __init__(self, outcome: str) -> None:
        super().__init__()
        self.outcome = outcome

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        if self.outcome == "failed":
            raise RuntimeError("simulated MCP transport failure")
        return "Partial MCP evidence.", {
            "phase": request.parameters["phase"],
            "partial": True,
            "termination_reason": "remote_partial_result",
        }


def settings_for(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        knowledge_sources=[],
    )


@pytest.mark.asyncio
async def test_no_selected_knowledge_source_is_reported_to_main_analysis(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "no-knowledge-source",
            "severity": "WARNING",
            "title": "MySQL slow query alert",
            "reason": "mysql_slow_query_400",
        },
    )

    assert result.recommendation is not None
    assert "未选择知识来源" in result.recommendation.knowledge_match_summary
    assert result.recommendation.knowledge_matches == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.parametrize("severity", ["CRITICAL", "WARNING", "INFO"])
async def test_every_severity_sends_one_final_ai_result(tmp_path: Path, severity: str) -> None:
    events: list[str] = []
    advisor = RecordingAdvisor(events)
    runtime = build_runtime(
        settings_for(tmp_path), advisor=advisor, notifier=RecordingNotifier(events)
    )
    await runtime.repository.initialize()
    payload = {
        "external_id": f"{severity.lower()}-1",
        "severity": severity,
        "title": f"{severity} alert",
        "reason": "unknown",
        "database": {"engine": "mysql", "instance": "orders-primary"},
    }

    first = await runtime.service.analyze("canonical", payload)
    second = await runtime.service.analyze("canonical", payload)

    assert events == ["ADVISOR", f"RESULT:{severity}"]
    assert advisor.calls == 1
    assert advisor.evidence_tool_names == []
    assert first.alert.id == second.alert.id
    assert first.status == AlertStatus.INCONCLUSIVE
    assert [item.kind for item in first.validations] == [ValidationKind.RULE]
    assert all(item.passed for item in first.validations)
    assert all(not item.evidence_sufficient for item in first.validations)
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filtered_severities",
    [
        [],
        [Severity.CRITICAL],
        [Severity.WARNING],
        [Severity.INFO],
        [Severity.CRITICAL, Severity.WARNING],
        [Severity.CRITICAL, Severity.INFO],
        [Severity.WARNING, Severity.INFO],
        [Severity.CRITICAL, Severity.WARNING, Severity.INFO],
    ],
)
async def test_analysis_filter_supports_every_severity_subset(
    tmp_path: Path,
    filtered_severities: list[Severity],
) -> None:
    settings = settings_for(tmp_path).model_copy(
        update={
            "alert_analysis_filter_enabled": bool(filtered_severities),
            "alert_analysis_filter_severities": filtered_severities,
        }
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()

    for severity in Severity:
        stored, created = await runtime.service.ingest(
            "canonical",
            {
                "external_id": (
                    f"filter-{'-'.join(item.value for item in filtered_severities) or 'none'}-"
                    f"{severity.value}"
                ),
                "severity": severity.value,
                "title": "Severity admission test",
                "reason": "test",
            },
        )
        assert created is True
        assert stored.status == (
            AlertStatus.FILTERED if severity in filtered_severities else AlertStatus.QUEUED
        )

    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_non_contiguous_filter_only_analyzes_unselected_severity(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    settings = settings_for(tmp_path).model_copy(
        update={
            "alert_analysis_filter_enabled": True,
            "alert_analysis_filter_severities": [Severity.CRITICAL, Severity.INFO],
        }
    )
    runtime = build_runtime(
        settings,
        advisor=RecordingAdvisor(events),
        notifier=RecordingNotifier(events),
    )
    await runtime.repository.initialize()

    results = {}
    for severity in Severity:
        results[severity] = await runtime.service.analyze(
            "canonical",
            {
                "external_id": f"non-contiguous-{severity.value}",
                "severity": severity.value,
                "title": "Non-contiguous severity admission test",
                "reason": "test",
            },
        )

    assert results[Severity.CRITICAL].status == AlertStatus.FILTERED
    assert results[Severity.CRITICAL].latest_run is None
    assert results[Severity.WARNING].status == AlertStatus.INCONCLUSIVE
    assert results[Severity.INFO].status == AlertStatus.FILTERED
    assert results[Severity.INFO].latest_run is None
    assert events == ["ADVISOR", "RESULT:WARNING"]

    retried = await runtime.service.analyze_by_id(str(results[Severity.CRITICAL].alert.id))
    assert retried.status == AlertStatus.FILTERED
    assert events == ["ADVISOR", "RESULT:WARNING"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_explicit_reanalysis_overrides_filtered_admission(tmp_path: Path) -> None:
    events: list[str] = []
    settings = settings_for(tmp_path).model_copy(
        update={
            "alert_analysis_filter_enabled": True,
            "alert_analysis_filter_severities": [
                Severity.CRITICAL,
                Severity.WARNING,
                Severity.INFO,
            ],
        }
    )
    runtime = build_runtime(
        settings,
        advisor=RecordingAdvisor(events),
        notifier=RecordingNotifier(events),
    )
    await runtime.repository.initialize()
    filtered, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "filtered-manual-reanalysis",
            "severity": "WARNING",
            "title": "Explicit reanalysis",
            "reason": "test",
        },
    )
    assert filtered.status == AlertStatus.FILTERED

    run, _ = await runtime.service.reanalyze(str(filtered.alert.id))
    current = await runtime.repository.get(str(filtered.alert.id))
    assert current is not None and current.latest_run is not None
    async with asyncio.timeout(3):
        while current.latest_run.status == RunStatus.RUNNING:
            await asyncio.sleep(0.01)
            current = await runtime.repository.get(str(filtered.alert.id))
            assert current is not None and current.latest_run is not None

    assert current.status == AlertStatus.INCONCLUSIVE
    assert current.latest_run.id == run.id
    assert current.latest_run.status == RunStatus.INCONCLUSIVE
    assert events == ["ADVISOR", "RESULT:WARNING"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_ai_failure_finishes_with_inconclusive_fallback(tmp_path: Path) -> None:
    events: list[str] = []
    runtime = build_runtime(
        settings_for(tmp_path), advisor=FailingAdvisor(), notifier=RecordingNotifier(events)
    )
    await runtime.repository.initialize()

    stored = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "failed",
            "severity": "CRITICAL",
            "title": "Critical",
            "reason": "x",
        },
    )

    assert stored.status == AlertStatus.INCONCLUSIVE
    assert stored.error is None
    assert stored.recommendation is not None
    assert stored.advisor_metadata is not None
    assert stored.advisor_metadata.provider == "conservative_fallback"
    assert any(item.metadata.get("fallback") is True for item in stored.validations)
    assert events == ["RESULT:CRITICAL"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_wecom_send_failure_does_not_change_analysis_status(tmp_path: Path) -> None:
    events: list[str] = []
    runtime = build_runtime(settings_for(tmp_path), notifier=RecordingNotifier(events, fail=True))
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "send-failed",
            "severity": "WARNING",
            "title": "Warning",
            "reason": "x",
        },
    )

    assert result.status == AlertStatus.INCONCLUSIVE
    assert events == ["RESULT:WARNING"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_failed_analysis_can_be_retried_then_sends_one_result(tmp_path: Path) -> None:
    events: list[str] = []
    advisor = FlakyAdvisor()
    settings = settings_for(tmp_path).model_copy(update={"ai_fallback_enabled": False})
    runtime = build_runtime(settings, advisor=advisor, notifier=RecordingNotifier(events))
    await runtime.repository.initialize()
    payload = {
        "external_id": "retry-critical",
        "severity": "CRITICAL",
        "title": "Critical",
        "reason": "x",
    }
    with pytest.raises(AnalysisFailedError) as exc_info:
        await runtime.service.analyze("canonical", payload)

    error_message = str(exc_info.value)
    assert "AI advisor failed: AdvisorError: temporary failure" in error_message
    assert "Missing run, alert, strategy, or recommendation in validate node" not in error_message

    failed = await runtime.service.get(exc_info.value.alert_id)
    assert failed.status == AlertStatus.FAILED
    assert failed.error is not None
    assert "AI advisor failed: AdvisorError: temporary failure" in failed.error

    result = await runtime.service.analyze("canonical", payload, retry_failed=True)

    assert result.status == AlertStatus.INCONCLUSIVE
    assert advisor.calls == 2
    assert events == ["RESULT:CRITICAL"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_main_agent_executes_one_outer_tool_per_round_then_finishes(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    advisor = ScriptedReActAdvisor(
        [
            InvestigationDecision(
                action="tool",
                tool_name="mcp_style_probe",
                parameters={"phase": "first"},
                objective="Collect the first read-only fact set.",
            ),
            InvestigationDecision(
                action="tool",
                tool_name="mcp_style_probe",
                parameters={"phase": "second"},
                objective="Collect a follow-up fact set from the prior observation.",
            ),
            InvestigationDecision(action="finish", reason="No more evidence is useful."),
        ],
        events=events,
        reasoning=["reason-one", "reason-two", "reason-finish"],
        final_reasoning="final-root-cause-reasoning",
    )
    tool = RecordingMCPStyleTool(events)
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"react_max_rounds": 8}),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "single-react-two-tools",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert events == [
        "REACT:1",
        "TOOL:first",
        "REACT:2",
        "TOOL:second",
        "REACT:3",
        "ADVISOR",
    ]
    assert advisor.decision_evidence == [
        [],
        [("mcp_style_probe", ToolStatus.SUCCESS)],
        [
            ("mcp_style_probe", ToolStatus.SUCCESS),
            ("mcp_style_probe", ToolStatus.SUCCESS),
        ],
    ]
    assert advisor.available_tool_names == [
        ["mcp_style_probe"],
        ["mcp_style_probe"],
        ["mcp_style_probe"],
    ]
    assert [item.parameters for item in tool.calls] == [
        {"phase": "first"},
        {"phase": "second"},
    ]
    assert all(item.required is False for item in tool.calls)
    assert advisor.evidence_tool_names == ["mcp_style_probe", "mcp_style_probe"]
    assert [
        item.details["outcome"]
        for item in result.progress
        if item.details.get("event") == "react_decision"
    ] == ["tool", "tool", "finish"]
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.latest_run is not None

    trace = [
        event
        for event in await runtime.repository.list_agent_events(str(result.latest_run.id))
        if event.kind
        in {
            AgentEventKind.TRACE_REASONING,
            AgentEventKind.TRACE_ACTION,
            AgentEventKind.TRACE_OBSERVATION,
        }
    ]
    assert [item.kind for item in trace] == [
        AgentEventKind.TRACE_REASONING,
        AgentEventKind.TRACE_ACTION,
        AgentEventKind.TRACE_OBSERVATION,
        AgentEventKind.TRACE_REASONING,
        AgentEventKind.TRACE_ACTION,
        AgentEventKind.TRACE_OBSERVATION,
        AgentEventKind.TRACE_REASONING,
        AgentEventKind.TRACE_ACTION,
        AgentEventKind.TRACE_REASONING,
    ]
    assert all(item.payload["scope"] == "main_agent" for item in trace)
    assert [
        item.payload["content"] for item in trace if item.kind == AgentEventKind.TRACE_REASONING
    ] == ["reason-one", "reason-two", "reason-finish", "final-root-cause-reasoning"]
    action_payloads = [
        json.loads(item.payload["content"])
        for item in trace
        if item.kind == AgentEventKind.TRACE_ACTION
    ]
    assert [item["action"] for item in action_payloads] == ["tool", "tool", "finish"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_main_agent_can_finish_without_mcp_or_fabricated_reasoning(
    tmp_path: Path,
) -> None:
    advisor = ScriptedReActAdvisor(
        [InvestigationDecision(action="finish", reason="No MCP is relevant.")]
    )
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "react-direct-finish",
            "severity": "INFO",
            "title": "Informational database alert",
            "reason": "informational",
        },
    )

    assert tool.calls == []
    assert advisor.decision_evidence == [[]]
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.latest_run is not None
    trace = await runtime.repository.list_agent_events(str(result.latest_run.id))
    assert not any(item.kind == AgentEventKind.TRACE_REASONING for item in trace)
    assert sum(item.kind == AgentEventKind.TRACE_ACTION for item in trace) == 1
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_react_structure_repairs_emit_each_provider_reasoning_immediately(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))
    await runtime.repository.initialize()
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "react-repair-reasoning",
            "severity": "INFO",
            "title": "Repair reasoning",
            "reason": "repair_reasoning",
        },
    )
    run = await runtime.repository.create_run(
        str(stored.alert.id),
        lease_owner="repair-reasoning-worker",
        lease_seconds=300,
    )
    assert run is not None

    advisor = object.__new__(OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "reasoning-model"
    calls = 0

    async def complete(_messages):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 2:
            prior_events = await runtime.repository.list_agent_events(str(run.id))
            assert [
                item.payload["content"]
                for item in prior_events
                if item.kind == AgentEventKind.TRACE_REASONING
            ] == ["first invalid action reasoning"]
        metadata = AdvisorMetadata(
            provider="openai_compatible",
            model="reasoning-model",
            prompt_version="test-v1",
            reasoning_content=(
                "first invalid action reasoning"
                if calls == 1
                else "second repaired action reasoning"
            ),
        )
        if calls == 1:
            return '{"action":"tool","tool_name":"not-configured"}', metadata
        return '{"action":"finish","reason":"done"}', metadata

    advisor._complete = complete
    runtime.service.agent.ctx.advisor = advisor
    state = AgentState(
        alert_id=str(stored.alert.id),
        alert=stored.alert,
        stored_alert=stored,
        run=run,
        react_max_rounds=8,
    )

    result = await react_decide_node(state, runtime.service.agent.ctx)

    assert result["react_decision"].action == "finish"
    assert calls == 2
    trace = await runtime.repository.list_agent_events(str(run.id))
    reasoning_events = [item for item in trace if item.kind == AgentEventKind.TRACE_REASONING]
    assert [item.payload["content"] for item in reasoning_events] == [
        "first invalid action reasoning",
        "second repaired action reasoning",
    ]
    assert [item.payload["trace_key"] for item in reasoning_events] == [
        "main-agent:react:1:request:0:react:1:attempt:0:delta:0",
        "main-agent:react:1:request:0:react:1:attempt:1:delta:0",
    ]
    assert max(item.sequence for item in reasoning_events) < next(
        item.sequence for item in trace if item.kind == AgentEventKind.TRACE_ACTION
    )
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_react_reasoning_attempts_resume_after_interrupted_decision(
    tmp_path: Path,
) -> None:
    class InterruptedAdvisor(FakeAIAdvisor):
        calls = 0

        async def decide_investigation(  # type: ignore[no-untyped-def]
            self,
            *,
            reasoning_callback,
            **_kwargs,
        ):
            self.calls += 1
            metadata = AdvisorMetadata(
                provider="test",
                model="interrupted-reasoning-model",
                prompt_version="test-v1",
                reasoning_content=f"reasoning attempt {self.calls}",
            )
            await reasoning_callback(
                metadata.reasoning_content,
                "react:1:attempt:0",
                0,
            )
            if self.calls == 1:
                raise asyncio.CancelledError
            return InvestigationDecisionResult(
                decision=InvestigationDecision(action="finish", reason="recovered"),
                metadata=metadata,
            )

    advisor = InterruptedAdvisor()
    runtime = build_runtime(settings_for(tmp_path), advisor=advisor)
    await runtime.repository.initialize()
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "react-interrupted-reasoning-resume",
            "severity": "INFO",
            "title": "Interrupted reasoning",
            "reason": "interrupted_reasoning",
        },
    )
    run = await runtime.repository.create_run(
        str(stored.alert.id),
        lease_owner="interrupted-reasoning-worker",
        lease_seconds=300,
    )
    assert run is not None
    state = AgentState(
        alert_id=str(stored.alert.id),
        alert=stored.alert,
        stored_alert=stored,
        run=run,
        react_max_rounds=8,
    )

    with pytest.raises(asyncio.CancelledError):
        await react_decide_node(state, runtime.service.agent.ctx)

    first_events = await runtime.repository.list_agent_events(str(run.id))
    assert not any(item.kind == AgentEventKind.MODEL_DECISION for item in first_events)

    result = await react_decide_node(state, runtime.service.agent.ctx)

    assert result["react_decision"].action == "finish"
    reasoning_events = [
        item
        for item in await runtime.repository.list_agent_events(str(run.id))
        if item.kind == AgentEventKind.TRACE_REASONING
    ]
    assert [item.payload["content"] for item in reasoning_events] == [
        "reasoning attempt 1",
        "reasoning attempt 2",
    ]
    assert [item.payload["trace_key"] for item in reasoning_events] == [
        "main-agent:react:1:request:0:react:1:attempt:0:delta:0",
        "main-agent:react:1:request:1:react:1:attempt:0:delta:0",
    ]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_react_node_supports_advisor_without_reasoning_callback(
    tmp_path: Path,
) -> None:
    class LegacyAdvisor(FakeAIAdvisor):
        async def decide_investigation(
            self,
            *,
            alert,
            knowledge,
            knowledge_match_summary,
            evidence,
            available_tools,
            react_round,
            react_max_rounds,
        ):  # type: ignore[no-untyped-def]
            del (
                alert,
                knowledge,
                knowledge_match_summary,
                evidence,
                available_tools,
                react_round,
                react_max_rounds,
            )
            return InvestigationDecisionResult(
                decision=InvestigationDecision(action="finish", reason="legacy finish"),
                metadata=AdvisorMetadata(
                    provider="legacy",
                    model="legacy-model",
                    prompt_version="legacy-v1",
                    reasoning_content="legacy provider reasoning",
                ),
            )

    runtime = build_runtime(settings_for(tmp_path), advisor=LegacyAdvisor())
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "legacy-reasoning-callback-compatibility",
            "severity": "INFO",
            "title": "Legacy advisor",
            "reason": "legacy_advisor",
        },
    )

    assert result.latest_run is not None
    events = await runtime.repository.list_agent_events(str(result.latest_run.id))
    assert [
        item.payload["content"] for item in events if item.kind == AgentEventKind.TRACE_REASONING
    ] == ["legacy provider reasoning"]
    await runtime.repository.close()  # type: ignore[attr-defined]


class _CallbackProbingAdvisor(ScriptedReActAdvisor):
    """Record whether the nodes forward a durable reasoning-delta callback."""

    def __init__(self) -> None:
        super().__init__(
            [
                InvestigationDecision(
                    action="tool",
                    tool_name="mcp_style_probe",
                    parameters={"phase": "probe"},
                    objective="collect probe evidence",
                ),
                InvestigationDecision(action="finish", reason="probe evidence ready"),
            ],
            reasoning=["round-one reasoning", "round-two reasoning"],
            final_reasoning="final complete reasoning",
        )
        self.decision_callbacks: list[object] = []
        self.advise_callbacks: list[object] = []

    async def decide_investigation(self, **kwargs):  # type: ignore[no-untyped-def]
        callback = kwargs.get("reasoning_callback", "absent")
        self.decision_callbacks.append(callback)
        if callable(callback):
            decision_index = len(self.decision_callbacks) - 1
            await callback(
                f"round-{decision_index + 1} streamed reasoning",
                f"probe-react-{decision_index}",
                0,
            )
        return await super().decide_investigation(**kwargs)

    async def advise(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        callback = kwargs.get("reasoning_callback", "absent")
        self.advise_callbacks.append(callback)
        if callable(callback):
            await callback("final streamed reasoning", "probe-final", 0)
        return await super().advise(*args, **kwargs)


@pytest.mark.asyncio
async def test_stream_main_agent_reasoning_disabled_records_reasoning_once(
    tmp_path: Path,
) -> None:
    advisor = _CallbackProbingAdvisor()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"stream_main_agent_reasoning": False}),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([RecordingMCPStyleTool()]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "main-agent-reasoning-once",
            "severity": "INFO",
            "title": "Reasoning once",
            "reason": "reasoning_once",
        },
    )

    # Durable delta persistence is disabled, so neither node forwards a
    # reasoning callback and each decision records one complete event.
    assert advisor.decision_callbacks == ["absent", "absent"]
    assert advisor.advise_callbacks == ["absent"]

    assert result.latest_run is not None
    assert result.latest_run.config_snapshot is not None
    assert result.latest_run.config_snapshot.stream_main_agent_reasoning is False
    events = await runtime.repository.list_agent_events(str(result.latest_run.id))
    reasoning_events = [item for item in events if item.kind == AgentEventKind.TRACE_REASONING]
    assert [item.payload["content"] for item in reasoning_events] == [
        "round-one reasoning",
        "round-two reasoning",
        "final complete reasoning",
    ]
    assert all("stream_id" not in item.payload for item in reasoning_events)
    assert all("delta_index" not in item.payload for item in reasoning_events)
    actions = [
        json.loads(item.payload["content"])
        for item in events
        if item.kind == AgentEventKind.TRACE_ACTION
    ]
    assert [item["action"] for item in actions] == ["tool", "finish"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_stream_main_agent_reasoning_enabled_passes_delta_callback(
    tmp_path: Path,
) -> None:
    advisor = _CallbackProbingAdvisor()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"stream_main_agent_reasoning": True}),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([RecordingMCPStyleTool()]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "main-agent-reasoning-stream",
            "severity": "INFO",
            "title": "Reasoning stream",
            "reason": "reasoning_stream",
        },
    )

    assert result.latest_run is not None
    assert result.latest_run.config_snapshot is not None
    assert result.latest_run.config_snapshot.stream_main_agent_reasoning is True
    assert all(callable(item) for item in advisor.decision_callbacks)
    assert callable(advisor.advise_callbacks[0])
    events = await runtime.repository.list_agent_events(str(result.latest_run.id))
    reasoning_events = [item for item in events if item.kind == AgentEventKind.TRACE_REASONING]
    assert [item.payload["content"] for item in reasoning_events] == [
        "round-1 streamed reasoning",
        "round-2 streamed reasoning",
        "final streamed reasoning",
    ]
    assert all(isinstance(item.payload.get("stream_id"), str) for item in reasoning_events)
    assert [item.payload["delta_index"] for item in reasoning_events] == [0, 0, 0]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_react_max_rounds_stops_normally_after_existing_observation(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    advisor = ScriptedReActAdvisor(
        [
            InvestigationDecision(
                action="tool",
                tool_name="mcp_style_probe",
                parameters={"phase": "only"},
            )
        ],
        events=events,
    )
    tool = RecordingMCPStyleTool(events)
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"react_max_rounds": 1}),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "react-round-ceiling",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
        },
    )

    assert events == ["REACT:1", "TOOL:only", "ADVISOR"]
    assert len(advisor.decision_evidence) == 1
    assert len(tool.calls) == 1
    assert [
        item.details["outcome"]
        for item in result.progress
        if item.details.get("event") == "react_decision"
    ] == ["tool", "max_rounds_reached"]
    assert result.status == AlertStatus.INCONCLUSIVE
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected_status"),
    [("failed", ToolStatus.FAILED), ("partial", ToolStatus.SUCCESS)],
)
async def test_failed_or_partial_observation_returns_to_main_agent_without_auto_retry(
    tmp_path: Path,
    outcome: str,
    expected_status: ToolStatus,
) -> None:
    advisor = ScriptedReActAdvisor(
        [
            InvestigationDecision(
                action="tool",
                tool_name="mcp_style_probe",
                parameters={"phase": outcome},
            ),
            InvestigationDecision(action="finish", reason="The result is insufficient."),
        ]
    )
    tool = StaticOutcomeTool(outcome)
    runtime = build_runtime(
        settings_for(tmp_path),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": f"react-{outcome}-observation",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
        },
    )

    assert len(tool.calls) == 1
    assert advisor.decision_evidence == [[], [("mcp_style_probe", expected_status)]]
    evidence = next(item for item in result.evidence_records if item.tool_name == tool.name)
    assert evidence.status == expected_status
    if outcome == "partial":
        assert "partial" not in evidence.structured_data
        assert evidence.structured_data["root_cause_eligible"] is False
        assert evidence.structured_data["processing_status"] == "completed"
    assert result.status == AlertStatus.INCONCLUSIVE
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_main_agent_selecting_unknown_tool_fails_the_run(tmp_path: Path) -> None:
    advisor = ScriptedReActAdvisor(
        [
            InvestigationDecision(
                action="tool",
                tool_name="not_configured",
                objective="This must be rejected as unavailable.",
            )
        ]
    )
    runtime = build_runtime(settings_for(tmp_path), advisor=advisor)
    await runtime.repository.initialize()

    with pytest.raises(AnalysisFailedError, match="selected unavailable tool") as exc_info:
        await runtime.service.analyze(
            "canonical",
            {
                "external_id": "react-unknown-tool",
                "severity": "INFO",
                "title": "Custom probe alert",
                "reason": "custom_probe",
            },
        )

    failed = await runtime.service.get(exc_info.value.alert_id)
    assert failed.status == AlertStatus.FAILED
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_evidence_persistence_failure_is_not_reclassified_as_tool_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advisor = ScriptedReActAdvisor(
        [
            InvestigationDecision(
                action="tool",
                tool_name="mcp_style_probe",
                parameters={"phase": "persist"},
            )
        ]
    )
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path),
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()
    save_attempts: list[ToolStatus] = []

    async def fail_save_evidence(_alert_id, evidence, **_kwargs):  # type: ignore[no-untyped-def]
        save_attempts.append(evidence.status)
        raise RuntimeError("local evidence store unavailable")

    monkeypatch.setattr(runtime.repository, "save_evidence", fail_save_evidence)

    with pytest.raises(AnalysisFailedError, match="local evidence store unavailable"):
        await runtime.service.analyze(
            "canonical",
            {
                "external_id": "react-evidence-persistence-failure",
                "severity": "WARNING",
                "title": "Database timeout",
                "reason": "database_timeout",
            },
        )

    assert len(tool.calls) == 1
    assert save_attempts == [ToolStatus.SUCCESS]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_persisted_react_reasoning_replays_idempotently_after_interruption(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))
    await runtime.repository.initialize()
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "react-reasoning-recovery",
            "severity": "INFO",
            "title": "Reasoning recovery",
            "reason": "checkpoint_recovery",
        },
    )
    run = await runtime.repository.create_run(
        str(stored.alert.id),
        lease_owner="reasoning-worker",
        lease_seconds=300,
    )
    assert run is not None
    decision = InvestigationDecision(action="finish", reason="Recovered finish.")
    reasoning = "真实 provider reasoning，必须在恢复后原样写入轨迹。"
    sink = RepositoryEventSink(
        runtime.repository,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )
    await sink.append(
        AgentEvent(
            run_id=run.id,
            kind=AgentEventKind.MODEL_DECISION,
            payload={
                "actor": "main_agent",
                "react_round": 1,
                "decision": decision.model_dump(mode="json"),
                "metadata": AdvisorMetadata(
                    provider="test",
                    model="reasoning-model",
                    prompt_version="test-v1",
                    reasoning_content=reasoning,
                ).model_dump(mode="json"),
            },
        )
    )
    state = AgentState(
        alert_id=str(stored.alert.id),
        alert=stored.alert,
        stored_alert=stored,
        run=run,
        react_max_rounds=8,
    )

    first = await react_decide_node(state, runtime.service.agent.ctx)
    second = await react_decide_node(state, runtime.service.agent.ctx)

    assert first["react_decision"] == decision
    assert second["react_decision"] == decision
    events = await runtime.repository.list_agent_events(str(run.id))
    assert sum(item.kind == AgentEventKind.MODEL_DECISION for item in events) == 1
    reasoning_events = [item for item in events if item.kind == AgentEventKind.TRACE_REASONING]
    assert [item.payload["content"] for item in reasoning_events] == [reasoning]
    assert sum(item.kind == AgentEventKind.TRACE_ACTION for item in events) == 1
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_runtime_settings_rebuild_agent_used_by_next_analysis(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    old_agent = runtime.service.agent

    updated = settings.model_copy(
        update={
            "react_max_rounds": 3,
            "stream_main_agent_reasoning": True,
        }
    )
    apply_runtime_settings(runtime, updated)
    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "runtime-refresh-1",
            "severity": "INFO",
            "title": "Runtime refresh",
            "reason": "runtime_refresh",
        },
    )

    assert runtime.service.agent is not old_agent
    assert runtime.service.agent.ctx.advisor is runtime.service.advisor
    assert runtime.service.react_max_rounds == 3
    assert result.latest_run is not None
    assert result.latest_run.config_snapshot is not None
    assert result.latest_run.config_snapshot.react_max_rounds == 3
    assert result.latest_run.config_snapshot.stream_main_agent_reasoning is True
    assert result.status == AlertStatus.INCONCLUSIVE
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_runtime_refresh_does_not_change_claimed_analysis_generation(
    tmp_path: Path,
) -> None:
    class RecordingTerminalAgent:
        def __init__(self) -> None:
            self.called = False

        async def run(self, state):  # type: ignore[no-untyped-def]
            self.called = True
            return state.model_copy(
                update={
                    "status": AlertStatus.INCONCLUSIVE,
                    "run_status": RunStatus.INCONCLUSIVE,
                    "current_stage": InvestigationStage.INCONCLUSIVE,
                }
            )

    settings = settings_for(tmp_path)
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "runtime-generation-isolation",
            "severity": "INFO",
            "title": "Freeze claimed runtime generation",
            "reason": "runtime_refresh",
        },
    )
    old_agent = RecordingTerminalAgent()
    runtime.service.agent = old_agent  # type: ignore[assignment]
    old_registry = runtime.service.tool_registry
    old_executor = runtime.service.tool_executor
    claim_started = asyncio.Event()
    release_claim = asyncio.Event()
    original_reclaim = runtime.repository.reclaim_expired_run

    async def blocked_reclaim(*args, **kwargs):  # type: ignore[no-untyped-def]
        claim_started.set()
        await release_claim.wait()
        return await original_reclaim(*args, **kwargs)

    runtime.repository.reclaim_expired_run = blocked_reclaim  # type: ignore[method-assign]
    analysis = asyncio.create_task(runtime.service.analyze_by_id(str(stored.alert.id)))
    await claim_started.wait()
    apply_runtime_settings(
        runtime,
        settings.model_copy(
            update={
                "react_max_rounds": settings.react_max_rounds + 4,
                "stream_main_agent_reasoning": True,
            }
        ),
    )
    release_claim.set()

    result = await analysis

    assert old_agent.called is True
    assert runtime.service.agent is not old_agent
    assert runtime.service.tool_registry is not old_registry
    assert runtime.service.tool_executor is not old_executor
    assert result.latest_run is not None
    assert result.latest_run.config_snapshot is not None
    assert result.latest_run.config_snapshot.react_max_rounds == settings.react_max_rounds
    assert result.latest_run.config_snapshot.stream_main_agent_reasoning is False
    await runtime.service.close()
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_workflow_binds_explain_to_exact_archery_history_sample(tmp_path: Path) -> None:
    long_sample = (
        "SELECT  * FROM orders WHERE note = 'A  B' AND id IN ("
        + ",".join(map(str, range(4_000)))
        + ")  ;"
    )
    source_a = {
        "id": 42,
        "checksum": "shared-checksum",
        "sample_sha256": "a" * 64,
        "sample": "SELECT * FROM orders WHERE customer_id = 42",
    }
    source_b = {
        "id": 43,
        "checksum": "shared-checksum",
        "sample_sha256": "b" * 64,
        "sample": long_sample,
        "raw": {"nested": ["business", {"raw": True}]},
        "raw_metric": 7,
        "artifact_count": 2,
        "hash": "business-hash",
        "content_hash": "business-content-hash",
        "request_id": "business-request-id",
        "usage": {"business_units": 9},
        "sha256": "business-sha256",
        "business_blob": "业务字段" * 10_001,
    }
    history_payload = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "column_list": list(source_b),
        "rows": [source_a, source_b],
        "row_count": 2,
    }
    slow_query_analysis = {
        "status": "partial",
        "explain_results": [
            {
                "source_history_row": source_a,
                "result": {"rows": [{"table": "orders", "type": "ALL"}]},
            }
        ],
        "table_structure_results": [],
        "index_results": [],
        "failures": [
            {
                "stage": "explain",
                "reason_code": "actual_sql_mismatch",
                "source_history_row": source_b,
            }
        ],
        "missing_stages": [],
    }

    class MultiSampleArcheryTool:
        name = "multi_sample_archery"
        source_system = "archery_mcp"
        read_only = True
        input_schema = {"type": "object", "properties": {}, "additionalProperties": False}

        async def execute(self, request, context):  # type: ignore[no-untyped-def]
            del request, context
            return "Archery history and supplemental analysis collected.", {
                "final_result_payload": history_payload,
                "slow_query_analysis": slow_query_analysis,
            }

    class MultiSampleAnalyzer:
        async def analyze(  # type: ignore[no-untyped-def]
            self,
            *,
            tool_name,
            source_system,
            request,
            raw_result,
            artifact,
        ):
            assert tool_name == MultiSampleArcheryTool.name
            assert source_system == "archery_mcp"
            assert request == {}
            structured_data = raw_result["structured_data"]
            return ToolResultAnalysis(
                summary="Archery 返回两个 history 样本及逐样本 supplemental 结果。",
                observations=[
                    ToolResultObservation(
                        statement="history 样本 43 的 EXPLAIN 因实际 SQL 不一致而失败。",
                        source_paths=[
                            "/structured_data/slow_query_analysis/failures/0/reason_code"
                        ],
                    )
                ],
                analysis_usable=True,
                source_coverage_complete=True,
                source_artifact_id=artifact.artifact_id,
                source_sha256=artifact.sha256,
                provider="deterministic-test",
                model="program-projection",
                prompt_version="test-v1",
                passthrough_payload=structured_data["final_result_payload"],
                slow_query_analysis=structured_data["slow_query_analysis"],
            )

    class MultiSampleAdvisor:
        def __init__(self) -> None:
            self.react_calls = 0

        async def decide_investigation(self, **kwargs):  # type: ignore[no-untyped-def]
            del kwargs
            self.react_calls += 1
            decision = (
                InvestigationDecision(
                    action="tool",
                    tool_name=MultiSampleArcheryTool.name,
                    objective="Collect bound history and EXPLAIN evidence.",
                )
                if self.react_calls == 1
                else InvestigationDecision(
                    action="finish",
                    reason="The exact history sample is sufficient for final synthesis.",
                )
            )
            return InvestigationDecisionResult(
                decision=decision,
                metadata=AdvisorMetadata(
                    provider="test",
                    model="multi-sample-advisor",
                    prompt_version="test-v1",
                ),
            )

        async def advise(  # type: ignore[no-untyped-def]
            self,
            alert,
            knowledge,
            evidence=None,
            knowledge_match_summary="",
            reasoning_callback=None,
        ):
            del alert, knowledge, reasoning_callback
            parent = next(item for item in evidence or [] if item.source_system == "archery_mcp")
            assert parent.contract_version == EVIDENCE_RECORD_V2
            history = next(unit for unit in parent.evidence_units if unit.stage == "history")
            assert any(
                unit.stage == "explain" and unit.status == EvidenceUnitStatus.SUCCESS
                for unit in parent.evidence_units
            )
            assert any(
                unit.stage == "explain"
                and unit.status == EvidenceUnitStatus.FAILED
                and unit.data["source_history_row"]["id"] == 43
                for unit in parent.evidence_units
            )
            history_ref = str(history.id)
            cause = "样本 43 的高频扫描持续占用连接槽位。"
            return (
                Recommendation(
                    summary=cause,
                    knowledge_match_summary=knowledge_match_summary,
                    likely_causes=[cause],
                    analysis_bases=[
                        AnalysisBasis(
                            source=AnalysisBasisSource.AI,
                            statement="依据样本 43 的完整 history 事实判断。",
                        )
                    ],
                    steps=[
                        RecommendationStep(
                            order=1,
                            action="优化样本 43 对应查询并限制其并发。",
                        )
                    ],
                    risks=[],
                    confidence=0.9,
                    root_causes=[
                        RootCauseAssessment(
                            cause=cause,
                            analysis_process=[
                                RootCauseAnalysisStep(
                                    observation="history 样本 43 显示高频慢查询。",
                                    inference="该样本持续占用连接槽位。",
                                    evidence_refs=[history_ref],
                                )
                            ],
                            problem_sql=RootCauseSqlEvidence(
                                statement=None,
                                structure="SELECT orders with predicates on note and id",
                                sample_id="43",
                                evidence_ref=history_ref,
                            ),
                            status=RootCauseStatus.SUPPORTED,
                            evidence_refs=[history_ref],
                            confidence=0.9,
                            verified=True,
                        )
                    ],
                ),
                AdvisorMetadata(
                    provider="test",
                    model="multi-sample-advisor",
                    prompt_version="test-v1",
                ),
            )

    runtime = build_runtime(
        settings_for(tmp_path),
        advisor=MultiSampleAdvisor(),
        tool_registry=InvestigationToolRegistry([MultiSampleArcheryTool()]),
        tool_result_analyzer=MultiSampleAnalyzer(),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "archery-explain-sample-binding",
            "severity": "WARNING",
            "title": "MySQL slow query alert",
            "reason": "mysql_slow_query_400",
        },
    )

    assert result.status == AlertStatus.COMPLETED
    assert result.latest_run is not None
    assert result.latest_run.status == RunStatus.COMPLETED
    assert result.recommendation is not None
    assert [cause.problem_sql.sample_id for cause in result.recommendation.root_causes] == ["43"]
    assert len(result.validations) == 1
    assert result.validations[0].passed is True
    assert result.validations[0].evidence_sufficient is True
    assert result.validations[0].issues == []
    archery_evidence = next(
        item for item in result.evidence_records if item.source_system == "archery_mcp"
    )
    history_unit = next(unit for unit in archery_evidence.evidence_units if unit.stage == "history")
    assert history_unit.data == history_payload
    trace_events = await runtime.repository.list_agent_events(str(result.latest_run.id))
    observations = [
        event for event in trace_events if event.kind == AgentEventKind.TRACE_OBSERVATION
    ]
    assert len(observations) == 1
    observation = json.loads(observations[0].payload["content"])
    assert observation == model_evidence_payload(archery_evidence)
    observation_history = next(
        unit for unit in observation["evidence_units"] if unit["stage"] == "history"
    )
    assert observation_history["data"] == history_payload
    serialized = observations[0].payload["content"]
    assert str(archery_evidence.source_artifact_id) not in serialized
    assert "business-request-id" in serialized
    assert long_sample in serialized
    await runtime.repository.close()  # type: ignore[attr-defined]
