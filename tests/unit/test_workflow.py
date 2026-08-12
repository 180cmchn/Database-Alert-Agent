import asyncio
from pathlib import Path
from uuid import uuid5

import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.investigation import InvestigationToolRegistry
from app.adapters.notification import LogManagementNotifier
from app.agents.nodes import enrich_alert_node
from app.agents.state import AgentState
from app.application.factory import apply_runtime_settings, build_runtime
from app.application.validation import enforce_post_evidence_root_cause_policy
from app.config import Settings
from app.domain.errors import AdvisorError, AnalysisFailedError
from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    AnalysisBasis,
    AnalysisBasisSource,
    DatabaseTarget,
    InvestigationStage,
    InvestigationStrategy,
    Recommendation,
    RecommendationStep,
    RootCauseAssessment,
    RootCauseStatus,
    RunStatus,
    ToolExecutionRequest,
    ToolStatus,
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

    class RecordingRunbookProvider:
        async def search(self, alert, limit=5):  # type: ignore[no-untyped-def]
            events.append("KNOWLEDGE")
            seen_hosts.append(alert.database.host if alert.database else None)
            return []

    class EmptyRunbookStore:
        async def search(self, _alert, limit=5):  # type: ignore[no-untyped-def]
            return []

        async def list(self):  # type: ignore[no-untyped-def]
            return []

        async def get(self, _runbook_id):  # type: ignore[no-untyped-def]
            raise AssertionError("not used")

    class RecordingStrategy:
        async def select(
            self,
            alert,
            runbooks=None,
            external_knowledge=None,
            knowledge_match_summary="",
        ):  # type: ignore[no-untyped-def]
            events.append("MCP_SELECTION")
            seen_hosts.append(alert.database.host if alert.database else None)
            return InvestigationStrategy(
                strategy_id="detail-first",
                title="Detail first",
                description="Use the enriched target.",
                tool_plan=[ToolExecutionRequest(tool_name="detail_probe")],
            )

    class RecordingTool:
        name = "detail_probe"
        source_system = "test_mcp"
        read_only = True
        input_schema = {"type": "object", "additionalProperties": False}

        async def execute(self, request, context):  # type: ignore[no-untyped-def]
            events.append("MCP_CALL")
            seen_hosts.append(
                context.alert.database.host if context.alert.database else None
            )
            return "detail endpoint observed", {"root_cause_eligible": False}

    provider = RecordingRunbookProvider()
    runtime = build_runtime(
        settings_for(tmp_path),
        runbook_provider=provider,
        runbook_store=EmptyRunbookStore(),
        strategy_provider=RecordingStrategy(),
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

    assert events[:4] == ["DETAIL", "KNOWLEDGE", "MCP_SELECTION", "MCP_CALL"]
    assert seen_hosts == ["detail-host", "detail-host", "detail-host"]
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
    assert detail_evidence.request["read_only"] is True
    assert detail_evidence.structured_data["read_only"] is True
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
async def test_zero_mcp_can_use_detail_evidence_but_reason_is_not_automatic_root_cause(
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

    class EmptyStrategy:
        async def select(
            self,
            alert,
            runbooks=None,
            external_knowledge=None,
            knowledge_match_summary="",
        ):  # type: ignore[no-untyped-def]
            return InvestigationStrategy(
                strategy_id="zero-mcp",
                title="No MCP needed",
                description="Use the authoritative alert detail facts.",
                tool_plan=[],
            )

    class DetailEvidenceAdvisor:
        async def advise(
            self,
            alert,
            runbooks,
            evidence=None,
            external_knowledge=None,
            knowledge_match_summary="",
            strategy=None,
            investigation_memory=None,
        ):  # type: ignore[no-untyped-def]
            del runbooks, external_knowledge, strategy, investigation_memory
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
                            action="只读核对连接来源与连接池使用情况。",
                        )
                    ],
                    risks=[],
                    confidence=0.9,
                    manual_matched=False,
                    root_causes=[
                        RootCauseAssessment(
                            cause=cause,
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

    class EmptyRunbookStore:
        async def list(self):  # type: ignore[no-untyped-def]
            return []

        async def get(self, _runbook_id):  # type: ignore[no-untyped-def]
            raise AssertionError("not used")

    runtime = build_runtime(
        settings_for(tmp_path).model_copy(update={"validation_enabled": False}),
        advisor=DetailEvidenceAdvisor(),
        runbook_provider=EmptyRunbookStore(),
        runbook_store=EmptyRunbookStore(),
        strategy_provider=EmptyStrategy(),
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
    assert result.recommendation.root_causes[0].cause != result.alert.reason
    assert [item.tool_name for item in result.evidence_records] == [
        "flashduty_alert_info"
    ]
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
@pytest.mark.parametrize("read_only", [None, False, True])
async def test_flashduty_detail_failure_closes_before_knowledge_and_mcp(
    tmp_path: Path,
    read_only: bool | None,
) -> None:
    calls: list[str] = []

    class UnusableDetailEnricher:
        async def enrich(self, _alert):  # type: ignore[no-untyped-def]
            calls.append("DETAIL")
            raise RuntimeError("detail unavailable")

    class RecordingRunbookProvider:
        async def search(self, _alert, limit=5):  # type: ignore[no-untyped-def]
            calls.append("KNOWLEDGE")
            return []

    class EmptyRunbookStore:
        async def list(self):  # type: ignore[no-untyped-def]
            return []

        async def get(self, _runbook_id):  # type: ignore[no-untyped-def]
            raise AssertionError("not used")

    class RecordingStrategy:
        async def select(
            self,
            _alert,
            runbooks=None,
            external_knowledge=None,
            knowledge_match_summary="",
        ):  # type: ignore[no-untyped-def]
            calls.append("MCP_SELECTION")
            raise AssertionError("MCP selection must not run without alert detail")

    runtime = build_runtime(
        settings_for(tmp_path),
        runbook_provider=RecordingRunbookProvider(),
        runbook_store=EmptyRunbookStore(),
        strategy_provider=RecordingStrategy(),
    )
    enricher = UnusableDetailEnricher()
    if read_only is not None:
        enricher.read_only = read_only  # type: ignore[attr-defined]
    runtime.service.agent.ctx.alert_detail_enricher = enricher  # type: ignore[assignment]
    await runtime.repository.initialize()

    with pytest.raises(AnalysisFailedError, match="FlashDuty alert detail"):
        await runtime.service.analyze(
            "flashduty",
            {
                "request_id": "req-list",
                "data": {
                    "alert_id": f"663a1b2c3d4e5f6789abcde{int(bool(read_only))}",
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

    assert calls == (["DETAIL"] if read_only is True else [])
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
        self.planner_calls = 0
        self.evidence_tool_names: list[str] = []

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        external_knowledge=None,
        knowledge_match_summary="",
        strategy=None,
        investigation_memory=None,
    ):
        self.events.append("ADVISOR")
        self.calls += 1
        self.evidence_tool_names = [item.tool_name for item in evidence or []]
        return await super().advise(
            alert,
            runbooks,
            evidence=evidence,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
            investigation_memory=investigation_memory,
        )

    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        self.planner_calls += 1
        raise AssertionError("the post-collection advisor must not plan evidence collection")


class FailingAdvisor:
    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        external_knowledge=None,
        knowledge_match_summary="",
        strategy=None,
        investigation_memory=None,
    ):
        raise AdvisorError("provider unavailable")


class FlakyAdvisor(FakeAIAdvisor):
    def __init__(self) -> None:
        self.calls = 0

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        external_knowledge=None,
        knowledge_match_summary="",
        strategy=None,
        investigation_memory=None,
    ):
        self.calls += 1
        if self.calls == 1:
            raise AdvisorError("temporary failure")
        return await super().advise(
            alert,
            runbooks,
            evidence=evidence,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
            investigation_memory=investigation_memory,
        )


class FlakyRetryableMCPTool:
    name = "retryable_mcp_probe"
    source_system = "test_mcp"
    read_only = True

    def __init__(self) -> None:
        self.calls: list[ToolExecutionRequest] = []

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        if len(self.calls) == 1:
            raise RuntimeError("transient MCP transport failure")
        return "MCP retry returned evidence.", {"matches": 1}


class PartialRetryableMCPTool:
    name = "partial_mcp_probe"
    source_system = "test_mcp"
    read_only = True

    def __init__(self) -> None:
        self.calls: list[ToolExecutionRequest] = []

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        if len(self.calls) == 1:
            return "Partial MCP evidence.", {
                "matches": 1,
                "partial": True,
                "termination_reason": "sse_error_after_partial_result",
            }
        return "Complete MCP evidence.", {"matches": 2, "partial": False}


class RecordingMCPStyleTool:
    name = "mcp_style_probe"
    source_system = "test_mcp"
    read_only = True

    def __init__(self, events: list[str] | None = None) -> None:
        self.calls: list[ToolExecutionRequest] = []
        self.events = events
        self.context_memories: list[dict] = []

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        self.context_memories.append(context.investigation_memory)
        if self.events is not None:
            self.events.append(f"TOOL:{request.parameters['phase']}")
        return "MCP evidence collected.", {"phase": request.parameters["phase"]}


class RetryableMCPStrategy:
    async def select(
        self,
        alert,
        runbooks=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):  # type: ignore[no-untyped-def]
        return InvestigationStrategy(
            strategy_id="retryable-mcp-strategy",
            title="Retryable MCP strategy",
            description="Retry one transiently failed MCP request.",
            tool_plan=[
                ToolExecutionRequest(
                    tool_name="retryable_mcp_probe",
                    parameters={"filters": {"environment": "test", "service": "orders"}},
                    timeout_seconds=240,
                )
            ],
            max_dynamic_turns=1,
        )


class PartialMCPStrategy:
    async def select(
        self,
        alert,
        runbooks=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):  # type: ignore[no-untyped-def]
        return InvestigationStrategy(
            strategy_id="partial-mcp-strategy",
            title="Partial MCP strategy",
            description="Retry one incomplete MCP result.",
            tool_plan=[
                ToolExecutionRequest(
                    tool_name="partial_mcp_probe",
                    parameters={"query": "up"},
                    timeout_seconds=240,
                )
            ],
            max_dynamic_turns=1,
        )


class LongTimeoutMCPStrategy:
    async def select(
        self,
        alert,
        runbooks=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):  # type: ignore[no-untyped-def]
        return InvestigationStrategy(
            strategy_id="long-timeout-mcp-strategy",
            title="Long timeout MCP strategy",
            description="Use the MCP host's bounded multi-step timeout.",
            tool_plan=[
                ToolExecutionRequest(
                    tool_name="mcp_style_probe",
                    parameters={"phase": "initial"},
                    timeout_seconds=240,
                    required=True,
                )
            ],
            max_dynamic_turns=1,
        )


class NoReactMCPStrategy:
    async def select(
        self,
        alert,
        runbooks=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):  # type: ignore[no-untyped-def]
        strategy = await LongTimeoutMCPStrategy().select(
            alert, runbooks, external_knowledge, knowledge_match_summary
        )
        return strategy.model_copy(update={"max_dynamic_turns": 0})


class TwoPhaseCollectionStrategy:
    async def select(
        self,
        alert,
        runbooks=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):  # type: ignore[no-untyped-def]
        return InvestigationStrategy(
            strategy_id="two-phase-collection",
            title="Two planned read-only collections",
            description="Collect both terminal observations before analysis.",
            tool_plan=[
                ToolExecutionRequest(
                    tool_name="mcp_style_probe",
                    parameters={"phase": phase},
                    hypothesis_ids=["legacy-hypothesis"],
                    timeout_seconds=240,
                )
                for phase in ("first", "second")
            ],
            max_dynamic_turns=2,
        )


class RequiredToolStrategy:
    async def select(
        self,
        alert,
        runbooks=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):  # type: ignore[no-untyped-def]
        return InvestigationStrategy(
            strategy_id="custom-required-tool",
            title="Custom required tool",
            description="Exercise required-tool validation from the selected strategy.",
            tool_plan=[
                ToolExecutionRequest(
                    tool_name="custom_required_probe",
                    required=True,
                )
            ],
        )


def settings_for(tmp_path: Path) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir(exist_ok=True)
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=runbooks,
    )


@pytest.mark.asyncio
async def test_missing_pdf_semantic_match_is_reported_to_main_analysis(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "missing-local-pdf-type",
            "severity": "WARNING",
            "title": "MySQL slow query alert",
            "reason": "mysql_slow_query_400",
        },
    )

    assert result.recommendation is not None
    assert (
        "本地 PDF 候选未达到匹配阈值，已拒绝匹配"
        in result.recommendation.knowledge_match_summary
    )
    assert result.manual_matches == []
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
    assert all(item.passed for item in first.validations)
    assert all(not item.evidence_sufficient for item in first.validations)
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
async def test_all_planned_collection_finishes_before_advisor_and_react_is_ignored(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    advisor = RecordingAdvisor(events)
    tool = RecordingMCPStyleTool(events)
    settings = settings_for(tmp_path).model_copy(
        update={"react_enabled": True, "react_max_dynamic_turns": 2}
    )
    runtime = build_runtime(
        settings,
        advisor=advisor,
        strategy_provider=TwoPhaseCollectionStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "strict-two-phase-order",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert events == ["TOOL:first", "TOOL:second", "ADVISOR"]
    assert advisor.calls == 1
    assert advisor.planner_calls == 0
    assert advisor.evidence_tool_names == ["mcp_style_probe", "mcp_style_probe"]
    assert [item.parameters for item in tool.calls] == [
        {"phase": "first"},
        {"phase": "second"},
    ]
    assert [item.hypothesis_ids for item in tool.calls] == [[], []]
    assert tool.context_memories == [{}, {}]
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    assert not any(item.details.get("event") == "react_decision" for item in result.progress)
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_planned_collection_does_not_repeat_terminal_failed_request(
    tmp_path: Path,
) -> None:
    tool = FlakyRetryableMCPTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FakeAIAdvisor(),
        strategy_provider=RetryableMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-retry-failure",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert len(tool.calls) == 1
    assert [item.status for item in result.evidence_records] == [ToolStatus.FAILED]
    assert tool.calls[0].timeout_seconds == 240
    react_progress = [
        item for item in result.progress if item.details.get("event") == "react_decision"
    ]
    assert react_progress == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_analysis_does_not_repeat_terminal_failed_probe(
    tmp_path: Path,
) -> None:
    tool = FlakyRetryableMCPTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FakeAIAdvisor(),
        strategy_provider=RetryableMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-finish-no-missing-probe-replay",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert len(tool.calls) == 1
    assert [item.status for item in result.evidence_records] == [ToolStatus.FAILED]
    react_progress = [
        item for item in result.progress if item.details.get("event") == "react_decision"
    ]
    assert react_progress == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_planned_collection_does_not_retry_partial_success(
    tmp_path: Path,
) -> None:
    tool = PartialRetryableMCPTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FakeAIAdvisor(),
        strategy_provider=PartialMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-retry-partial",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert len(tool.calls) == 1
    assert [item.status for item in result.evidence_records] == [ToolStatus.SUCCESS]
    assert [item.structured_data["partial"] for item in result.evidence_records] == [
        True,
    ]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_planned_mcp_request_uses_strategy_timeout_and_required(
    tmp_path: Path,
) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FakeAIAdvisor(),
        strategy_provider=LongTimeoutMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-mcp-timeout",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert [item.parameters for item in tool.calls] == [
        {"phase": "initial"},
    ]
    assert [item.timeout_seconds for item in tool.calls] == [240]
    assert [item.required for item in tool.calls] == [True]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_post_collection_analysis_does_not_promote_alert_symptom(
    tmp_path: Path,
) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FakeAIAdvisor(),
        strategy_provider=LongTimeoutMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-assessed-finish",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert len(tool.calls) == 1
    assert not any(item.details.get("event") == "react_decision" for item in result.progress)
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_ambiguous_target_stops_before_first_tool_call(tmp_path: Path) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path),
        strategy_provider=LongTimeoutMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "ambiguous-target-stops-tools",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
        },
    )

    assert len(tool.calls) == 1
    assert len(result.evidence_records) == 1
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_explicit_target_runs_baseline_but_keeps_unknown_cause_inconclusive(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "baseline-context-before-causal-probe",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    strategy_progress = next(
        item
        for item in result.progress
        if "tool_count" in item.details and "analysis_deferred" in item.details
    )
    assert strategy_progress.details == {"tool_count": 0, "analysis_deferred": True}
    assert result.evidence_records == []
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_planned_tool_result_is_analyzed_only_after_collection(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    advisor = RecordingAdvisor(events)
    tool = RecordingMCPStyleTool(events)
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=advisor,
        strategy_provider=LongTimeoutMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "assess-last-budgeted-result",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert advisor.planner_calls == 0
    assert events == ["TOOL:initial", "ADVISOR"]
    assert [item.parameters for item in tool.calls] == [
        {"phase": "initial"},
    ]
    react_outcomes = [
        item.details["outcome"]
        for item in result.progress
        if item.details.get("event") == "react_decision"
    ]
    assert react_outcomes == []
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_evidence_persistence_failure_is_not_reclassified_as_tool_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path),
        strategy_provider=LongTimeoutMCPStrategy(),
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
                "external_id": "evidence-persistence-failure",
                "severity": "WARNING",
                "title": "Database timeout",
                "reason": "database_timeout",
                "database": {"engine": "mysql", "instance": "orders-primary"},
            },
        )

    assert len(tool.calls) == 1
    assert save_attempts == [ToolStatus.SUCCESS]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_legacy_react_settings_do_not_add_duplicate_collection(tmp_path: Path) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FakeAIAdvisor(),
        strategy_provider=LongTimeoutMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "duplicate-keeps-assessment",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert len(tool.calls) == 1
    assert not any(item.details.get("event") == "react_decision" for item in result.progress)
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_zero_dynamic_budget_keeps_unresolved_memory_inconclusive(
    tmp_path: Path,
) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path),
        strategy_provider=NoReactMCPStrategy(),
        tool_registry=InvestigationToolRegistry([tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "zero-dynamic-budget",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert len(tool.calls) == 1
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    assert not any(item.details.get("event") == "react_decision" for item in result.progress)
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_legacy_react_settings_do_not_invoke_a_planner(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path).model_copy(
        update={"react_enabled": True, "react_max_dynamic_turns": 1}
    )
    events: list[str] = []
    advisor = RecordingAdvisor(events)
    runtime = build_runtime(settings, advisor=advisor)
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-planner-failure",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    react_progress = [
        item for item in result.progress if item.details.get("event") == "react_decision"
    ]
    assert react_progress == []
    assert advisor.planner_calls == 0
    assert events == ["ADVISOR"]
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_legacy_react_settings_keep_only_planned_collection(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path).model_copy(
        update={"react_enabled": True, "react_max_dynamic_turns": 1}
    )
    events: list[str] = []
    advisor = RecordingAdvisor(events)
    runtime = build_runtime(settings, advisor=advisor)
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-duplicate",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert result.evidence_records == []
    react_progress = [
        item for item in result.progress if item.details.get("event") == "react_decision"
    ]
    assert react_progress == []
    assert advisor.planner_calls == 0
    assert events == ["ADVISOR"]
    assert result.recommendation is not None
    assert result.recommendation.root_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_unavailable_selected_tool_does_not_create_global_required_failure(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(
        settings_for(tmp_path),
        strategy_provider=RequiredToolStrategy(),
        tool_registry=InvestigationToolRegistry(),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "custom-required-1",
            "severity": "INFO",
            "title": "Custom probe alert",
            "reason": "custom_probe",
        },
    )

    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.validations[0].passed is True
    assert result.validations[0].evidence_sufficient is False
    assert "required_tool_failures" not in result.validations[0].metadata
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_runtime_settings_rebuild_agent_used_by_next_analysis(tmp_path: Path) -> None:
    class RecordingRunbookProvider:
        def __init__(self) -> None:
            self.limits: list[int] = []

        async def search(self, alert, limit=5):  # type: ignore[no-untyped-def]
            self.limits.append(limit)
            return []

    class EmptyRunbookStore:
        async def list(self):  # type: ignore[no-untyped-def]
            return []

        async def get(self, runbook_id):  # type: ignore[no-untyped-def]
            raise AssertionError("not used")

    provider = RecordingRunbookProvider()
    settings = settings_for(tmp_path)
    runtime = build_runtime(
        settings,
        runbook_provider=provider,
        runbook_store=EmptyRunbookStore(),
    )
    await runtime.repository.initialize()
    old_agent = runtime.service.agent

    updated = settings.model_copy(
        update={
            "runbook_limit": 9,
            "react_enabled": True,
            "react_max_dynamic_turns": 3,
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
    assert runtime.service.agent.ctx.runbook_limit == 9
    assert runtime.service.max_dynamic_turns == 3
    assert provider.limits == [9]
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
        settings.model_copy(update={"runbook_limit": settings.runbook_limit + 4}),
    )
    release_claim.set()

    result = await analysis

    assert old_agent.called is True
    assert runtime.service.agent is not old_agent
    assert runtime.service.tool_registry is not old_registry
    assert runtime.service.tool_executor is not old_executor
    assert result.latest_run is not None
    assert result.latest_run.config_snapshot is not None
    assert result.latest_run.config_snapshot.runbook_limit == settings.runbook_limit
    await runtime.service.close()
    await runtime.repository.close()  # type: ignore[attr-defined]
