import asyncio
from pathlib import Path

import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.investigation import AlertContextTool, InvestigationToolRegistry
from app.adapters.notification import LogManagementNotifier
from app.application.factory import apply_runtime_settings, build_runtime
from app.config import Settings
from app.domain.errors import AdvisorError, AnalysisFailedError
from app.domain.models import (
    AlertStatus,
    InvestigationDecision,
    InvestigationEvidenceAssessment,
    InvestigationStage,
    InvestigationStrategy,
    RunStatus,
    ToolExecutionRequest,
    ToolStatus,
)


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


class DynamicAdvisor(FakeAIAdvisor):
    def __init__(self) -> None:
        self.decisions = 0
        self.strategy_ids: list[str] = []

    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        self.strategy_ids.append(context.strategy.strategy_id)
        self.decisions += 1
        if self.decisions == 1:
            return InvestigationDecision(
                action="tool",
                tool_name="query_logs",
                parameters={"query": "database timeout"},
                reason="Collect one additional log sample",
            )
        return InvestigationDecision(action="finish", reason="Evidence is sufficient")


class FailingDynamicPlanner(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        raise AdvisorError("planner unavailable token=planner-secret")


class DuplicateDynamicAdvisor(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        return InvestigationDecision(
            action="tool",
            tool_name="alert_context",
            parameters={},
            reason="The alert context should be collected again",
        )


class RecordingDynamicTool:
    name = "query_logs"
    source_system = "test_logs"

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request.parameters)
        return "Found matching database timeout logs.", {"matches": 3}


class RetryFailedRequestAdvisor(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        return InvestigationDecision(
            action="tool",
            tool_name="retryable_mcp_probe",
            parameters={"filters": {"service": "orders", "environment": "test"}},
            reason="Retry the transiently failed read-only probe",
        )


class RetryPartialRequestAdvisor(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        return InvestigationDecision(
            action="tool",
            tool_name="partial_mcp_probe",
            parameters={"query": "up"},
            reason="Complete the partial MCP investigation in a fresh session",
        )


class FollowupMCPAdvisor(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        return InvestigationDecision(
            action="tool",
            tool_name="mcp_style_probe",
            parameters={"phase": "followup"},
            reason="Collect a second MCP evidence sample",
        )


class AssessingFinishAdvisor(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        hypothesis_id = context.investigation_memory["hypotheses"][0]["hypothesis_id"]
        return InvestigationDecision(
            action="finish",
            reason="The live MCP observation supports the candidate mechanism",
            evidence_assessments=[
                InvestigationEvidenceAssessment(
                    hypothesis_id=hypothesis_id,
                    evidence_id=str(evidence[-1].id),
                    relation="SUPPORTS",
                    rationale="The complete live observation matches the mechanism.",
                )
            ],
        )


class SelectThenAssessAdvisor(FakeAIAdvisor):
    def __init__(self) -> None:
        self.planner_calls = 0

    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        self.planner_calls += 1
        hypothesis_id = context.investigation_memory["hypotheses"][0]["hypothesis_id"]
        if self.planner_calls == 1:
            return InvestigationDecision(
                action="tool",
                tool_name="mcp_style_probe",
                parameters={"phase": "followup"},
                hypothesis_ids=[hypothesis_id],
                reason="Collect one final discriminating observation",
            )
        return InvestigationDecision(
            action="finish",
            reason="The final observation supports the candidate mechanism",
            evidence_assessments=[
                InvestigationEvidenceAssessment(
                    hypothesis_id=hypothesis_id,
                    evidence_id=str(evidence[-1].id),
                    relation="SUPPORTS",
                    rationale="The final complete observation matches the mechanism.",
                )
            ],
        )


class AssessingDuplicateAdvisor(FakeAIAdvisor):
    async def choose_next_tool(  # type: ignore[no-untyped-def]
        self, context, evidence, available_tools
    ):
        hypothesis_id = context.investigation_memory["hypotheses"][0]["hypothesis_id"]
        return InvestigationDecision(
            action="tool",
            tool_name="mcp_style_probe",
            parameters={"phase": "initial"},
            hypothesis_ids=[hypothesis_id],
            reason="Repeat the completed probe",
            evidence_assessments=[
                InvestigationEvidenceAssessment(
                    hypothesis_id=hypothesis_id,
                    evidence_id=str(evidence[-1].id),
                    relation="CONTRADICTS",
                    rationale="The live result conflicts with a necessary prediction.",
                )
            ],
        )


class FlakyRetryableMCPTool:
    name = "retryable_mcp_probe"
    source_system = "test_mcp"

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

    def __init__(self) -> None:
        self.calls: list[ToolExecutionRequest] = []

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        return "MCP evidence collected.", {"phase": request.parameters["phase"]}


class RetryableMCPStrategy:
    async def select(self, alert, runbooks=None):  # type: ignore[no-untyped-def]
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
    async def select(self, alert, runbooks=None):  # type: ignore[no-untyped-def]
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
    async def select(self, alert, runbooks=None):  # type: ignore[no-untyped-def]
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
    async def select(self, alert, runbooks=None):  # type: ignore[no-untyped-def]
        strategy = await LongTimeoutMCPStrategy().select(alert, runbooks)
        return strategy.model_copy(update={"max_dynamic_turns": 0})


class RequiredToolStrategy:
    async def select(self, alert, runbooks=None):  # type: ignore[no-untyped-def]
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
    assert advisor.evidence_tool_names == ["alert_context"]
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
async def test_shadow_mode_is_always_inconclusive(tmp_path: Path) -> None:
    settings = settings_for(tmp_path).model_copy(update={"shadow_enabled": True})
    runtime = build_runtime(settings)
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "shadow-warning",
            "severity": "WARNING",
            "title": "Unknown warning",
            "reason": "unknown_warning",
        },
    )

    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert result.recommendation.analysis_mode == "shadow"
    # The notification step appends a REPORTING progress record after the
    # INCONCLUSIVE record. Find the shadow progress record explicitly.
    shadow_records = [
        record for record in result.progress if record.details.get("shadow_enabled") is True
    ]
    assert shadow_records, "expected a progress record with shadow_enabled=True"
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_investigation_executes_selected_tool_and_preserves_strategy(
    tmp_path: Path,
) -> None:
    advisor = DynamicAdvisor()
    dynamic_tool = RecordingDynamicTool()
    settings = settings_for(tmp_path).model_copy(
        update={"react_enabled": True, "react_max_dynamic_turns": 2}
    )
    runtime = build_runtime(
        settings,
        advisor=advisor,
        tool_registry=InvestigationToolRegistry([AlertContextTool(), dynamic_tool]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-1",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
            "database": {"engine": "mysql", "instance": "orders-primary"},
        },
    )

    assert dynamic_tool.calls == [{"query": "database timeout"}]
    assert advisor.decisions == 2
    assert advisor.strategy_ids == [
        "generic-alert-investigation-v2",
        "generic-alert-investigation-v2",
    ]
    assert [item.tool_name for item in result.evidence_records] == [
        "alert_context",
        "query_logs",
    ]
    react_progress = [
        item for item in result.progress if item.details.get("event") == "react_decision"
    ]
    assert [item.details["outcome"] for item in react_progress] == [
        "tool_selected",
        "finish",
    ]
    assert react_progress[0].details == {
        "event": "react_decision",
        "outcome": "tool_selected",
        "turns_remaining": 1,
        "evidence_count": 1,
        "tool_name": "query_logs",
        "reason": "Collect one additional log sample",
    }
    assert react_progress[1].details["reason"] == "Evidence is sufficient"
    assert all(item.sequence > 0 for item in react_progress)
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_investigation_does_not_repeat_terminal_failed_request(
    tmp_path: Path,
) -> None:
    tool = FlakyRetryableMCPTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=RetryFailedRequestAdvisor(),
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
    assert [item.details["outcome"] for item in react_progress] == ["duplicate_rejected"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_finish_fallback_does_not_repeat_terminal_failed_probe(
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
    assert [item.details["outcome"] for item in react_progress] == ["finish"]
    assert react_progress[0].details["stop_reason"] == "NO_SAFE_PROBE"
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_investigation_retries_same_request_after_partial_success(
    tmp_path: Path,
) -> None:
    tool = PartialRetryableMCPTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=RetryPartialRequestAdvisor(),
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

    assert len(tool.calls) == 2
    assert [item.status for item in result.evidence_records] == [
        ToolStatus.SUCCESS,
        ToolStatus.SUCCESS,
    ]
    assert [item.structured_data["partial"] for item in result.evidence_records] == [
        True,
        False,
    ]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_mcp_request_inherits_strategy_timeout_and_required(
    tmp_path: Path,
) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=FollowupMCPAdvisor(),
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
        {"phase": "followup"},
    ]
    assert [item.timeout_seconds for item in tool.calls] == [240, 240]
    assert [item.required for item in tool.calls] == [True, True]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_finish_cannot_promote_placeholder_hypothesis(
    tmp_path: Path,
) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=AssessingFinishAdvisor(),
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

    finish = next(item for item in result.progress if item.details.get("event") == "react_decision")
    assert finish.details["outcome"] == "finish"
    assert finish.details["stop_reason"] == "NO_SAFE_PROBE"
    assert finish.details["supported_hypothesis_ids"] == []
    assert result.status == AlertStatus.INCONCLUSIVE
    assert (
        "unresolved:unresolved-cause"
        in result.validations[0].metadata["host_inconclusive_reasons"]
    )
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

    assert tool.calls == []
    assert result.evidence_records == []
    assert result.status == AlertStatus.INCONCLUSIVE
    assert (
        "stop:TARGET_AMBIGUOUS"
        in result.validations[0].metadata["host_inconclusive_reasons"]
    )
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
        if "tool_count" in item.details and "stop_reason" in item.details
    )
    assert strategy_progress.details == {"tool_count": 1, "stop_reason": "CONTINUE"}
    assert [item.tool_name for item in result.evidence_records] == ["alert_context"]
    assert result.status == AlertStatus.INCONCLUSIVE
    assert result.recommendation is not None
    assert (
        "unresolved:unresolved-cause"
        in result.validations[0].metadata["host_inconclusive_reasons"]
    )
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_last_budgeted_tool_result_receives_final_assessment(
    tmp_path: Path,
) -> None:
    advisor = SelectThenAssessAdvisor()
    tool = RecordingMCPStyleTool()
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

    assert advisor.planner_calls == 2
    assert [item.parameters for item in tool.calls] == [
        {"phase": "initial"},
        {"phase": "followup"},
    ]
    react_outcomes = [
        item.details["outcome"]
        for item in result.progress
        if item.details.get("event") == "react_decision"
    ]
    assert react_outcomes == ["tool_selected", "final_assessment"]
    final_assessment = next(
        item for item in result.progress if item.details.get("outcome") == "final_assessment"
    )
    assert final_assessment.details["stop_reason"] == "BUDGET_EXHAUSTED"
    assert result.status == AlertStatus.INCONCLUSIVE
    assert (
        "unresolved:unresolved-cause"
        in result.validations[0].metadata["host_inconclusive_reasons"]
    )
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
async def test_duplicate_rejection_preserves_planner_assessment(tmp_path: Path) -> None:
    tool = RecordingMCPStyleTool()
    runtime = build_runtime(
        settings_for(tmp_path).model_copy(
            update={"react_enabled": True, "react_max_dynamic_turns": 1}
        ),
        advisor=AssessingDuplicateAdvisor(),
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
    duplicate = next(
        item for item in result.progress if item.details.get("outcome") == "duplicate_rejected"
    )
    assert duplicate.details["stop_reason"] == "HUMAN_REQUIRED"
    inconclusive_reasons = result.validations[0].metadata["host_inconclusive_reasons"]
    assert "stop:HUMAN_REQUIRED" in inconclusive_reasons
    assert "unresolved:unresolved-cause" in inconclusive_reasons
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
    inconclusive_reasons = result.validations[0].metadata["host_inconclusive_reasons"]
    assert "stop:BUDGET_EXHAUSTED" in inconclusive_reasons
    assert "unresolved:unresolved-cause" in inconclusive_reasons
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_investigation_persists_sanitized_planner_failure(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path).model_copy(
        update={"react_enabled": True, "react_max_dynamic_turns": 1}
    )
    runtime = build_runtime(settings, advisor=FailingDynamicPlanner())
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
    assert len(react_progress) == 1
    assert react_progress[0].details == {
        "event": "react_decision",
        "outcome": "planner_error",
        "turns_remaining": 1,
        "evidence_count": 1,
        "error_type": "AdvisorError",
    }
    assert "planner-secret" not in str(react_progress[0].details)
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dynamic_investigation_persists_duplicate_rejection(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path).model_copy(
        update={"react_enabled": True, "react_max_dynamic_turns": 1}
    )
    runtime = build_runtime(settings, advisor=DuplicateDynamicAdvisor())
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

    assert [item.tool_name for item in result.evidence_records] == ["alert_context"]
    react_progress = [
        item for item in result.progress if item.details.get("event") == "react_decision"
    ]
    assert len(react_progress) == 1
    assert react_progress[0].details["outcome"] == "duplicate_rejected"
    assert react_progress[0].details["tool_name"] == "alert_context"
    assert react_progress[0].details["turns_remaining"] == 1
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_required_tool_failure_comes_from_selected_strategy(tmp_path: Path) -> None:
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
    assert result.validations[0].metadata["required_tool_failures"] == ["custom_required_probe"]
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
