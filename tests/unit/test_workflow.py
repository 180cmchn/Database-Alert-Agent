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
    InvestigationStrategy,
    ToolExecutionRequest,
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

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        knowledge_cases=None,
        external_knowledge=None,
        knowledge_match_summary="",
        strategy=None,
    ):
        self.events.append("ADVISOR")
        self.calls += 1
        return await super().advise(
            alert,
            runbooks,
            evidence=evidence,
            knowledge_cases=knowledge_cases,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
        )


class FailingAdvisor:
    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        knowledge_cases=None,
        external_knowledge=None,
        knowledge_match_summary="",
        strategy=None,
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
        knowledge_cases=None,
        external_knowledge=None,
        knowledge_match_summary="",
        strategy=None,
    ):
        self.calls += 1
        if self.calls == 1:
            raise AdvisorError("temporary failure")
        return await super().advise(
            alert,
            runbooks,
            evidence=evidence,
            knowledge_cases=knowledge_cases,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
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
@pytest.mark.parametrize("severity", ["CRITICAL", "WARNING", "INFO"])
async def test_every_severity_sends_one_final_ai_result(
    tmp_path: Path, severity: str
) -> None:
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
    }

    first = await runtime.service.analyze("canonical", payload)
    second = await runtime.service.analyze("canonical", payload)

    assert events == ["ADVISOR", f"RESULT:{severity}"]
    assert advisor.calls == 1
    assert first.alert.id == second.alert.id
    assert first.status == AlertStatus.REVIEW_REQUIRED
    assert all(item.passed for item in first.validations)
    assert all(not item.evidence_sufficient for item in first.validations)
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_ai_failure_finishes_with_review_required_fallback(tmp_path: Path) -> None:
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

    assert stored.status == AlertStatus.REVIEW_REQUIRED
    assert stored.error is None
    assert stored.recommendation is not None
    assert stored.recommendation.requires_human is True
    assert stored.advisor_metadata is not None
    assert stored.advisor_metadata.provider == "conservative_fallback"
    assert any(item.metadata.get("fallback") is True for item in stored.validations)
    assert events == ["RESULT:CRITICAL"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_wecom_send_failure_does_not_change_analysis_status(tmp_path: Path) -> None:
    events: list[str] = []
    runtime = build_runtime(
        settings_for(tmp_path), notifier=RecordingNotifier(events, fail=True)
    )
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

    assert result.status == AlertStatus.REVIEW_REQUIRED
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

    assert result.status == AlertStatus.REVIEW_REQUIRED
    assert advisor.calls == 2
    assert events == ["RESULT:CRITICAL"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_shadow_mode_always_requires_review(tmp_path: Path) -> None:
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

    assert result.status == AlertStatus.REVIEW_REQUIRED
    assert result.recommendation is not None
    assert result.recommendation.analysis_mode == "shadow"
    assert result.recommendation.requires_human is True
    # The notification step appends a REPORTING progress record after the
    # REVIEW_REQUIRED record. Find the shadow progress record explicitly.
    shadow_records = [
        record for record in result.progress
        if record.details.get("shadow_enabled") is True
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
        tool_registry=InvestigationToolRegistry(
            [AlertContextTool(), dynamic_tool]
        ),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "dynamic-investigation-1",
            "severity": "WARNING",
            "title": "Database timeout",
            "reason": "database_timeout",
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
        item
        for item in result.progress
        if item.details.get("event") == "react_decision"
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
        },
    )

    react_progress = [
        item
        for item in result.progress
        if item.details.get("event") == "react_decision"
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
        },
    )

    assert [item.tool_name for item in result.evidence_records] == ["alert_context"]
    react_progress = [
        item
        for item in result.progress
        if item.details.get("event") == "react_decision"
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

    assert result.status == AlertStatus.REVIEW_REQUIRED
    assert result.validations[0].passed is True
    assert result.validations[0].evidence_sufficient is False
    assert result.validations[0].metadata["required_tool_failures"] == [
        "custom_required_probe"
    ]
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
    assert result.status == AlertStatus.REVIEW_REQUIRED
    await runtime.repository.close()  # type: ignore[attr-defined]
