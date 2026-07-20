from pathlib import Path

import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.notification import LogManagementNotifier
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.errors import AdvisorError, AnalysisFailedError
from app.domain.models import AlertStatus, NotificationPhase


class RecordingNotifier(LogManagementNotifier):
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def send(self, event):  # type: ignore[no-untyped-def]
        self.events.append(event.phase.value)
        return f"recorded-{event.phase.value}"


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
        strategy=None,
    ):
        self.events.append("ADVISOR")
        self.calls += 1
        return await super().advise(
            alert,
            runbooks,
            evidence=evidence,
            knowledge_cases=knowledge_cases,
            strategy=strategy,
        )


class FailingAdvisor:
    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        knowledge_cases=None,
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
            strategy=strategy,
        )


def settings_for(tmp_path: Path) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir(exist_ok=True)
    return Settings(
        ai_provider="fake",
        notifier_mode="log",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_dir=runbooks,
        notification_retry_backoff_seconds=0,
    )


@pytest.mark.asyncio
async def test_critical_notifies_before_and_after_advisor_and_deduplicates(tmp_path: Path) -> None:
    events: list[str] = []
    advisor = RecordingAdvisor(events)
    runtime = build_runtime(
        settings_for(tmp_path), advisor=advisor, notifier=RecordingNotifier(events)
    )
    await runtime.repository.initialize()
    payload = {
        "external_id": "critical-1",
        "severity": "CRITICAL",
        "title": "Critical alert",
        "reason": "unknown",
    }
    first = await runtime.service.analyze("canonical", payload)
    second = await runtime.service.analyze("canonical", payload)

    assert events == ["ADVISOR", "ADVICE_READY"]
    assert advisor.calls == 1
    assert first.alert.id == second.alert.id
    assert first.status == AlertStatus.COMPLETED
    assert [item.phase for item in first.notifications] == [
        NotificationPhase.ADVICE_READY
    ]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_warning_does_not_send_ai_result_notification(tmp_path: Path) -> None:
    events: list[str] = []
    runtime = build_runtime(
        settings_for(tmp_path),
        advisor=RecordingAdvisor(events),
        notifier=RecordingNotifier(events),
    )
    await runtime.repository.initialize()
    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "warning-1",
            "severity": "WARNING",
            "title": "Warning",
            "reason": "x",
        },
    )
    assert result.status == AlertStatus.COMPLETED
    assert events == ["ADVISOR"]
    assert result.notifications == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_critical_advisor_failure_is_audited_and_notified(tmp_path: Path) -> None:
    events: list[str] = []
    runtime = build_runtime(
        settings_for(tmp_path), advisor=FailingAdvisor(), notifier=RecordingNotifier(events)
    )
    await runtime.repository.initialize()
    with pytest.raises(AnalysisFailedError) as caught:
        await runtime.service.analyze(
            "canonical",
            {
                "external_id": "critical-failed",
                "severity": "CRITICAL",
                "title": "Critical",
                "reason": "x",
            },
        )
    stored = await runtime.service.get(caught.value.alert_id)
    assert stored.status == AlertStatus.FAILED
    assert "provider unavailable" in (stored.error or "")
    assert events == ["ANALYSIS_FAILED"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_failed_record_can_be_explicitly_retried_without_duplicate_notifications(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    advisor = FlakyAdvisor()
    runtime = build_runtime(
        settings_for(tmp_path), advisor=advisor, notifier=RecordingNotifier(events)
    )
    await runtime.repository.initialize()
    payload = {
        "external_id": "retry-critical",
        "severity": "CRITICAL",
        "title": "Critical",
        "reason": "x",
    }
    with pytest.raises(AnalysisFailedError):
        await runtime.service.analyze("canonical", payload)

    result = await runtime.service.analyze("canonical", payload, retry_failed=True)
    assert result.status == AlertStatus.COMPLETED
    assert advisor.calls == 2
    assert events == ["ANALYSIS_FAILED", "ADVICE_READY"]
    assert [item.phase for item in result.notifications] == [
        NotificationPhase.ANALYSIS_FAILED,
        NotificationPhase.ADVICE_READY,
    ]
    await runtime.repository.close()  # type: ignore[attr-defined]
