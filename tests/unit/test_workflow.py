from pathlib import Path

import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.notification import LogManagementNotifier
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.errors import AdvisorError, AnalysisFailedError
from app.domain.models import AlertStatus


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
    assert first.status == AlertStatus.COMPLETED
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_ai_failure_does_not_send_a_fake_final_result(tmp_path: Path) -> None:
    events: list[str] = []
    runtime = build_runtime(
        settings_for(tmp_path), advisor=FailingAdvisor(), notifier=RecordingNotifier(events)
    )
    await runtime.repository.initialize()

    with pytest.raises(AnalysisFailedError) as caught:
        await runtime.service.analyze(
            "canonical",
            {
                "external_id": "failed",
                "severity": "CRITICAL",
                "title": "Critical",
                "reason": "x",
            },
        )

    stored = await runtime.service.get(caught.value.alert_id)
    assert stored.status == AlertStatus.FAILED
    assert "provider unavailable" in (stored.error or "")
    assert events == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_wecom_send_failure_does_not_change_completed_analysis(tmp_path: Path) -> None:
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

    assert result.status == AlertStatus.COMPLETED
    assert events == ["RESULT:WARNING"]
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_failed_analysis_can_be_retried_then_sends_one_result(tmp_path: Path) -> None:
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
    assert result.progress[-1].details["shadow_enabled"] is True
    await runtime.repository.close()  # type: ignore[attr-defined]
