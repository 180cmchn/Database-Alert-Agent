from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from app.adapters.alert_sources import AlertSourceRegistry
from app.application.sanitization import sanitize_alert
from app.domain.errors import AlertNotFoundError, AnalysisFailedError
from app.domain.models import (
    AlertStatus,
    NormalizedAlert,
    NotificationEvent,
    NotificationPhase,
    NotificationRecord,
    NotificationStatus,
    Recommendation,
    StoredAlert,
)
from app.domain.ports import AIAdvisor, AlertRepository, ManagementNotifier, RunbookProvider


class AlertAnalysisService:
    def __init__(
        self,
        *,
        source_registry: AlertSourceRegistry,
        runbook_provider: RunbookProvider,
        advisor: AIAdvisor,
        notifier: ManagementNotifier,
        repository: AlertRepository,
        escalation_severities: set[str],
        runbook_limit: int = 5,
        notification_max_attempts: int = 3,
        notification_backoff_seconds: float = 0.5,
        alert_sanitizer: Callable[[NormalizedAlert], NormalizedAlert] = sanitize_alert,
    ) -> None:
        self.source_registry = source_registry
        self.runbook_provider = runbook_provider
        self.advisor = advisor
        self.notifier = notifier
        self.repository = repository
        self.escalation_severities = {item.upper() for item in escalation_severities}
        self.runbook_limit = runbook_limit
        self.notification_max_attempts = notification_max_attempts
        self.notification_backoff_seconds = notification_backoff_seconds
        self.alert_sanitizer = alert_sanitizer

    async def analyze(
        self, source: str, payload: dict[str, Any], *, retry_failed: bool = False
    ) -> StoredAlert:
        normalized = self.source_registry.normalize(source, payload)
        alert = self.alert_sanitizer(normalized)
        stored, created = await self.repository.create_or_get(alert)
        is_retry = not created and retry_failed and stored.status == AlertStatus.FAILED
        if not created and not is_retry:
            return stored

        if is_retry:
            # Reuse the persisted/sanitized identity instead of a newly generated UUID.
            alert = stored.alert

        alert_id = str(alert.id)
        await self.repository.set_status(alert_id, AlertStatus.ANALYZING)
        should_escalate = alert.severity.value in self.escalation_severities
        existing_notification_phases = {item.phase for item in stored.notifications}
        if should_escalate and NotificationPhase.INITIAL_ALERT not in existing_notification_phases:
            await self._notify(
                alert,
                phase=NotificationPhase.INITIAL_ALERT,
                message="收到最高等级数据库告警，AI 正在分析；请管理人员立即关注。",
            )

        runbooks = []
        try:
            runbooks = await self.runbook_provider.search(alert, limit=self.runbook_limit)
            recommendation, advisor_metadata = await self.advisor.advise(alert, runbooks)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            await self.repository.save_analysis(
                alert_id,
                AlertStatus.FAILED,
                runbooks=runbooks,
                error=error,
            )
            if (
                should_escalate
                and NotificationPhase.ANALYSIS_FAILED not in existing_notification_phases
            ):
                await self._notify(
                    alert,
                    phase=NotificationPhase.ANALYSIS_FAILED,
                    message=f"AI 分析失败，需要人工介入。错误：{error}",
                )
            raise AnalysisFailedError(alert_id, error) from exc

        await self.repository.save_analysis(
            alert_id,
            AlertStatus.COMPLETED,
            runbooks=runbooks,
            recommendation=recommendation,
            advisor_metadata=advisor_metadata,
        )
        if should_escalate and NotificationPhase.ADVICE_READY not in existing_notification_phases:
            await self._notify(
                alert,
                phase=NotificationPhase.ADVICE_READY,
                recommendation=recommendation,
                message="数据库告警 AI 分析已完成，请结合手册依据人工复核处理建议。",
            )
        result = await self.repository.get(alert_id)
        if result is None:  # pragma: no cover - defensive repository contract guard
            raise AlertNotFoundError(alert_id)
        return result

    async def get(self, alert_id: str) -> StoredAlert:
        stored = await self.repository.get(alert_id)
        if not stored:
            raise AlertNotFoundError(alert_id)
        return stored

    async def _notify(
        self,
        alert: NormalizedAlert,
        *,
        phase: NotificationPhase,
        message: str,
        recommendation: Recommendation | None = None,
    ) -> NotificationRecord:
        event = NotificationEvent(
            phase=phase,
            alert=alert,
            recommendation=recommendation,
            message=message,
        )
        error: str | None = None
        external_id: str | None = None
        attempts = 0
        for attempt in range(1, self.notification_max_attempts + 1):
            attempts = attempt
            try:
                external_id = await self.notifier.send(event)
                error = None
                break
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                if attempt < self.notification_max_attempts and self.notification_backoff_seconds:
                    await asyncio.sleep(self.notification_backoff_seconds * (2 ** (attempt - 1)))

        record = NotificationRecord(
            phase=phase,
            status=NotificationStatus.SENT if error is None else NotificationStatus.FAILED,
            attempts=attempts,
            error=error,
            external_delivery_id=external_id,
        )
        await self.repository.save_notification(str(alert.id), record)
        return record
