from __future__ import annotations

from typing import Any, Protocol

from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    NormalizedAlert,
    NotificationEvent,
    NotificationRecord,
    Recommendation,
    RunbookExcerpt,
    StoredAlert,
)


class AlertSourceAdapter(Protocol):
    @property
    def source(self) -> str: ...

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert: ...


class RunbookProvider(Protocol):
    async def search(self, alert: NormalizedAlert, limit: int = 5) -> list[RunbookExcerpt]: ...


class AIAdvisor(Protocol):
    async def advise(
        self, alert: NormalizedAlert, runbooks: list[RunbookExcerpt]
    ) -> tuple[Recommendation, AdvisorMetadata]: ...


class ManagementNotifier(Protocol):
    async def send(self, event: NotificationEvent) -> str | None: ...


class AlertRepository(Protocol):
    async def initialize(self) -> None: ...

    async def ping(self) -> None: ...

    async def create_or_get(self, alert: NormalizedAlert) -> tuple[StoredAlert, bool]: ...

    async def set_status(self, alert_id: str, status: AlertStatus) -> None: ...

    async def save_analysis(
        self,
        alert_id: str,
        status: AlertStatus,
        runbooks: list[RunbookExcerpt],
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
    ) -> None: ...

    async def save_notification(
        self, alert_id: str, notification: NotificationRecord
    ) -> None: ...

    async def get(self, alert_id: str) -> StoredAlert | None: ...
