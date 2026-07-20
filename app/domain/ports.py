from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from app.domain.models import (
    AdvisorMetadata,
    AlertListResult,
    AlertStatus,
    DashboardSummary,
    EvidenceRecord,
    FeedbackRecord,
    InvestigationContext,
    InvestigationDecision,
    InvestigationRun,
    InvestigationStage,
    InvestigationStrategy,
    KnowledgeCase,
    NormalizedAlert,
    NotificationEvent,
    NotificationRecord,
    ProgressRecord,
    Recommendation,
    RunbookDocument,
    RunbookExcerpt,
    StoredAlert,
    ToolExecutionRequest,
    ValidationRecord,
)
from app.domain.routing import (
    AlertIncident,
    EscalationDelivery,
    IncidentState,
    RoutingPolicy,
)


class AlertSourceAdapter(Protocol):
    @property
    def source(self) -> str: ...

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert: ...


class RunbookProvider(Protocol):
    async def search(self, alert: NormalizedAlert, limit: int = 5) -> list[RunbookExcerpt]: ...


class RunbookStore(Protocol):
    """Administrative CRUD port for the same corpus exposed by a runbook provider."""

    async def list(self) -> list[RunbookDocument]: ...

    async def get(self, runbook_id: str) -> RunbookDocument: ...

    async def create(self, document: RunbookDocument) -> RunbookDocument: ...

    async def update(
        self,
        runbook_id: str,
        document: RunbookDocument,
        *,
        expected_version: int | None = None,
    ) -> RunbookDocument: ...

    async def delete(self, runbook_id: str) -> None: ...


class AIAdvisor(Protocol):
    async def advise(
        self,
        alert: NormalizedAlert,
        runbooks: list[RunbookExcerpt],
        evidence: list[EvidenceRecord] | None = None,
        knowledge_cases: list[KnowledgeCase] | None = None,
        strategy: InvestigationStrategy | None = None,
    ) -> tuple[Recommendation, AdvisorMetadata]: ...

    async def choose_next_tool(
        self,
        context: InvestigationContext,
        evidence: list[EvidenceRecord],
        available_tools: list[str],
    ) -> InvestigationDecision: ...


class ManagementNotifier(Protocol):
    async def send(self, event: NotificationEvent) -> str | None: ...


class InvestigationTool(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def source_system(self) -> str: ...

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]: ...


class InvestigationStrategyProvider(Protocol):
    async def select(self, alert: NormalizedAlert) -> InvestigationStrategy: ...


class ConclusionValidator(Protocol):
    async def validate(
        self,
        run: InvestigationRun,
        alert: NormalizedAlert,
        recommendation: Recommendation,
        evidence: list[EvidenceRecord],
        runbooks: list[RunbookExcerpt],
    ) -> ValidationRecord: ...


class AnalysisJobScheduler(Protocol):
    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def enqueue(self, alert_id: str) -> None: ...


class AlertSignalRouter(Protocol):
    async def handle_signal(self, alert: NormalizedAlert) -> AlertIncident | None: ...

    async def acknowledge(self, incident_id: str, actor: str) -> AlertIncident | None: ...

    async def get_incident(self, incident_id: str) -> AlertIncident | None: ...

    async def get_incident_for_alert(self, alert_id: str) -> AlertIncident | None: ...


class AlertRoutingRepository(Protocol):
    async def upsert_firing_incident(
        self,
        alert: NormalizedAlert,
        policy: RoutingPolicy,
        policy_version: str,
        first_action_at: datetime,
    ) -> tuple[AlertIncident, bool]: ...

    async def resolve_incident(
        self, dedup_key: str, resolved_at: datetime
    ) -> AlertIncident | None: ...

    async def acknowledge_incident(
        self, incident_id: str, actor: str, acknowledged_at: datetime
    ) -> AlertIncident | None: ...

    async def get_incident(self, incident_id: str) -> AlertIncident | None: ...

    async def get_incident_for_alert(self, alert_id: str) -> AlertIncident | None: ...

    async def claim_due_incidents(
        self, owner: str, now: datetime, lease_seconds: int, limit: int = 20
    ) -> list[AlertIncident]: ...

    async def complete_incident_step(
        self,
        incident_id: str,
        owner: str,
        expected_step: int,
        *,
        next_action_at: datetime | None,
        state: IncidentState,
    ) -> None: ...

    async def release_incident_claim(
        self, incident_id: str, owner: str, retry_at: datetime
    ) -> None: ...

    async def save_escalation_delivery(
        self, delivery: EscalationDelivery
    ) -> EscalationDelivery: ...


class AlertRepository(Protocol):
    async def initialize(self) -> None: ...

    async def ping(self) -> None: ...

    async def create_or_get(self, alert: NormalizedAlert) -> tuple[StoredAlert, bool]: ...

    async def set_status(self, alert_id: str, status: AlertStatus) -> None: ...

    async def save_runbooks(
        self, alert_id: str, runbooks: list[RunbookExcerpt]
    ) -> None: ...

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

    async def list_by_status(self, statuses: set[AlertStatus]) -> list[StoredAlert]: ...

    async def list_alerts(
        self,
        *,
        page: int,
        page_size: int,
        statuses: set[AlertStatus] | None = None,
        severities: set[str] | None = None,
        source: str | None = None,
        environment: str | None = None,
        search: str | None = None,
    ) -> AlertListResult: ...

    async def dashboard_summary(self) -> DashboardSummary: ...

    async def create_run(
        self, alert_id: str, lease_owner: str, lease_seconds: int
    ) -> InvestigationRun | None: ...

    async def update_run(
        self,
        run_id: str,
        *,
        status: str | None = None,
        stage: InvestigationStage | None = None,
        strategy_id: str | None = None,
        error: str | None = None,
    ) -> None: ...

    async def append_progress(self, alert_id: str, record: ProgressRecord) -> ProgressRecord: ...

    async def save_evidence(self, alert_id: str, evidence: EvidenceRecord) -> None: ...

    async def save_validation(self, alert_id: str, validation: ValidationRecord) -> None: ...

    async def find_knowledge_cases(
        self, fingerprint: str, fingerprint_version: str, limit: int = 3
    ) -> list[KnowledgeCase]: ...

    async def save_feedback(
        self, feedback: FeedbackRecord, knowledge_case: KnowledgeCase | None = None
    ) -> FeedbackRecord: ...
