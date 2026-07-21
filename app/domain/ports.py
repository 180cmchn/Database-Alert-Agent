from __future__ import annotations

from typing import Any, Protocol

from app.domain.models import (
    AdvisorMetadata,
    AlertListResult,
    AlertStatus,
    AnalysisResultEvent,
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
    ProgressRecord,
    Recommendation,
    RunbookDocument,
    RunbookExcerpt,
    StoredAlert,
    ToolExecutionRequest,
    ValidationRecord,
)


class AlertSourceAdapter(Protocol):
    @property
    def source(self) -> str: ...

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert: ...


class RunbookProvider(Protocol):
    async def search(self, alert: NormalizedAlert, limit: int = 5) -> list[RunbookExcerpt]: ...


class RunbookStore(Protocol):
    """Read-only inventory port for the same local PDFs exposed by the provider."""

    async def list(self) -> list[RunbookDocument]: ...

    async def get(self, runbook_id: str) -> RunbookDocument: ...


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
    async def send(self, event: AnalysisResultEvent) -> str | None: ...


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
