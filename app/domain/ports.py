from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from app.domain.models import (
    AdvisorMetadata,
    AlertListResult,
    AlertStatus,
    AnalysisConfigSnapshot,
    AnalysisResultEvent,
    DashboardSummary,
    EvidenceRecord,
    ExternalKnowledgeExcerpt,
    InvestigationContext,
    InvestigationDecision,
    InvestigationRun,
    InvestigationStage,
    InvestigationStrategy,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookDocument,
    RunbookExcerpt,
    RunStatus,
    StoredAlert,
    ToolExecutionRequest,
    ToolExecutionResult,
    ValidationRecord,
)

if TYPE_CHECKING:
    from app.agent_runtime.contracts import (
        ArtifactRef,
        RunCheckpoint,
        RunManifest,
        ToolInvocation,
        ToolInvocationStatus,
        ToolSpec,
    )
    from app.agent_runtime.events import AgentEvent
    from app.investigations.models import InvestigationMemory


class AgentEventSequenceConflict(RuntimeError):
    """An event append used a stale run sequence."""

    def __init__(self, run_id: str, expected: int, actual: int) -> None:
        self.run_id = run_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Agent event sequence conflict for run {run_id}: expected {expected}, actual {actual}"
        )


class AgentCheckpointVersionConflict(RuntimeError):
    """A checkpoint save used a stale run checkpoint version."""

    def __init__(self, run_id: str, expected: int, actual: int) -> None:
        self.run_id = run_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Agent checkpoint version conflict for run {run_id}: "
            f"expected {expected}, actual {actual}"
        )


class ToolInvocationConflict(RuntimeError):
    """An invocation insert or update conflicts with persisted identity/state."""

    def __init__(self, invocation_id: str, detail: str) -> None:
        self.invocation_id = invocation_id
        self.detail = detail
        super().__init__(f"Tool invocation conflict for {invocation_id}: {detail}")


class EvidenceRecordConflict(RuntimeError):
    """A deterministic evidence ID was reused for different content."""

    def __init__(self, evidence_id: str, detail: str) -> None:
        self.evidence_id = evidence_id
        self.detail = detail
        super().__init__(f"Evidence record conflict for {evidence_id}: {detail}")


class RunLeaseConflict(RuntimeError):
    """A fenced write could not prove ownership of an active run lease."""

    def __init__(self, run_id: str, detail: str) -> None:
        self.run_id = run_id
        self.detail = detail
        super().__init__(f"Run lease conflict for {run_id}: {detail}")


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
        external_knowledge: list[ExternalKnowledgeExcerpt] | None = None,
        knowledge_match_summary: str = "",
        strategy: InvestigationStrategy | None = None,
        investigation_memory: InvestigationMemory | None = None,
    ) -> tuple[Recommendation, AdvisorMetadata]: ...

    async def choose_next_tool(
        self,
        context: InvestigationContext,
        evidence: list[EvidenceRecord],
        available_tools: list[str | ToolSpec],
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
    ) -> tuple[str, dict[str, Any]] | ToolExecutionResult: ...


class InvestigationStrategyProvider(Protocol):
    async def select(
        self, alert: NormalizedAlert, runbooks: list[RunbookExcerpt] | None = None
    ) -> InvestigationStrategy: ...


class ConclusionValidator(Protocol):
    async def validate(
        self,
        run: InvestigationRun,
        alert: NormalizedAlert,
        recommendation: Recommendation,
        evidence: list[EvidenceRecord],
        runbooks: list[RunbookExcerpt],
        investigation_memory: InvestigationMemory | None = None,
    ) -> ValidationRecord: ...


class AnalysisJobScheduler(Protocol):
    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def sync_workers(self, workers: int) -> None: ...

    async def enqueue(self, alert_id: str) -> None: ...


class AlertRepository(Protocol):
    async def initialize(self) -> None: ...

    async def ping(self) -> None: ...

    async def cleanup_expired_alerts(self, cutoff: datetime) -> int: ...

    async def create_or_get(self, alert: NormalizedAlert) -> tuple[StoredAlert, bool]: ...

    async def set_status(self, alert_id: str, status: AlertStatus) -> None: ...

    async def save_runbooks(
        self,
        alert_id: str,
        runbooks: list[RunbookExcerpt],
        *,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
    ) -> None: ...

    async def save_analysis(
        self,
        alert_id: str,
        status: AlertStatus,
        runbooks: list[RunbookExcerpt] | None = None,
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
        run_id: str | None = None,
    ) -> None: ...

    async def finalize_run(
        self,
        alert_id: str,
        run_id: str,
        *,
        lease_owner: str,
        fencing_token: int,
        run_status: RunStatus,
        final_stage: InvestigationStage,
        alert_status: AlertStatus,
        progress: ProgressRecord,
        runbooks: list[RunbookExcerpt] | None = None,
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
    ) -> ProgressRecord: ...

    async def get(self, alert_id: str, run_id: str | None = None) -> StoredAlert | None: ...

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
        self,
        alert_id: str,
        lease_owner: str,
        lease_seconds: int,
        *,
        config_snapshot: AnalysisConfigSnapshot | None = None,
        manifest: RunManifest | None = None,
    ) -> InvestigationRun | None: ...

    async def create_run_for_reanalyze(
        self,
        alert_id: str,
        lease_owner: str,
        lease_seconds: int,
        config_snapshot: AnalysisConfigSnapshot,
        *,
        manifest: RunManifest | None = None,
        force: bool = False,
    ) -> InvestigationRun | None: ...

    async def reclaim_expired_run(
        self,
        alert_id: str,
        lease_owner: str,
        lease_seconds: int,
    ) -> InvestigationRun | None: ...

    async def renew_run_lease(
        self,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool: ...

    async def renew(
        self,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool: ...

    async def get_run_manifest(self, run_id: str) -> RunManifest | None: ...

    async def append_agent_events(
        self,
        run_id: str,
        events: list[AgentEvent],
        *,
        expected_sequence: int,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> int: ...

    async def list_agent_events(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
    ) -> list[AgentEvent]: ...

    async def get_agent_event_sequence(self, run_id: str) -> int: ...

    async def save_checkpoint(
        self,
        checkpoint: RunCheckpoint,
        *,
        expected_version: int,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> RunCheckpoint: ...

    async def load_checkpoint(
        self,
        run_id: str,
        *,
        namespace: str = "agent",
    ) -> RunCheckpoint | None: ...

    async def load_checkpoint_by_id(
        self,
        run_id: str,
        checkpoint_id: str,
        *,
        namespace: str = "agent",
    ) -> RunCheckpoint | None: ...

    async def list_checkpoints(
        self,
        run_id: str,
        *,
        namespace: str = "agent",
        before_version: int | None = None,
        limit: int | None = None,
    ) -> list[RunCheckpoint]: ...

    async def put_checkpoint_writes(
        self,
        run_id: str,
        checkpoint_id: str,
        writes: list[dict[str, Any]],
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None: ...

    async def list_checkpoint_writes(
        self,
        run_id: str,
        checkpoint_id: str,
    ) -> list[dict[str, Any]]: ...

    async def save_tool_invocation(
        self,
        invocation: ToolInvocation,
        *,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ToolInvocation: ...

    async def update_tool_invocation(
        self,
        invocation: ToolInvocation,
        *,
        result: dict[str, Any] | None = None,
        expected_status: ToolInvocationStatus | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ToolInvocation: ...

    async def get_tool_invocation(self, invocation_id: str) -> ToolInvocation | None: ...

    async def get_tool_invocation_result(self, invocation_id: str) -> dict[str, Any] | None: ...

    async def save_agent_artifact(
        self,
        run_id: str,
        artifact: ArtifactRef,
        content: bytes | str | dict[str, Any],
        *,
        invocation_id: str | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ArtifactRef: ...

    async def get_agent_artifact(
        self, artifact_id: str
    ) -> tuple[ArtifactRef, bytes | str | dict[str, Any]] | None: ...

    async def update_run(
        self,
        run_id: str,
        *,
        stage: InvestigationStage | None = None,
        strategy_id: str | None = None,
        error: str | None = None,
        lease_owner: str,
        fencing_token: int,
    ) -> None: ...

    async def append_progress(
        self,
        alert_id: str,
        record: ProgressRecord,
        *,
        lease_owner: str,
        fencing_token: int,
        allow_terminal: bool = False,
    ) -> ProgressRecord: ...

    async def save_evidence(
        self,
        alert_id: str,
        evidence: EvidenceRecord,
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None: ...

    async def save_validation(
        self,
        alert_id: str,
        validation: ValidationRecord,
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None: ...
