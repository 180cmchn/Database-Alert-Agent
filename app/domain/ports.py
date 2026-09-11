from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from app.domain.models import (
    AdvisorMetadata,
    AlertListResult,
    AlertStatus,
    AnalysisConfigSnapshot,
    AnalysisDispatchControl,
    DashboardSummary,
    DispatchValidationResult,
    EvidenceRecord,
    FlashDutyPollState,
    InvestigationContext,
    InvestigationDecisionResult,
    InvestigationRun,
    InvestigationStage,
    KnowledgeExcerpt,
    ManagementNotificationEvent,
    ModelFailure,
    NormalizedAlert,
    NotificationDelivery,
    NotificationKind,
    ProgressRecord,
    Recommendation,
    RunStatus,
    StoredAlert,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolResultAnalysis,
    ValidationRecord,
    WeComMentionEngineOwner,
    WeComMentionFlashDutyMember,
    WeComMentionTarget,
)
from app.domain.tool_calling import ReasoningTraceCallback

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


class AnalysisDispatchConflict(RuntimeError):
    def __init__(self, expected: int, actual: int) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Analysis dispatch control changed: expected version {expected}, actual {actual}"
        )


class RunLeaseConflict(RuntimeError):
    """A fenced write could not prove ownership of an active run lease."""

    def __init__(self, run_id: str, detail: str) -> None:
        self.run_id = run_id
        self.detail = detail
        super().__init__(f"Run lease conflict for {run_id}: {detail}")


class RunCancellationConflict(RuntimeError):
    """A cancellation request conflicts with the run's persisted state."""

    def __init__(self, run_id: str, status: str) -> None:
        self.run_id = run_id
        self.status = status
        super().__init__(f"Run cancellation conflict for {run_id}: status is {status}")


class RunCancellationRequested(RuntimeError):
    """The active run has a durable cancellation request."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(f"Run cancellation requested for {run_id}")


class AlertSourceAdapter(Protocol):
    @property
    def source(self) -> str: ...

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert: ...


class AlertDetailEnricher(Protocol):
    """Load the authoritative detail view used by an investigation."""

    async def enrich(self, alert: NormalizedAlert) -> NormalizedAlert: ...


class KnowledgeSource(Protocol):
    """One independently deployable source of optional advisory knowledge."""

    @property
    def name(self) -> str: ...

    async def search(self, alert: NormalizedAlert) -> list[KnowledgeExcerpt]: ...


class AIAdvisor(Protocol):
    async def decide_investigation(
        self,
        *,
        alert: NormalizedAlert,
        knowledge: list[KnowledgeExcerpt],
        knowledge_match_summary: str,
        evidence: list[EvidenceRecord],
        available_tools: list[ToolSpec],
        react_round: int,
        react_max_rounds: int,
        reasoning_callback: ReasoningTraceCallback | None = None,
    ) -> InvestigationDecisionResult: ...

    async def probe(self) -> AdvisorMetadata: ...

    async def advise(
        self,
        alert: NormalizedAlert,
        knowledge: list[KnowledgeExcerpt],
        evidence: list[EvidenceRecord] | None = None,
        knowledge_match_summary: str = "",
        reasoning_callback: ReasoningTraceCallback | None = None,
    ) -> tuple[Recommendation, AdvisorMetadata]: ...


class ToolResultAnalyzer(Protocol):
    """Project a complete sanitized result into traceable facts and anomalies.

    Program-side projection does not authorize causal or root-cause decisions.
    """

    async def analyze(
        self,
        *,
        tool_name: str,
        source_system: str,
        request: dict[str, Any],
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis: ...


class ManagementNotifier(Protocol):
    async def send(self, event: ManagementNotificationEvent) -> str | None: ...


class InvestigationTool(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def source_system(self) -> str: ...

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]] | ToolExecutionResult: ...


class ConclusionValidator(Protocol):
    async def validate(
        self,
        run: InvestigationRun,
        alert: NormalizedAlert,
        recommendation: Recommendation,
        evidence: list[EvidenceRecord],
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

    async def get_dispatch_control(self) -> AnalysisDispatchControl: ...

    async def pause_analysis_dispatch(
        self,
        failure: ModelFailure,
        *,
        trigger_run_id: str,
        settings_revision: str,
    ) -> AnalysisDispatchControl: ...

    async def record_dispatch_validation(
        self,
        *,
        expected_version: int,
        validation: DispatchValidationResult,
    ) -> AnalysisDispatchControl: ...

    async def resume_analysis_dispatch(
        self,
        *,
        expected_version: int,
        expected_settings_revision: str,
        resumed_by: str,
        validation: DispatchValidationResult,
    ) -> AnalysisDispatchControl: ...

    async def get_flashduty_poll_state(self) -> FlashDutyPollState: ...

    async def record_flashduty_poll_started(self, *, start_time: int, end_time: int) -> None: ...

    async def record_flashduty_poll_completed(
        self,
        *,
        start_time: int,
        end_time: int,
        fetched_count: int,
        created_count: int,
        deduplicated_count: int,
    ) -> None: ...

    async def record_flashduty_poll_failed(
        self, *, start_time: int | None, end_time: int | None, error: str
    ) -> None: ...

    async def claim_notification_deliveries(
        self,
        *,
        owner: str,
        limit: int,
        lease_seconds: int,
    ) -> list[NotificationDelivery]: ...

    async def complete_notification_delivery(
        self, delivery_id: str, *, owner: str, message_id: str | None
    ) -> None: ...

    async def fail_notification_delivery(
        self,
        delivery_id: str,
        *,
        owner: str,
        error: str,
        unknown_outcome: bool,
    ) -> None: ...

    async def list_wecom_mention_engine_owners(self) -> list[WeComMentionEngineOwner]: ...

    async def get_wecom_mention_engine_owner(
        self, engine: str
    ) -> WeComMentionEngineOwner | None: ...

    async def upsert_wecom_mention_engine_owner(
        self,
        engine: str,
        target: WeComMentionTarget,
        *,
        updated_by: str,
    ) -> WeComMentionEngineOwner: ...

    async def delete_wecom_mention_engine_owner(self, engine: str) -> bool: ...

    async def list_wecom_mention_flashduty_members(
        self,
    ) -> list[WeComMentionFlashDutyMember]: ...

    async def get_wecom_mention_flashduty_members(
        self, person_ids: set[int]
    ) -> dict[int, WeComMentionFlashDutyMember]: ...

    async def upsert_wecom_mention_flashduty_member(
        self,
        flashduty_person_id: int,
        flashduty_member_name: str,
        target: WeComMentionTarget,
        *,
        updated_by: str,
    ) -> WeComMentionFlashDutyMember: ...

    async def delete_wecom_mention_flashduty_member(self, flashduty_person_id: int) -> bool: ...

    async def create_or_get(
        self,
        alert: NormalizedAlert,
        *,
        initial_status: AlertStatus = AlertStatus.QUEUED,
    ) -> tuple[StoredAlert, bool]: ...

    async def update_alert(
        self,
        alert_id: str,
        alert: NormalizedAlert,
        *,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
    ) -> None: ...

    async def set_status(self, alert_id: str, status: AlertStatus) -> None: ...

    async def save_analysis(
        self,
        alert_id: str,
        status: AlertStatus,
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
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
        model_failure: ModelFailure | None = None,
        pause_settings_revision: str | None = None,
        notification_kind: NotificationKind | None = None,
        notification_event: dict[str, Any] | None = None,
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

    async def request_run_cancellation(
        self,
        alert_id: str,
        run_id: str,
        requested_by: str,
    ) -> InvestigationRun | None: ...

    async def is_run_cancellation_requested(self, run_id: str) -> bool: ...

    async def finalize_requested_cancellation(
        self,
        alert_id: str,
        run_id: str,
    ) -> InvestigationRun | None: ...

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
        limit: int | None = None,
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
