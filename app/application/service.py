"""Alert analysis service using LangGraph for investigation.

This service provides the public API for alert ingestion and analysis. It
delegates investigation to the LangGraph InvestigationAgent.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable, Collection
from typing import Any
from uuid import UUID, uuid4

from app.adapters.alert_sources import AlertSourceRegistry
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.adapters.knowledge import KnowledgeSourceRegistry
from app.adapters.notification import WeComManagementNotifier
from app.agent_runtime.contracts import RunManifest
from app.agent_runtime.leases import LeaseLostError, RunLeaseGuard
from app.agents.graph import InvestigationAgent
from app.agents.state import AgentState, create_initial_state
from app.application.analysis_control import (
    ActiveAnalysisRegistry,
    wait_for_persisted_cancellation,
)
from app.application.sanitization import sanitize, sanitize_alert
from app.application.wecom_mention import (
    WeComMentionFlashDutyClient,
    resolve_wecom_mention_targets,
)
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.errors import (
    AdvisorError,
    AlertNotFoundError,
    AnalysisDispatchPausedError,
    AnalysisFailedError,
    AnalysisSettingsRevisionConflict,
    InvalidAlertPayloadError,
    NotificationError,
)
from app.domain.models import (
    AlertListResult,
    AlertStatus,
    AnalysisConfigSnapshot,
    AnalysisDispatchControl,
    AnalysisDispatchState,
    AnalysisFailureEvent,
    AnalysisResultEvent,
    DashboardSummary,
    DispatchValidationResult,
    InvestigationRun,
    InvestigationStage,
    ManagementNotificationEvent,
    ModelFailure,
    ModelFailureCategory,
    NormalizedAlert,
    NotificationKind,
    ProgressRecord,
    RunStatus,
    Severity,
    StoredAlert,
    WeComMentionMode,
)
from app.domain.ports import (
    AIAdvisor,
    AlertDetailEnricher,
    AlertRepository,
    AnalysisDispatchConflict,
    ConclusionValidator,
    ManagementNotifier,
    RunCancellationRequested,
    RunLeaseConflict,
    ToolResultAnalyzer,
)

logger = logging.getLogger(__name__)


class AlertAnalysisService:
    """Service for alert analysis using LangGraph.

    This service handles alert ingestion, enqueuing for investigation,
    and provides query APIs for alert status and history.
    """

    def __init__(
        self,
        *,
        source_registry: AlertSourceRegistry,
        knowledge_registry: KnowledgeSourceRegistry,
        advisor: AIAdvisor,
        notifier: ManagementNotifier,
        repository: AlertRepository,
        alert_detail_enricher: AlertDetailEnricher | None = None,
        tool_registry: InvestigationToolRegistry,
        tool_executor: ToolExecutor,
        tool_result_analyzer: ToolResultAnalyzer | None = None,
        rule_validator: ConclusionValidator,
        fallback_advisor: AIAdvisor | None = None,
        investigation_lease_seconds: int = 300,
        lease_heartbeat_interval_seconds: float | None = None,
        ai_fallback_enabled: bool = True,
        stream_main_agent_reasoning: bool = True,
        alert_sanitizer: Callable[[NormalizedAlert], NormalizedAlert] = sanitize_alert,
        react_max_rounds: int = 8,
        analysis_timeout_seconds: int = 1800,
        alert_analysis_filter_enabled: bool = False,
        alert_analysis_filter_severities: Collection[Severity] = frozenset({Severity.INFO}),
        external_knowledge_min_relevance: float = 0.60,
        knowledge_sources: list[str] | None = None,
        runtime_manifest_config: dict[str, Any] | None = None,
        flashduty_client: WeComMentionFlashDutyClient | None = None,
        wecom_mention_enabled: bool = False,
        wecom_mention_mode: WeComMentionMode = WeComMentionMode.ON_CALL_PERSON,
    ) -> None:
        self.source_registry = source_registry
        self.knowledge_registry = knowledge_registry
        self.advisor = advisor
        self.notifier = notifier
        self.repository = repository
        self.alert_detail_enricher = alert_detail_enricher
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.tool_result_analyzer = tool_result_analyzer
        self.rule_validator = rule_validator
        self.fallback_advisor = fallback_advisor
        self.investigation_lease_seconds = investigation_lease_seconds
        self.lease_heartbeat_interval_seconds = lease_heartbeat_interval_seconds
        self.ai_fallback_enabled = ai_fallback_enabled
        self.stream_main_agent_reasoning = stream_main_agent_reasoning
        self.alert_sanitizer = alert_sanitizer
        self.react_max_rounds = react_max_rounds
        self.analysis_timeout_seconds = analysis_timeout_seconds
        self.alert_analysis_filter_enabled = alert_analysis_filter_enabled
        self.alert_analysis_filter_severities = frozenset(alert_analysis_filter_severities)
        self.external_knowledge_min_relevance = external_knowledge_min_relevance
        self.knowledge_sources = knowledge_sources or []
        self.runtime_manifest_config = dict(runtime_manifest_config or {})
        self.flashduty_client = flashduty_client
        self.wecom_mention_enabled = wecom_mention_enabled
        self.wecom_mention_mode = wecom_mention_mode
        self._active_analyses = 0
        self._retired_adapters: list[object] = []
        self._retired_adapter_ids: set[int] = set()
        self._retirement_task: asyncio.Task[None] | None = None
        self._analysis_registry = ActiveAnalysisRegistry()
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._notification_delivery_task: asyncio.Task[None] | None = None

        # Build the LangGraph agent
        self.agent = InvestigationAgent(
            repository=repository,
            knowledge_registry=knowledge_registry,
            advisor=advisor,
            fallback_advisor=fallback_advisor,
            rule_validator=rule_validator,
            tool_registry=tool_registry,
            tool_executor=tool_executor,
            tool_result_analyzer=tool_result_analyzer,
            alert_detail_enricher=alert_detail_enricher,
            knowledge_sources=knowledge_sources,
        )

    def _initial_alert_status(self, severity: Severity) -> AlertStatus:
        if self.alert_analysis_filter_enabled and severity in self.alert_analysis_filter_severities:
            return AlertStatus.FILTERED
        return AlertStatus.QUEUED

    async def ingest(self, source: str, payload: dict[str, Any]) -> tuple[StoredAlert, bool]:
        """Ingest an alert from a source.

        Args:
            source: The alert source identifier
            payload: The raw alert payload

        Returns:
            Tuple of (stored alert, was_created)
        """
        normalized = preprocess_normalized_alert(self.source_registry.normalize(source, payload))
        alert = self.alert_sanitizer(normalized)
        stored, created = await self.repository.create_or_get(
            alert,
            initial_status=self._initial_alert_status(alert.severity),
        )
        if not created:
            return stored, False

        alert_id = str(alert.id)
        queued = await self.repository.get(alert_id)
        if queued is None:  # pragma: no cover - repository contract guard
            raise AlertNotFoundError(alert_id)
        return queued, True

    async def is_dispatch_enabled(self) -> bool:
        control = await self.repository.get_dispatch_control()
        return control.state == AnalysisDispatchState.ENABLED

    async def require_dispatch_enabled(self) -> None:
        control = await self.repository.get_dispatch_control()
        if control.state == AnalysisDispatchState.PAUSED:
            raise AnalysisDispatchPausedError(
                control.version,
                control.reason.safe_detail if control.reason else "Analysis dispatch is paused",
            )

    async def validate_and_resume_dispatch(
        self,
        *,
        expected_version: int,
        expected_ai_settings_revision: str,
        resumed_by: str,
    ) -> tuple[AnalysisDispatchControl, bool]:
        control = await self.repository.get_dispatch_control()
        if control.version != expected_version:
            raise AnalysisDispatchConflict(expected_version, control.version)
        if control.state != AnalysisDispatchState.PAUSED:
            raise ValueError("Analysis dispatch is not paused")
        current_revision = str(self.runtime_manifest_config.get("ai_settings_revision", ""))
        if current_revision != expected_ai_settings_revision:
            raise AnalysisSettingsRevisionConflict(
                expected_ai_settings_revision,
                current_revision,
            )

        advisor = self.advisor
        self._active_analyses += 1
        try:
            try:
                metadata = await advisor.probe()
            except Exception as exc:
                if (
                    str(self.runtime_manifest_config.get("ai_settings_revision", ""))
                    != current_revision
                ):
                    raise AnalysisSettingsRevisionConflict(
                        expected_ai_settings_revision,
                        str(self.runtime_manifest_config.get("ai_settings_revision", "")),
                    ) from exc
                failure = self._model_failure_from_exception(exc) or ModelFailure(
                    category=ModelFailureCategory.INTERNAL,
                    provider=str(getattr(advisor, "provider", "unknown")),
                    model=str(getattr(advisor, "model", "")),
                    phase="unknown",
                    safe_detail=sanitize(f"{type(exc).__name__}: {exc}"),
                )
                validation = DispatchValidationResult(
                    success=False,
                    settings_revision=current_revision,
                    provider=failure.provider,
                    model=failure.model,
                    detail=failure.safe_detail or "AI provider validation failed",
                    failure=failure,
                    validated_by=resumed_by,
                )
                return (
                    await self.repository.record_dispatch_validation(
                        expected_version=expected_version,
                        validation=validation,
                    ),
                    False,
                )

            latest_revision = str(self.runtime_manifest_config.get("ai_settings_revision", ""))
            if latest_revision != current_revision:
                raise AnalysisSettingsRevisionConflict(
                    expected_ai_settings_revision,
                    latest_revision,
                )
            validation = DispatchValidationResult(
                success=True,
                settings_revision=current_revision,
                provider=metadata.provider,
                model=metadata.model,
                detail="AI provider validation succeeded",
                validated_by=resumed_by,
            )
            return (
                await self.repository.resume_analysis_dispatch(
                    expected_version=expected_version,
                    expected_settings_revision=current_revision,
                    resumed_by=resumed_by,
                    validation=validation,
                ),
                True,
            )
        finally:
            self._active_analyses -= 1
            if self._active_analyses == 0:
                self._schedule_retired_adapter_close()

    async def analyze(self, source: str, payload: dict[str, Any]) -> StoredAlert:
        """Analyze a newly ingested alert synchronously."""

        stored, _created = await self.ingest(source, payload)
        if stored.status in {
            AlertStatus.COMPLETED,
            AlertStatus.INCONCLUSIVE,
            AlertStatus.FAILED,
            AlertStatus.FILTERED,
            AlertStatus.CANCELLED,
        }:
            return stored
        return await self.analyze_by_id(str(stored.alert.id))

    async def analyze_by_id(self, alert_id: str) -> StoredAlert:
        """Analyze an alert by ID using LangGraph.

        This method runs the LangGraph investigation graph synchronously.

        Args:
            alert_id: The alert ID to analyze

        Returns:
            The stored alert after analysis
        """
        stored = await self.get(alert_id)
        if stored.status in {
            AlertStatus.COMPLETED,
            AlertStatus.INCONCLUSIVE,
            AlertStatus.FAILED,
            AlertStatus.FILTERED,
            AlertStatus.CANCELLED,
        }:
            return stored
        await self.require_dispatch_enabled()

        self._active_analyses += 1
        try:
            agent = self.agent
            generation_snapshot = self._create_config_snapshot()
            lease_owner = f"direct-{uuid4()}"
            run = await self.repository.reclaim_expired_run(
                alert_id,
                lease_owner,
                self.investigation_lease_seconds,
            )
            if run is not None:
                incompatible_fields = await self._resume_manifest_incompatible_fields(
                    run, generation_snapshot
                )
                if incompatible_fields:
                    if not run.lease_owner:
                        raise LeaseLostError(
                            run_id=str(run.id),
                            lease_owner="",
                            fencing_token=run.fencing_token,
                            reason="reclaimed run has no lease owner",
                        )
                    fields = ", ".join(incompatible_fields)
                    error = (
                        f"Frozen run manifest is incompatible with the current runtime: {fields}"
                    )
                    failure = ModelFailure(
                        category=ModelFailureCategory.INTERNAL,
                        provider="runtime",
                        model=(run.config_snapshot.ai_model if run.config_snapshot else ""),
                        phase="unknown",
                        safe_detail=error,
                    )
                    notification_event = AnalysisFailureEvent(
                        alert=stored.alert,
                        status=AlertStatus.FAILED,
                        message=error,
                        run_id=run.id,
                        failure=failure,
                    )
                    try:
                        await self.repository.finalize_run(
                            alert_id,
                            str(run.id),
                            lease_owner=run.lease_owner,
                            fencing_token=run.fencing_token,
                            run_status=RunStatus.FAILED,
                            final_stage=InvestigationStage.FAILED,
                            alert_status=AlertStatus.FAILED,
                            progress=ProgressRecord(
                                run_id=run.id,
                                stage=InvestigationStage.FAILED,
                                message="运行环境已变更，旧检查点无法安全恢复。",
                                details={
                                    "reason": "incompatible_resume_manifest",
                                    "incompatible_fields": incompatible_fields,
                                },
                            ),
                            error=error,
                            model_failure=failure,
                            notification_kind=NotificationKind.ANALYSIS_FAILURE,
                            notification_event=notification_event.model_dump(mode="json"),
                        )
                    except RunCancellationRequested:
                        await self.repository.finalize_requested_cancellation(alert_id, str(run.id))
                    except RunLeaseConflict as exc:
                        raise LeaseLostError(
                            run_id=str(run.id),
                            lease_owner=run.lease_owner,
                            fencing_token=run.fencing_token,
                            reason=(
                                "the lease was lost before the incompatible run could be terminated"
                            ),
                        ) from exc
                    await self.deliver_pending_notifications()
                    return await self.get(alert_id)
            if run is None:
                run_id = uuid4()
                manifest = self._create_run_manifest(run_id, generation_snapshot)
                run = await self.repository.create_run(
                    alert_id,
                    lease_owner=lease_owner,
                    lease_seconds=self.investigation_lease_seconds,
                    config_snapshot=generation_snapshot,
                    manifest=manifest,
                )
            if run is None:
                return await self.get(alert_id)

            return await self._analyze_claimed_alert(
                stored,
                alert_id,
                run,
                agent=agent,
                generation_snapshot=generation_snapshot,
            )
        finally:
            self._active_analyses -= 1
            if self._active_analyses == 0:
                self._schedule_retired_adapter_close()

    async def _analyze_claimed_alert(
        self,
        stored: StoredAlert,
        alert_id: str,
        run: InvestigationRun,
        *,
        agent: InvestigationAgent,
        generation_snapshot: AnalysisConfigSnapshot,
    ) -> StoredAlert:
        """Run a claimed investigation while its adapter generation stays alive."""

        if not run.lease_owner:
            raise LeaseLostError(
                run_id=str(run.id),
                lease_owner="",
                fencing_token=run.fencing_token,
                reason="claimed run has no lease owner",
            )

        run_snapshot = run.config_snapshot or generation_snapshot

        # Create initial state for LangGraph
        initial_state = create_initial_state(
            alert_id=alert_id,
            alert=preprocess_normalized_alert(stored.alert),
            stored_alert=stored,
            run=run,
            react_max_rounds=run_snapshot.react_max_rounds,
            ai_fallback_enabled=run_snapshot.ai_fallback_enabled,
            stream_main_agent_reasoning=run_snapshot.stream_main_agent_reasoning,
            knowledge_sources=run_snapshot.knowledge_sources,
        )

        try:
            await self._require_compatible_resume_manifest(run, generation_snapshot)
            await self.repository.append_progress(
                alert_id,
                ProgressRecord(
                    run_id=run.id,
                    stage=InvestigationStage.RECEIVED,
                    message="调查 Worker 已领取任务。",
                ),
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
            )
            lease_guard = RunLeaseGuard(
                self.repository,
                run_id=str(run.id),
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
                lease_seconds=self.investigation_lease_seconds,
                heartbeat_interval_seconds=self.lease_heartbeat_interval_seconds,
            )
            controlled = self._analysis_registry.start(
                str(run.id),
                self._run_agent_with_controls(
                    run_id=str(run.id),
                    operation=lease_guard.run(agent.run(initial_state)),
                    timeout_seconds=run_snapshot.analysis_timeout_seconds,
                ),
            )
            try:
                final_state = await controlled
            except asyncio.CancelledError:
                try:
                    cancellation_requested = await self.repository.is_run_cancellation_requested(
                        str(run.id)
                    )
                except Exception:
                    logger.warning(
                        "Could not verify cancellation request run_id=%s",
                        run.id,
                        exc_info=True,
                    )
                    raise
                if cancellation_requested:
                    raise RunCancellationRequested(str(run.id)) from None
                raise
        except RunCancellationRequested:
            await self.repository.finalize_requested_cancellation(alert_id, str(run.id))
            return await self.get(alert_id)
        except asyncio.CancelledError:
            raise
        except LeaseLostError:
            logger.warning(
                "Investigation stopped after losing its run lease alert_id=%s run_id=%s",
                alert_id,
                run.id,
            )
            raise
        except RunLeaseConflict as exc:
            raise LeaseLostError(
                run_id=str(run.id),
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
                reason="a fenced run update was rejected",
            ) from exc
        except Exception as exc:
            model_failure = self._model_failure_from_exception(exc)
            pause_settings_revision = self._pause_revision_for(run, model_failure)
            error = f"{type(exc).__name__}: {sanitize(str(exc))}"
            notification_failure = model_failure or ModelFailure(
                category=ModelFailureCategory.INTERNAL,
                provider="database-alert-agent",
                phase="unknown",
                safe_detail=error,
            )
            notification_event = AnalysisFailureEvent(
                alert=initial_state.alert,
                status=AlertStatus.FAILED,
                message=error,
                run_id=run.id,
                failure=notification_failure,
            )
            try:
                await self.repository.finalize_run(
                    alert_id,
                    str(run.id),
                    lease_owner=run.lease_owner,
                    fencing_token=run.fencing_token,
                    run_status=RunStatus.FAILED,
                    final_stage=InvestigationStage.FAILED,
                    alert_status=AlertStatus.FAILED,
                    progress=ProgressRecord(
                        run_id=run.id,
                        stage=InvestigationStage.FAILED,
                        message="调查执行失败。",
                        details={"error": error},
                    ),
                    error=error,
                    model_failure=notification_failure,
                    pause_settings_revision=pause_settings_revision,
                    notification_kind=NotificationKind.ANALYSIS_FAILURE,
                    notification_event=notification_event.model_dump(mode="json"),
                )
            except RunLeaseConflict as lease_exc:
                raise LeaseLostError(
                    run_id=str(run.id),
                    lease_owner=run.lease_owner,
                    fencing_token=run.fencing_token,
                    reason="the lease was lost before failure could be recorded",
                ) from lease_exc
            await self.deliver_pending_notifications()
            raise AnalysisFailedError(alert_id, error) from exc

        try:
            await self._persist_terminal_state(alert_id, run, final_state)
        except RunCancellationRequested:
            await self.repository.finalize_requested_cancellation(alert_id, str(run.id))
            return await self.get(alert_id)
        except RunLeaseConflict as exc:
            raise LeaseLostError(
                run_id=str(run.id),
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
                reason="the lease was lost before the final result could be recorded",
            ) from exc

        await self.deliver_pending_notifications()
        if final_state.status == AlertStatus.FAILED:
            error = final_state.error or "Investigation failed"
            raise AnalysisFailedError(alert_id, error)
        return await self.get(alert_id)

    async def _run_agent_with_controls(
        self,
        *,
        run_id: str,
        operation: Any,
        timeout_seconds: int,
    ) -> AgentState:
        operation_task = asyncio.ensure_future(operation)
        cancellation_task = asyncio.create_task(
            wait_for_persisted_cancellation(self.repository, run_id),
            name=f"analysis-cancellation-watch-{run_id}",
        )
        try:
            try:
                async with asyncio.timeout(timeout_seconds):
                    done, _ = await asyncio.wait(
                        {operation_task, cancellation_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if cancellation_task in done:
                        await cancellation_task
                        raise RunCancellationRequested(run_id)
                    return await operation_task
            except TimeoutError:
                raise TimeoutError(f"Analysis timed out after {timeout_seconds} seconds") from None
        finally:
            for task in (operation_task, cancellation_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(operation_task, cancellation_task, return_exceptions=True)

    async def _resume_manifest_incompatible_fields(
        self,
        run: InvestigationRun,
        generation_snapshot: AnalysisConfigSnapshot,
    ) -> list[str]:
        if run.fencing_token <= run.attempt:
            return []
        frozen = await self.repository.get_run_manifest(str(run.id))
        if frozen is None:
            raise RuntimeError("Reclaimed run does not have a frozen manifest")
        current = self._create_run_manifest(run.id, generation_snapshot)
        ignored = {"created_at"}
        frozen_payload = frozen.model_dump(mode="json", exclude=ignored)
        current_payload = current.model_dump(mode="json", exclude=ignored)
        return sorted(
            key for key in frozen_payload if frozen_payload.get(key) != current_payload.get(key)
        )

    async def _require_compatible_resume_manifest(
        self,
        run: InvestigationRun,
        generation_snapshot: AnalysisConfigSnapshot,
    ) -> None:
        incompatible_fields = await self._resume_manifest_incompatible_fields(
            run, generation_snapshot
        )
        if incompatible_fields:
            fields = ", ".join(incompatible_fields)
            raise RuntimeError(
                f"Frozen run manifest is incompatible with the current runtime: {fields}"
            )

    async def _persist_terminal_state(
        self,
        alert_id: str,
        run: InvestigationRun,
        final_state: AgentState,
    ) -> None:
        terminal = {
            AlertStatus.COMPLETED: (
                RunStatus.COMPLETED,
                InvestigationStage.COMPLETED,
                "调查完成。",
            ),
            AlertStatus.INCONCLUSIVE: (
                RunStatus.INCONCLUSIVE,
                InvestigationStage.INCONCLUSIVE,
                "调查结束，结论不充分。",
            ),
            AlertStatus.FAILED: (
                RunStatus.FAILED,
                InvestigationStage.FAILED,
                "调查执行失败。",
            ),
        }.get(final_state.status)
        if terminal is None:
            raise RuntimeError(
                f"Investigation returned non-terminal status: {final_state.status.value}"
            )
        run_status, final_stage, message = terminal
        details: dict[str, Any]
        model_failure = final_state.model_failure
        if final_state.status == AlertStatus.FAILED and model_failure is None:
            model_failure = ModelFailure(
                category=ModelFailureCategory.INTERNAL,
                provider="database-alert-agent",
                phase="unknown",
                safe_detail=final_state.error or "Investigation failed",
            )
        pause_settings_revision = self._pause_revision_for(run, model_failure)
        notification_kind: NotificationKind | None = None
        notification_event: ManagementNotificationEvent | None = None
        if final_state.alert is not None:
            if final_state.status == AlertStatus.FAILED or (
                final_state.advisor_degraded and model_failure is not None
            ):
                assert model_failure is not None
                notification_kind = NotificationKind.ANALYSIS_FAILURE
                notification_event = AnalysisFailureEvent(
                    alert=final_state.alert,
                    status=final_state.status,
                    message=(
                        model_failure.safe_detail
                        or final_state.error
                        or "AI provider request failed"
                    ),
                    run_id=run.id,
                    failure=model_failure,
                )
            elif final_state.recommendation is not None:
                notification_kind = NotificationKind.ANALYSIS_RESULT
                notification_event = AnalysisResultEvent(
                    alert=final_state.alert,
                    recommendation=final_state.recommendation,
                    status=final_state.status,
                    message=(
                        "数据库告警分析已完成。"
                        if final_state.status == AlertStatus.COMPLETED
                        else "数据库告警分析已结束，结论不充分。"
                    ),
                    run_id=run.id,
                )
        if final_state.status == AlertStatus.FAILED:
            details = {"error": final_state.error or "Investigation failed"}
        else:
            details = {
                "validation_passed": final_state.validation_passed,
                "evidence_sufficient": final_state.evidence_sufficient,
                "advisor_degraded": final_state.advisor_degraded,
            }
        await self.repository.finalize_run(
            alert_id,
            str(run.id),
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
            run_status=run_status,
            final_stage=final_stage,
            alert_status=final_state.status,
            progress=ProgressRecord(
                run_id=run.id,
                stage=final_stage,
                message=message,
                details=details,
            ),
            recommendation=final_state.recommendation,
            advisor_metadata=final_state.advisor_metadata,
            error=final_state.error,
            model_failure=model_failure,
            pause_settings_revision=pause_settings_revision,
            notification_kind=notification_kind,
            notification_event=(
                notification_event.model_dump(mode="json")
                if notification_event is not None
                else None
            ),
        )

    @staticmethod
    def _model_failure_from_exception(exc: BaseException) -> ModelFailure | None:
        current: BaseException | None = exc
        seen: set[int] = set()
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            if isinstance(current, AdvisorError) and current.failure is not None:
                return current.failure
            current = current.__cause__ or current.__context__
        return None

    def _pause_revision_for(
        self,
        run: InvestigationRun,
        failure: ModelFailure | None,
    ) -> str | None:
        if failure is None or not failure.pauses_dispatch or run.config_snapshot is None:
            return None
        run_revision = run.config_snapshot.ai_settings_revision
        current_revision = str(self.runtime_manifest_config.get("ai_settings_revision", ""))
        return run_revision if run_revision and run_revision == current_revision else None

    def retire_adapters(self, *adapters: object) -> None:
        """Defer closing replaced adapters until no investigation still uses them."""

        for adapter in adapters:
            if adapter is None or id(adapter) in self._retired_adapter_ids:
                continue
            self._retired_adapters.append(adapter)
            self._retired_adapter_ids.add(id(adapter))
        if self._active_analyses == 0:
            self._schedule_retired_adapter_close()

    def _schedule_retired_adapter_close(self) -> None:
        if not self._retired_adapters or self._retirement_task is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Runtime settings may be changed by synchronous bootstrap code. The
            # application shutdown hook will close these adapters later.
            return
        self._retirement_task = loop.create_task(
            self._close_retired_adapters(), name="retired-ai-adapter-close"
        )

    async def _close_retired_adapters(self) -> None:
        try:
            while self._active_analyses == 0 and self._retired_adapters:
                adapters = self._retired_adapters
                self._retired_adapters = []
                self._retired_adapter_ids.clear()
                await self._close_adapters(adapters)
        finally:
            self._retirement_task = None
            if self._active_analyses == 0 and self._retired_adapters:
                self._schedule_retired_adapter_close()

    @staticmethod
    async def _close_adapters(adapters: list[object]) -> None:
        closed_ids: set[int] = set()
        for adapter in adapters:
            if id(adapter) in closed_ids:
                continue
            closed_ids.add(id(adapter))
            closer = getattr(adapter, "aclose", None) or getattr(adapter, "close", None)
            if not callable(closer):
                continue
            try:
                result = closer()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.warning("Failed to close retired AI adapter", exc_info=True)

    async def close(self) -> None:
        """Close current and retired AI adapters during application shutdown."""

        await self._analysis_registry.close()
        background_tasks = list(self._background_tasks)
        for task in background_tasks:
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        retirement_task = self._retirement_task
        if retirement_task is not None and retirement_task is not asyncio.current_task():
            await retirement_task
        adapters = [
            *self._retired_adapters,
            self.advisor,
            self.tool_result_analyzer,
        ]
        self._retired_adapters = []
        self._retired_adapter_ids.clear()
        await self._close_adapters(adapters)

    async def get(self, alert_id: str, run_id: str | None = None) -> StoredAlert:
        """Get an alert by ID.

        Args:
            alert_id: The alert ID
            run_id: Optional investigation run whose persisted result should be shown

        Returns:
            The stored alert

        Raises:
            AlertNotFoundError: If the alert doesn't exist
        """
        stored = (
            await self.repository.get(alert_id)
            if run_id is None
            else await self.repository.get(alert_id, run_id=run_id)
        )
        if not stored:
            raise AlertNotFoundError(alert_id)
        return stored

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
    ) -> AlertListResult:
        """List alerts with filtering and pagination.

        Args:
            page: Page number (1-indexed)
            page_size: Number of items per page
            statuses: Filter by status set
            severities: Filter by severity set
            source: Filter by source
            environment: Filter by environment
            search: Search string

        Returns:
            Alert list result with pagination info
        """
        return await self.repository.list_alerts(
            page=page,
            page_size=page_size,
            statuses=statuses,
            severities=severities,
            source=source,
            environment=environment,
            search=search,
        )

    async def dashboard_summary(self) -> DashboardSummary:
        """Get dashboard summary statistics.

        Returns:
            Dashboard summary
        """
        return await self.repository.dashboard_summary()

    def _create_config_snapshot(self) -> AnalysisConfigSnapshot:
        """Create a snapshot of the current analysis configuration.

        This captures the key runtime settings for tracking across re-analyses.
        """
        tool_specs = self.tool_registry.available_specs()
        return AnalysisConfigSnapshot(
            knowledge_sources=list(self.knowledge_sources),
            external_knowledge_enabled=("external_knowledge" in self.knowledge_registry.names()),
            external_knowledge_min_relevance=(self.external_knowledge_min_relevance),
            react_max_rounds=self.react_max_rounds,
            analysis_timeout_seconds=self.analysis_timeout_seconds,
            prometheus_mcp_timeout_seconds=float(
                self.runtime_manifest_config.get("prometheus_mcp_timeout_seconds", 60)
            ),
            prometheus_investigation_budget_seconds=float(
                self.runtime_manifest_config.get("prometheus_investigation_budget_seconds", 180)
            ),
            prometheus_mcp_tool_timeout_seconds=float(
                self.runtime_manifest_config.get("prometheus_mcp_tool_timeout_seconds", 780)
            ),
            validation_enabled=True,
            ai_fallback_enabled=self.ai_fallback_enabled,
            stream_main_agent_reasoning=self.stream_main_agent_reasoning,
            ai_model=getattr(self.advisor, "model", ""),
            ai_provider=getattr(self.advisor, "provider", ""),
            ai_settings_revision=str(self.runtime_manifest_config.get("ai_settings_revision", "")),
            ai_react_model=getattr(self.advisor, "react_model", "")
            or getattr(self.advisor, "model", ""),
            ai_mcp_model=getattr(self.advisor, "mcp_model", "")
            or getattr(self.advisor, "model", ""),
            ai_react_reasoning_effort=getattr(self.advisor, "react_reasoning_effort", ""),
            ai_reasoning_effort=getattr(self.advisor, "reasoning_effort", ""),
            ai_mcp_reasoning_effort=getattr(self.advisor, "mcp_reasoning_effort", ""),
            ai_max_retries=max(
                int(self.runtime_manifest_config.get("ai_provider_max_attempts", 3)) - 1,
                0,
            ),
            ai_max_tokens=int(self.runtime_manifest_config.get("ai_max_tokens", 16_384)),
            prompt_version=str(
                self.runtime_manifest_config.get("prompt_version")
                or getattr(self.advisor, "prompt_version", "")
            ),
            code_version=str(self.runtime_manifest_config.get("code_version", "0.1.0")),
            tool_schema_versions={item.name: item.schema_version for item in tool_specs},
            tool_policy_versions={item.name: item.policy_version for item in tool_specs},
        )

    @staticmethod
    def _create_run_manifest(
        run_id: UUID,
        config_snapshot: AnalysisConfigSnapshot,
    ) -> RunManifest:
        return RunManifest(
            run_id=run_id,
            agent_name="database-alert-investigation",
            code_version=config_snapshot.code_version or "unknown",
            model_provider=config_snapshot.ai_provider,
            model_name=config_snapshot.ai_model,
            prompt_version=config_snapshot.prompt_version or "unknown",
            tool_schema_versions=dict(config_snapshot.tool_schema_versions),
            tool_policy_versions=dict(config_snapshot.tool_policy_versions),
            configuration=config_snapshot.model_dump(mode="json"),
        )

    async def reanalyze(
        self,
        alert_id: str,
        *,
        force: bool = False,
    ) -> tuple[InvestigationRun, AnalysisConfigSnapshot]:
        """Re-analyze an alert with current runtime settings.

        This method allows re-running analysis on completed/inconclusive alerts
        for debugging purposes. The configuration snapshot is saved for tracking.

        Args:
            alert_id: The alert ID to re-analyze
            force: Force re-analysis even if a run is already in progress

        Returns:
            Tuple of (investigation run, config snapshot)

        Raises:
            AlertNotFoundError: If the alert doesn't exist
            InvalidAlertPayloadError: If a run is already in progress and force=False
        """
        stored = await self.get(alert_id)
        await self.require_dispatch_enabled()

        # Check if a run is already in progress
        if stored.latest_run and stored.latest_run.status == RunStatus.RUNNING:
            if not force:
                raise InvalidAlertPayloadError(
                    "An analysis is already in progress. Use force=True to override."
                )

        agent = self.agent
        config_snapshot = self._create_config_snapshot()
        run_id = uuid4()
        manifest = self._create_run_manifest(run_id, config_snapshot)
        run = await self.repository.create_run_for_reanalyze(
            alert_id,
            lease_owner=f"reanalyze-{uuid4()}",
            lease_seconds=self.investigation_lease_seconds,
            config_snapshot=config_snapshot,
            manifest=manifest,
            force=force,
        )
        if run is None:
            raise InvalidAlertPayloadError("Failed to create investigation run")

        task = asyncio.create_task(
            self._run_background_reanalysis(
                stored,
                alert_id,
                run,
                agent=agent,
                generation_snapshot=config_snapshot,
            ),
            name=f"reanalyze-{run.id}",
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return run, config_snapshot

    async def _run_background_reanalysis(
        self,
        stored: StoredAlert,
        alert_id: str,
        run: InvestigationRun,
        *,
        agent: InvestigationAgent,
        generation_snapshot: AnalysisConfigSnapshot,
    ) -> None:
        self._active_analyses += 1
        try:
            await self._analyze_claimed_alert(
                stored,
                alert_id,
                run,
                agent=agent,
                generation_snapshot=generation_snapshot,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Background re-analysis failed alert_id=%s run_id=%s",
                alert_id,
                run.id,
            )
        finally:
            self._active_analyses -= 1
            if self._active_analyses == 0:
                self._schedule_retired_adapter_close()

    async def cancel_run(
        self,
        alert_id: str,
        run_id: str,
        *,
        requested_by: str,
    ) -> InvestigationRun:
        run = await self.repository.request_run_cancellation(
            alert_id,
            run_id,
            requested_by,
        )
        if run is None:
            raise AlertNotFoundError(f"{alert_id}/runs/{run_id}")
        self._analysis_registry.cancel(run_id)
        return run

    async def deliver_pending_notifications(self, *, limit: int = 20) -> int:
        """Claim and deliver durable notification intents without rerunning analysis."""

        owner = f"notification-{uuid4()}"
        deliveries = await self.repository.claim_notification_deliveries(
            owner=owner,
            limit=limit,
            lease_seconds=60,
        )
        completed = 0
        for delivery in deliveries:
            try:
                if delivery.kind == NotificationKind.ANALYSIS_FAILURE:
                    event: ManagementNotificationEvent = AnalysisFailureEvent.model_validate(
                        delivery.event
                    )
                else:
                    event = AnalysisResultEvent.model_validate(delivery.event)
            except Exception as exc:
                await self.repository.fail_notification_delivery(
                    str(delivery.id),
                    owner=owner,
                    error=f"Invalid persisted notification event: {sanitize(str(exc))}",
                    unknown_outcome=False,
                )
                continue

            try:
                message_id = await self.notifier.send(event)
            except NotificationError as exc:
                await self.repository.fail_notification_delivery(
                    str(delivery.id),
                    owner=owner,
                    error=str(exc),
                    unknown_outcome=exc.unknown_outcome,
                )
                logger.warning(
                    "notification_delivery_failed delivery_id=%s kind=%s error=%s",
                    delivery.id,
                    delivery.kind.value,
                    sanitize(str(exc)),
                )
                continue
            except Exception as exc:
                await self.repository.fail_notification_delivery(
                    str(delivery.id),
                    owner=owner,
                    error=f"{type(exc).__name__}: {sanitize(str(exc))}",
                    unknown_outcome=False,
                )
                logger.warning(
                    "notification_delivery_failed delivery_id=%s kind=%s error=%s",
                    delivery.id,
                    delivery.kind.value,
                    sanitize(str(exc)),
                )
                continue

            try:
                await self.repository.complete_notification_delivery(
                    str(delivery.id),
                    owner=owner,
                    message_id=message_id,
                )
            except Exception as exc:
                logger.error(
                    "notification_delivery_commit_failed delivery_id=%s error=%s",
                    delivery.id,
                    sanitize(str(exc)),
                )
                try:
                    await self.repository.fail_notification_delivery(
                        str(delivery.id),
                        owner=owner,
                        error=f"Delivery outcome could not be persisted: {sanitize(str(exc))}",
                        unknown_outcome=True,
                    )
                except Exception:
                    logger.exception(
                        "notification_delivery_unknown_outcome_not_persisted delivery_id=%s",
                        delivery.id,
                    )
                continue
            await self._send_wecom_mention_best_effort(event)
            completed += 1
        return completed

    async def _send_wecom_mention_best_effort(
        self, event: ManagementNotificationEvent
    ) -> None:
        """Best-effort "请查收@xxx" follow-up after a WeCom card is delivered.

        Every failure here (resolution or send) is only logged. It must never
        raise: WeCom's webhook has no idempotency key, so retrying this
        delivery through the outbox would resend the already-delivered
        analysis card.
        """
        if not self.wecom_mention_enabled or not isinstance(
            self.notifier, WeComManagementNotifier
        ):
            return
        try:
            targets = await resolve_wecom_mention_targets(
                event.alert,
                mode=self.wecom_mention_mode,
                repository=self.repository,
                flashduty_client=self.flashduty_client,
            )
            if not targets:
                return
            await self.notifier.send_mention(event, targets)
        except Exception as exc:
            logger.warning(
                "wecom_mention_skipped alert_id=%s error=%s",
                event.alert.id,
                sanitize(str(exc)),
            )

    def start_notification_delivery_worker(self, *, interval_seconds: float = 10.0) -> None:
        if self._notification_delivery_task is not None:
            return

        async def run() -> None:
            while True:
                try:
                    await self.deliver_pending_notifications()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Durable notification delivery cycle failed")
                await asyncio.sleep(interval_seconds)

        task = asyncio.create_task(run(), name="notification-delivery-worker")
        self._notification_delivery_task = task
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        def clear_worker(completed: asyncio.Task[None]) -> None:
            if self._notification_delivery_task is completed:
                self._notification_delivery_task = None

        task.add_done_callback(clear_worker)
