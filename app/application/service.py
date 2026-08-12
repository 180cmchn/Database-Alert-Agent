"""Alert analysis service using LangGraph for investigation.

This service provides the public API for alert ingestion and analysis. It
delegates investigation to the LangGraph InvestigationAgent.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

from app.adapters.alert_sources import AlertSourceRegistry
from app.adapters.external_knowledge import ExternalKnowledgeClient
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agent_runtime.contracts import RunManifest
from app.agent_runtime.leases import LeaseLostError, RunLeaseGuard
from app.agents.graph import InvestigationAgent
from app.agents.state import AgentState, create_initial_state
from app.application.sanitization import sanitize, sanitize_alert
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.errors import (
    AlertNotFoundError,
    AnalysisFailedError,
    InvalidAlertPayloadError,
)
from app.domain.models import (
    AlertListResult,
    AlertStatus,
    AnalysisConfigSnapshot,
    DashboardSummary,
    InvestigationRun,
    InvestigationStage,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunStatus,
    StoredAlert,
)
from app.domain.ports import (
    AIAdvisor,
    AlertDetailEnricher,
    AlertRepository,
    ConclusionValidator,
    InvestigationStrategyProvider,
    ManagementNotifier,
    RunbookProvider,
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
        runbook_provider: RunbookProvider,
        advisor: AIAdvisor,
        notifier: ManagementNotifier,
        repository: AlertRepository,
        strategy_provider: InvestigationStrategyProvider,
        alert_detail_enricher: AlertDetailEnricher | None = None,
        tool_registry: InvestigationToolRegistry,
        tool_executor: ToolExecutor,
        tool_result_analyzer: ToolResultAnalyzer | None = None,
        tool_result_analysis_threshold_chars: int = 12_000,
        rule_validator: ConclusionValidator,
        conclusion_validator: ConclusionValidator,
        fallback_advisor: AIAdvisor | None = None,
        runbook_limit: int = 5,
        investigation_lease_seconds: int = 300,
        lease_heartbeat_interval_seconds: float | None = None,
        react_enabled: bool = False,
        validation_enabled: bool = True,
        ai_fallback_enabled: bool = True,
        alert_sanitizer: Callable[[NormalizedAlert], NormalizedAlert] = sanitize_alert,
        max_dynamic_turns: int = 0,
        external_knowledge_client: ExternalKnowledgeClient | None = None,
        external_knowledge_limit: int = 5,
        external_knowledge_min_relevance: float = 0.60,
        runbook_match_min_score: float = 12,
        runbook_match_min_confidence: float = 0.35,
        knowledge_sources: list[str] | None = None,
        runtime_manifest_config: dict[str, Any] | None = None,
    ) -> None:
        self.source_registry = source_registry
        self.runbook_provider = runbook_provider
        self.advisor = advisor
        self.notifier = notifier
        self.repository = repository
        self.strategy_provider = strategy_provider
        self.alert_detail_enricher = alert_detail_enricher
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.tool_result_analyzer = tool_result_analyzer
        self.tool_result_analysis_threshold_chars = tool_result_analysis_threshold_chars
        self.rule_validator = rule_validator
        self.conclusion_validator = conclusion_validator
        self.fallback_advisor = fallback_advisor
        self.runbook_limit = runbook_limit
        self.investigation_lease_seconds = investigation_lease_seconds
        self.lease_heartbeat_interval_seconds = lease_heartbeat_interval_seconds
        self.react_enabled = react_enabled
        self.validation_enabled = validation_enabled
        self.ai_fallback_enabled = ai_fallback_enabled
        self.alert_sanitizer = alert_sanitizer
        self.max_dynamic_turns = max_dynamic_turns
        self.external_knowledge_client = external_knowledge_client
        self.external_knowledge_limit = external_knowledge_limit
        self.external_knowledge_min_relevance = external_knowledge_min_relevance
        self.runbook_match_min_score = runbook_match_min_score
        self.runbook_match_min_confidence = runbook_match_min_confidence
        self.knowledge_sources = (
            knowledge_sources if knowledge_sources is not None else ["local_pdf"]
        )
        self.runtime_manifest_config = dict(runtime_manifest_config or {})
        self._active_analyses = 0
        self._retired_adapters: list[object] = []
        self._retired_adapter_ids: set[int] = set()
        self._retirement_task: asyncio.Task[None] | None = None

        # Build the LangGraph agent
        self.agent = InvestigationAgent(
            repository=repository,
            runbook_provider=runbook_provider,
            advisor=advisor,
            fallback_advisor=fallback_advisor,
            rule_validator=rule_validator,
            conclusion_validator=conclusion_validator,
            tool_registry=tool_registry,
            tool_executor=tool_executor,
            tool_result_analyzer=tool_result_analyzer,
            tool_result_analysis_threshold_chars=tool_result_analysis_threshold_chars,
            strategy_provider=strategy_provider,
            alert_detail_enricher=alert_detail_enricher,
            runbook_limit=runbook_limit,
            external_knowledge_client=external_knowledge_client,
            external_knowledge_limit=external_knowledge_limit,
            external_knowledge_min_relevance=external_knowledge_min_relevance,
            knowledge_sources=knowledge_sources,
        )

    async def ingest(self, source: str, payload: dict[str, Any]) -> tuple[StoredAlert, bool]:
        """Ingest an alert from a source.

        Args:
            source: The alert source identifier
            payload: The raw alert payload

        Returns:
            Tuple of (stored alert, was_created)
        """
        normalized = preprocess_normalized_alert(
            self.source_registry.normalize(source, payload)
        )
        alert = self.alert_sanitizer(normalized)
        stored, created = await self.repository.create_or_get(alert)
        if not created:
            return stored, False

        alert_id = str(alert.id)
        queued = await self.repository.get(alert_id)
        if queued is None:  # pragma: no cover - repository contract guard
            raise AlertNotFoundError(alert_id)
        return queued, True

    async def analyze(
        self, source: str, payload: dict[str, Any], *, retry_failed: bool = False
    ) -> StoredAlert:
        """Analyze an alert synchronously (blocking).

        This method is primarily for testing and direct API calls.
        For production, use ingest + scheduler.enqueue.

        Args:
            source: The alert source identifier
            payload: The raw alert payload
            retry_failed: Whether to retry failed analyses

        Returns:
            The stored alert after analysis
        """
        stored, created = await self.ingest(source, payload)
        if not created and stored.status in {
            AlertStatus.COMPLETED,
            AlertStatus.INCONCLUSIVE,
        }:
            return stored
        if not created and stored.status == AlertStatus.FAILED and not retry_failed:
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
        if stored.status in {AlertStatus.COMPLETED, AlertStatus.INCONCLUSIVE}:
            return stored

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
            max_dynamic_turns=(
                run_snapshot.react_max_dynamic_turns
                if run_snapshot.react_enabled
                else 0
            ),
            validation_enabled=run_snapshot.validation_enabled,
            ai_fallback_enabled=run_snapshot.ai_fallback_enabled,
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
            final_state = await lease_guard.run(agent.run(initial_state))
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
            error = f"{type(exc).__name__}: {sanitize(str(exc))}"
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
                )
            except RunLeaseConflict as lease_exc:
                raise LeaseLostError(
                    run_id=str(run.id),
                    lease_owner=run.lease_owner,
                    fencing_token=run.fencing_token,
                    reason="the lease was lost before failure could be recorded",
                ) from lease_exc
            raise AnalysisFailedError(alert_id, error) from exc

        try:
            await self._persist_terminal_state(alert_id, run, final_state)
        except RunLeaseConflict as exc:
            raise LeaseLostError(
                run_id=str(run.id),
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
                reason="the lease was lost before the final result could be recorded",
            ) from exc

        if final_state.status == AlertStatus.FAILED:
            error = final_state.error or "Investigation failed"
            raise AnalysisFailedError(alert_id, error)

        # Send notification
        if final_state.recommendation and final_state.alert:
            if final_state.status == AlertStatus.COMPLETED:
                message = "数据库告警分析已完成。"
            else:
                message = "数据库告警分析已结束，结论不充分。"
            await self._send_analysis_result(
                final_state.alert,
                run_id=run.id,
                status=final_state.status,
                message=message,
                recommendation=final_state.recommendation,
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
            )

        return await self.get(alert_id)

    async def _require_compatible_resume_manifest(
        self,
        run: InvestigationRun,
        generation_snapshot: AnalysisConfigSnapshot,
    ) -> None:
        if run.fencing_token <= run.attempt:
            return
        frozen = await self.repository.get_run_manifest(str(run.id))
        if frozen is None:
            raise RuntimeError("Reclaimed run does not have a frozen manifest")
        current = self._create_run_manifest(run.id, generation_snapshot)
        ignored = {"created_at"}
        frozen_payload = frozen.model_dump(mode="json", exclude=ignored)
        current_payload = current.model_dump(mode="json", exclude=ignored)
        incompatible_fields = sorted(
            key
            for key in frozen_payload
            if frozen_payload.get(key) != current_payload.get(key)
        )
        if incompatible_fields:
            fields = ", ".join(incompatible_fields)
            raise RuntimeError(
                "Frozen run manifest is incompatible with the current runtime: "
                f"{fields}"
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
            runbooks=final_state.runbooks,
            recommendation=final_state.recommendation,
            advisor_metadata=final_state.advisor_metadata,
            error=final_state.error,
        )

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

        retirement_task = self._retirement_task
        if retirement_task is not None and retirement_task is not asyncio.current_task():
            await retirement_task
        adapters = [
            *self._retired_adapters,
            self.advisor,
            self.conclusion_validator,
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
            external_knowledge_enabled=self.external_knowledge_client is not None,
            external_knowledge_base_url=(
                self.external_knowledge_client.base_url if self.external_knowledge_client else ""
            ),
            runbook_limit=self.runbook_limit,
            runbook_match_min_score=self.runbook_match_min_score,
            runbook_match_min_confidence=self.runbook_match_min_confidence,
            external_knowledge_min_relevance=(
                self.external_knowledge_min_relevance
            ),
            react_enabled=self.react_enabled,
            react_max_dynamic_turns=self.max_dynamic_turns,
            validation_enabled=self.validation_enabled,
            ai_fallback_enabled=self.ai_fallback_enabled,
            ai_model=getattr(self.advisor, "model", ""),
            ai_provider=(
                "fake"
                if self.advisor.__class__.__name__ == "FakeAIAdvisor"
                else "openai_compatible"
            ),
            ai_timeout_seconds=float(
                self.runtime_manifest_config.get("ai_timeout_seconds", 300)
            ),
            ai_max_retries=int(self.runtime_manifest_config.get("ai_max_retries", 2)),
            ai_max_tokens=int(self.runtime_manifest_config.get("ai_max_tokens", 16_384)),
            prompt_version=str(
                self.runtime_manifest_config.get("prompt_version")
                or getattr(self.advisor, "prompt_version", "")
            ),
            code_version=str(
                self.runtime_manifest_config.get("code_version", "0.1.0")
            ),
            archery_mcp_max_agent_steps=int(
                self.runtime_manifest_config.get("archery_mcp_max_agent_steps", 0)
            ),
            prometheus_mcp_max_agent_steps=int(
                self.runtime_manifest_config.get("prometheus_mcp_max_agent_steps", 0)
            ),
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

        # Check if a run is already in progress
        if stored.latest_run and stored.latest_run.status == RunStatus.RUNNING:
            if not force:
                raise InvalidAlertPayloadError(
                    "An analysis is already in progress. Use force=True to override."
                )

        self._active_analyses += 1
        try:
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

            await self._analyze_claimed_alert(
                stored,
                alert_id,
                run,
                agent=agent,
                generation_snapshot=config_snapshot,
            )
            return run, config_snapshot
        finally:
            self._active_analyses -= 1
            if self._active_analyses == 0:
                self._schedule_retired_adapter_close()

    async def _send_analysis_result(
        self,
        alert: NormalizedAlert,
        *,
        run_id: UUID,
        status: AlertStatus,
        message: str,
        recommendation: Recommendation,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        """Send analysis result notification and persist delivery status."""
        from app.domain.models import AnalysisResultEvent

        event = AnalysisResultEvent(
            alert=alert,
            recommendation=recommendation,
            status=status,
            message=message,
            run_id=run_id,
        )
        try:
            await self.notifier.send(event)
            await self.repository.append_progress(
                str(alert.id),
                ProgressRecord(
                    run_id=run_id,
                    stage=InvestigationStage.REPORTING,
                    message="企微机器人通知已发送",
                ),
                lease_owner=lease_owner,
                fencing_token=fencing_token,
                allow_terminal=True,
            )
        except RunLeaseConflict:
            raise
        except Exception as exc:
            error_msg = sanitize(f"{type(exc).__name__}: {exc}")
            logger.warning(
                "wecom_analysis_result_send_failed alert_id=%s error=%s",
                alert.id,
                error_msg,
            )
            await self.repository.append_progress(
                str(alert.id),
                ProgressRecord(
                    run_id=run_id,
                    stage=InvestigationStage.REPORTING,
                    message="企微机器人通知失败",
                    details={"error": error_msg},
                ),
                lease_owner=lease_owner,
                fencing_token=fencing_token,
                allow_terminal=True,
            )
