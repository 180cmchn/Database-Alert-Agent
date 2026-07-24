"""Alert analysis service using LangGraph for investigation.

This service provides the public API for alert ingestion, analysis,
and feedback submission. It delegates investigation to the LangGraph
InvestigationAgent.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from app.adapters.alert_sources import AlertSourceRegistry
from app.adapters.external_knowledge import ExternalKnowledgeClient
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agents.graph import InvestigationAgent
from app.agents.state import create_initial_state
from app.application.sanitization import sanitize, sanitize_alert
from app.domain.errors import (
    AlertNotFoundError,
    AnalysisFailedError,
    FeedbackAlreadySubmittedError,
    InvalidAlertPayloadError,
)
from app.domain.models import (
    AlertListResult,
    AlertStatus,
    DashboardSummary,
    FeedbackRecord,
    FeedbackVerdict,
    InvestigationRun,
    InvestigationStage,
    KnowledgeCase,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookMatchVerdict,
    RunStatus,
    StoredAlert,
)
from app.domain.ports import (
    AIAdvisor,
    AlertRepository,
    ConclusionValidator,
    InvestigationStrategyProvider,
    ManagementNotifier,
    RunbookProvider,
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
        tool_registry: InvestigationToolRegistry,
        tool_executor: ToolExecutor,
        rule_validator: ConclusionValidator,
        conclusion_validator: ConclusionValidator,
        fallback_advisor: AIAdvisor | None = None,
        runbook_limit: int = 5,
        investigation_lease_seconds: int = 300,
        react_enabled: bool = False,
        validation_enabled: bool = True,
        shadow_enabled: bool = False,
        ai_fallback_enabled: bool = True,
        alert_sanitizer: Callable[[NormalizedAlert], NormalizedAlert] = sanitize_alert,
        max_dynamic_turns: int = 0,
        external_knowledge_client: ExternalKnowledgeClient | None = None,
        external_knowledge_limit: int = 5,
        knowledge_sources: list[str] | None = None,
    ) -> None:
        self.source_registry = source_registry
        self.runbook_provider = runbook_provider
        self.advisor = advisor
        self.notifier = notifier
        self.repository = repository
        self.strategy_provider = strategy_provider
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.rule_validator = rule_validator
        self.conclusion_validator = conclusion_validator
        self.fallback_advisor = fallback_advisor
        self.runbook_limit = runbook_limit
        self.investigation_lease_seconds = investigation_lease_seconds
        self.react_enabled = react_enabled
        self.validation_enabled = validation_enabled
        self.shadow_enabled = shadow_enabled
        self.ai_fallback_enabled = ai_fallback_enabled
        self.alert_sanitizer = alert_sanitizer
        self.max_dynamic_turns = max_dynamic_turns
        self.external_knowledge_client = external_knowledge_client
        self.external_knowledge_limit = external_knowledge_limit
        self.knowledge_sources = knowledge_sources or ["local_pdf"]
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
            strategy_provider=strategy_provider,
            runbook_limit=runbook_limit,
            external_knowledge_client=external_knowledge_client,
            external_knowledge_limit=external_knowledge_limit,
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
        normalized = self.source_registry.normalize(source, payload)
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
            AlertStatus.REVIEW_REQUIRED,
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
        if stored.status in {AlertStatus.COMPLETED, AlertStatus.REVIEW_REQUIRED}:
            return stored

        run = await self.repository.create_run(
            alert_id,
            lease_owner=f"direct-{uuid4()}",
            lease_seconds=self.investigation_lease_seconds,
        )
        if run is None:
            return await self.get(alert_id)

        self._active_analyses += 1
        try:
            return await self._analyze_claimed_alert(stored, alert_id, run)
        finally:
            self._active_analyses -= 1
            if self._active_analyses == 0:
                self._schedule_retired_adapter_close()

    async def _analyze_claimed_alert(
        self,
        stored: StoredAlert,
        alert_id: str,
        run: InvestigationRun,
    ) -> StoredAlert:
        """Run a claimed investigation while its adapter generation stays alive."""

        # Create initial state for LangGraph
        initial_state = create_initial_state(
            alert_id=alert_id,
            alert=stored.alert,
            stored_alert=stored,
            run=run,
            max_dynamic_turns=self.max_dynamic_turns,
            validation_enabled=self.validation_enabled,
            shadow_enabled=self.shadow_enabled,
            ai_fallback_enabled=self.ai_fallback_enabled,
            knowledge_sources=self.knowledge_sources,
        )

        # Record initial progress
        await self.repository.append_progress(
            alert_id,
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.RECEIVED,
                message="调查 Worker 已领取任务。",
            ),
        )

        try:
            # Run the LangGraph investigation
            final_state = await self.agent.run(initial_state)

            # Check if the investigation ended with FAILED status
            if final_state.status == AlertStatus.FAILED:
                error = final_state.error or "Investigation failed"
                raise AnalysisFailedError(alert_id, error)

            # Send notification
            if final_state.recommendation and final_state.alert:
                if final_state.status == AlertStatus.COMPLETED:
                    message = "数据库告警分析已完成。"
                elif final_state.recommendation.analysis_mode == "shadow":
                    message = "数据库告警已生成影子分析，请人工复核。"
                else:
                    message = "数据库告警已生成候选分析，请人工复核。"
                await self._send_analysis_result(
                    final_state.alert,
                    status=final_state.status,
                    message=message,
                    recommendation=final_state.recommendation,
                )

            return await self.get(alert_id)

        except Exception as exc:
            error = f"{type(exc).__name__}: {sanitize(str(exc))}"
            await self.repository.update_run(
                str(run.id),
                status=RunStatus.FAILED.value,
                stage=InvestigationStage.FAILED,
                error=error,
            )
            await self.repository.append_progress(
                alert_id,
                ProgressRecord(
                    run_id=run.id,
                    stage=InvestigationStage.FAILED,
                    message="调查执行失败。",
                    details={"error": error},
                ),
            )
            await self.repository.save_analysis(
                alert_id, AlertStatus.FAILED, runbooks=None, error=error
            )
            raise AnalysisFailedError(alert_id, error) from exc

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
        adapters = [*self._retired_adapters, self.advisor, self.conclusion_validator]
        self._retired_adapters = []
        self._retired_adapter_ids.clear()
        await self._close_adapters(adapters)

    async def submit_feedback(
        self,
        alert_id: str,
        *,
        idempotency_key: str,
        verdict: FeedbackVerdict,
        reviewer: str,
        final_root_cause: str | None = None,
        actual_resolution: str | None = None,
        recovered: bool | None = None,
        runbook_match_verdict: RunbookMatchVerdict = RunbookMatchVerdict.UNKNOWN,
        correct_runbook_id: str | None = None,
        correct_runbook_section: str | None = None,
        missed_runbook_ids: list[str] | None = None,
        supporting_evidence_ids: list[str] | None = None,
        wrong_agent_claims: list[str] | None = None,
        accepted_step_orders: list[int] | None = None,
    ) -> FeedbackRecord:
        """Submit feedback for a completed investigation.

        Args:
            alert_id: The alert ID
            idempotency_key: Unique key for idempotency
            verdict: The feedback verdict
            reviewer: The reviewer name
            final_root_cause: Confirmed root cause (required for CONFIRMED/CORRECTED)
            actual_resolution: Actual resolution taken (required for CONFIRMED/CORRECTED)
            recovered: Whether the issue was recovered
            runbook_match_verdict: Verdict on runbook match quality
            correct_runbook_id: ID of the correct runbook
            correct_runbook_section: Section of the correct runbook
            missed_runbook_ids: IDs of runbooks that should have been matched
            supporting_evidence_ids: IDs of supporting evidence
            wrong_agent_claims: Claims made by the agent that were wrong
            accepted_step_orders: Orders of accepted recommendation steps

        Returns:
            The saved feedback record
        """
        stored = await self.get(alert_id)
        if stored.status not in {AlertStatus.COMPLETED, AlertStatus.REVIEW_REQUIRED}:
            raise InvalidAlertPayloadError("Only completed investigations can receive feedback")
        if not stored.latest_run:
            raise InvalidAlertPayloadError("Investigation run is missing")
        existing_feedback = next(
            (
                item
                for item in stored.feedback
                if item.run_id == stored.latest_run.id
            ),
            None,
        )
        if existing_feedback:
            if existing_feedback.idempotency_key == idempotency_key:
                return existing_feedback
            raise FeedbackAlreadySubmittedError(alert_id, str(stored.latest_run.id))
        if verdict in {FeedbackVerdict.CONFIRMED, FeedbackVerdict.CORRECTED} and (
            not final_root_cause or not actual_resolution
        ):
            raise InvalidAlertPayloadError(
                "Confirmed or corrected feedback requires final_root_cause and actual_resolution"
            )
        if runbook_match_verdict == RunbookMatchVerdict.CORRECT and not correct_runbook_id:
            if len(stored.manual_matches) == 1:
                correct_runbook_id = stored.manual_matches[0].runbook_id
                correct_runbook_section = (
                    correct_runbook_section or stored.manual_matches[0].section
                )
            else:
                raise InvalidAlertPayloadError(
                    "CORRECT runbook feedback requires correct_runbook_id "
                    "when matches are ambiguous"
                )
        retrieved_runbook_ids = {item.runbook_id for item in stored.manual_matches}
        if (
            runbook_match_verdict == RunbookMatchVerdict.CORRECT
            and correct_runbook_id not in retrieved_runbook_ids
        ):
            raise InvalidAlertPayloadError(
                "CORRECT runbook feedback must reference a retrieved runbook"
            )
        if (
            runbook_match_verdict
            in {
                RunbookMatchVerdict.INCORRECT,
                RunbookMatchVerdict.MISSED,
            }
            and not correct_runbook_id
        ):
            raise InvalidAlertPayloadError(
                "INCORRECT or MISSED runbook feedback requires correct_runbook_id"
            )
        if (
            runbook_match_verdict == RunbookMatchVerdict.MISSED
            and correct_runbook_id in retrieved_runbook_ids
        ):
            raise InvalidAlertPayloadError(
                "MISSED runbook feedback must reference a runbook that was not retrieved"
            )
        if runbook_match_verdict == RunbookMatchVerdict.NOT_APPLICABLE and correct_runbook_id:
            raise InvalidAlertPayloadError(
                "NOT_APPLICABLE runbook feedback cannot provide correct_runbook_id"
            )

        from app.domain.models import ToolStatus

        evidence_ids = list(dict.fromkeys(supporting_evidence_ids or []))
        evidence_by_id = {str(item.id): item for item in stored.evidence_records}
        invalid_evidence = [
            evidence_id
            for evidence_id in evidence_ids
            if evidence_id not in evidence_by_id
            or evidence_by_id[evidence_id].status != ToolStatus.SUCCESS
        ]
        if invalid_evidence:
            raise InvalidAlertPayloadError(
                "supporting_evidence_ids must reference SUCCESS evidence from this investigation"
            )

        accepted_orders = sorted(set(accepted_step_orders or []))
        valid_orders = {
            step.order for step in (stored.recommendation.steps if stored.recommendation else [])
        }
        if not set(accepted_orders).issubset(valid_orders):
            raise InvalidAlertPayloadError(
                "accepted_step_orders must reference recommendation steps from this investigation"
            )

        feedback = FeedbackRecord(
            alert_id=stored.alert.id,
            run_id=stored.latest_run.id,
            idempotency_key=idempotency_key,
            verdict=verdict,
            final_root_cause=sanitize(final_root_cause),
            actual_resolution=sanitize(actual_resolution),
            recovered=recovered,
            runbook_match_verdict=runbook_match_verdict,
            correct_runbook_id=sanitize(correct_runbook_id),
            correct_runbook_section=sanitize(correct_runbook_section),
            missed_runbook_ids=sanitize(list(dict.fromkeys(missed_runbook_ids or []))),
            supporting_evidence_ids=evidence_ids,
            wrong_agent_claims=sanitize(wrong_agent_claims or []),
            accepted_step_orders=accepted_orders,
            reviewer=sanitize(reviewer),
        )

        knowledge_case = None
        if (
            verdict in {FeedbackVerdict.CONFIRMED, FeedbackVerdict.CORRECTED}
            and recovered is True
            and final_root_cause
            and actual_resolution
        ):
            knowledge_case = KnowledgeCase(
                source_alert_id=stored.alert.id,
                source_run_id=stored.latest_run.id,
                incident_fingerprint=stored.alert.incident_fingerprint,
                fingerprint_version=stored.alert.fingerprint_version,
                environment=stored.alert.environment,
                service_name=stored.alert.service_name,
                alert_type=stored.alert.alert_type,
                database_engine=(stored.alert.database.engine if stored.alert.database else None),
                correct_runbook_id=sanitize(correct_runbook_id),
                correct_runbook_section=sanitize(correct_runbook_section),
                supporting_evidence_ids=evidence_ids,
                final_root_cause=sanitize(final_root_cause),
                actual_resolution=sanitize(actual_resolution),
                recommendation=stored.recommendation,
                confirmed_by=sanitize(reviewer),
            )
        saved = await self.repository.save_feedback(feedback, knowledge_case)
        if saved.id != feedback.id and saved.idempotency_key != feedback.idempotency_key:
            raise FeedbackAlreadySubmittedError(alert_id, str(stored.latest_run.id))
        return saved

    async def get(self, alert_id: str) -> StoredAlert:
        """Get an alert by ID.

        Args:
            alert_id: The alert ID

        Returns:
            The stored alert

        Raises:
            AlertNotFoundError: If the alert doesn't exist
        """
        stored = await self.repository.get(alert_id)
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

    async def _send_analysis_result(
        self,
        alert: NormalizedAlert,
        *,
        status: AlertStatus,
        message: str,
        recommendation: Recommendation,
    ) -> None:
        """Send analysis result notification."""
        from app.domain.models import AnalysisResultEvent

        event = AnalysisResultEvent(
            alert=alert,
            recommendation=recommendation,
            status=status,
            message=message,
        )
        try:
            await self.notifier.send(event)
        except Exception as exc:
            logger.warning(
                "wecom_analysis_result_send_failed alert_id=%s error=%s",
                alert.id,
                sanitize(f"{type(exc).__name__}: {exc}"),
            )
