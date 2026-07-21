from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from app.adapters.alert_sources import AlertSourceRegistry
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.application.sanitization import sanitize, sanitize_alert
from app.domain.errors import AlertNotFoundError, AnalysisFailedError, InvalidAlertPayloadError
from app.domain.models import (
    AlertListResult,
    AlertStatus,
    AnalysisResultEvent,
    DashboardSummary,
    EvidenceRecord,
    FeedbackRecord,
    FeedbackVerdict,
    InvestigationContext,
    InvestigationRun,
    InvestigationStage,
    KnowledgeCase,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookMatchVerdict,
    RunbookQualityStatus,
    RunStatus,
    StoredAlert,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
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
        runbook_limit: int = 5,
        investigation_lease_seconds: int = 300,
        react_enabled: bool = False,
        validation_enabled: bool = True,
        shadow_enabled: bool = False,
        alert_sanitizer: Callable[[NormalizedAlert], NormalizedAlert] = sanitize_alert,
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
        self.runbook_limit = runbook_limit
        self.investigation_lease_seconds = investigation_lease_seconds
        self.react_enabled = react_enabled
        self.validation_enabled = validation_enabled
        self.shadow_enabled = shadow_enabled
        self.alert_sanitizer = alert_sanitizer

    async def ingest(
        self, source: str, payload: dict[str, Any]
    ) -> tuple[StoredAlert, bool]:
        normalized = self.source_registry.normalize(source, payload)
        alert = self.alert_sanitizer(normalized)
        stored, created = await self.repository.create_or_get(alert)
        if not created:
            return stored, False

        alert_id = str(alert.id)
        await self.repository.set_status(alert_id, AlertStatus.QUEUED)
        queued = await self.repository.get(alert_id)
        if queued is None:  # pragma: no cover - repository contract guard
            raise AlertNotFoundError(alert_id)
        return queued, True

    async def analyze(
        self, source: str, payload: dict[str, Any], *, retry_failed: bool = False
    ) -> StoredAlert:
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
        stored = await self.get(alert_id)
        if stored.status in {AlertStatus.COMPLETED, AlertStatus.REVIEW_REQUIRED}:
            return stored

        run = await self.repository.create_run(
            alert_id,
            lease_owner=f"worker-{uuid4()}",
            lease_seconds=self.investigation_lease_seconds,
        )
        if run is None:
            return await self.get(alert_id)

        alert = stored.alert
        runbooks = []
        evidence: list[EvidenceRecord] = []
        try:
            await self._progress(
                alert_id, run, InvestigationStage.RECEIVED, "调查 Worker 已领取任务。"
            )
            await self._progress(
                alert_id,
                run,
                InvestigationStage.FINGERPRINTING,
                "问题指纹已生成。",
                {"incident_fingerprint": alert.incident_fingerprint},
            )

            await self._progress(
                alert_id,
                run,
                InvestigationStage.KNOWLEDGE_MATCHING,
                "正在匹配人工确认的历史案例。",
            )
            knowledge_cases = await self.repository.find_knowledge_cases(
                alert.incident_fingerprint, alert.fingerprint_version, limit=3
            )

            await self._progress(
                alert_id,
                run,
                InvestigationStage.RUNBOOK_MATCHING,
                "正在检索告警处理手册。",
                {"knowledge_matches": len(knowledge_cases)},
            )
            runbooks = await self.runbook_provider.search(alert, limit=self.runbook_limit)
            await self.repository.save_runbooks(alert_id, runbooks)
            strategy = await self.strategy_provider.select(alert, runbooks)
            await self.repository.update_run(str(run.id), strategy_id=strategy.strategy_id)

            await self._progress(
                alert_id,
                run,
                InvestigationStage.INVESTIGATING,
                f"执行调查策略 {strategy.strategy_id}。",
                {"tool_count": len(strategy.tool_plan)},
            )
            context = InvestigationContext(run_id=run.id, alert=alert, strategy=strategy)
            for request in strategy.tool_plan:
                result = await self.tool_executor.execute(request, context)
                evidence.append(result)
                await self.repository.save_evidence(alert_id, result)

            if self.react_enabled and strategy.max_dynamic_turns:
                await self._run_dynamic_investigation(
                    alert_id, run, context, evidence, strategy.max_dynamic_turns
                )

            await self._progress(
                alert_id,
                run,
                InvestigationStage.ADVISING,
                "正在以命中手册为首要依据生成结构化处理建议。",
                {"runbook_matches": len(runbooks), "evidence_count": len(evidence)},
            )
            recommendation, advisor_metadata = await self.advisor.advise(
                alert,
                runbooks,
                evidence=evidence,
                knowledge_cases=knowledge_cases,
                strategy=strategy,
            )

            await self._progress(
                alert_id,
                run,
                InvestigationStage.VALIDATING,
                "正在进行规则验收和独立结论验收。",
            )
            rule_validation = await self.rule_validator.validate(
                run, alert, recommendation, evidence, runbooks
            )
            required_failures = self._required_tool_failures(strategy.tool_plan, evidence)
            if required_failures:
                rule_validation = rule_validation.model_copy(
                    update={
                        "passed": False,
                        "issues": [
                            *rule_validation.issues,
                            f"必需调查工具未成功：{', '.join(required_failures)}",
                        ],
                    }
                )
            await self.repository.save_validation(alert_id, rule_validation)

            agent_validation: ValidationRecord | None = None
            if rule_validation.passed and self.validation_enabled:
                try:
                    agent_validation = await self.conclusion_validator.validate(
                        run, alert, recommendation, evidence, runbooks
                    )
                except Exception as exc:
                    agent_validation = ValidationRecord(
                        run_id=run.id,
                        kind=ValidationKind.AGENT,
                        passed=False,
                        issues=[f"独立验收不可用：{type(exc).__name__}: {sanitize(str(exc))}"],
                    )
                await self.repository.save_validation(alert_id, agent_validation)

            validation_passed = rule_validation.passed and (
                not self.validation_enabled
                or (agent_validation is not None and agent_validation.passed)
            )
            unapproved_runbook = any(
                item.quality_status != RunbookQualityStatus.APPROVED
                for item in runbooks
            )
            passed = (
                validation_passed
                and not self.shadow_enabled
                and not unapproved_runbook
            )
            final_status = AlertStatus.COMPLETED if passed else AlertStatus.REVIEW_REQUIRED
            run_status = RunStatus.COMPLETED if passed else RunStatus.REVIEW_REQUIRED
            final_stage = (
                InvestigationStage.COMPLETED
                if passed
                else InvestigationStage.REVIEW_REQUIRED
            )
            if not passed:
                recommendation = recommendation.model_copy(
                    update={
                        "requires_human": True,
                        "confidence": min(recommendation.confidence, 0.5),
                        "analysis_mode": (
                            "shadow" if self.shadow_enabled else "assist"
                        ),
                    }
                )
            else:
                recommendation = recommendation.model_copy(
                    update={"analysis_mode": "assist"}
                )

            await self._progress(
                alert_id,
                run,
                InvestigationStage.REPORTING,
                "正在保存建议、依据和审计结果。",
                {"final_status": final_status.value},
            )
            await self.repository.update_run(
                str(run.id), status=run_status.value, stage=final_stage
            )
            await self.repository.append_progress(
                alert_id,
                ProgressRecord(
                    run_id=run.id,
                    stage=final_stage,
                    message="调查完成。" if passed else "结论需要人工复核。",
                    details={
                        "validation_passed": validation_passed,
                        "shadow_enabled": self.shadow_enabled,
                        "unapproved_runbook": unapproved_runbook,
                    },
                ),
            )
            # Publish the alert-level terminal status only after the run and its
            # terminal progress are visible. Detail clients can never observe a
            # completed alert whose investigation still appears to be REPORTING.
            await self.repository.save_analysis(
                alert_id,
                final_status,
                runbooks=runbooks,
                recommendation=recommendation,
                advisor_metadata=advisor_metadata,
            )
            await self._send_analysis_result(
                alert,
                status=final_status,
                recommendation=recommendation,
                message=(
                    "数据库告警分析已完成。"
                    if passed
                    else (
                        "数据库告警已生成影子分析，请人工复核。"
                        if self.shadow_enabled
                        else "数据库告警已生成候选分析，请人工复核。"
                    )
                ),
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
                alert_id, AlertStatus.FAILED, runbooks=runbooks, error=error
            )
            raise AnalysisFailedError(alert_id, error) from exc

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
        stored = await self.get(alert_id)
        if stored.status not in {AlertStatus.COMPLETED, AlertStatus.REVIEW_REQUIRED}:
            raise InvalidAlertPayloadError("Only completed investigations can receive feedback")
        if not stored.latest_run:
            raise InvalidAlertPayloadError("Investigation run is missing")
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
        if runbook_match_verdict in {
            RunbookMatchVerdict.INCORRECT,
            RunbookMatchVerdict.MISSED,
        } and not correct_runbook_id:
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
        if (
            runbook_match_verdict == RunbookMatchVerdict.NOT_APPLICABLE
            and correct_runbook_id
        ):
            raise InvalidAlertPayloadError(
                "NOT_APPLICABLE runbook feedback cannot provide correct_runbook_id"
            )
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
                database_engine=(
                    stored.alert.database.engine if stored.alert.database else None
                ),
                correct_runbook_id=sanitize(correct_runbook_id),
                correct_runbook_section=sanitize(correct_runbook_section),
                supporting_evidence_ids=evidence_ids,
                final_root_cause=sanitize(final_root_cause),
                actual_resolution=sanitize(actual_resolution),
                recommendation=stored.recommendation,
                confirmed_by=sanitize(reviewer),
            )
        return await self.repository.save_feedback(feedback, knowledge_case)

    async def get(self, alert_id: str) -> StoredAlert:
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
        return await self.repository.dashboard_summary()

    async def _run_dynamic_investigation(
        self,
        alert_id: str,
        run: InvestigationRun,
        context: InvestigationContext,
        evidence: list[EvidenceRecord],
        max_turns: int,
    ) -> None:
        seen_requests = {
            (item.tool_name, str(sorted(item.request.items()))) for item in evidence
        }
        for _ in range(max_turns):
            decision = await self.advisor.choose_next_tool(
                context, evidence, self.tool_registry.names()
            )
            if decision.action == "finish":
                return
            if not decision.tool_name:
                return
            request_key = (decision.tool_name, str(sorted(decision.parameters.items())))
            if request_key in seen_requests:
                return
            seen_requests.add(request_key)
            from app.domain.models import ToolExecutionRequest

            request = ToolExecutionRequest(
                tool_name=decision.tool_name,
                parameters=decision.parameters,
                timeout_seconds=10,
            )
            result = await self.tool_executor.execute(request, context)
            evidence.append(result)
            await self.repository.save_evidence(alert_id, result)

    @staticmethod
    def _required_tool_failures(requests, evidence: list[EvidenceRecord]) -> list[str]:  # type: ignore[no-untyped-def]
        statuses: dict[str, list[ToolStatus]] = {}
        for item in evidence:
            statuses.setdefault(item.tool_name, []).append(item.status)
        return [
            request.tool_name
            for request in requests
            if request.required
            and ToolStatus.SUCCESS not in statuses.get(request.tool_name, [])
        ]

    async def _progress(
        self,
        alert_id: str,
        run: InvestigationRun,
        stage: InvestigationStage,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        await self.repository.update_run(str(run.id), stage=stage)
        await self.repository.append_progress(
            alert_id,
            ProgressRecord(
                run_id=run.id,
                stage=stage,
                message=message,
                details=sanitize(details or {}),
            ),
        )

    async def _send_analysis_result(
        self,
        alert: NormalizedAlert,
        *,
        status: AlertStatus,
        message: str,
        recommendation: Recommendation,
    ) -> None:
        event = AnalysisResultEvent(
            alert=alert,
            recommendation=recommendation,
            status=status,
            message=message,
        )
        try:
            await self.notifier.send(event)
        except Exception as exc:
            # Delivery acknowledgement, retries and escalation are intentionally
            # outside this project's boundary. A send failure must not rewrite the
            # completed analysis state.
            logger.warning(
                "wecom_analysis_result_send_failed alert_id=%s error=%s",
                alert.id,
                sanitize(f"{type(exc).__name__}: {exc}"),
            )
