"""LangGraph node functions for alert investigation workflow."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import uuid5

from app.adapters.external_knowledge import (
    ExternalKnowledgeClient,
    format_items_for_advisor,
)
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agent_runtime.outer_dispatch import DurableOuterToolDispatcher
from app.agents.state import AgentState
from app.application.sanitization import sanitize, sanitize_alert
from app.application.validation import enforce_post_evidence_root_cause_policy
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.errors import RunbookAlertTypeNotFoundError
from app.domain.models import (
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
    AdvisorMetadata,
    AlertStatus,
    EvidenceRecord,
    ExternalKnowledgeExcerpt,
    InvestigationContext,
    InvestigationRun,
    InvestigationStage,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookExcerpt,
    RunStatus,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)
from app.domain.ports import (
    AIAdvisor,
    AlertDetailEnricher,
    AlertRepository,
    ConclusionValidator,
    InvestigationStrategyProvider,
    RunbookProvider,
    ToolResultAnalyzer,
)
from app.investigations.models import InvestigationMemory

logger = logging.getLogger(__name__)


class NodeContext:
    """Context object holding dependencies for node execution.

    This is injected at graph build time and provides access to all
    the external dependencies needed by nodes.
    """

    def __init__(
        self,
        *,
        repository: AlertRepository,
        runbook_provider: RunbookProvider,
        advisor: AIAdvisor,
        fallback_advisor: AIAdvisor | None,
        rule_validator: ConclusionValidator,
        conclusion_validator: ConclusionValidator,
        tool_registry: InvestigationToolRegistry,
        tool_executor: ToolExecutor,
        tool_result_analyzer: ToolResultAnalyzer | None = None,
        tool_result_analysis_threshold_chars: int = 12_000,
        strategy_provider: InvestigationStrategyProvider,
        alert_detail_enricher: AlertDetailEnricher | None = None,
        runbook_limit: int = 5,
        external_knowledge_client: ExternalKnowledgeClient | None = None,
        external_knowledge_limit: int = 5,
        external_knowledge_min_relevance: float = 0.60,
        knowledge_sources: list[str] | None = None,
    ) -> None:
        self.repository = repository
        self.runbook_provider = runbook_provider
        self.advisor = advisor
        self.fallback_advisor = fallback_advisor
        self.rule_validator = rule_validator
        self.conclusion_validator = conclusion_validator
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.tool_result_analyzer = tool_result_analyzer
        self.tool_result_analysis_threshold_chars = tool_result_analysis_threshold_chars
        self.strategy_provider = strategy_provider
        self.alert_detail_enricher = alert_detail_enricher
        self.runbook_limit = runbook_limit
        self.external_knowledge_client = external_knowledge_client
        self.external_knowledge_limit = external_knowledge_limit
        self.external_knowledge_min_relevance = external_knowledge_min_relevance
        self.knowledge_sources = (
            knowledge_sources if knowledge_sources is not None else ["local_pdf"]
        )


async def enrich_alert_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Load authoritative alert detail before knowledge and tool decisions."""

    alert = state.alert
    run = state.run
    if not alert or not run:
        return {"error": "Missing run or alert in alert detail node"}
    if alert.source.casefold() != "flashduty":
        return {}

    evidence_id = uuid5(
        run.id,
        f"flashduty-alert-info-evidence-v1:{alert.external_id}",
    )
    existing_evidence = next((item for item in state.evidence if item.id == evidence_id), None)
    stored_for_run = state.stored_alert
    if existing_evidence is None:
        stored_for_run = await ctx.repository.get(state.alert_id, run_id=str(run.id))
        if stored_for_run is not None:
            existing_evidence = next(
                (
                    item
                    for item in stored_for_run.evidence_records
                    if item.id == evidence_id
                    and item.tool_name == "flashduty_alert_info"
                    and item.source_system == "flashduty_alert_detail"
                ),
                None,
            )
    if existing_evidence is not None:
        detail_data = existing_evidence.structured_data
        if (
            existing_evidence.status != ToolStatus.SUCCESS
            or detail_data.get("read_only") is not True
            or detail_data.get("partial") is not False
            or detail_data.get("authoritative_source") != "/alert/info"
            or not isinstance(detail_data.get("alert_detail"), dict)
        ):
            raise RuntimeError("Persisted FlashDuty alert detail evidence is invalid")
        replay_alert = NormalizedAlert.model_validate(detail_data["alert_detail"]).model_copy(
            update={
                "raw_payload": {
                    "flashduty_alert_info": detail_data.get("flashduty_alert_info"),
                }
            }
        )
        if (
            replay_alert.id != alert.id
            or replay_alert.external_id != alert.external_id
            or replay_alert.source.casefold() != "flashduty"
        ):
            raise RuntimeError("Persisted FlashDuty alert detail identity does not match")
        existing_progress = next(
            (
                item
                for item in (stored_for_run.progress if stored_for_run is not None else [])
                if item.details.get("flashduty_detail_status") == "loaded"
            ),
            None,
        )
        return {
            "alert": replay_alert,
            "stored_alert": (
                state.stored_alert.model_copy(update={"alert": replay_alert})
                if state.stored_alert is not None
                else stored_for_run
            ),
            "evidence": [] if existing_evidence in state.evidence else [existing_evidence],
            "progress": (
                []
                if existing_progress is None or existing_progress in state.progress
                else [existing_progress]
            ),
        }

    database = alert.database
    baseline = alert.model_copy(
        update={
            "database": (
                database.model_copy(update={"host": None, "port": None})
                if database is not None
                else None
            )
        }
    )
    # Clear any endpoint persisted by an older release before attempting the
    # authoritative read. A failed detail lookup must never leave stale host or
    # port data available to later retries or operators.
    await ctx.repository.update_alert(
        state.alert_id,
        baseline,
        run_id=str(run.id),
        **_lease_fence(run),
    )

    enricher = ctx.alert_detail_enricher
    if enricher is None:
        raise RuntimeError(
            "FlashDuty alert detail is required before knowledge matching and MCP selection"
        )
    if getattr(enricher, "read_only", None) is not True:
        raise RuntimeError(
            "FlashDuty alert detail enricher must explicitly declare read_only=true"
        )
    try:
        enriched = sanitize_alert(
            preprocess_normalized_alert(await enricher.enrich(baseline))
        )
    except Exception as exc:
        logger.warning(
            "flashduty_alert_detail_unavailable alert_id=%s error=%s: %s",
            alert.external_id,
            type(exc).__name__,
            sanitize(str(exc)),
        )
        raise RuntimeError(
            "FlashDuty alert detail is unavailable; investigation cannot continue"
        ) from exc

    await ctx.repository.update_alert(
        state.alert_id,
        enriched,
        run_id=str(run.id),
        **_lease_fence(run),
    )
    detail_evidence = EvidenceRecord(
        id=evidence_id,
        run_id=run.id,
        tool_name="flashduty_alert_info",
        source_system="flashduty_alert_detail",
        status=ToolStatus.SUCCESS,
        request={
            "operation": "alert_info",
            "alert_id": enriched.external_id,
            "read_only": True,
        },
        summary="已获取权威 FlashDuty 告警详情；该记录仅陈述告警事实，不代表根因结论。",
        structured_data={
            "read_only": True,
            "partial": False,
            "authoritative_source": "/alert/info",
            "flashduty_alert_info": enriched.raw_payload.get("flashduty_alert_info"),
            "alert_detail": enriched.model_dump(mode="json", exclude={"raw_payload"}),
        },
        started_at=run.created_at,
        collected_at=run.created_at,
    )
    await ctx.repository.save_evidence(
        state.alert_id,
        detail_evidence,
        **_lease_fence(run),
    )
    progress = ProgressRecord(
        run_id=run.id,
        stage=InvestigationStage.RECEIVED,
        message=(
            "已获取 FlashDuty 告警详情。"
        ),
        details={
            "flashduty_detail_status": "loaded",
            "read_only": True,
        },
    )
    await ctx.repository.append_progress(
        state.alert_id,
        progress,
        **_lease_fence(run),
    )
    stored_alert = state.stored_alert
    return {
        "alert": enriched,
        "stored_alert": (
            stored_alert.model_copy(update={"alert": enriched})
            if stored_alert is not None
            else None
        ),
        "evidence": [detail_evidence],
        "progress": [progress],
    }


async def fingerprint_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate incident fingerprint for the alert."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert

    if not run or not alert:
        return {"error": "Missing run or alert in fingerprint node"}

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.FINGERPRINTING,
        "问题指纹已生成。",
        {"incident_fingerprint": alert.incident_fingerprint},
    )

    return {
        "current_stage": InvestigationStage.FINGERPRINTING,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.FINGERPRINTING,
                message="问题指纹已生成。",
                details={"incident_fingerprint": alert.incident_fingerprint},
            )
        ],
    }


async def runbook_match_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Search local PDF runbooks and external knowledge in parallel.

    Selected knowledge sources are queried concurrently via ``asyncio.gather``.
    Each source is gated by the ``knowledge_sources`` selection in the state:

    - ``local_pdf``: query the local PDF runbook library.
    - ``external_knowledge``: query the optional external knowledge API. This
      additionally requires a configured ``ExternalKnowledgeClient``.

    A failed source is reported as unavailable evidence, not as a negative
    diagnostic signal. Candidates below the configured relevance threshold are
    explicitly rejected and never reach the advisor.

    External knowledge results may include incident cases; they remain ordinary
    knowledge clues and do not replace live evidence for the current alert.
    """
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert

    if not run or not alert:
        return {"error": "Missing run or alert in runbook match node"}

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.RUNBOOK_MATCHING,
        "正在检索已选择的知识来源。",
    )

    local_pdf_enabled = "local_pdf" in state.knowledge_sources
    external_enabled = (
        "external_knowledge" in state.knowledge_sources
        and ctx.external_knowledge_client is not None
    )

    async def _search_local_pdf() -> tuple[list[RunbookExcerpt], str | None]:
        if not local_pdf_enabled:
            return [], None
        try:
            return (
                await ctx.runbook_provider.search(alert, limit=ctx.runbook_limit),
                None,
            )
        except RunbookAlertTypeNotFoundError as exc:
            logger.info(
                "local_runbook_alert_type_missing alert_type=%s",
                sanitize(exc.alert_type),
            )
            return [], str(exc)
        except Exception as exc:
            logger.warning(
                "local_runbook_search_failed error=%s: %s",
                type(exc).__name__,
                sanitize(str(exc)),
            )
            return [], f"本地 PDF 查询失败（{type(exc).__name__}），未作为分析依据"

    async def _search_external_knowledge() -> tuple[
        list[ExternalKnowledgeExcerpt], int, str | None
    ]:
        if not external_enabled:
            missing_client = (
                "NotConfigured" if "external_knowledge" in state.knowledge_sources else None
            )
            return [], 0, missing_client
        try:
            response = await ctx.external_knowledge_client.search_alert(
                alert, top_k=ctx.external_knowledge_limit
            )
            accepted = [
                item
                for item in response.items
                if item.relevance >= ctx.external_knowledge_min_relevance
            ]
            return (
                format_items_for_advisor(accepted),
                max(0, len(response.items) - len(accepted)),
                None,
            )
        except Exception as exc:
            logger.warning(
                "external_knowledge_search_failed error=%s: %s",
                type(exc).__name__,
                sanitize(str(exc)),
            )
            await _update_progress(
                ctx.repository,
                alert_id,
                run,
                InvestigationStage.RUNBOOK_MATCHING,
                "外部知识库查询失败，已忽略该来源并继续分析。",
                {"external_knowledge_error": type(exc).__name__},
            )
            return [], 0, type(exc).__name__

    local_result, external_result = await asyncio.gather(
        _search_local_pdf(),
        _search_external_knowledge(),
    )
    runbooks, local_error = local_result
    external_knowledge, external_rejected_count, external_error = external_result

    source_summaries: list[str] = []
    if local_pdf_enabled:
        if local_error:
            source_summaries.append(local_error)
        elif runbooks:
            source_summaries.append(f"本地 PDF 命中 {len(runbooks)} 条")
        else:
            source_summaries.append("本地 PDF 候选未达到匹配阈值，已拒绝匹配")
    if "external_knowledge" in state.knowledge_sources:
        if external_error:
            source_summaries.append(f"外部知识库查询失败（{external_error}），未作为分析依据")
        elif external_knowledge:
            source_summaries.append(f"外部知识库命中 {len(external_knowledge)} 条")
            if external_rejected_count:
                source_summaries.append(
                    f"另有 {external_rejected_count} 条低于相关度阈值，已拒绝匹配"
                )
        else:
            source_summaries.append("外部知识库候选未达到相关度阈值，已拒绝匹配")
    knowledge_match_summary = "知识匹配结果：" + "；".join(source_summaries) + "。"
    if not runbooks and not external_knowledge:
        knowledge_match_summary += "所选知识来源均未命中，Agent 将仅使用告警、实时证据和通用推理。"

    await ctx.repository.save_runbooks(
        alert_id,
        runbooks,
        run_id=str(run.id),
        **_lease_fence(run),
    )

    if external_knowledge:
        await _update_progress(
            ctx.repository,
            alert_id,
            run,
            InvestigationStage.RUNBOOK_MATCHING,
            f"外部知识库返回 {len(external_knowledge)} 条匹配知识。",
            {"external_knowledge_count": len(external_knowledge)},
        )

    return {
        "current_stage": InvestigationStage.RUNBOOK_MATCHING,
        "runbooks": runbooks,
        "external_knowledge": external_knowledge,
        "knowledge_match_summary": knowledge_match_summary,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.RUNBOOK_MATCHING,
                message="正在检索已选择的知识来源。",
                details={
                    "local_pdf_enabled": local_pdf_enabled,
                    "external_knowledge_enabled": external_enabled,
                    "external_knowledge_count": len(external_knowledge),
                    "external_knowledge_rejected_count": external_rejected_count,
                    "knowledge_match_summary": knowledge_match_summary,
                },
            )
        ],
    }


async def select_strategy_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Select investigation strategy based on alert and runbooks."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks

    if not run or not alert:
        return {"error": "Missing run or alert in strategy selection node"}

    strategy = await ctx.strategy_provider.select(
        alert,
        runbooks,
        state.external_knowledge,
        state.knowledge_match_summary,
    )
    await ctx.repository.update_run(
        str(run.id),
        strategy_id=strategy.strategy_id,
        **_lease_fence(run),
    )

    pending_requests = [
        request.model_copy(update={"hypothesis_ids": []}) for request in strategy.tool_plan
    ]

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.INVESTIGATING,
        f"执行调查策略 {strategy.strategy_id}。",
        {
            "tool_count": len(pending_requests),
            "analysis_deferred": True,
        },
    )

    return {
        "current_stage": InvestigationStage.INVESTIGATING,
        "strategy": strategy,
        "investigation_memory": InvestigationMemory(),
        "stop_decision": None,
        "pending_tool_requests": pending_requests,
        "dynamic_turns_remaining": 0,
        "max_dynamic_turns": 0,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.INVESTIGATING,
                message=f"执行调查策略 {strategy.strategy_id}。",
                details={
                    "tool_count": len(pending_requests),
                    "analysis_deferred": True,
                },
            )
        ],
    }


async def execute_tools_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Execute pending tool requests and collect evidence."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    strategy = state.strategy
    pending_requests = state.pending_tool_requests

    if not run or not alert or not strategy:
        return {"error": "Missing run, alert, or strategy in tool execution node"}

    new_evidence: list[EvidenceRecord] = []
    known_evidence_ids = {item.id for item in state.evidence}
    context = InvestigationContext(
        run_id=run.id,
        alert=alert,
        strategy=strategy,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
        investigation_memory={},
    )
    dispatcher = DurableOuterToolDispatcher(
        ctx.repository,
        ctx.tool_executor,
        result_analyzer=ctx.tool_result_analyzer,
        analysis_threshold_chars=ctx.tool_result_analysis_threshold_chars,
    )

    for request in pending_requests:
        result = await dispatcher.execute(
            alert_id=alert_id,
            request=request,
            context=context,
            tool_spec=ctx.tool_registry.spec(request.tool_name),
            prior_evidence=[*state.evidence, *new_evidence],
        )

        # Local state application and persistence failures are not provider
        # failures. Let them escape so checkpoint recovery can preserve the real
        # remote outcome instead of manufacturing a misleading FAILED record.
        await ctx.repository.save_evidence(
            alert_id,
            result,
            **_lease_fence(run),
        )
        if result.id not in known_evidence_ids:
            new_evidence.append(result)
            known_evidence_ids.add(result.id)

    return {
        "evidence": new_evidence,
        "pending_tool_requests": [],  # Clear pending requests after execution
    }


async def advise_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate recommendation using AI advisor."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    evidence = state.evidence
    external_knowledge = state.external_knowledge
    knowledge_match_summary = state.knowledge_match_summary
    strategy = state.strategy
    ai_fallback_enabled = state.ai_fallback_enabled

    if not run or not alert or not strategy:
        return {"error": "Missing run, alert, or strategy in advise node"}

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.ADVISING,
        "知识匹配与实时证据采集已完成，正在统一分析根因和处理建议。",
        {
            "runbook_matches": len(runbooks),
            "external_knowledge_matches": len(external_knowledge),
            "evidence_count": len(evidence),
        },
    )

    advisor_degraded = False
    primary_advisor_error: Exception | None = None
    recommendation: Recommendation | None = None
    advisor_metadata: AdvisorMetadata | None = None

    try:
        recommendation, advisor_metadata = await ctx.advisor.advise(
            alert,
            runbooks,
            evidence=evidence,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
            investigation_memory=None,
        )
    except Exception as exc:
        primary_advisor_error = exc
        if not ai_fallback_enabled or ctx.fallback_advisor is None:
            logger.warning(
                "advise_failed_no_fallback error=%s: %s",
                type(exc).__name__,
                sanitize(str(exc)),
            )
            return {"error": f"AI advisor failed: {type(exc).__name__}: {exc}"}
        advisor_degraded = True
        recommendation, advisor_metadata = await ctx.fallback_advisor.advise(
            alert,
            runbooks,
            evidence=evidence,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
            investigation_memory=None,
        )
        advisor_metadata = advisor_metadata.model_copy(
            update={"usage": {"fallback_reason": type(exc).__name__}}
        )
        await ctx.repository.append_progress(
            alert_id,
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.ADVISING,
                message="AI 主分析未返回合规结果，已生成固定的无法得出根因结果。",
                details={
                    "error_type": type(exc).__name__,
                    "error_detail": sanitize(str(exc)),
                },
            ),
            **_lease_fence(run),
        )

    recommendation = recommendation.model_copy(
        update={
            "knowledge_match_summary": knowledge_match_summary,
            "external_knowledge_matches": external_knowledge,
        }
    )
    if not runbooks and not external_knowledge:
        recommendation = recommendation.model_copy(
            update={
                "summary": f"{knowledge_match_summary} {recommendation.summary}".strip(),
                "confidence": min(recommendation.confidence, 0.45),
            }
        )
    recommendation = enforce_post_evidence_root_cause_policy(
        recommendation,
        evidence,
        alert,
        None,
    )
    host_inconclusive_reasons = _host_inconclusive_reasons(state)
    if host_inconclusive_reasons:
        recommendation = recommendation.model_copy(
            update={
                "confidence": min(recommendation.confidence, 0.5),
            }
        )

    return {
        "current_stage": InvestigationStage.ADVISING,
        "recommendation": recommendation,
        "advisor_metadata": advisor_metadata,
        "advisor_degraded": advisor_degraded,
        "primary_advisor_error": (
            type(primary_advisor_error).__name__ if primary_advisor_error else None
        ),
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.ADVISING,
                message="知识匹配与实时证据采集已完成，正在统一分析根因和处理建议。",
                details={
                    "runbook_matches": len(runbooks),
                    "external_knowledge_matches": len(external_knowledge),
                    "evidence_count": len(evidence),
                },
            )
        ],
    }


async def validate_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Validate the recommendation using rule and agent validators."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    evidence = state.evidence
    strategy = state.strategy
    recommendation = state.recommendation
    validation_enabled = state.validation_enabled
    advisor_degraded = state.advisor_degraded
    primary_advisor_error = state.primary_advisor_error

    if not run or not alert or not strategy or not recommendation:
        return {"error": "Missing run, alert, strategy, or recommendation in validate node"}

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.VALIDATING,
        "正在进行规则验收和独立结论验收。",
    )

    # Rule validation
    rule_validation = await ctx.rule_validator.validate(
        run,
        alert,
        recommendation,
        evidence,
        runbooks,
        None,
    )

    host_inconclusive_reasons = _host_inconclusive_reasons(state)
    if host_inconclusive_reasons:
        rule_validation = rule_validation.model_copy(
            update={
                "evidence_sufficient": False,
                "metadata": {
                    **rule_validation.metadata,
                    "host_inconclusive_reasons": host_inconclusive_reasons,
                },
            }
        )
    await ctx.repository.save_validation(
        alert_id,
        rule_validation,
        **_lease_fence(run),
    )

    # Agent validation
    agent_validation: ValidationRecord | None = None
    if advisor_degraded and validation_enabled:
        agent_validation = ValidationRecord(
            run_id=run.id,
            kind=ValidationKind.AGENT,
            passed=False,
            issues=["AI 主分析不可用，现有结果无法得出根因"],
            metadata={
                "fallback": True,
                "primary_error_type": primary_advisor_error or "Unknown",
            },
        )
        await ctx.repository.save_validation(
            alert_id,
            agent_validation,
            **_lease_fence(run),
        )
    elif rule_validation.passed and validation_enabled:
        try:
            agent_validation = await ctx.conclusion_validator.validate(
                run,
                alert,
                recommendation,
                evidence,
                runbooks,
                None,
            )
        except Exception as exc:
            agent_validation = ValidationRecord(
                run_id=run.id,
                kind=ValidationKind.AGENT,
                passed=False,
                evidence_sufficient=False,
                issues=[f"独立验收不可用：{type(exc).__name__}: {sanitize(str(exc))}"],
            )
        if agent_validation.evidence_sufficient and not rule_validation.evidence_sufficient:
            agent_validation = agent_validation.model_copy(
                update={
                    "evidence_sufficient": False,
                    "metadata": {
                        **agent_validation.metadata,
                        "evidence_sufficiency_clamped_by_rules": True,
                    },
                }
            )
        await ctx.repository.save_validation(
            alert_id,
            agent_validation,
            **_lease_fence(run),
        )

    # Contract validity and evidence sufficiency are independent. The fixed
    # no-root-cause result can pass the contract while remaining evidence-insufficient.
    validation_passed = rule_validation.passed and (
        not validation_enabled or (agent_validation is not None and agent_validation.passed)
    )
    evidence_sufficient = rule_validation.evidence_sufficient and (
        not validation_enabled
        or (agent_validation is not None and agent_validation.evidence_sufficient)
    )

    return {
        "current_stage": InvestigationStage.VALIDATING,
        "rule_validation": rule_validation,
        "agent_validation": agent_validation,
        "validation_passed": validation_passed,
        "evidence_sufficient": evidence_sufficient,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.VALIDATING,
                message="正在进行规则验收和独立结论验收。",
            )
        ],
    }


async def report_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate final report and update status."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    recommendation = state.recommendation
    validation_passed = state.validation_passed
    evidence_sufficient = state.evidence_sufficient
    advisor_degraded = state.advisor_degraded
    error = state.error
    host_inconclusive_reasons = _host_inconclusive_reasons(state)

    if not run or not alert:
        return {"error": "Missing run or alert in report node"}

    if error:
        return {
            "current_stage": InvestigationStage.FAILED,
            "status": AlertStatus.FAILED,
            "run_status": RunStatus.FAILED,
        }

    # Determine final status
    passed = (
        validation_passed
        and evidence_sufficient
        and not advisor_degraded
        and not host_inconclusive_reasons
    )
    final_status = AlertStatus.COMPLETED if passed else AlertStatus.INCONCLUSIVE
    run_status = RunStatus.COMPLETED if passed else RunStatus.INCONCLUSIVE
    final_stage = InvestigationStage.COMPLETED if passed else InvestigationStage.INCONCLUSIVE

    if not passed and recommendation:
        recommendation = recommendation.model_copy(
            update={
                "summary": INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
                "likely_causes": [],
                "root_causes": [],
                "confidence": 0,
            }
        )

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.REPORTING,
        "正在保存建议、依据和审计结果。",
        {"final_status": final_status.value},
    )

    return {
        "current_stage": final_stage,
        "status": final_status,
        "run_status": run_status,
        "recommendation": recommendation,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=final_stage,
                message="调查完成。" if passed else "调查结束，结论不充分。",
                details={
                    "validation_passed": validation_passed,
                    "evidence_sufficient": evidence_sufficient,
                    "advisor_degraded": advisor_degraded,
                    "host_inconclusive_reasons": host_inconclusive_reasons,
                },
            )
        ],
    }


def _host_inconclusive_reasons(state: AgentState) -> list[str]:
    """Return deterministic reasons that forbid autonomous completion."""

    reasons: list[str] = []
    decision = state.stop_decision
    if decision is not None and decision.requires_human:
        reasons.append(f"stop:{decision.reason.value}")

    return list(dict.fromkeys(reasons))


async def _update_progress(
    repository: AlertRepository,
    alert_id: str,
    run: InvestigationRun,
    stage: InvestigationStage,
    message: str,
    details: dict[str, Any] | None = None,
) -> ProgressRecord:
    """Update run stage and append progress record."""
    await repository.update_run(str(run.id), stage=stage, **_lease_fence(run))
    return await repository.append_progress(
        alert_id,
        ProgressRecord(
            run_id=run.id,
            stage=stage,
            message=message,
            details=details or {},
        ),
        **_lease_fence(run),
    )


def _lease_fence(run: InvestigationRun) -> dict[str, Any]:
    """Return the ownership identity required for every active-run update."""

    if not run.lease_owner:
        raise ValueError("active investigation run is missing its lease owner")
    return {
        "lease_owner": run.lease_owner,
        "fencing_token": run.fencing_token,
    }
