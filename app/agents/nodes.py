"""LangGraph node functions for alert investigation workflow."""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.adapters.investigation import DefaultInvestigationStrategyProvider
from app.application.sanitization import sanitize
from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    EvidenceRecord,
    InvestigationContext,
    InvestigationDecision,
    InvestigationRun,
    InvestigationStage,
    KnowledgeCase,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunStatus,
    RunbookExcerpt,
    RunbookQualityStatus,
    ToolExecutionRequest,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)
from app.domain.ports import (
    AIAdvisor,
    AlertRepository,
    ConclusionValidator,
    InvestigationStrategyProvider,
    RunbookProvider,
)
from app.agents.state import AgentState

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
        strategy_provider: InvestigationStrategyProvider,
        runbook_limit: int = 5,
    ) -> None:
        self.repository = repository
        self.runbook_provider = runbook_provider
        self.advisor = advisor
        self.fallback_advisor = fallback_advisor
        self.rule_validator = rule_validator
        self.conclusion_validator = conclusion_validator
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.strategy_provider = strategy_provider
        self.runbook_limit = runbook_limit


async def fingerprint_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate incident fingerprint for the alert."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    
    if not run or not alert:
        return {"error": "Missing run or alert in fingerprint node"}
    
    await _update_progress(ctx.repository, alert_id, run, InvestigationStage.FINGERPRINTING, 
                          "问题指纹已生成。", {"incident_fingerprint": alert.incident_fingerprint})
    
    return {
        "current_stage": InvestigationStage.FINGERPRINTING,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=InvestigationStage.FINGERPRINTING,
            message="问题指纹已生成。",
            details={"incident_fingerprint": alert.incident_fingerprint},
        )]
    }


async def knowledge_match_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Match against confirmed historical cases."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    
    if not run or not alert:
        return {"error": "Missing run or alert in knowledge match node"}
    
    await _update_progress(ctx.repository, alert_id, run, InvestigationStage.KNOWLEDGE_MATCHING,
                          "正在匹配人工确认的历史案例。")
    
    knowledge_cases = await ctx.repository.find_knowledge_cases(
        alert.incident_fingerprint, alert.fingerprint_version, limit=3
    )
    
    return {
        "current_stage": InvestigationStage.KNOWLEDGE_MATCHING,
        "knowledge_cases": knowledge_cases,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=InvestigationStage.KNOWLEDGE_MATCHING,
            message="正在匹配人工确认的历史案例。",
        )]
    }


async def runbook_match_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Search for matching runbooks."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    
    if not run or not alert:
        return {"error": "Missing run or alert in runbook match node"}
    
    await _update_progress(ctx.repository, alert_id, run, InvestigationStage.RUNBOOK_MATCHING,
                          "正在检索告警处理手册。", {"knowledge_matches": len(state.knowledge_cases)})
    
    runbooks = await ctx.runbook_provider.search(alert, limit=ctx.runbook_limit)
    await ctx.repository.save_runbooks(alert_id, runbooks)
    
    return {
        "current_stage": InvestigationStage.RUNBOOK_MATCHING,
        "runbooks": runbooks,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=InvestigationStage.RUNBOOK_MATCHING,
            message="正在检索告警处理手册。",
            details={"knowledge_matches": len(state.knowledge_cases)},
        )]
    }


async def select_strategy_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Select investigation strategy based on alert and runbooks."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    
    if not run or not alert:
        return {"error": "Missing run or alert in strategy selection node"}
    
    strategy = await ctx.strategy_provider.select(alert, runbooks)
    await ctx.repository.update_run(str(run.id), strategy_id=strategy.strategy_id)
    
    # Build tool plan from strategy
    pending_requests = list(strategy.tool_plan)
    
    await _update_progress(ctx.repository, alert_id, run, InvestigationStage.INVESTIGATING,
                          f"执行调查策略 {strategy.strategy_id}。", {"tool_count": len(strategy.tool_plan)})
    
    return {
        "current_stage": InvestigationStage.INVESTIGATING,
        "pending_tool_requests": pending_requests,
        "dynamic_turns_remaining": strategy.max_dynamic_turns,
        "max_dynamic_turns": strategy.max_dynamic_turns,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=InvestigationStage.INVESTIGATING,
            message=f"执行调查策略 {strategy.strategy_id}。",
            details={"tool_count": len(strategy.tool_plan)},
        )]
    }


async def execute_tools_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Execute pending tool requests and collect evidence."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    pending_requests = state.pending_tool_requests
    
    if not run or not alert:
        return {"error": "Missing run or alert in tool execution node"}
    
    new_evidence: list[EvidenceRecord] = []
    executed_requests: list[ToolExecutionRequest] = []
    
    # Create investigation context for tool execution
    from app.domain.models import InvestigationStrategy
    strategy = InvestigationStrategy(
        strategy_id="dynamic",
        title="Dynamic Investigation",
        description="Dynamic tool execution",
        tool_plan=pending_requests,
    )
    context = InvestigationContext(run_id=run.id, alert=alert, strategy=strategy)
    
    for request in pending_requests:
        try:
            result = await ctx.tool_executor.execute(request, context)
            new_evidence.append(result)
            await ctx.repository.save_evidence(alert_id, result)
            executed_requests.append(request)
        except Exception as exc:
            logger.exception("tool_execution_failed tool=%s", request.tool_name)
            # Create a failed evidence record
            failed_evidence = EvidenceRecord(
                run_id=run.id,
                tool_name=request.tool_name,
                source_system="unknown",
                status=ToolStatus.FAILED,
                request=request.parameters,
                summary=f"工具 {request.tool_name} 执行失败。",
                error=f"{type(exc).__name__}: {sanitize(str(exc))}",
            )
            new_evidence.append(failed_evidence)
            await ctx.repository.save_evidence(alert_id, failed_evidence)
    
    return {
        "evidence": new_evidence,
        "pending_tool_requests": [],  # Clear pending requests after execution
    }


async def dynamic_investigation_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Decide whether to continue investigation with dynamic tool selection.
    
    This node implements the React pattern: if evidence is insufficient and
    dynamic turns remain, the AI advisor can choose additional tools to run.
    """
    from app.domain.models import InvestigationStrategy as InvStrategy
    
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    evidence = state.evidence
    dynamic_turns_remaining = state.dynamic_turns_remaining
    
    if not run or not alert:
        return {"should_continue_investigation": False}
    
    if dynamic_turns_remaining <= 0:
        return {"should_continue_investigation": False}
    
    # Ask the AI advisor to choose the next tool
    try:
        decision = await ctx.advisor.choose_next_tool(
            InvestigationContext(
                run_id=run.id,
                alert=alert,
                strategy=InvStrategy(
                    strategy_id="dynamic",
                    title="Dynamic",
                    description="Dynamic investigation",
                )
            ),
            evidence,
            ctx.tool_registry.names(),
        )
    except Exception as exc:
        logger.warning("dynamic_tool_selection_failed error=%s", type(exc).__name__)
        return {"should_continue_investigation": False}
    
    if decision.action == "finish" or not decision.tool_name:
        return {"should_continue_investigation": False}
    
    # Check for duplicate tool calls
    seen_requests = {
        (e.tool_name, str(sorted(e.request.items()))) 
        for e in evidence
    }
    request_key = (decision.tool_name, str(sorted(decision.parameters.items())))
    if request_key in seen_requests:
        return {"should_continue_investigation": False}
    
    # Queue the new tool request
    new_request = ToolExecutionRequest(
        tool_name=decision.tool_name,
        parameters=decision.parameters,
        timeout_seconds=10,
    )
    
    return {
        "pending_tool_requests": [new_request],
        "dynamic_turns_remaining": dynamic_turns_remaining - 1,
        "should_continue_investigation": True,
    }


async def advise_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate recommendation using AI advisor."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    evidence = state.evidence
    knowledge_cases = state.knowledge_cases
    validation_enabled = state.validation_enabled
    ai_fallback_enabled = state.ai_fallback_enabled
    
    if not run or not alert:
        return {"error": "Missing run or alert in advise node"}
    
    await _update_progress(ctx.repository, alert_id, run, InvestigationStage.ADVISING,
                          "正在以命中手册为首要依据生成结构化处理建议。",
                          {"runbook_matches": len(runbooks), "evidence_count": len(evidence)})
    
    advisor_degraded = False
    primary_advisor_error: Exception | None = None
    recommendation: Recommendation | None = None
    advisor_metadata: AdvisorMetadata | None = None
    
    # Build strategy for context
    from app.domain.models import InvestigationStrategy
    strategy = InvestigationStrategy(
        strategy_id="investigated",
        title="Investigated",
        description="Investigation completed",
    )
    
    try:
        recommendation, advisor_metadata = await ctx.advisor.advise(
            alert,
            runbooks,
            evidence=evidence,
            knowledge_cases=knowledge_cases,
            strategy=strategy,
        )
    except Exception as exc:
        primary_advisor_error = exc
        if not ai_fallback_enabled or ctx.fallback_advisor is None:
            return {"error": f"AI advisor failed: {type(exc).__name__}: {exc}"}
        advisor_degraded = True
        recommendation, advisor_metadata = await ctx.fallback_advisor.advise(
            alert,
            runbooks,
            evidence=evidence,
            knowledge_cases=knowledge_cases,
            strategy=strategy,
        )
        advisor_metadata = advisor_metadata.model_copy(
            update={"usage": {"fallback_reason": type(exc).__name__}}
        )
        await ctx.repository.append_progress(
            alert_id,
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.ADVISING,
                message="AI 主分析未返回合规结果，已生成保守候选建议并转人工复核。",
                details={"error_type": type(exc).__name__},
            ),
        )
    
    return {
        "current_stage": InvestigationStage.ADVISING,
        "recommendation": recommendation,
        "advisor_metadata": advisor_metadata,
        "advisor_degraded": advisor_degraded,
        "primary_advisor_error": str(primary_advisor_error) if primary_advisor_error else None,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=InvestigationStage.ADVISING,
            message="正在以命中手册为首要依据生成结构化处理建议。",
            details={"runbook_matches": len(runbooks), "evidence_count": len(evidence)},
        )]
    }


async def validate_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Validate the recommendation using rule and agent validators."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    evidence = state.evidence
    recommendation = state.recommendation
    validation_enabled = state.validation_enabled
    advisor_degraded = state.advisor_degraded
    primary_advisor_error = state.primary_advisor_error
    
    if not run or not alert or not recommendation:
        return {"error": "Missing run, alert, or recommendation in validate node"}
    
    await _update_progress(ctx.repository, alert_id, run, InvestigationStage.VALIDATING,
                          "正在进行规则验收和独立结论验收。")
    
    # Rule validation
    rule_validation = await ctx.rule_validator.validate(
        run, alert, recommendation, evidence, runbooks
    )
    
    # Check for required tool failures
    required_failures = _required_tool_failures(state.pending_tool_requests + [], evidence)
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
    await ctx.repository.save_validation(alert_id, rule_validation)
    
    # Agent validation
    agent_validation: ValidationRecord | None = None
    if advisor_degraded and validation_enabled:
        agent_validation = ValidationRecord(
            run_id=run.id,
            kind=ValidationKind.AGENT,
            passed=False,
            issues=["AI 主分析不可用，保守候选建议必须由人工复核"],
            metadata={
                "fallback": True,
                "primary_error_type": primary_advisor_error or "Unknown",
            },
        )
        await ctx.repository.save_validation(alert_id, agent_validation)
    elif rule_validation.passed and validation_enabled:
        try:
            agent_validation = await ctx.conclusion_validator.validate(
                run, alert, recommendation, evidence, runbooks
            )
        except Exception as exc:
            agent_validation = ValidationRecord(
                run_id=run.id,
                kind=ValidationKind.AGENT,
                passed=False,
                issues=[f"独立验收不可用：{type(exc).__name__}: {sanitize(str(exc))}"],
            )
        await ctx.repository.save_validation(alert_id, agent_validation)
    
    # Determine validation passed
    validation_passed = rule_validation.passed and (
        not validation_enabled or (agent_validation is not None and agent_validation.passed)
    )
    
    # Check for unapproved runbooks
    unapproved_runbook = any(
        item.quality_status != RunbookQualityStatus.APPROVED
        for item in runbooks
    )
    
    return {
        "current_stage": InvestigationStage.VALIDATING,
        "rule_validation": rule_validation,
        "agent_validation": agent_validation,
        "validation_passed": validation_passed,
        "unapproved_runbook": unapproved_runbook,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=InvestigationStage.VALIDATING,
            message="正在进行规则验收和独立结论验收。",
        )]
    }


async def report_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate final report and update status."""
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    recommendation = state.recommendation
    advisor_metadata = state.advisor_metadata
    evidence = state.evidence
    validation_passed = state.validation_passed
    unapproved_runbook = state.unapproved_runbook
    advisor_degraded = state.advisor_degraded
    shadow_enabled = state.shadow_enabled
    error = state.error
    
    if not run or not alert:
        return {"error": "Missing run or alert in report node"}
    
    if error:
        # Handle error case
        await ctx.repository.update_run(
            str(run.id),
            status=RunStatus.FAILED.value,
            stage=InvestigationStage.FAILED,
            error=error,
        )
        await ctx.repository.append_progress(
            alert_id,
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.FAILED,
                message="调查执行失败。",
                details={"error": error},
            ),
        )
        await ctx.repository.save_analysis(
            alert_id, AlertStatus.FAILED, runbooks=runbooks, error=error
        )
        return {
            "current_stage": InvestigationStage.FAILED,
            "status": AlertStatus.FAILED,
            "run_status": RunStatus.FAILED,
        }
    
    # Determine final status
    passed = (
        validation_passed
        and not shadow_enabled
        and not unapproved_runbook
        and not advisor_degraded
    )
    final_status = AlertStatus.COMPLETED if passed else AlertStatus.REVIEW_REQUIRED
    run_status = RunStatus.COMPLETED if passed else RunStatus.REVIEW_REQUIRED
    final_stage = InvestigationStage.COMPLETED if passed else InvestigationStage.REVIEW_REQUIRED
    
    if not passed and recommendation:
        recommendation = recommendation.model_copy(
            update={
                "requires_human": True,
                "confidence": min(recommendation.confidence, 0.5),
                "analysis_mode": "shadow" if shadow_enabled else "assist",
            }
        )
    elif recommendation:
        recommendation = recommendation.model_copy(update={"analysis_mode": "assist"})
    
    await ctx.repository.update_run(
        str(run.id), status=run_status.value, stage=final_stage
    )
    await ctx.repository.append_progress(
        alert_id,
        ProgressRecord(
            run_id=run.id,
            stage=final_stage,
            message="调查完成。" if passed else "结论需要人工复核。",
            details={
                "validation_passed": validation_passed,
                "shadow_enabled": shadow_enabled,
                "unapproved_runbook": unapproved_runbook,
                "advisor_degraded": advisor_degraded,
            },
        ),
    )
    await ctx.repository.save_analysis(
        alert_id,
        final_status,
        runbooks=runbooks,
        recommendation=recommendation,
        advisor_metadata=advisor_metadata,
    )
    
    return {
        "current_stage": final_stage,
        "status": final_status,
        "run_status": run_status,
        "recommendation": recommendation,
        "progress": [ProgressRecord(
            run_id=run.id,
            stage=final_stage,
            message="调查完成。" if passed else "结论需要人工复核。",
            details={
                "validation_passed": validation_passed,
                "shadow_enabled": shadow_enabled,
                "unapproved_runbook": unapproved_runbook,
                "advisor_degraded": advisor_degraded,
            },
        )]
    }


def _required_tool_failures(requests: list[ToolExecutionRequest], evidence: list[EvidenceRecord]) -> list[str]:
    """Get list of required tools that failed."""
    statuses: dict[str, list[ToolStatus]] = {}
    for item in evidence:
        statuses.setdefault(item.tool_name, []).append(item.status)
    return [
        request.tool_name
        for request in requests
        if request.required
        and ToolStatus.SUCCESS not in statuses.get(request.tool_name, [])
    ]


async def _update_progress(
    repository: AlertRepository,
    alert_id: str,
    run: InvestigationRun,
    stage: InvestigationStage,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Update run stage and append progress record."""
    await repository.update_run(str(run.id), stage=stage)
    await repository.append_progress(
        alert_id,
        ProgressRecord(
            run_id=run.id,
            stage=stage,
            message=message,
            details=details or {},
        ),
    )