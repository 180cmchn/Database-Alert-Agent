"""LangGraph node functions for alert investigation workflow."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.adapters.external_knowledge import (
    ExternalKnowledgeClient,
    format_items_for_advisor,
)
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agent_runtime.outer_dispatch import DurableOuterToolDispatcher
from app.agents.state import AgentState
from app.application.sanitization import sanitize
from app.application.validation import enforce_post_evidence_root_cause_policy
from app.domain.errors import RunbookAlertTypeNotFoundError
from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    EvidenceRecord,
    ExternalKnowledgeExcerpt,
    InvestigationContext,
    InvestigationEvidenceAssessment,
    InvestigationRun,
    InvestigationStage,
    InvestigationStrategy,
    ProgressRecord,
    Recommendation,
    RootCauseStatus,
    RunbookExcerpt,
    RunStatus,
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
from app.investigations.models import (
    EvidenceAssessment,
    EvidenceRelation,
    InvestigationMemory,
    is_terminal_probe_attempt,
    update_memory,
)
from app.investigations.seeding import seed_investigation_memory
from app.investigations.stop import StopDecision, StopEvaluator, StopReason

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
        self.strategy_provider = strategy_provider
        self.runbook_limit = runbook_limit
        self.external_knowledge_client = external_knowledge_client
        self.external_knowledge_limit = external_knowledge_limit
        self.external_knowledge_min_relevance = external_knowledge_min_relevance
        self.knowledge_sources = (
            knowledge_sources if knowledge_sources is not None else ["local_pdf"]
        )


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


async def knowledge_match_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Match against confirmed historical cases.

    Historical cases are always queried and not controlled by ``knowledge_sources``.
    External knowledge and local PDF runbook matching happen in the subsequent
    ``runbook_match_node`` where they run in parallel.
    """
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert

    if not run or not alert:
        return {"error": "Missing run or alert in knowledge match node"}

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.KNOWLEDGE_MATCHING,
        "正在匹配人工确认的历史案例。",
    )

    knowledge_cases = await ctx.repository.find_knowledge_cases(
        alert.incident_fingerprint, alert.fingerprint_version, limit=3
    )

    return {
        "current_stage": InvestigationStage.KNOWLEDGE_MATCHING,
        "knowledge_cases": knowledge_cases,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.KNOWLEDGE_MATCHING,
                message="正在匹配人工确认的历史案例。",
                details={"knowledge_cases_count": len(knowledge_cases)},
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

    Historical cases are handled in the preceding ``knowledge_match_node`` and
    are not touched here.
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
        {"knowledge_matches": len(state.knowledge_cases)},
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
                    "knowledge_matches": len(state.knowledge_cases),
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

    strategy = await ctx.strategy_provider.select(alert, runbooks)
    await ctx.repository.update_run(
        str(run.id),
        strategy_id=strategy.strategy_id,
        **_lease_fence(run),
    )

    # Build the explicit Host-owned memory before any live tool may run. Hard stop
    # conditions therefore gate the deterministic plan as well as later ReAct turns.
    investigation_memory = seed_investigation_memory(
        alert,
        runbooks,
        strategy,
        available_tools=set(ctx.tool_registry.available_names()),
    )
    stop_decision = StopEvaluator().evaluate(investigation_memory)
    pending_requests = list(strategy.tool_plan)
    if stop_decision.should_stop and stop_decision.reason in {
        StopReason.TARGET_AMBIGUOUS,
        StopReason.WINDOW_AMBIGUOUS,
        StopReason.HUMAN_REQUIRED,
        StopReason.BUDGET_EXHAUSTED,
        StopReason.DEADLINE_EXCEEDED,
    }:
        pending_requests = []
    elif pending_requests and stop_decision.reason == StopReason.NO_SAFE_PROBE:
        # A deterministic baseline plan may collect safe context even when no
        # causal probe is yet known. It cannot clear UNKNOWN or human review.
        stop_decision = StopDecision(
            should_stop=False,
            reason=StopReason.CONTINUE,
            requires_human=False,
            rationale=(
                "The approved deterministic baseline plan may collect context; "
                "causal uncertainty remains unresolved."
            ),
        )

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.INVESTIGATING,
        f"执行调查策略 {strategy.strategy_id}。",
        {
            "tool_count": len(pending_requests),
            "stop_reason": stop_decision.reason.value,
        },
    )

    return {
        "current_stage": InvestigationStage.INVESTIGATING,
        "strategy": strategy,
        "investigation_memory": investigation_memory,
        "stop_decision": stop_decision,
        "pending_tool_requests": pending_requests,
        "dynamic_turns_remaining": strategy.max_dynamic_turns,
        "max_dynamic_turns": strategy.max_dynamic_turns,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.INVESTIGATING,
                message=f"执行调查策略 {strategy.strategy_id}。",
                details={
                    "tool_count": len(pending_requests),
                    "stop_reason": stop_decision.reason.value,
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
    investigation_memory = state.investigation_memory

    context = InvestigationContext(
        run_id=run.id,
        alert=alert,
        strategy=strategy,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
        investigation_memory=state.investigation_memory.model_dump(mode="json"),
    )
    dispatcher = DurableOuterToolDispatcher(ctx.repository, ctx.tool_executor)

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
        investigation_memory = update_memory(investigation_memory, result)
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
        "investigation_memory": investigation_memory,
        "pending_tool_requests": [],  # Clear pending requests after execution
    }


async def _record_react_outcome(
    ctx: NodeContext,
    *,
    alert_id: str,
    run: InvestigationRun,
    outcome: str,
    message: str,
    turns_remaining: int,
    evidence_count: int,
    details: dict[str, Any] | None = None,
) -> ProgressRecord:
    """Persist one sanitized ReAct planning outcome without storing tool parameters."""
    outcome_details: dict[str, Any] = {
        "event": "react_decision",
        "outcome": outcome,
        "turns_remaining": max(0, turns_remaining),
        "evidence_count": evidence_count,
    }
    if details:
        outcome_details.update(details)
    return await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.INVESTIGATING,
        message,
        sanitize(outcome_details),
    )


async def dynamic_investigation_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Decide whether to continue investigation with dynamic tool selection.

    This node implements the React pattern: if evidence is insufficient and
    dynamic turns remain, the AI advisor can choose additional tools to run.
    """
    if state.error:
        return {
            "should_continue_investigation": False,
            "stop_decision": StopDecision(
                should_stop=True,
                reason=StopReason.HUMAN_REQUIRED,
                requires_human=True,
                rationale="The investigation already contains an execution error.",
            ),
        }

    run = state.run
    alert = state.alert
    strategy = state.strategy
    evidence = state.evidence
    dynamic_turns_remaining = state.dynamic_turns_remaining

    if not run or not alert or not strategy:
        return {
            "should_continue_investigation": False,
            "stop_decision": StopDecision(
                should_stop=True,
                reason=StopReason.HUMAN_REQUIRED,
                requires_human=True,
                rationale="The investigation state is incomplete.",
            ),
        }

    pre_planning_stop = StopEvaluator().evaluate(state.investigation_memory)
    if pre_planning_stop.should_stop and pre_planning_stop.reason in {
        StopReason.SUPPORTED_CAUSE,
        StopReason.TARGET_AMBIGUOUS,
        StopReason.WINDOW_AMBIGUOUS,
        StopReason.HUMAN_REQUIRED,
        StopReason.BUDGET_EXHAUSTED,
        StopReason.DEADLINE_EXCEEDED,
    }:
        return {
            "investigation_memory": state.investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": pre_planning_stop,
        }

    # A final assessment turn is still required after the last permitted tool
    # dispatch. A run configured with zero ReAct turns has no such pending turn.
    assessment_only = dynamic_turns_remaining <= 0 and state.max_dynamic_turns > 0
    if dynamic_turns_remaining <= 0 and not assessment_only:
        return {
            "investigation_memory": state.investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": StopEvaluator().evaluate(
                state.investigation_memory,
                budget_exhausted=True,
            ),
        }

    # Ask the AI advisor to choose the next tool
    try:
        decision = await ctx.advisor.choose_next_tool(
            InvestigationContext(
                run_id=run.id,
                alert=alert,
                strategy=strategy,
                lease_owner=run.lease_owner,
                fencing_token=run.fencing_token,
                investigation_memory=state.investigation_memory.model_dump(mode="json"),
            ),
            evidence,
            ctx.tool_registry.available_specs(),
        )
        investigation_memory = _apply_planner_assessments(
            state.investigation_memory,
            decision.evidence_assessments,
        )
    except Exception as exc:
        logger.warning("dynamic_tool_selection_failed error=%s", type(exc).__name__)
        if assessment_only:
            progress = await _record_react_outcome(
                ctx,
                alert_id=state.alert_id,
                run=run,
                outcome="assessment_error",
                message="ReAct 最终证据评估失败，已停止追加工具并转人工复核。",
                turns_remaining=0,
                evidence_count=len(evidence),
                details={"error_type": type(exc).__name__},
            )
            return {
                "investigation_memory": state.investigation_memory,
                "should_continue_investigation": False,
                "stop_decision": StopDecision(
                    should_stop=True,
                    reason=StopReason.HUMAN_REQUIRED,
                    requires_human=True,
                    rationale=(
                        "The final evidence assessment failed after the tool budget was exhausted."
                    ),
                ),
                "progress": [progress],
            }
        fallback_request = _next_safe_probe_request(
            state.investigation_memory,
            evidence,
            strategy,
            ctx.tool_registry,
        )
        if fallback_request is not None:
            remaining_after_selection = dynamic_turns_remaining - 1
            progress = await _record_react_outcome(
                ctx,
                alert_id=state.alert_id,
                run=run,
                outcome="planner_fallback_probe",
                message="ReAct 规划失败，Host 改用最高优先级的已批准只读探针。",
                turns_remaining=remaining_after_selection,
                evidence_count=len(evidence),
                details={
                    "error_type": type(exc).__name__,
                    "tool_name": str(sanitize(fallback_request.tool_name))[:128],
                    "hypothesis_ids": fallback_request.hypothesis_ids,
                },
            )
            return {
                "investigation_memory": state.investigation_memory,
                "pending_tool_requests": [fallback_request],
                "dynamic_turns_remaining": remaining_after_selection,
                "should_continue_investigation": True,
                "stop_decision": StopDecision(
                    should_stop=False,
                    reason=StopReason.CONTINUE,
                    requires_human=False,
                    rationale=("The planner failed, but an approved discriminating probe remains."),
                ),
                "progress": [progress],
            }
        progress = await _record_react_outcome(
            ctx,
            alert_id=state.alert_id,
            run=run,
            outcome="planner_error",
            message=("ReAct 动态调查规划失败，已停止追加工具并基于现有证据继续分析。"),
            turns_remaining=dynamic_turns_remaining,
            evidence_count=len(evidence),
            details={"error_type": type(exc).__name__},
        )
        return {
            "investigation_memory": state.investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": StopDecision(
                should_stop=True,
                reason=StopReason.HUMAN_REQUIRED,
                requires_human=True,
                rationale=("The planner failed and no deterministic approved probe was available."),
            ),
            "progress": [progress],
        }

    if assessment_only:
        if decision.action == "finish" or not decision.tool_name:
            investigation_memory = InvestigationMemory.model_validate(
                {
                    **investigation_memory.model_dump(mode="python"),
                    "model_finish_requested": True,
                }
            )
        stop_decision = StopEvaluator().evaluate(
            investigation_memory,
            budget_exhausted=True,
        )
        progress = await _record_react_outcome(
            ctx,
            alert_id=state.alert_id,
            run=run,
            outcome="final_assessment",
            message="ReAct 已评估最后一次工具结果，调用预算已结束。",
            turns_remaining=0,
            evidence_count=len(evidence),
            details={
                "decision_action": decision.action,
                "stop_reason": stop_decision.reason.value,
                "supported_hypothesis_ids": stop_decision.supported_hypothesis_ids,
            },
        )
        return {
            "investigation_memory": investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": stop_decision,
            "progress": [progress],
        }

    if decision.action == "finish" or not decision.tool_name:
        investigation_memory = InvestigationMemory.model_validate(
            {
                **investigation_memory.model_dump(mode="python"),
                "model_finish_requested": True,
            }
        )
        stop_decision = StopEvaluator().evaluate(investigation_memory)
        if not stop_decision.should_stop:
            fallback_request = _next_safe_probe_request(
                investigation_memory,
                evidence,
                strategy,
                ctx.tool_registry,
            )
            if fallback_request is not None:
                remaining_after_selection = dynamic_turns_remaining - 1
                progress = await _record_react_outcome(
                    ctx,
                    alert_id=state.alert_id,
                    run=run,
                    outcome="finish_overridden",
                    message="ReAct 的结束请求未通过 Host 停止条件，继续执行已批准只读探针。",
                    turns_remaining=remaining_after_selection,
                    evidence_count=len(evidence),
                    details={
                        "tool_name": str(sanitize(fallback_request.tool_name))[:128],
                        "hypothesis_ids": fallback_request.hypothesis_ids,
                        "reason": str(sanitize(decision.reason))[:500],
                    },
                )
                return {
                    "investigation_memory": investigation_memory,
                    "pending_tool_requests": [fallback_request],
                    "dynamic_turns_remaining": remaining_after_selection,
                    "should_continue_investigation": True,
                    "stop_decision": stop_decision,
                    "progress": [progress],
                }
            stop_decision = StopDecision(
                should_stop=True,
                reason=StopReason.NO_SAFE_PROBE,
                requires_human=True,
                rationale=(
                    "The model requested finish and every approved probe was already "
                    "completed or unavailable."
                ),
                model_finish_requested=True,
            )
        progress = await _record_react_outcome(
            ctx,
            alert_id=state.alert_id,
            run=run,
            outcome="finish",
            message="ReAct 判定无需追加只读工具，结束动态调查。",
            turns_remaining=dynamic_turns_remaining,
            evidence_count=len(evidence),
            details={
                "decision_action": decision.action,
                "reason": str(sanitize(decision.reason))[:500],
                "stop_reason": stop_decision.reason.value,
                "supported_hypothesis_ids": stop_decision.supported_hypothesis_ids,
            },
        )
        return {
            "investigation_memory": investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": stop_decision,
            "progress": [progress],
        }

    stop_decision = StopEvaluator().evaluate(investigation_memory)
    if stop_decision.should_stop and stop_decision.reason != StopReason.NO_SAFE_PROBE:
        progress = await _record_react_outcome(
            ctx,
            alert_id=state.alert_id,
            run=run,
            outcome="host_stop",
            message="Host 停止条件已满足，不再追加只读探针。",
            turns_remaining=dynamic_turns_remaining,
            evidence_count=len(evidence),
            details={
                "stop_reason": stop_decision.reason.value,
                "supported_hypothesis_ids": stop_decision.supported_hypothesis_ids,
            },
        )
        return {
            "investigation_memory": investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": stop_decision,
            "progress": [progress],
        }

    # A terminal result closes this logical probe for the current outer run.
    # Missing outcomes affect scheduling only and remain ineligible as causal evidence.
    attempted_requests = {
        _tool_request_fingerprint(e.tool_name, e.request)
        for e in evidence
        if is_terminal_probe_attempt(e)
    }
    request_key = _tool_request_fingerprint(decision.tool_name, decision.parameters)
    safe_tool_name = str(sanitize(decision.tool_name))[:128]
    if request_key in attempted_requests:
        duplicate_stop = StopDecision(
            should_stop=True,
            reason=StopReason.HUMAN_REQUIRED,
            requires_human=True,
            rationale=(
                "The planner repeated a terminal logical probe instead of selecting "
                "an unattempted discriminating probe."
            ),
        )
        progress = await _record_react_outcome(
            ctx,
            alert_id=state.alert_id,
            run=run,
            outcome="duplicate_rejected",
            message="ReAct 拒绝重复工具调用，结束动态调查。",
            turns_remaining=dynamic_turns_remaining,
            evidence_count=len(evidence),
            details={
                "tool_name": safe_tool_name,
                "reason": str(sanitize(decision.reason))[:500],
                "stop_reason": duplicate_stop.reason.value,
            },
        )
        return {
            "investigation_memory": investigation_memory,
            "should_continue_investigation": False,
            "stop_decision": duplicate_stop,
            "progress": [progress],
        }

    # Reuse the strategy's per-tool execution policy. Prefer an exact request
    # template when a strategy contains more than one call to the same tool.
    request_template = next(
        (
            request
            for request in strategy.tool_plan
            if _tool_request_fingerprint(request.tool_name, request.parameters) == request_key
        ),
        None,
    )
    if request_template is None:
        request_template = next(
            (request for request in strategy.tool_plan if request.tool_name == decision.tool_name),
            None,
        )

    request_policy: dict[str, Any] = {}
    if request_template is not None:
        request_policy = {
            "timeout_seconds": request_template.timeout_seconds,
            "required": request_template.required,
        }

    # Queue the new tool request. Tools absent from the deterministic strategy use
    # the domain model's defaults rather than a node-specific timeout.
    new_request = ToolExecutionRequest(
        tool_name=decision.tool_name,
        parameters=decision.parameters,
        objective=decision.objective or decision.reason,
        hypothesis_ids=decision.hypothesis_ids,
        **request_policy,
    )
    remaining_after_selection = dynamic_turns_remaining - 1
    progress = await _record_react_outcome(
        ctx,
        alert_id=state.alert_id,
        run=run,
        outcome="tool_selected",
        message=f"ReAct 选择追加只读工具 {safe_tool_name}。",
        turns_remaining=remaining_after_selection,
        evidence_count=len(evidence),
        details={
            "tool_name": safe_tool_name,
            **({"hypothesis_ids": decision.hypothesis_ids} if decision.hypothesis_ids else {}),
            "reason": str(sanitize(decision.reason))[:500],
        },
    )

    return {
        "investigation_memory": investigation_memory,
        "pending_tool_requests": [new_request],
        "dynamic_turns_remaining": remaining_after_selection,
        "should_continue_investigation": True,
        "stop_decision": StopDecision(
            should_stop=False,
            reason=StopReason.CONTINUE,
            requires_human=False,
            rationale="The planner selected an approved read-only investigation tool.",
        ),
        "progress": [progress],
    }


def _apply_planner_assessments(
    memory: InvestigationMemory,
    proposed: list[InvestigationEvidenceAssessment],
) -> InvestigationMemory:
    """Apply model semantics without allowing ineligible evidence to change a cause."""

    if not proposed:
        return memory
    evidence_by_id = memory.evidence_by_id()
    grouped: dict[str, list[EvidenceAssessment]] = {}
    for item in proposed:
        evidence = evidence_by_id.get(item.evidence_id)
        if evidence is None:
            raise ValueError("planner assessment references unknown evidence")
        assessment = EvidenceAssessment(
            hypothesis_id=item.hypothesis_id,
            evidence_id=item.evidence_id,
            relation=EvidenceRelation(item.relation),
            rationale=item.rationale,
        )
        grouped.setdefault(item.evidence_id, []).append(assessment)
    updated = memory
    for evidence_id, assessments in grouped.items():
        updated = update_memory(updated, evidence_by_id[evidence_id], assessments)
    return updated


def _next_safe_probe_request(
    memory: InvestigationMemory,
    evidence: list[EvidenceRecord],
    strategy: InvestigationStrategy,
    registry: InvestigationToolRegistry,
) -> ToolExecutionRequest | None:
    """Choose the highest-priority uncompleted probe already approved by the Host."""

    attempted = {
        _tool_request_fingerprint(item.tool_name, item.request)
        for item in evidence
        if is_terminal_probe_attempt(item)
    }
    hypothesis_by_need = {
        item.next_probe.need_id: item.hypothesis_id
        for item in memory.hypotheses
        if item.next_probe is not None
    }
    for probe in memory.safe_unattempted_probes():
        if not probe.tool_name:
            continue
        spec = registry.spec(probe.tool_name)
        if spec is None or not spec.read_only:
            continue
        parameters = dict(probe.parameters)
        if _tool_request_fingerprint(probe.tool_name, parameters) in attempted:
            continue
        template = next(
            (
                item
                for item in strategy.tool_plan
                if item.tool_name == probe.tool_name and item.parameters == parameters
            ),
            None,
        ) or next(
            (item for item in strategy.tool_plan if item.tool_name == probe.tool_name),
            None,
        )
        policy: dict[str, Any] = {}
        if template is not None:
            policy = {
                "timeout_seconds": template.timeout_seconds,
                "required": template.required,
            }
        hypothesis_id = hypothesis_by_need.get(probe.need_id)
        return ToolExecutionRequest(
            tool_name=probe.tool_name,
            parameters=parameters,
            objective=probe.objective,
            hypothesis_ids=[hypothesis_id] if hypothesis_id else [],
            **policy,
        )
    return None


def _tool_request_fingerprint(tool_name: str, parameters: dict[str, Any]) -> tuple[str, str]:
    """Return a stable, sanitized identity for one logical tool request."""

    canonical_parameters = json.dumps(
        sanitize(parameters),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return tool_name, canonical_parameters


async def advise_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate recommendation using AI advisor."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    runbooks = state.runbooks
    evidence = state.evidence
    knowledge_cases = state.knowledge_cases
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
        "实时证据采集已完成，正在根据告警与实时证据生成可能根因和处理建议。",
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
            knowledge_cases=knowledge_cases,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
            investigation_memory=state.investigation_memory,
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
            knowledge_cases=knowledge_cases,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
            strategy=strategy,
            investigation_memory=state.investigation_memory,
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
                "requires_human": True,
            }
        )
    recommendation = enforce_post_evidence_root_cause_policy(
        recommendation,
        evidence,
        alert,
        state.investigation_memory,
    )
    host_review_reasons = _host_review_reasons(state)
    if host_review_reasons:
        recommendation = recommendation.model_copy(
            update={
                "requires_human": True,
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
                message=("实时证据采集已完成，正在根据告警与实时证据生成可能根因和处理建议。"),
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
        state.investigation_memory,
    )

    required_failures = _required_tool_failures(strategy.tool_plan, evidence)
    if required_failures:
        rule_validation = rule_validation.model_copy(
            update={
                "evidence_sufficient": False,
                "metadata": {
                    **rule_validation.metadata,
                    "required_tool_failures": required_failures,
                    "evidence_gap": (f"必需调查工具未成功：{', '.join(required_failures)}"),
                },
            }
        )
    host_review_reasons = _host_review_reasons(state)
    if host_review_reasons:
        rule_validation = rule_validation.model_copy(
            update={
                "evidence_sufficient": False,
                "metadata": {
                    **rule_validation.metadata,
                    "host_review_reasons": host_review_reasons,
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
            issues=["AI 主分析不可用，保守候选建议必须由人工复核"],
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
                state.investigation_memory,
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

    # Contract validity and evidence sufficiency are independent. An honest
    # UNKNOWN can pass validation while still requiring human review.
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
    shadow_enabled = state.shadow_enabled
    error = state.error
    host_review_reasons = _host_review_reasons(state)

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
        and not shadow_enabled
        and not advisor_degraded
        and not host_review_reasons
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
                message="调查完成。" if passed else "结论需要人工复核。",
                details={
                    "validation_passed": validation_passed,
                    "evidence_sufficient": evidence_sufficient,
                    "shadow_enabled": shadow_enabled,
                    "advisor_degraded": advisor_degraded,
                    "host_review_reasons": host_review_reasons,
                },
            )
        ],
    }


def _required_tool_failures(
    requests: list[ToolExecutionRequest], evidence: list[EvidenceRecord]
) -> list[str]:
    """Get list of required tools that failed."""
    statuses: dict[str, list[ToolStatus]] = {}
    for item in evidence:
        statuses.setdefault(item.tool_name, []).append(item.status)
    return [
        request.tool_name
        for request in requests
        if request.required and ToolStatus.SUCCESS not in statuses.get(request.tool_name, [])
    ]


def _host_review_reasons(state: AgentState) -> list[str]:
    """Return deterministic reasons that forbid autonomous completion."""

    reasons: list[str] = []
    decision = state.stop_decision
    if decision is not None and decision.requires_human:
        reasons.append(f"stop:{decision.reason.value}")

    unresolved = sorted(
        hypothesis.hypothesis_id
        for hypothesis in state.investigation_memory.hypotheses
        if hypothesis.status == RootCauseStatus.UNKNOWN
    )
    reasons.extend(f"unresolved:{hypothesis_id}" for hypothesis_id in unresolved)
    if not state.investigation_memory.hypotheses:
        reasons.append("no_hypotheses")
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
