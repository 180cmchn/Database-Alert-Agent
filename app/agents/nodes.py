"""LangGraph node functions for alert investigation workflow."""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any
from uuid import uuid5

from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.adapters.knowledge import KnowledgeSourceRegistry
from app.agent_runtime.events import AgentEvent, AgentEventKind
from app.agent_runtime.outer_dispatch import DurableOuterToolDispatcher
from app.agent_runtime.persistence import RepositoryEventSink
from app.agent_runtime.trace import AgentTraceEmitter, AgentTraceScope
from app.agents.state import AgentState
from app.application.sanitization import sanitize, sanitize_alert
from app.application.validation import enforce_post_evidence_root_cause_policy
from app.domain.alert_preprocessing import preprocess_alert_data, preprocess_normalized_alert
from app.domain.models import (
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
    AdvisorMetadata,
    AlertStatus,
    EvidenceRecord,
    InvestigationContext,
    InvestigationDecision,
    InvestigationDecisionResult,
    InvestigationRun,
    InvestigationStage,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunStatus,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.ports import (
    AIAdvisor,
    AlertDetailEnricher,
    AlertRepository,
    ConclusionValidator,
    ToolResultAnalyzer,
)

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
        knowledge_registry: KnowledgeSourceRegistry,
        advisor: AIAdvisor,
        fallback_advisor: AIAdvisor | None,
        rule_validator: ConclusionValidator,
        tool_registry: InvestigationToolRegistry,
        tool_executor: ToolExecutor,
        tool_result_analyzer: ToolResultAnalyzer | None = None,
        alert_detail_enricher: AlertDetailEnricher | None = None,
        knowledge_sources: list[str] | None = None,
    ) -> None:
        self.repository = repository
        self.knowledge_registry = knowledge_registry
        self.advisor = advisor
        self.fallback_advisor = fallback_advisor
        self.rule_validator = rule_validator
        self.tool_registry = tool_registry
        self.tool_executor = tool_executor
        self.tool_result_analyzer = tool_result_analyzer
        self.alert_detail_enricher = alert_detail_enricher
        self.knowledge_sources = knowledge_sources or []


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
        },
        summary="已获取权威 FlashDuty 告警详情；该记录仅陈述告警事实，不代表根因结论。",
        structured_data={
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


async def knowledge_match_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Search every selected source independently and always continue analysis."""
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
        "正在检索已选择的知识来源。",
    )
    selected_sources = list(dict.fromkeys(state.knowledge_sources))
    results = await ctx.knowledge_registry.search(selected_sources, alert)
    knowledge = [match for result in results for match in result.matches]
    source_details = [
        {
            "source": result.source,
            "match_count": len(result.matches),
            "error": result.error,
        }
        for result in results
    ]
    if not selected_sources:
        knowledge_match_summary = "未选择知识来源，Agent 将使用告警、实时证据和通用推理。"
    else:
        source_summaries = [
            (
                f"{result.source} 查询失败（{result.error}），已忽略"
                if result.error
                else f"{result.source} 命中 {len(result.matches)} 条"
            )
            for result in results
        ]
        knowledge_match_summary = "知识匹配结果：" + "；".join(source_summaries) + "。"
        if not knowledge:
            knowledge_match_summary += (
                "所选知识来源均未命中或不可用，Agent 将使用告警、实时证据和通用推理。"
            )

    return {
        "current_stage": InvestigationStage.KNOWLEDGE_MATCHING,
        "knowledge": knowledge,
        "knowledge_match_summary": knowledge_match_summary,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.KNOWLEDGE_MATCHING,
                message="正在检索已选择的知识来源。",
                details={
                    "sources": source_details,
                    "knowledge_match_count": len(knowledge),
                    "knowledge_match_summary": knowledge_match_summary,
                },
            )
        ],
    }


async def react_decide_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Ask the single main Agent for one ReAct tool-or-finish decision."""

    if state.error:
        return {"react_finished": True, "pending_tool_requests": []}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    if not run or not alert:
        return {"error": "Missing run or alert in ReAct decision node"}

    next_round = state.react_round + 1
    sink = RepositoryEventSink(ctx.repository, **_lease_fence(run))
    emitter = AgentTraceEmitter(
        sink,
        run_id=run.id,
        actor="main_agent",
        provider=str(getattr(ctx.advisor, "provider", type(ctx.advisor).__name__)),
        scope=AgentTraceScope.MAIN_AGENT,
    )
    if state.react_round >= state.react_max_rounds:
        decision = InvestigationDecision(
            action="finish",
            reason="react_max_rounds_reached",
        )
        await emitter.emit_action(
            json.dumps(decision.model_dump(mode="json"), ensure_ascii=False),
            trace_key=f"react:{state.react_round}:max-rounds",
        )
        progress = await _update_progress(
            ctx.repository,
            alert_id,
            run,
            InvestigationStage.INVESTIGATING,
            "ReAct 已达到配置的最大轮次，基于现有证据正常结束调查。",
            {
                "event": "react_decision",
                "outcome": "max_rounds_reached",
                "react_round": state.react_round,
                "react_max_rounds": state.react_max_rounds,
            },
        )
        return {
            "current_stage": InvestigationStage.INVESTIGATING,
            "react_decision": decision,
            "react_finished": True,
            "pending_tool_requests": [],
            "progress": [progress],
        }

    result = await _load_react_decision(sink, run, next_round)
    reasoning_request_attempt = await _next_reasoning_request_attempt(
        sink,
        run,
        prefix=f"main-agent:react:{next_round}:request:",
    )
    reasoning_callback_invoked = False
    if result is None:
        decide = getattr(ctx.advisor, "decide_investigation", None)
        if decide is None:
            result = InvestigationDecisionResult(
                decision=InvestigationDecision(
                    action="finish",
                    reason="configured advisor does not expose ReAct decisions",
                ),
                metadata=AdvisorMetadata(
                    provider=str(getattr(ctx.advisor, "provider", "compatibility")),
                    model=str(getattr(ctx.advisor, "model", type(ctx.advisor).__name__)),
                    prompt_version=str(getattr(ctx.advisor, "prompt_version", "compatibility")),
                ),
            )
        else:
            try:
                decision_kwargs = {
                    "alert": alert,
                    "knowledge": state.knowledge,
                    "knowledge_match_summary": state.knowledge_match_summary,
                    "evidence": state.evidence,
                    "available_tools": ctx.tool_registry.available_specs(),
                    "react_round": next_round,
                    "react_max_rounds": state.react_max_rounds,
                }

                async def emit_response_reasoning(
                    content: str,
                    stream_id: str,
                    delta_index: int,
                ) -> None:
                    nonlocal reasoning_callback_invoked
                    durable_stream_id = (
                        f"main-agent:react:{next_round}:request:"
                        f"{reasoning_request_attempt}:{stream_id}"
                    )
                    emitted = await emitter.emit_reasoning_delta(
                        content,
                        stream_id=durable_stream_id,
                        delta_index=delta_index,
                        trace_key=f"{durable_stream_id}:delta:{delta_index}",
                    )
                    reasoning_callback_invoked = (
                        reasoning_callback_invoked or emitted is not None
                    )

                # Persisting one durable event per main-Agent reasoning
                # delta (insert plus a full-history idempotency read)
                # dominates decision wall time, so durable delta streaming
                # is opt-in; the complete reasoning is recorded once per
                # decision through the fallback below otherwise.
                if _accepts_keyword_argument(decide, "reasoning_callback") and (
                    state.stream_main_agent_reasoning
                ):
                    result = await decide(
                        **decision_kwargs,
                        reasoning_callback=emit_response_reasoning,
                    )
                else:
                    result = await decide(**decision_kwargs)
            except Exception as exc:
                logger.warning(
                    "react_decision_failed run_id=%s round=%s error=%s",
                    run.id,
                    next_round,
                    type(exc).__name__,
                )
                result = InvestigationDecisionResult(
                    decision=InvestigationDecision(
                        action="finish",
                        reason=f"ReAct decision unavailable: {type(exc).__name__}",
                    ),
                    metadata=AdvisorMetadata(
                        provider=str(getattr(ctx.advisor, "provider", "unavailable")),
                        model=str(getattr(ctx.advisor, "model", type(ctx.advisor).__name__)),
                        prompt_version=str(
                            getattr(ctx.advisor, "prompt_version", "unavailable")
                        ),
                    ),
                )
        await sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.MODEL_DECISION,
                payload={
                    "actor": "main_agent",
                    "react_round": next_round,
                    "decision": result.decision.model_dump(mode="json"),
                    "metadata": result.metadata.model_dump(mode="json"),
                },
            )
        )

    if not reasoning_callback_invoked:
        await emitter.emit_reasoning(
            result.metadata.reasoning_content,
            trace_key=f"react:{next_round}:reasoning",
        )
    await emitter.emit_action(
        json.dumps(result.decision.model_dump(mode="json"), ensure_ascii=False),
        trace_key=f"react:{next_round}:action",
    )

    pending: list[ToolExecutionRequest] = []
    if result.decision.action == "tool":
        spec = ctx.tool_registry.spec(result.decision.tool_name or "")
        if spec is None or result.decision.tool_name not in ctx.tool_registry.available_names():
            raise RuntimeError(
                f"ReAct Agent selected unavailable tool: {result.decision.tool_name}"
            )
        pending = [
            ToolExecutionRequest(
                tool_name=result.decision.tool_name,
                parameters=result.decision.parameters,
                objective=result.decision.objective or result.decision.reason or spec.capability,
                hypothesis_ids=[],
                timeout_seconds=spec.timeout,
                required=False,
            )
        ]

    outcome = "tool" if pending else "finish"
    progress = await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.INVESTIGATING,
        (
            f"ReAct 第 {next_round} 轮选择工具 {pending[0].tool_name}。"
            if pending
            else f"ReAct 第 {next_round} 轮输出 finish，结束证据调查。"
        ),
        {
            "event": "react_decision",
            "outcome": outcome,
            "react_round": next_round,
            "react_max_rounds": state.react_max_rounds,
            **({"tool_name": pending[0].tool_name} if pending else {}),
        },
    )
    return {
        "current_stage": InvestigationStage.INVESTIGATING,
        "react_round": next_round,
        "react_decision": result.decision,
        "react_finished": not pending,
        "pending_tool_requests": pending,
        "progress": [progress],
    }


async def execute_react_tool_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Execute exactly one outer tool and emit its projected observation."""

    if state.error:
        return {"pending_tool_requests": []}
    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    pending_requests = state.pending_tool_requests
    if not run or not alert or len(pending_requests) != 1:
        return {"error": "ReAct tool node requires one run, alert, and pending request"}

    request = pending_requests[0]
    context = InvestigationContext(
        run_id=run.id,
        alert=alert,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )
    dispatcher = DurableOuterToolDispatcher(
        ctx.repository,
        ctx.tool_executor,
        result_analyzer=ctx.tool_result_analyzer,
    )

    result = await dispatcher.execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=ctx.tool_registry.spec(request.tool_name),
        prior_evidence=state.evidence,
    )
    await ctx.repository.save_evidence(alert_id, result, **_lease_fence(run))
    new_evidence = [] if any(item.id == result.id for item in state.evidence) else [result]
    emitter = AgentTraceEmitter(
        RepositoryEventSink(ctx.repository, **_lease_fence(run)),
        run_id=run.id,
        actor="main_agent",
        provider=str(getattr(ctx.advisor, "provider", type(ctx.advisor).__name__)),
        scope=AgentTraceScope.MAIN_AGENT,
    )
    observation = preprocess_alert_data(result.model_dump(mode="json"))
    await emitter.emit_observation(
        json.dumps(observation, ensure_ascii=False),
        actor=request.tool_name,
        provider=result.source_system,
        trace_key=f"react:{state.react_round}:observation:{result.id}",
    )

    return {
        "evidence": new_evidence,
        "pending_tool_requests": [],
    }


async def _load_react_decision(
    sink: RepositoryEventSink,
    run: InvestigationRun,
    react_round: int,
) -> InvestigationDecisionResult | None:
    for event in reversed(await sink.read(run.id)):
        if (
            event.kind == AgentEventKind.MODEL_DECISION
            and event.payload.get("actor") == "main_agent"
            and event.payload.get("react_round") == react_round
        ):
            return InvestigationDecisionResult(
                decision=InvestigationDecision.model_validate(event.payload.get("decision")),
                metadata=AdvisorMetadata.model_validate(event.payload.get("metadata")),
            )
    return None


async def _next_reasoning_request_attempt(
    sink: RepositoryEventSink,
    run: InvestigationRun,
    *,
    prefix: str,
) -> int:
    attempts: list[int] = []
    for event in await sink.read(run.id):
        if event.kind != AgentEventKind.TRACE_REASONING:
            continue
        stream_id = event.payload.get("stream_id")
        if not isinstance(stream_id, str) or not stream_id.startswith(prefix):
            continue
        request_attempt = stream_id.removeprefix(prefix).partition(":")[0]
        if request_attempt.isdigit():
            attempts.append(int(request_attempt))
    return max(attempts, default=-1) + 1


def _accepts_keyword_argument(callable_obj: Any, argument: str) -> bool:
    """Check callback support without masking a TypeError raised inside an advisor."""

    try:
        parameters = inspect.signature(callable_obj).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == argument
        or parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


async def advise_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Generate recommendation using AI advisor."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    knowledge = state.knowledge
    evidence = state.evidence
    knowledge_match_summary = state.knowledge_match_summary
    ai_fallback_enabled = state.ai_fallback_enabled

    if not run or not alert:
        return {"error": "Missing run or alert in advise node"}

    sink = RepositoryEventSink(ctx.repository, **_lease_fence(run))
    emitter = AgentTraceEmitter(
        sink,
        run_id=run.id,
        actor="main_agent",
        provider=str(getattr(ctx.advisor, "provider", type(ctx.advisor).__name__)),
        scope=AgentTraceScope.MAIN_AGENT,
    )
    reasoning_request_attempt = await _next_reasoning_request_attempt(
        sink,
        run,
        prefix="main-agent:final:request:",
    )

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.ADVISING,
        "知识匹配与实时证据采集已完成，正在统一分析根因和处理建议。",
        {
            "knowledge_matches": len(knowledge),
            "evidence_count": len(evidence),
        },
    )

    advisor_degraded = False
    primary_advisor_error: Exception | None = None
    recommendation: Recommendation | None = None
    advisor_metadata: AdvisorMetadata | None = None
    final_reasoning_callback_invoked = False

    async def emit_final_reasoning(
        content: str,
        stream_id: str,
        delta_index: int,
    ) -> None:
        nonlocal final_reasoning_callback_invoked
        durable_stream_id = (
            f"main-agent:final:request:{reasoning_request_attempt}:{stream_id}"
        )
        emitted = await emitter.emit_reasoning_delta(
            content,
            stream_id=durable_stream_id,
            delta_index=delta_index,
            trace_key=f"{durable_stream_id}:delta:{delta_index}",
        )
        final_reasoning_callback_invoked = (
            final_reasoning_callback_invoked or emitted is not None
        )

    try:
        advise_kwargs = {
            "evidence": evidence,
            "knowledge_match_summary": knowledge_match_summary,
        }
        # Same rationale as the ReAct node: durable delta persistence
        # dominates the final-analysis wall time, so it stays opt-in and
        # the complete reasoning is recorded once after advise returns.
        if _accepts_keyword_argument(
            ctx.advisor.advise, "reasoning_callback"
        ) and state.stream_main_agent_reasoning:
            recommendation, advisor_metadata = await ctx.advisor.advise(
                alert,
                knowledge,
                **advise_kwargs,
                reasoning_callback=emit_final_reasoning,
            )
        else:
            recommendation, advisor_metadata = await ctx.advisor.advise(
                alert,
                knowledge,
                **advise_kwargs,
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
            knowledge,
            evidence=evidence,
            knowledge_match_summary=knowledge_match_summary,
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
            "knowledge_matches": knowledge,
        }
    )
    recommendation = enforce_post_evidence_root_cause_policy(
        recommendation,
        evidence,
        alert,
    )

    if not final_reasoning_callback_invoked:
        await emitter.emit_reasoning(
            advisor_metadata.reasoning_content,
            trace_key=f"final:request:{reasoning_request_attempt}:reasoning",
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
                    "knowledge_matches": len(knowledge),
                    "evidence_count": len(evidence),
                },
            )
        ],
    }


async def validate_node(state: AgentState, ctx: NodeContext) -> dict[str, Any]:
    """Check the main Agent's output with deterministic contract rules only."""
    if state.error:
        return {}

    alert_id = state.alert_id
    run = state.run
    alert = state.alert
    evidence = state.evidence
    recommendation = state.recommendation
    advisor_degraded = state.advisor_degraded
    primary_advisor_error = state.primary_advisor_error

    if not run or not alert or not recommendation:
        return {"error": "Missing run, alert, or recommendation in validate node"}

    await _update_progress(
        ctx.repository,
        alert_id,
        run,
        InvestigationStage.VALIDATING,
        "正在进行确定性分析契约校验。",
    )

    rule_validation = await ctx.rule_validator.validate(
        run,
        alert,
        recommendation,
        evidence,
    )
    if advisor_degraded:
        rule_validation = rule_validation.model_copy(
            update={
                "metadata": {
                    **rule_validation.metadata,
                    "fallback": True,
                    "primary_error_type": primary_advisor_error or "Unknown",
                },
            }
        )
    await ctx.repository.save_validation(
        alert_id,
        rule_validation,
        **_lease_fence(run),
    )

    return {
        "current_stage": InvestigationStage.VALIDATING,
        "rule_validation": rule_validation,
        "validation_passed": rule_validation.passed,
        "evidence_sufficient": rule_validation.evidence_sufficient,
        "progress": [
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.VALIDATING,
                message="正在进行确定性分析契约校验。",
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
                },
            )
        ],
    }


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
