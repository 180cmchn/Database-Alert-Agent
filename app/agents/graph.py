"""LangGraph investigation graph definition."""

from __future__ import annotations

import logging
from functools import partial
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, StateGraph

from app.adapters.external_knowledge import ExternalKnowledgeClient
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agent_runtime.langgraph_checkpoint import RepositoryLangGraphCheckpointer
from app.agents.nodes import (
    NodeContext,
    advise_node,
    enrich_alert_node,
    execute_react_tool_node,
    fingerprint_node,
    react_decide_node,
    report_node,
    runbook_match_node,
    validate_node,
)
from app.agents.state import AgentState
from app.domain.ports import (
    AIAdvisor,
    AlertDetailEnricher,
    AlertRepository,
    ConclusionValidator,
    RunbookProvider,
    ToolResultAnalyzer,
)

logger = logging.getLogger(__name__)


# Node names for the graph
NODE_ENRICH_ALERT = "enrich_alert"
NODE_FINGERPRINT = "fingerprint"
NODE_RUNBOOK = "runbook"
NODE_REACT_DECIDE = "react_decide"
NODE_EXECUTE_REACT_TOOL = "execute_react_tool"
NODE_ADVISE = "advise"
NODE_VALIDATE = "validate"
NODE_REPORT = "report"


def build_investigation_graph(
    ctx: NodeContext,
    *,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> StateGraph:
    """Build the LangGraph investigation graph.

    The graph implements the following flow:

    START -> enrich_alert -> fingerprint -> runbook -> react_decide
          -> execute_react_tool -> react_decide -> ... -> advise -> validate
          -> report -> END

    Every ReAct round lets the main Agent either call exactly one configured
    outer tool or finish evidence collection. The final root-cause synthesis
    runs only after ``finish`` or the configured ReAct round ceiling.

    Args:
        ctx: NodeContext containing all dependencies for node execution

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create the graph with AgentState
    graph = StateGraph(AgentState)

    # Add nodes - use partial to bind context while preserving async function signature
    # partial keeps the async nature intact, unlike lambda which returns a coroutine object
    graph.add_node(NODE_ENRICH_ALERT, partial(enrich_alert_node, ctx=ctx))
    graph.add_node(NODE_FINGERPRINT, partial(fingerprint_node, ctx=ctx))
    graph.add_node(NODE_RUNBOOK, partial(runbook_match_node, ctx=ctx))
    graph.add_node(NODE_REACT_DECIDE, partial(react_decide_node, ctx=ctx))
    graph.add_node(
        NODE_EXECUTE_REACT_TOOL,
        partial(execute_react_tool_node, ctx=ctx),
    )
    graph.add_node(NODE_ADVISE, partial(advise_node, ctx=ctx))
    graph.add_node(NODE_VALIDATE, partial(validate_node, ctx=ctx))
    graph.add_node(NODE_REPORT, partial(report_node, ctx=ctx))

    # Set entry point
    graph.set_entry_point(NODE_ENRICH_ALERT)

    # Add linear edges
    graph.add_edge(NODE_ENRICH_ALERT, NODE_FINGERPRINT)
    graph.add_edge(NODE_FINGERPRINT, NODE_RUNBOOK)
    graph.add_edge(NODE_RUNBOOK, NODE_REACT_DECIDE)
    graph.add_conditional_edges(
        NODE_REACT_DECIDE,
        _route_after_react_decision,
        {
            "tool": NODE_EXECUTE_REACT_TOOL,
            "finish": NODE_ADVISE,
        },
    )
    graph.add_edge(NODE_EXECUTE_REACT_TOOL, NODE_REACT_DECIDE)
    graph.add_edge(NODE_ADVISE, NODE_VALIDATE)
    graph.add_edge(NODE_VALIDATE, NODE_REPORT)
    graph.add_edge(NODE_REPORT, END)

    return graph.compile(checkpointer=checkpointer)


def _route_after_react_decision(state: AgentState) -> str:
    """Route one ReAct decision without introducing alert-type branches."""

    if state.error or state.react_finished:
        return "finish"
    return "tool" if len(state.pending_tool_requests) == 1 else "finish"


class InvestigationAgent:
    """High-level agent that wraps the LangGraph investigation graph.

    This class provides a simple interface for running investigations
    while managing the state and context internally.
    """

    def __init__(
        self,
        *,
        repository: AlertRepository,
        runbook_provider: RunbookProvider,
        advisor: AIAdvisor,
        fallback_advisor: AIAdvisor | None = None,
        rule_validator: ConclusionValidator,
        tool_registry: InvestigationToolRegistry,
        tool_executor: ToolExecutor,
        tool_result_analyzer: ToolResultAnalyzer | None = None,
        alert_detail_enricher: AlertDetailEnricher | None = None,
        runbook_limit: int = 5,
        external_knowledge_client: ExternalKnowledgeClient | None = None,
        external_knowledge_limit: int = 5,
        external_knowledge_min_relevance: float = 0.60,
        knowledge_sources: list[str] | None = None,
    ) -> None:
        """Initialize the investigation agent.

        Args:
            repository: Alert repository for persistence
            runbook_provider: Runbook search provider
            advisor: Primary AI advisor
            fallback_advisor: Fallback AI advisor for degraded mode
            rule_validator: Deterministic recommendation-contract validator
            tool_registry: Registry of investigation tools
            tool_executor: Tool execution engine
            runbook_limit: Maximum runbooks to retrieve per alert
            external_knowledge_client: Optional external knowledge API client
            external_knowledge_limit: Maximum external knowledge items to retrieve
            external_knowledge_min_relevance: Minimum accepted external relevance
            knowledge_sources: Which knowledge sources to use ("local_pdf",
                "external_knowledge")
        """
        self.ctx = NodeContext(
            repository=repository,
            runbook_provider=runbook_provider,
            advisor=advisor,
            fallback_advisor=fallback_advisor,
            rule_validator=rule_validator,
            tool_registry=tool_registry,
            tool_executor=tool_executor,
            tool_result_analyzer=tool_result_analyzer,
            alert_detail_enricher=alert_detail_enricher,
            runbook_limit=runbook_limit,
            external_knowledge_client=external_knowledge_client,
            external_knowledge_limit=external_knowledge_limit,
            external_knowledge_min_relevance=external_knowledge_min_relevance,
            knowledge_sources=knowledge_sources,
        )
        self.graph = build_investigation_graph(self.ctx)

    async def run(self, initial_state: AgentState) -> AgentState:
        """Run the investigation graph with the given initial state.

        Args:
            initial_state: The initial state for the investigation

        Returns:
            The final state after investigation completes
        """
        run = initial_state.run
        invocation_config: RunnableConfig = {
            "recursion_limit": max(25, initial_state.react_max_rounds * 2 + 12),
        }
        if run is None or not run.lease_owner:
            result = await self.graph.ainvoke(initial_state, invocation_config)
            return AgentState.model_validate(result)

        manifest = await self.ctx.repository.get_run_manifest(str(run.id))
        if manifest is None:
            result = await self.graph.ainvoke(initial_state, invocation_config)
            return AgentState.model_validate(result)
        if manifest.run_id != run.id:
            raise RuntimeError("Run manifest identity does not match the investigation run")

        checkpointer = RepositoryLangGraphCheckpointer(
            self.ctx.repository,
            run_id=run.id,
            manifest_hash=manifest.digest(),
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )
        graph = build_investigation_graph(self.ctx, checkpointer=checkpointer)
        config: RunnableConfig = {
            "recursion_limit": max(25, initial_state.react_max_rounds * 2 + 12),
            "configurable": {
                "thread_id": str(run.id),
            }
        }
        saved = await checkpointer.aget_tuple(config)
        if saved is None:
            result = await graph.ainvoke(initial_state, config)
            return AgentState.model_validate(result)

        resume_config = await graph.aupdate_state(
            saved.config,
            {"run": run},
        )
        result = await graph.ainvoke(None, resume_config)
        return AgentState.model_validate(result)
