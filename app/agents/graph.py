"""LangGraph investigation graph definition."""

from __future__ import annotations

import logging
from functools import partial
from typing import Any, Literal

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, StateGraph

from app.adapters.external_knowledge import ExternalKnowledgeClient
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agent_runtime.langgraph_checkpoint import RepositoryLangGraphCheckpointer
from app.agents.nodes import (
    NodeContext,
    advise_node,
    dynamic_investigation_node,
    execute_tools_node,
    fingerprint_node,
    knowledge_match_node,
    report_node,
    runbook_match_node,
    select_strategy_node,
    validate_node,
)
from app.agents.state import AgentState
from app.domain.ports import (
    AIAdvisor,
    AlertRepository,
    ConclusionValidator,
    InvestigationStrategyProvider,
    RunbookProvider,
)

logger = logging.getLogger(__name__)


# Node names for the graph
NODE_FINGERPRINT = "fingerprint"
NODE_KNOWLEDGE = "knowledge"
NODE_RUNBOOK = "runbook"
NODE_STRATEGY = "strategy"
NODE_EXECUTE_TOOLS = "execute_tools"
NODE_DYNAMIC_INVESTIGATION = "dynamic_investigation"
NODE_ADVISE = "advise"
NODE_VALIDATE = "validate"
NODE_REPORT = "report"


def should_continue_dynamic_investigation(state: AgentState) -> Literal["execute_tools", "advise"]:
    """Determine if dynamic investigation should continue or proceed to advise.

    This is the conditional edge function for the investigation loop.
    """
    if state.should_continue_investigation and state.pending_tool_requests:
        return "execute_tools"
    return "advise"


def should_start_tool_investigation(state: AgentState) -> Literal["execute_tools", "advise"]:
    """Apply Host stop conditions before the first live tool dispatch."""

    if state.stop_decision is not None and state.stop_decision.should_stop:
        return "advise"
    return "execute_tools"


def build_investigation_graph(
    ctx: NodeContext,
    *,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> StateGraph:
    """Build the LangGraph investigation graph.

    The graph implements the following flow:

    START -> fingerprint -> knowledge -> runbook -> strategy
         -> execute_tools -> dynamic_investigation --(loop)--> execute_tools
                                |
                                v
                              advise -> validate -> report -> END

    The dynamic_investigation node can loop back to execute_tools if the AI
    advisor decides more tools are needed (React pattern).

    Args:
        ctx: NodeContext containing all dependencies for node execution

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create the graph with AgentState
    graph = StateGraph(AgentState)

    # Add nodes - use partial to bind context while preserving async function signature
    # partial keeps the async nature intact, unlike lambda which returns a coroutine object
    graph.add_node(NODE_FINGERPRINT, partial(fingerprint_node, ctx=ctx))
    graph.add_node(NODE_KNOWLEDGE, partial(knowledge_match_node, ctx=ctx))
    graph.add_node(NODE_RUNBOOK, partial(runbook_match_node, ctx=ctx))
    graph.add_node(NODE_STRATEGY, partial(select_strategy_node, ctx=ctx))
    graph.add_node(NODE_EXECUTE_TOOLS, partial(execute_tools_node, ctx=ctx))
    graph.add_node(NODE_DYNAMIC_INVESTIGATION, partial(dynamic_investigation_node, ctx=ctx))
    graph.add_node(NODE_ADVISE, partial(advise_node, ctx=ctx))
    graph.add_node(NODE_VALIDATE, partial(validate_node, ctx=ctx))
    graph.add_node(NODE_REPORT, partial(report_node, ctx=ctx))

    # Set entry point
    graph.set_entry_point(NODE_FINGERPRINT)

    # Add linear edges
    graph.add_edge(NODE_FINGERPRINT, NODE_KNOWLEDGE)
    graph.add_edge(NODE_KNOWLEDGE, NODE_RUNBOOK)
    graph.add_edge(NODE_RUNBOOK, NODE_STRATEGY)
    graph.add_conditional_edges(
        NODE_STRATEGY,
        should_start_tool_investigation,
        {
            "execute_tools": NODE_EXECUTE_TOOLS,
            "advise": NODE_ADVISE,
        },
    )

    # The deterministic plan always runs first. Dynamic investigation then decides
    # whether to queue one additional tool call or finish with the gathered evidence.
    graph.add_edge(NODE_EXECUTE_TOOLS, NODE_DYNAMIC_INVESTIGATION)
    graph.add_conditional_edges(
        NODE_DYNAMIC_INVESTIGATION,
        should_continue_dynamic_investigation,
        {
            "execute_tools": NODE_EXECUTE_TOOLS,
            "advise": NODE_ADVISE,
        },
    )

    # Continue linear flow
    graph.add_edge(NODE_ADVISE, NODE_VALIDATE)
    graph.add_edge(NODE_VALIDATE, NODE_REPORT)
    graph.add_edge(NODE_REPORT, END)

    return graph.compile(checkpointer=checkpointer)


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
        """Initialize the investigation agent.

        Args:
            repository: Alert repository for persistence
            runbook_provider: Runbook search provider
            advisor: Primary AI advisor
            fallback_advisor: Fallback AI advisor for degraded mode
            rule_validator: Rule-based validator
            conclusion_validator: AI-based conclusion validator
            tool_registry: Registry of investigation tools
            tool_executor: Tool execution engine
            strategy_provider: Investigation strategy provider
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
            conclusion_validator=conclusion_validator,
            tool_registry=tool_registry,
            tool_executor=tool_executor,
            strategy_provider=strategy_provider,
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
        if run is None or not run.lease_owner:
            result = await self.graph.ainvoke(initial_state)
            return AgentState.model_validate(result)

        manifest = await self.ctx.repository.get_run_manifest(str(run.id))
        if manifest is None:
            result = await self.graph.ainvoke(initial_state)
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
