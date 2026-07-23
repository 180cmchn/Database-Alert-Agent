"""LangGraph investigation graph definition."""

from __future__ import annotations

import logging
from functools import partial
from typing import Literal

from langgraph.graph import END, StateGraph

from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
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


def build_investigation_graph(ctx: NodeContext) -> StateGraph:
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
    graph.add_edge(NODE_STRATEGY, NODE_EXECUTE_TOOLS)

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

    return graph.compile()


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
        )
        self.graph = build_investigation_graph(self.ctx)

    async def run(self, initial_state: AgentState) -> AgentState:
        """Run the investigation graph with the given initial state.

        Args:
            initial_state: The initial state for the investigation

        Returns:
            The final state after investigation completes
        """
        result = await self.graph.ainvoke(initial_state)
        return AgentState.model_validate(result)
