from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    ArtifactRef,
    BudgetLedger,
    InMemoryEventSink,
    RuntimeStopReason,
    ToolInvocationStatus,
    ToolSpec,
)
from app.mcp_runtime import (
    DiscoveredMCPTool,
    Finish,
    HarnessObservation,
    MCPAgentHarnessRuntime,
    PreparedCall,
    ReplayCallFixture,
    ReplayCallOutcome,
    ReplayErrorFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
    RetryDirective,
    ScenarioTransition,
    ScriptedPlanner,
)


@dataclass
class _ScenarioState:
    successful_queries: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)


class _Scenario:
    provider = "fixture-mcp"

    def initial_state(self) -> _ScenarioState:
        return _ScenarioState()

    def initial_messages(self, state: _ScenarioState) -> list[dict[str, Any]]:
        assert not state.successful_queries
        return [{"role": "system", "content": "Collect read-only evidence."}]

    async def bootstrap(self, session: Any, state: _ScenarioState) -> _ScenarioState:
        del session
        return state

    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]:
        return [
            ToolSpec(
                name=tool.name,
                provider=self.provider,
                capability="fixture.query",
                input_schema=tool.input_schema,
                policy_version="fixture-policy-v1",
                schema_version="fixture-schema-v1",
                timeout=1,
            )
            for tool in tools
        ]

    def prepare_call(
        self,
        action: Any,
        *,
        state: _ScenarioState,
    ) -> PreparedCall:
        assert state is not None
        return PreparedCall(
            tool_name=action.tool_name,
            objective=action.objective,
            hypothesis_ids=action.hypothesis_ids,
            model_arguments=action.arguments,
            effective_arguments=action.arguments,
        )

    def on_result(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
        updated = deepcopy(state)
        query = str(call.effective_arguments.get("query", ""))
        updated.successful_queries.append(query)
        status = (
            ToolInvocationStatus.NO_DATA
            if isinstance(result, dict) and result.get("no_data")
            else ToolInvocationStatus.SUCCEEDED
        )
        return ScenarioTransition(
            state=updated,
            observation={"query": query, "result": result},
            message={"role": "user", "content": f"Observed result for {query}"},
            status=status,
        )

    def result_error_directive(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        error: Exception,
    ) -> RetryDirective | None:
        del state, call, error
        return None

    def on_failure(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        error: Any,
        status: ToolInvocationStatus,
    ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
        updated = deepcopy(state)
        updated.failures.append(status.value)
        query = str(call.effective_arguments.get("query", ""))
        return ScenarioTransition(
            state=updated,
            observation={"query": query, "error_code": error.code},
            message={"role": "user", "content": f"Missing evidence for {query}"},
        )

    def retry_directive(
        self,
        state: _ScenarioState,
        call: PreparedCall | None,
        error: Exception,
    ) -> RetryDirective:
        del state, call
        unknown_outcome = bool(getattr(error, "unknown_outcome", False))
        retryable = bool(getattr(error, "retryable", False))
        return RetryDirective(
            reason=str(error),
            reconnect=retryable,
            continue_run=retryable,
            unknown_outcome=unknown_outcome,
        )

    def completion(
        self,
        state: _ScenarioState,
        observations: Sequence[HarnessObservation[dict[str, Any]]],
    ) -> Finish | None:
        del state, observations
        return None

class _InterruptAfterDecisionSink(InMemoryEventSink):
    def __init__(self) -> None:
        super().__init__()
        self.interrupt_after_decision = True

    async def append(
        self,
        event: AgentEvent,
        *,
        expected_version: int | None = None,
    ) -> AgentEvent:
        committed = await super().append(event, expected_version=expected_version)
        if (
            self.interrupt_after_decision
            and event.kind == AgentEventKind.MODEL_DECISION
            and event.payload.get("decision_key")
        ):
            self.interrupt_after_decision = False
            raise asyncio.CancelledError
        return committed


class _BootstrapScenario(_Scenario):
    async def bootstrap(self, session: Any, state: _ScenarioState) -> _ScenarioState:
        await session.call_tool("fixture.login", {"credential_ref": "redacted-fixture"})
        return state


class _ResultProcessingFailureScenario(_Scenario):
    def on_result(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
        del state, call, result
        raise ValueError("fixture Host result parser failed")


class _ResultErrorDirectiveFailureScenario(_ResultProcessingFailureScenario):
    def result_error_directive(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        error: Exception,
    ) -> RetryDirective | None:
        del state, call, error
        raise RuntimeError("fixture result-error classifier failed")


class _RewritingScenario(_Scenario):
    def prepare_call(
        self,
        action: Any,
        *,
        state: _ScenarioState,
    ) -> PreparedCall:
        prepared = super().prepare_call(action, state=state)
        return prepared.model_copy(
            update={
                "tool_name": "fixture.rewritten",
                "model_arguments": {"query": "rewritten"},
                "effective_arguments": {"query": "rewritten"},
            }
        )


class _NativePreparedScenario(_Scenario):
    def __init__(self, metadata: dict[str, Any] | None = None) -> None:
        self._pending_metadata = deepcopy(metadata or {})

    def prepare_call(
        self,
        action: Any,
        *,
        state: _ScenarioState,
    ) -> PreparedCall:
        prepared = super().prepare_call(action, state=state)
        metadata = self._pending_metadata
        self._pending_metadata = {}
        return prepared.model_copy(update={"metadata": metadata}, deep=True)

    def on_result(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
        transition = super().on_result(state, call, result)
        provider_items = call.metadata.get("provider_output_items")
        if not isinstance(provider_items, list) or not provider_items:
            return transition
        return ScenarioTransition(
            state=transition.state,
            observation=transition.observation,
            message=[
                *(deepcopy(item) for item in provider_items),
                {
                    "type": "function_call_output",
                    "call_id": str(call.metadata.get("call_id") or ""),
                    "output": json.dumps(result, sort_keys=True),
                },
            ],
            status=transition.status,
            artifact_ref=transition.artifact_ref,
        )


class _CatalogAwareScenario(_Scenario):
    def build_tool_specs(self, tools: list[DiscoveredMCPTool]) -> list[ToolSpec]:
        specs = super().build_tool_specs(tools)
        versions = {
            tool.name: str(tool.annotations.get("policy_version") or "fixture-policy-v1")
            for tool in tools
        }
        return [spec.model_copy(update={"policy_version": versions[spec.name]}) for spec in specs]


class _BootstrapCatalogAwareScenario(_CatalogAwareScenario):
    async def bootstrap(self, session: Any, state: _ScenarioState) -> _ScenarioState:
        await session.call_tool("fixture.login", {"credential_ref": "redacted-fixture"})
        return state


class _ArtifactScenario(_Scenario):
    def on_result(
        self,
        state: _ScenarioState,
        call: PreparedCall,
        result: Any,
    ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
        transition = super().on_result(state, call, result)
        return ScenarioTransition(
            state=transition.state,
            observation=transition.observation,
            message=transition.message,
            status=transition.status,
            artifact_ref=ArtifactRef(kind="prometheus-result", uri="memory://result/1"),
        )


class _RecordingInvocationStore:
    def __init__(self) -> None:
        self.statuses: list[ToolInvocationStatus] = []
        self.latest: dict[Any, Any] = {}

    async def save(self, invocation: Any) -> None:
        self.statuses.append(invocation.status)
        self.latest[invocation.invocation_id] = invocation.model_copy(deep=True)

    async def load(self, invocation_id: Any) -> Any | None:
        invocation = self.latest.get(invocation_id)
        return invocation.model_copy(deep=True) if invocation is not None else None


class _InterruptAfterStartedInvocationStore(_RecordingInvocationStore):
    def __init__(self) -> None:
        super().__init__()
        self._interrupted = False

    async def save(self, invocation: Any) -> None:
        await super().save(invocation)
        if invocation.status == ToolInvocationStatus.STARTED and not self._interrupted:
            self._interrupted = True
            raise asyncio.CancelledError


class _RecordingArtifactStore:
    def __init__(self) -> None:
        self.artifacts: list[ArtifactRef] = []

    async def save(self, *, run_id: Any, invocation_id: Any, artifact: ArtifactRef) -> None:
        del run_id, invocation_id
        self.artifacts.append(artifact)


class _RecordingRemoteResponseStore:
    def __init__(self) -> None:
        self.responses: list[dict[str, Any]] = []

    async def save(self, **record: Any) -> None:
        self.responses.append(deepcopy(record))

    async def load(self, **identity: Any) -> Any | None:
        for record in self.responses:
            if all(record.get(key) == value for key, value in identity.items()):
                return deepcopy(record["response"])
        return None


class _InterruptBeforeArtifactStore(_RecordingArtifactStore):
    def __init__(self) -> None:
        super().__init__()
        self._interrupted = False

    async def save(self, *, run_id: Any, invocation_id: Any, artifact: ArtifactRef) -> None:
        if not self._interrupted:
            self._interrupted = True
            raise asyncio.CancelledError
        await super().save(
            run_id=run_id,
            invocation_id=invocation_id,
            artifact=artifact,
        )


class _InterruptingConnector:
    provider = "fixture-mcp"

    async def open_session(self) -> Any:
        raise asyncio.CancelledError


class _InterruptAfterCommittedEventSink(InMemoryEventSink):
    def __init__(self, kind: AgentEventKind, *, remote_debit_only: bool = False) -> None:
        super().__init__()
        self.kind = kind
        self.remote_debit_only = remote_debit_only
        self._interrupted = False

    async def append(self, event: Any, *, expected_version: int | None = None) -> Any:
        committed = await super().append(event, expected_version=expected_version)
        is_remote_debit = bool(event.payload.get("amounts", {}).get("remote_tool_calls"))
        if (
            not self._interrupted
            and event.kind == self.kind
            and (not self.remote_debit_only or is_remote_debit)
        ):
            self._interrupted = True
            raise asyncio.CancelledError
        return committed


class _TrackingSession:
    def __init__(
        self,
        *,
        cancel_discovery: bool = False,
        block_tool: bool = False,
    ) -> None:
        self._cancel_discovery = cancel_discovery
        self._block_tool = block_tool
        self.close_calls = 0
        self.call_calls = 0

    @property
    def session_id(self) -> str:
        return "tracking-session"

    async def list_tools(self) -> list[DiscoveredMCPTool]:
        if self._cancel_discovery:
            raise asyncio.CancelledError
        return [_tool()]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        del name, arguments
        self.call_calls += 1
        if self._block_tool:
            await asyncio.Event().wait()
        return {"rows": [1]}

    async def close(self) -> None:
        self.close_calls += 1


class _SingleSessionConnector:
    provider = "fixture-mcp"

    def __init__(self, session: _TrackingSession) -> None:
        self.session = session
        self.open_calls = 0

    async def open_session(self) -> _TrackingSession:
        self.open_calls += 1
        return self.session


class _RemoteDebitBarrierSink(InMemoryEventSink):
    """Hold the first remote debit until a sibling reaches the same CAS."""

    def __init__(self) -> None:
        super().__init__()
        self.first_remote_debit = asyncio.Event()
        self._both_remote_debits = asyncio.Event()
        self._remote_debit_arrivals = 0

    async def append(self, event: Any, *, expected_version: int | None = None) -> Any:
        if (
            event.kind == AgentEventKind.BUDGET_DEBITED
            and event.payload.get("amounts", {}).get("remote_tool_calls") == 1
        ):
            self._remote_debit_arrivals += 1
            self.first_remote_debit.set()
            if self._remote_debit_arrivals == 2:
                self._both_remote_debits.set()
            await self._both_remote_debits.wait()
        return await super().append(event, expected_version=expected_version)


class _BlockingOpenConnector:
    provider = "fixture-mcp"

    async def open_session(self) -> Any:
        await asyncio.Event().wait()


class _BlockingPlanner:
    async def plan(self, **kwargs: Any) -> Any:
        del kwargs
        await asyncio.Event().wait()


class _CallThenBlockingPlanner:
    def __init__(self, query: str) -> None:
        self.query = query
        self.requests = 0
        self.blocked = asyncio.Event()

    async def plan(self, **kwargs: Any) -> Any:
        del kwargs
        self.requests += 1
        if self.requests == 1:
            return _call(self.query)
        self.blocked.set()
        await asyncio.Event().wait()


class _CancelledBootstrapScenario(_Scenario):
    async def bootstrap(self, session: Any, state: _ScenarioState) -> _ScenarioState:
        del session, state
        raise asyncio.CancelledError


class _LocalResultScenario(_NativePreparedScenario):
    def prepare_call(
        self,
        action: Any,
        *,
        state: _ScenarioState,
    ) -> PreparedCall:
        prepared = super().prepare_call(action, state=state)
        return prepared.model_copy(
            update={"local_result": {"rejected": True, "reason": "unsafe"}},
            deep=True,
        )


def _tool(
    *,
    input_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
) -> DiscoveredMCPTool:
    return DiscoveredMCPTool(
        name="fixture.query",
        description="Query a sanitized replay source",
        input_schema=input_schema
        or {"type": "object", "properties": {"query": {"type": "string"}}},
        annotations=annotations or {},
    )


def _session(
    session_id: str,
    *calls: ReplayCallFixture,
) -> ReplaySessionFixture:
    return ReplaySessionFixture(session_id=session_id, tools=[_tool()], calls=list(calls))


def _call(query: str, **arguments: Any) -> dict[str, Any]:
    return {
        "action": "call_tool",
        "tool_name": "fixture.query",
        "objective": f"Collect evidence for {query}",
        "hypothesis_ids": ["hypothesis-1"],
        "arguments": {"query": query, **arguments},
    }


def _finish() -> dict[str, Any]:
    return {
        "action": "finish",
        "reason": "COMPLETED",
        "summary": "The replay scenario is complete.",
    }


def _budget(**overrides: int | float) -> BudgetLedger:
    limits = {
        "planner_requests": 20,
        "accepted_decisions": 20,
        "remote_tool_calls": 10,
        "host_bootstrap_calls": 5,
        "session_attempts": 5,
        "model_tokens": 1000,
        "wall_time_seconds": 60,
    }
    limits.update(overrides)
    return BudgetLedger(limits)


@pytest.mark.asyncio
async def test_local_prepared_result_never_crosses_transport_or_remote_budget() -> None:
    session = _TrackingSession()
    checkpoints: list[Any] = []
    response_store = _RecordingRemoteResponseStore()

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    result = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(session),
        planner=ScriptedPlanner([_call("locally-rejected"), _finish()]),
        scenario=_LocalResultScenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
        checkpoint_hook=capture_checkpoint,
        remote_response_store=response_store,
    ).run(run_id=uuid4())

    assert session.call_calls == 0
    assert result.budget.consumed.remote_tool_calls == 0
    assert result.state.successful_queries == ["locally-rejected"]
    assert result.observations[0].payload == {
        "query": "locally-rejected",
        "result": {"rejected": True, "reason": "unsafe"},
    }
    assert len(result.remote_responses) == 1
    assert result.remote_responses[0].is_remote is False
    assert result.remote_responses[0].response == {
        "rejected": True,
        "reason": "unsafe",
    }
    assert any(
        snapshot.remote_responses and not snapshot.observations
        for snapshot in checkpoints
    )
    assert response_store.responses == []


@pytest.mark.asyncio
async def test_completed_local_result_checkpoint_resumes_without_session_or_artifact() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    checkpoints: list[Any] = []
    response_store = _RecordingRemoteResponseStore()

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    first = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(_TrackingSession()),
        planner=ScriptedPlanner([_call("completed-local"), _finish()]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=capture_checkpoint,
        remote_response_store=response_store,
    ).run(run_id=run_id)

    snapshot = checkpoints[-1]
    assert snapshot.finish is not None
    resume_connector = ReplayMCPConnector("fixture-mcp", [])
    resumed = await MCPAgentHarnessRuntime(
        connector=resume_connector,
        planner=ScriptedPlanner([]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert resumed.finish == first.finish
    assert resumed.state == first.state
    assert resumed.observations == first.observations
    assert resumed.invocations == first.invocations
    assert resumed.budget == first.budget
    assert resume_connector.opened_session_ids == []
    assert resumed.remote_responses[0].is_remote is False
    assert response_store.responses == []


@pytest.mark.asyncio
async def test_staged_local_result_checkpoint_replays_without_transport_or_artifact() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    staged_checkpoints: list[Any] = []

    async def interrupt_staged_local_result(snapshot: Any) -> None:
        if (
            snapshot.remote_responses
            and snapshot.remote_responses[-1].is_remote is False
            and not snapshot.observations
        ):
            staged_checkpoints.append(snapshot)
            raise asyncio.CancelledError

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("staged-local")]),
            scenario=_LocalResultScenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_staged_local_result,
        ).run(run_id=run_id)

    snapshot = staged_checkpoints[-1]
    assert snapshot.invocations[-1].status == ToolInvocationStatus.STARTED
    second_session = _TrackingSession()
    response_store = _RecordingRemoteResponseStore()
    resumed = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(second_session),
        planner=ScriptedPlanner([_finish()]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_session.call_calls == second_session.call_calls == 0
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.state.successful_queries == ["staged-local"]
    assert len(resumed.observations) == 1
    assert resumed.remote_responses[0].is_remote is False
    assert response_store.responses == []


@pytest.mark.asyncio
async def test_pending_local_result_adopts_durable_started_without_remote_debit() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    pending_checkpoints: list[Any] = []
    invocation_store = _InterruptAfterStartedInvocationStore()

    async def capture_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("pending-local")]),
            scenario=_LocalResultScenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=capture_pending_checkpoint,
            invocation_store=invocation_store,
        ).run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    durable = await invocation_store.load(snapshot.invocations[-1].invocation_id)
    assert durable is not None
    assert durable.status == ToolInvocationStatus.STARTED
    response_store = _RecordingRemoteResponseStore()
    second_session = _TrackingSession()
    resumed = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(second_session),
        planner=ScriptedPlanner([_finish()]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_session.call_calls == second_session.call_calls == 0
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.state.successful_queries == ["pending-local"]
    assert resumed.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert len(resumed.remote_responses) == 1
    assert resumed.remote_responses[0].is_remote is False
    assert response_store.responses == []


@pytest.mark.asyncio
async def test_pending_checkpoint_reapplies_current_local_policy_before_transport() -> None:
    class _StateTrackingLocalResultScenario(_LocalResultScenario):
        def __init__(self) -> None:
            super().__init__()
            self.current_state: _ScenarioState | None = None
            self.result_state_was_restored = False

        def prepare_call(
            self,
            action: Any,
            *,
            state: _ScenarioState,
        ) -> PreparedCall:
            self.current_state = state
            return super().prepare_call(action, state=state)

        def restore_state(self, state: _ScenarioState) -> None:
            self.current_state = state

        def on_result(
            self,
            state: _ScenarioState,
            call: PreparedCall,
            result: Any,
        ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
            self.result_state_was_restored = self.current_state is state
            return super().on_result(state, call, result)

    run_id = uuid4()
    sink = InMemoryEventSink()
    pending_checkpoints: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)
            raise asyncio.CancelledError

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("newly-rejected")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_pending_checkpoint,
        ).run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    assert snapshot.active_call is not None
    assert snapshot.active_call.local_result is None
    second_session = _TrackingSession()
    response_store = _RecordingRemoteResponseStore()
    resumed_scenario = _StateTrackingLocalResultScenario()
    resumed = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(second_session),
        planner=ScriptedPlanner([_finish()]),
        scenario=resumed_scenario,
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_session.call_calls == second_session.call_calls == 0
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.state.successful_queries == ["newly-rejected"]
    assert resumed.observations[0].payload == {
        "query": "newly-rejected",
        "result": {"rejected": True, "reason": "unsafe"},
    }
    assert resumed.remote_responses[0].is_remote is False
    assert response_store.responses == []
    assert resumed_scenario.result_state_was_restored is True


@pytest.mark.asyncio
async def test_refreshed_pending_local_policy_resumes_without_opening_session() -> None:
    class _FailOnOpenConnector:
        provider = "fixture-mcp"

        def __init__(self) -> None:
            self.open_calls = 0

        async def open_session(self) -> Any:
            self.open_calls += 1
            raise AssertionError("local checkpoint recovery must not open an MCP session")

    run_id = uuid4()
    sink = InMemoryEventSink()
    pending_checkpoints: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)
            raise asyncio.CancelledError

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("offline-local-rejection")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_pending_checkpoint,
        ).run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    assert snapshot.active_call is not None
    assert snapshot.active_call.local_result is None
    connector = _FailOnOpenConnector()
    artifact_store = _RecordingArtifactStore()
    response_store = _RecordingRemoteResponseStore()

    resumed = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
        artifact_store=artifact_store,
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert connector.open_calls == 0
    assert resumed.finish is not None
    assert resumed.finish.reason == RuntimeStopReason.COMPLETED
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.state.successful_queries == ["offline-local-rejection"]
    assert resumed.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert resumed.invocations[0].artifact_ref is None
    assert resumed.observations[0].payload == {
        "query": "offline-local-rejection",
        "result": {"rejected": True, "reason": "unsafe"},
    }
    assert len(resumed.remote_responses) == 1
    assert resumed.remote_responses[0].is_remote is False
    assert resumed.remote_responses[0].response == {
        "rejected": True,
        "reason": "unsafe",
    }
    assert artifact_store.artifacts == []
    assert response_store.responses == []


@pytest.mark.asyncio
async def test_expired_checkpoint_settles_pending_local_policy_before_deadline() -> None:
    class _FailOnOpenConnector:
        provider = "fixture-mcp"

        def __init__(self) -> None:
            self.open_calls = 0

        async def open_session(self) -> Any:
            self.open_calls += 1
            raise AssertionError("expired local recovery must not open an MCP session")

    run_id = uuid4()
    sink = InMemoryEventSink()
    pending_checkpoints: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)
            raise asyncio.CancelledError

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("expired-local-rejection")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_pending_checkpoint,
        ).run(run_id=run_id)

    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    snapshot = replace(
        pending_checkpoints[-1],
        deadline=expired_at,
        wall_time_deadline=expired_at,
    )
    connector = _FailOnOpenConnector()
    resumed = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert connector.open_calls == 0
    assert first_session.call_calls == 0
    assert resumed.finish is not None
    assert resumed.finish.reason == RuntimeStopReason.DEADLINE_EXCEEDED
    assert resumed.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert resumed.active_call is None
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.state.successful_queries == ["expired-local-rejection"]
    assert len(resumed.observations) == 1
    assert resumed.remote_responses[0].is_remote is False


@pytest.mark.asyncio
async def test_pending_policy_refresh_preserves_committed_remote_debit_reservation() -> None:
    run_id = uuid4()
    sink = _InterruptAfterCommittedEventSink(
        AgentEventKind.BUDGET_DEBITED,
        remote_debit_only=True,
    )
    invocation_store = _RecordingInvocationStore()
    pending_checkpoints: list[Any] = []

    async def capture_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("reserved-before-policy-upgrade")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=capture_pending_checkpoint,
            invocation_store=invocation_store,
        ).run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    second_connector = _SingleSessionConnector(_TrackingSession())
    resumed = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_LocalResultScenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    remote_debits = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload.get("amounts", {}).get("remote_tool_calls") == 1
    ]
    assert first_session.call_calls == second_connector.session.call_calls == 0
    assert second_connector.open_calls == 0
    assert resumed.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert resumed.remote_responses[0].is_remote is False
    assert resumed.budget.consumed.remote_tool_calls == 1
    assert len(remote_debits) == 1


@pytest.mark.asyncio
async def test_pending_policy_refresh_restores_scenario_state_when_prepare_fails() -> None:
    class _FailingStateTrackingScenario(_Scenario):
        def __init__(self) -> None:
            self.policy_state: _ScenarioState | None = None
            self.current_state: _ScenarioState | None = None

        def prepare_call(
            self,
            action: Any,
            *,
            state: _ScenarioState,
        ) -> PreparedCall:
            del action
            self.policy_state = state
            self.current_state = state
            raise RuntimeError("policy refresh failed")

        def restore_state(self, state: _ScenarioState) -> None:
            self.current_state = state

    run_id = uuid4()
    sink = InMemoryEventSink()
    pending_checkpoints: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(_TrackingSession()),
            planner=ScriptedPlanner([_call("policy-error")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_pending_checkpoint,
        ).run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    resumed_scenario = _FailingStateTrackingScenario()
    with pytest.raises(RuntimeError, match="policy refresh failed"):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(_TrackingSession()),
            planner=ScriptedPlanner([_finish()]),
            scenario=resumed_scenario,
            event_sink=sink,
            budget=_budget(),
        ).resume(
            snapshot,
            restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
        )

    assert resumed_scenario.policy_state is not None
    assert resumed_scenario.current_state is not resumed_scenario.policy_state
    assert resumed_scenario.current_state == snapshot.state


@pytest.mark.asyncio
async def test_pending_checkpoint_never_relaxes_durable_local_policy_to_transport() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    pending_checkpoints: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            pending_checkpoints.append(snapshot)
            raise asyncio.CancelledError

    first_session = _TrackingSession()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("durably-rejected")]),
            scenario=_LocalResultScenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_pending_checkpoint,
        ).run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    assert snapshot.active_call is not None
    assert snapshot.active_call.local_result is not None
    second_session = _TrackingSession()
    resumed = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(second_session),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_session.call_calls == second_session.call_calls == 0
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.observations[0].payload == {
        "query": "durably-rejected",
        "result": {"rejected": True, "reason": "unsafe"},
    }
    assert resumed.remote_responses[0].is_remote is False


@pytest.mark.asyncio
async def test_provider_remote_usage_is_shared_across_sequential_dispatch_scopes() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    sessions = [_TrackingSession() for _ in range(3)]

    results = []
    for index, session in enumerate(sessions):
        result = await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(session),
            planner=ScriptedPlanner([_call(f"scope-{index}"), _finish()]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(remote_tool_calls=10),
            child_budget_limits={"remote_tool_calls": 2},
            dispatch_scope_id=uuid4(),
        ).run(run_id=run_id)
        results.append(result)

    assert [session.call_calls for session in sessions] == [1, 1, 1]
    assert results[-1].finish is not None
    assert results[-1].finish.reason == RuntimeStopReason.COMPLETED
    assert results[-1].budget.consumed.remote_tool_calls == 1
    remote_debits = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload.get("amounts", {}).get("remote_tool_calls") == 1
    ]
    assert len(remote_debits) == 3
    assert len({event.payload.get("dispatch_scope_id") for event in remote_debits}) == 3
    assert [event.payload["provider_remote_tool_calls"]["consumed"] for event in remote_debits] == [
        1,
        2,
        3,
    ]


@pytest.mark.asyncio
async def test_provider_remote_usage_cas_records_both_concurrent_sibling_scopes() -> None:
    run_id = uuid4()
    sink = _RemoteDebitBarrierSink()
    first_session = _TrackingSession()
    second_session = _TrackingSession()

    def runtime(session: _TrackingSession, scope_id: Any) -> MCPAgentHarnessRuntime:
        return MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(session),
            planner=ScriptedPlanner([_call(str(scope_id)), _finish()]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(remote_tool_calls=1),
            dispatch_scope_id=scope_id,
        )

    first_scope = uuid4()
    second_scope = uuid4()
    first_task = asyncio.create_task(runtime(first_session, first_scope).run(run_id=run_id))
    await sink.first_remote_debit.wait()
    second_task = asyncio.create_task(runtime(second_session, second_scope).run(run_id=run_id))
    outcomes = await asyncio.gather(first_task, second_task, return_exceptions=True)

    remote_debits = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload.get("amounts", {}).get("remote_tool_calls") == 1
    ]
    assert len(remote_debits) == 2
    assert first_session.call_calls == second_session.call_calls == 1
    assert {event.payload["dispatch_scope_id"] for event in remote_debits} == {
        str(first_scope),
        str(second_scope),
    }
    assert sorted(
        event.payload["provider_remote_tool_calls"]["consumed"]
        for event in remote_debits
    ) == [1, 2]
    assert all(
        not isinstance(outcome, Exception)
        and outcome.finish is not None
        and outcome.finish.reason == RuntimeStopReason.COMPLETED
        for outcome in outcomes
    )


@pytest.mark.asyncio
async def test_started_checkpoint_adopts_existing_debit_without_double_count_or_replay() -> None:
    run_id = uuid4()
    scope_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []
    first_session = _TrackingSession()

    async def interrupt_started_checkpoint(snapshot: Any) -> None:
        if snapshot.invocations and snapshot.invocations[-1].status == ToolInvocationStatus.STARTED:
            captured.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(first_session),
            planner=ScriptedPlanner([_call("checkpoint-started")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(remote_tool_calls=1),
            checkpoint_hook=interrupt_started_checkpoint,
            dispatch_scope_id=scope_id,
        ).run(run_id=run_id)

    snapshot = captured[0]
    second_session = _TrackingSession()
    result = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(second_session),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(remote_tool_calls=1),
        dispatch_scope_id=scope_id,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_session.call_calls == 0
    assert second_session.call_calls == 0
    assert result.budget.consumed.remote_tool_calls == 1
    assert result.invocations[0].status == ToolInvocationStatus.UNKNOWN_OUTCOME
    remote_debits = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload.get("amounts", {}).get("remote_tool_calls") == 1
    ]
    assert len(remote_debits) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["session", "planner", "tool"])
async def test_wall_time_budget_bounds_every_remote_phase(phase: str) -> None:
    session = _TrackingSession(block_tool=phase == "tool")
    connector: Any = (
        _BlockingOpenConnector() if phase == "session" else _SingleSessionConnector(session)
    )
    planner: Any = _BlockingPlanner() if phase == "planner" else ScriptedPlanner([_call("blocked")])
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_Scenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(wall_time_seconds=0.03),
        planner_timeout_seconds=1,
        session_timeout_seconds=1,
    )

    started = asyncio.get_running_loop().time()
    result = await runtime.run(run_id=uuid4())
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 0.5
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.DEADLINE_EXCEEDED
    assert result.deadline == result.wall_time_deadline
    assert result.budget.consumed.wall_time_seconds == pytest.approx(0.03, abs=0.003)
    assert result.budget.remaining.wall_time_seconds == pytest.approx(0, abs=0.003)
    if phase != "session":
        assert session.close_calls == 1
    if phase == "tool":
        assert result.invocations[-1].status == ToolInvocationStatus.TIMED_OUT
        assert result.invocations[-1].error is not None


@pytest.mark.asyncio
async def test_wall_time_deadline_survives_checkpoint_downtime() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []

    async def interrupt_initial_checkpoint(snapshot: Any) -> None:
        captured.append(snapshot)
        raise asyncio.CancelledError

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("unused-session")]),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(wall_time_seconds=0.03),
        checkpoint_hook=interrupt_initial_checkpoint,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = captured[0]
    assert snapshot.deadline is not None
    assert snapshot.wall_time_deadline == snapshot.deadline
    assert 0 <= snapshot.budget.consumed.wall_time_seconds < 0.03
    await asyncio.sleep(0.04)

    connector = ReplayMCPConnector(
        "fixture-mcp",
        [_session("must-not-open")],
    )
    result = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert connector.opened_session_ids == []
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.DEADLINE_EXCEEDED
    assert result.deadline == snapshot.deadline
    assert result.wall_time_deadline == snapshot.wall_time_deadline
    assert result.budget.consumed.wall_time_seconds == pytest.approx(0.03, abs=0.003)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["bootstrap", "discovery"])
async def test_candidate_session_is_closed_when_setup_is_cancelled(phase: str) -> None:
    session = _TrackingSession(cancel_discovery=phase == "discovery")
    runtime = MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(session),
        planner=ScriptedPlanner([]),
        scenario=(_CancelledBootstrapScenario() if phase == "bootstrap" else _Scenario()),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
    )

    with pytest.raises(asyncio.CancelledError):
        await runtime.run(run_id=uuid4())

    assert session.close_calls == 1


@pytest.mark.asyncio
async def test_no_tool_call_gets_exactly_one_repair_request() -> None:
    planner = ScriptedPlanner([None, _finish()])
    connector = ReplayMCPConnector("fixture-mcp", [_session("session-1")])
    sink = InMemoryEventSink()
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert len(planner.requests) == 2
    assert "Return exactly one valid Agent action" in planner.requests[1].messages[-1]["content"]
    assert result.budget.consumed.planner_requests == 2
    assert result.budget.consumed.accepted_decisions == 1
    assert result.budget.consumed.remote_tool_calls == 0
    kinds = [event.kind for event in await sink.read(result.run_id)]
    assert kinds.count(AgentEventKind.PLANNER_REPAIR_REQUESTED) == 1


@pytest.mark.asyncio
async def test_runtime_forwards_unknown_tool_and_arguments_without_host_rewrite() -> None:
    raw_arguments = {"query": "unrestricted", "custom_parameter": True}
    planner = ScriptedPlanner(
        [
            {
                "action": "call_tool",
                "tool_name": "fixture.dynamic",
                "objective": "Exercise a deployment-specific MCP capability",
                "hypothesis_ids": [],
                "arguments": raw_arguments,
            },
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.dynamic",
                    expected_arguments=raw_arguments,
                    result={"rows": [1]},
                ),
            )
        ],
    )
    sink = InMemoryEventSink()
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_RewritingScenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert result.budget.consumed.accepted_decisions == 2
    assert result.budget.consumed.remote_tool_calls == 1
    assert len(result.invocations) == 1
    assert result.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert result.invocations[0].tool_name == "fixture.dynamic"
    assert result.invocations[0].model_arguments == raw_arguments
    assert result.invocations[0].effective_arguments == raw_arguments


@pytest.mark.asyncio
async def test_reconnect_preserves_partial_results_state_messages_and_budget() -> None:
    disconnect = ReplayErrorFixture(
        code="connection_lost",
        message="Connection closed while awaiting response",
        retryable=True,
        unknown_outcome=True,
    )
    first_session = _session(
        "session-1",
        ReplayCallFixture(
            tool_name="fixture.query",
            expected_arguments={"query": "first"},
            result={"rows": [1]},
        ),
        ReplayCallFixture(
            tool_name="fixture.query",
            expected_arguments={"query": "disconnect"},
            outcome=ReplayCallOutcome.DISCONNECT,
            error=disconnect,
        ),
    )
    second_session = _session(
        "session-2",
        ReplayCallFixture(
            tool_name="fixture.query",
            expected_arguments={"query": "after-reconnect"},
            result={"rows": [2]},
        ),
    )
    planner = ScriptedPlanner(
        [_call("first"), _call("disconnect"), _call("after-reconnect"), _finish()]
    )
    connector = ReplayMCPConnector("fixture-mcp", [first_session, second_session])
    sink = InMemoryEventSink()
    checkpoints: list[Any] = []

    async def checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=checkpoint,
    )

    result = await runtime.run(run_id=uuid4())

    assert connector.opened_session_ids == ["session-1", "session-2"]
    assert [item.status for item in result.observations] == [
        ToolInvocationStatus.SUCCEEDED,
        ToolInvocationStatus.UNKNOWN_OUTCOME,
        ToolInvocationStatus.SUCCEEDED,
    ]
    assert result.state.successful_queries == ["first", "after-reconnect"]
    assert result.state.failures == ["UNKNOWN_OUTCOME"]
    assert result.budget.consumed.remote_tool_calls == 3
    assert result.budget.consumed.session_attempts == 2
    assert result.budget.consumed.host_bootstrap_calls == 0
    assert any(
        len(snapshot.observations) == 2
        and snapshot.observations[0].status == ToolInvocationStatus.SUCCEEDED
        for snapshot in checkpoints
    )
    unknown = result.invocations[1]
    assert unknown.status == ToolInvocationStatus.UNKNOWN_OUTCOME
    assert unknown.error is not None
    assert unknown.error.details["unknown_outcome"] is True


@pytest.mark.asyncio
async def test_unknown_outcome_is_not_replayed_without_new_agent_action() -> None:
    disconnect = ReplayErrorFixture(
        code="connection_lost",
        message="Connection closed while awaiting response",
        retryable=True,
        unknown_outcome=True,
    )
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "same-read-only-query"},
                    outcome=ReplayCallOutcome.DISCONNECT,
                    error=disconnect,
                ),
            ),
            _session(
                "session-2",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "same-read-only-query"},
                    result={"rows": [1]},
                ),
            ),
        ],
    )
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_call("same-read-only-query"), _finish()]),
        scenario=_Scenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert connector.opened_session_ids == ["session-1", "session-2"]
    assert [item.status for item in result.invocations] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME
    ]
    assert result.state.successful_queries == []
    assert result.budget.consumed.remote_tool_calls == 1


@pytest.mark.asyncio
async def test_host_result_processing_failure_is_not_replayed_or_reconnected() -> None:
    sink = InMemoryEventSink()
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "host-parser"},
                    result={"rows": [1]},
                ),
            ),
            _session("must-not-reconnect"),
        ],
    )
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_call("host-parser")]),
        scenario=_ResultProcessingFailureScenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert connector.opened_session_ids == ["session-1"]
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.FAILED
    assert result.finish.requires_human is True
    assert result.budget.consumed.remote_tool_calls == 1
    assert len(result.invocations) == 1
    assert result.invocations[0].status == ToolInvocationStatus.FAILED
    assert result.invocations[0].error is not None
    assert result.invocations[0].error.code == "host_result_processing_error"
    assert result.invocations[0].error.retryable is False
    assert result.observations[0].error == result.invocations[0].error
    failure_events = [
        event
        for event in await sink.read(result.run_id)
        if event.kind == AgentEventKind.TOOL_INVOCATION_FAILED
    ]
    assert failure_events[0].payload["evidence_disposition"] == "MISSING"
    assert failure_events[0].payload["is_contradiction"] is False


@pytest.mark.asyncio
async def test_result_error_classifier_failure_is_not_replayed_or_reconnected() -> None:
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "classifier-failure"},
                    result={"rows": [1]},
                ),
            ),
            _session("must-not-reconnect"),
        ],
    )
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_call("classifier-failure")]),
        scenario=_ResultErrorDirectiveFailureScenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert connector.opened_session_ids == ["session-1"]
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.FAILED
    assert result.budget.consumed.remote_tool_calls == 1
    assert len(result.invocations) == 1
    invocation = result.invocations[0]
    assert invocation.status == ToolInvocationStatus.FAILED
    assert invocation.error is not None
    assert invocation.error.code == "host_result_processing_error"
    assert invocation.error.retryable is False
    assert invocation.error.details["unknown_outcome"] is False
    assert invocation.error.details["cause_type"] == "RuntimeError"


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["input_schema", "policy_version"])
async def test_second_explicit_action_uses_refreshed_tool_catalog(
    drift: str,
) -> None:
    baseline_tool = _tool(annotations={"policy_version": "fixture-policy-v1"})
    if drift == "input_schema":
        changed_tool = _tool(
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "step": {"type": "integer"},
                },
            },
            annotations={"policy_version": "fixture-policy-v1"},
        )
    else:
        changed_tool = _tool(annotations={"policy_version": "fixture-policy-v2"})
    disconnect = ReplayErrorFixture(
        code="connection_lost",
        message="Connection closed while awaiting response",
        retryable=True,
        unknown_outcome=True,
    )
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            ReplaySessionFixture(
                session_id="session-1",
                tools=[baseline_tool],
                calls=[
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "catalog-drift"},
                        outcome=ReplayCallOutcome.DISCONNECT,
                        error=disconnect,
                    )
                ],
            ),
            ReplaySessionFixture(
                session_id="session-2",
                tools=[changed_tool],
                calls=[
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "catalog-drift"},
                        result={"rows": [1]},
                    )
                ],
            ),
        ],
    )
    sink = InMemoryEventSink()
    result = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner(
            [_call("catalog-drift"), _call("catalog-drift"), _finish()]
        ),
        scenario=_CatalogAwareScenario(),
        event_sink=sink,
        budget=_budget(),
    ).run(run_id=uuid4())

    assert connector.opened_session_ids == ["session-1", "session-2"]
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert result.budget.consumed.remote_tool_calls == 2
    assert [item.status for item in result.invocations] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME,
        ToolInvocationStatus.SUCCEEDED,
    ]
    assert all(
        item.model_arguments == item.effective_arguments == {"query": "catalog-drift"}
        for item in result.invocations
    )
    refreshed = next(item for item in result.tool_specs if item.name == "fixture.query")
    if drift == "input_schema":
        assert "step" in refreshed.input_schema["properties"]
    else:
        assert refreshed.policy_version == "fixture-policy-v2"


@pytest.mark.asyncio
async def test_reconnect_bootstraps_changed_catalog_before_second_explicit_action() -> None:
    baseline_tool = _tool(annotations={"policy_version": "fixture-policy-v1"})
    changed_tool = _tool(annotations={"policy_version": "fixture-policy-v2"})
    disconnect = ReplayErrorFixture(
        code="connection_lost",
        message="Connection closed while awaiting response",
        retryable=True,
        unknown_outcome=True,
    )
    login = ReplayCallFixture(
        tool_name="fixture.login",
        expected_arguments={"credential_ref": "redacted-fixture"},
        result={"authenticated": True},
    )
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            ReplaySessionFixture(
                session_id="session-1",
                tools=[baseline_tool],
                calls=[
                    login,
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "catalog-before-bootstrap"},
                        outcome=ReplayCallOutcome.DISCONNECT,
                        error=disconnect,
                    ),
                ],
            ),
            ReplaySessionFixture(
                session_id="session-2",
                tools=[changed_tool],
                calls=[
                    login,
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "catalog-before-bootstrap"},
                        result={"rows": [1]},
                    ),
                ],
            ),
        ],
    )
    result = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner(
            [
                _call("catalog-before-bootstrap"),
                _call("catalog-before-bootstrap"),
                _finish(),
            ]
        ),
        scenario=_BootstrapCatalogAwareScenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
    ).run(run_id=uuid4())

    assert connector.opened_session_ids == ["session-1", "session-2"]
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert result.budget.consumed.host_bootstrap_calls == 2
    assert result.budget.consumed.remote_tool_calls == 2
    assert [item.status for item in result.invocations] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME,
        ToolInvocationStatus.SUCCEEDED,
    ]


@pytest.mark.asyncio
async def test_identical_explicit_calls_are_both_forwarded_to_remote() -> None:
    replay_call = ReplayCallFixture(
        tool_name="fixture.query",
        expected_arguments={"query": "same"},
        result={"rows": [1]},
    )
    planner = ScriptedPlanner([_call("same"), _call("same"), _finish()])
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [_session("session-1", replay_call, replay_call.model_copy(deep=True))],
    )
    sink = InMemoryEventSink()
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert len(result.invocations) == 2
    assert result.budget.consumed.remote_tool_calls == 2
    assert result.budget.consumed.accepted_decisions == 3
    assert result.state.successful_queries == ["same", "same"]
    assert [item.status for item in result.invocations] == [
        ToolInvocationStatus.SUCCEEDED,
        ToolInvocationStatus.SUCCEEDED,
    ]


@pytest.mark.asyncio
async def test_remote_usage_limit_is_audit_only_and_keeps_all_observations() -> None:
    planner = ScriptedPlanner([_call("first"), _call("second"), _finish()])
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "first"},
                    result={"rows": [1]},
                ),
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "second"},
                    result={"rows": [2]},
                ),
            )
        ],
    )
    sink = InMemoryEventSink()
    parent_budget = _budget(remote_tool_calls=1)
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_Scenario(),
        event_sink=sink,
        budget=parent_budget,
        child_budget_limits={"remote_tool_calls": 1},
    )

    result = await runtime.run(run_id=uuid4())

    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert [item.payload["query"] for item in result.observations] == ["first", "second"]
    assert result.state.successful_queries == ["first", "second"]
    assert result.budget.consumed.remote_tool_calls == 2
    assert parent_budget.snapshot().consumed.remote_tool_calls == 2
    assert result.budget.consumed.planner_requests == 3
    assert result.budget.consumed.accepted_decisions == 3


@pytest.mark.asyncio
async def test_bootstrap_is_counted_only_when_hook_calls_remote_tool() -> None:
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.login",
                    expected_arguments={"credential_ref": "redacted-fixture"},
                    result={"authenticated": True},
                ),
            )
        ],
    )
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_BootstrapScenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert result.budget.consumed.host_bootstrap_calls == 1
    assert result.budget.consumed.remote_tool_calls == 0
    assert result.budget.consumed.session_attempts == 1
    assert result.invocations == ()


@pytest.mark.asyncio
async def test_model_finish_ends_without_remote_call() -> None:
    connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "required"},
                    result={"rows": [1]},
                ),
            )
        ],
    )
    planner = ScriptedPlanner([_finish(), _call("required"), _finish()])
    sink = InMemoryEventSink()
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=planner,
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert result.state.successful_queries == []
    assert result.budget.consumed.accepted_decisions == 1
    assert result.budget.consumed.remote_tool_calls == 0


@pytest.mark.asyncio
async def test_schema_mismatch_is_forwarded_to_remote_unchanged() -> None:
    invalid_call = _call("placeholder")
    invalid_call["arguments"] = {"query": 42}
    sink = InMemoryEventSink()
    runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-1",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": 42},
                        result={"rows": [1]},
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([invalid_call, _finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert result.budget.consumed.accepted_decisions == 2
    assert result.budget.consumed.remote_tool_calls == 1
    assert result.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert result.invocations[0].model_arguments == {"query": 42}
    assert result.invocations[0].effective_arguments == {"query": 42}


@pytest.mark.asyncio
async def test_pending_checkpoint_resumes_same_invocation_before_remote_debit() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    invocation_store = _RecordingInvocationStore()
    captured: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if snapshot.invocations and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING:
            captured.append(snapshot)
            raise asyncio.CancelledError

    first_connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "pending-before-debit"},
                    result={"rows": [1]},
                ),
            )
        ],
    )
    first_runtime = MCPAgentHarnessRuntime(
        connector=first_connector,
        planner=ScriptedPlanner([_call("pending-before-debit")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(remote_tool_calls=1),
        checkpoint_hook=interrupt_pending_checkpoint,
        invocation_store=invocation_store,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = captured[0]
    pending_id = snapshot.invocations[-1].invocation_id
    assert snapshot.budget.consumed.remote_tool_calls == 0
    assert snapshot.active_call is not None
    assert invocation_store.statuses == []

    second_connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-2",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "pending-before-debit"},
                    result={"rows": [1]},
                ),
            )
        ],
    )
    result = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_connector.opened_session_ids == ["session-1"]
    assert second_connector.opened_session_ids == ["session-2"]
    assert len(result.invocations) == 1
    assert result.invocations[0].invocation_id == pending_id
    assert result.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert result.budget.consumed.remote_tool_calls == 1


@pytest.mark.asyncio
async def test_resume_uses_pending_call_when_tool_catalog_changes() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []

    async def interrupt_pending_checkpoint(snapshot: Any) -> None:
        if snapshot.invocations and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING:
            captured.append(snapshot)
            raise asyncio.CancelledError

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                ReplaySessionFixture(
                    session_id="session-1",
                    tools=[_tool(annotations={"policy_version": "fixture-policy-v1"})],
                )
            ],
        ),
        planner=ScriptedPlanner([_call("resume-catalog-drift")]),
        scenario=_CatalogAwareScenario(),
        event_sink=sink,
        budget=_budget(remote_tool_calls=1),
        checkpoint_hook=interrupt_pending_checkpoint,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = captured[0]
    result = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                ReplaySessionFixture(
                    session_id="session-2",
                    tools=[_tool(annotations={"policy_version": "fixture-policy-v2"})],
                    calls=[
                        ReplayCallFixture(
                            tool_name="fixture.query",
                            expected_arguments={"query": "resume-catalog-drift"},
                            result={"rows": [1]},
                        )
                    ],
                )
            ],
        ),
        planner=ScriptedPlanner([_finish()]),
        scenario=_CatalogAwareScenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert result.budget.consumed.remote_tool_calls == 1
    assert [item.status for item in result.invocations] == [ToolInvocationStatus.SUCCEEDED]
    assert result.invocations[0].model_arguments == {"query": "resume-catalog-drift"}
    assert result.invocations[0].effective_arguments == {"query": "resume-catalog-drift"}


@pytest.mark.asyncio
async def test_remote_debit_tail_resumes_pending_invocation_without_double_debit() -> None:
    run_id = uuid4()
    sink = _InterruptAfterCommittedEventSink(
        AgentEventKind.BUDGET_DEBITED,
        remote_debit_only=True,
    )
    invocation_store = _RecordingInvocationStore()
    pending_checkpoints: list[Any] = []

    async def capture_pending_checkpoint(snapshot: Any) -> None:
        if snapshot.invocations and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING:
            pending_checkpoints.append(snapshot)

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("session-1")]),
        planner=ScriptedPlanner([_call("debit-tail")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(remote_tool_calls=1),
        checkpoint_hook=capture_pending_checkpoint,
        invocation_store=invocation_store,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    pending_id = snapshot.invocations[-1].invocation_id
    assert snapshot.budget.consumed.remote_tool_calls == 0
    remote_debits = [
        event
        for event in await sink.read(run_id, after_sequence=snapshot.event_version)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload["amounts"].get("remote_tool_calls") == 1
    ]
    assert [event.invocation_id for event in remote_debits] == [pending_id]
    assert invocation_store.statuses == [ToolInvocationStatus.PENDING]

    result = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-2",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "debit-tail"},
                        result={"rows": [1]},
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert len(result.invocations) == 1
    assert result.invocations[0].invocation_id == pending_id
    assert result.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    assert result.budget.consumed.remote_tool_calls == 1
    all_remote_debits = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload["amounts"].get("remote_tool_calls") == 1
    ]
    assert len(all_remote_debits) == 1


@pytest.mark.asyncio
async def test_persisted_started_row_recovers_as_unknown_without_remote_replay() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    invocation_store = _InterruptAfterStartedInvocationStore()
    pending_checkpoints: list[Any] = []

    async def capture_pending_checkpoint(snapshot: Any) -> None:
        if snapshot.invocations and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING:
            pending_checkpoints.append(snapshot)

    first_connector = ReplayMCPConnector(
        "fixture-mcp",
        [_session("session-1")],
    )
    first_runtime = MCPAgentHarnessRuntime(
        connector=first_connector,
        planner=ScriptedPlanner([_call("started-row")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(remote_tool_calls=1),
        checkpoint_hook=capture_pending_checkpoint,
        invocation_store=invocation_store,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    pending_id = snapshot.invocations[-1].invocation_id
    assert invocation_store.latest[pending_id].status == ToolInvocationStatus.STARTED

    second_connector = ReplayMCPConnector(
        "fixture-mcp",
        [_session("session-2")],
    )
    result = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert first_connector.opened_session_ids == ["session-1"]
    assert second_connector.opened_session_ids == ["session-2"]
    assert len(result.invocations) == 1
    assert result.invocations[0].invocation_id == pending_id
    assert result.invocations[0].status == ToolInvocationStatus.UNKNOWN_OUTCOME
    assert result.observations[0].status == ToolInvocationStatus.UNKNOWN_OUTCOME
    assert result.budget.consumed.remote_tool_calls == 1


@pytest.mark.asyncio
async def test_started_event_tail_recovers_as_unknown_without_remote_replay() -> None:
    run_id = uuid4()
    sink = _InterruptAfterCommittedEventSink(AgentEventKind.TOOL_INVOCATION_STARTED)
    pending_checkpoints: list[Any] = []

    async def capture_pending_checkpoint(snapshot: Any) -> None:
        if snapshot.invocations and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING:
            pending_checkpoints.append(snapshot)

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("session-1")]),
        planner=ScriptedPlanner([_call("started-event")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(remote_tool_calls=1),
        checkpoint_hook=capture_pending_checkpoint,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = pending_checkpoints[-1]
    pending_id = snapshot.invocations[-1].invocation_id
    result = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("session-2")]),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert len(result.invocations) == 1
    assert result.invocations[0].invocation_id == pending_id
    assert result.invocations[0].status == ToolInvocationStatus.UNKNOWN_OUTCOME
    assert result.observations[0].status == ToolInvocationStatus.UNKNOWN_OUTCOME
    assert result.budget.consumed.remote_tool_calls == 1


@pytest.mark.asyncio
async def test_resume_restores_context_budget_and_does_not_repeat_run_started() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []

    async def interrupt_after_first_observation(snapshot: Any) -> None:
        if len(snapshot.observations) == 1:
            captured.append(snapshot)
            raise asyncio.CancelledError

    first_budget = _budget()
    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-1",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "first"},
                        result={"rows": [1]},
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_call("first")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=first_budget,
        checkpoint_hook=interrupt_after_first_observation,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    assert len(captured) == 1
    snapshot = captured[0]
    second_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-2",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "second"},
                        result={"rows": [2]},
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_call("second"), _finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    )
    with pytest.raises(ValueError, match="restored BudgetLedger"):
        await second_runtime.resume(snapshot, restored_budget=_budget())

    result = await second_runtime.resume(snapshot, restored_budget=first_runtime.budget)

    assert result.state.successful_queries == ["first", "second"]
    assert [item.payload["query"] for item in result.observations] == ["first", "second"]
    assert result.budget.consumed.remote_tool_calls == 2
    assert result.budget.consumed.session_attempts == 2
    events = await sink.read(run_id)
    assert sum(event.kind == AgentEventKind.RUN_STARTED for event in events) == 1


@pytest.mark.asyncio
async def test_resume_reuses_durable_decision_and_emits_one_trace_sequence() -> None:
    run_id = uuid4()
    sink = _InterruptAfterDecisionSink()
    checkpoints: list[Any] = []
    first_planner = ScriptedPlanner([_call("durable-decision")])
    provider_output_items = [
        {
            "type": "reasoning",
            "id": "durable-reasoning-item",
            "encrypted_content": "encrypted-durable-reasoning",
            "summary": [],
        },
        {
            "type": "function_call",
            "id": "durable-function-item",
            "call_id": "durable-function-call",
            "name": "fixture.query",
            "arguments": json.dumps({"query": "durable-decision"}),
            "status": "completed",
        },
    ]

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("session-1")]),
        planner=first_planner,
        scenario=_NativePreparedScenario(
            {
                "call_id": "durable-function-call",
                "request_id": "durable-response",
                "provider_output_items": provider_output_items,
            }
        ),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=capture_checkpoint,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    stale_checkpoint = checkpoints[-1]
    second_planner = ScriptedPlanner([_finish()])
    resumed = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-2",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "durable-decision"},
                        result={"rows": [1]},
                    ),
                )
            ],
        ),
        planner=second_planner,
        scenario=_NativePreparedScenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(
        stale_checkpoint,
        restored_budget=BudgetLedger.from_snapshot(stale_checkpoint.budget),
    )

    assert len(first_planner.requests) == 1
    assert len(second_planner.requests) == 1
    assert resumed.state.successful_queries == ["durable-decision"]
    resumed_messages = second_planner.requests[0].messages
    assert sum(item.get("id") == "durable-reasoning-item" for item in resumed_messages) == 1
    assert sum(item.get("id") == "durable-function-item" for item in resumed_messages) == 1
    assert sum(
        item.get("type") == "function_call_output"
        and item.get("call_id") == "durable-function-call"
        for item in resumed_messages
    ) == 1
    events = await sink.read(run_id)
    durable_decisions = [
        event
        for event in events
        if event.kind == AgentEventKind.MODEL_DECISION
        and event.payload.get("decision_key")
    ]
    action_traces = [
        event for event in events if event.kind == AgentEventKind.TRACE_ACTION
    ]
    observation_traces = [
        event for event in events if event.kind == AgentEventKind.TRACE_OBSERVATION
    ]
    assert len(durable_decisions) == 2
    assert [event.payload["decision"]["action"] for event in durable_decisions] == [
        "call_tool",
        "finish",
    ]
    assert durable_decisions[0].payload["prepared_call"]["metadata"] == {
        "call_id": "durable-function-call",
        "request_id": "durable-response",
        "provider_output_items": provider_output_items,
    }
    assert len(action_traces) == 2
    assert len(observation_traces) == 1
    assert all(event.payload["scope"] == "mcp_internal" for event in action_traces)
    assert observation_traces[0].payload["scope"] == "mcp_internal"


@pytest.mark.asyncio
async def test_resume_reapplies_current_local_policy_to_legacy_durable_decision() -> None:
    class _LegacyDecisionSink(_InterruptAfterDecisionSink):
        async def append(
            self,
            event: AgentEvent,
            *,
            expected_version: int | None = None,
        ) -> AgentEvent:
            prepared = event.payload.get("prepared_call")
            if event.kind == AgentEventKind.MODEL_DECISION and isinstance(prepared, dict):
                payload = deepcopy(event.payload)
                payload["prepared_call"].pop("local_result", None)
                event = event.model_copy(update={"payload": payload}, deep=True)
            return await super().append(event, expected_version=expected_version)

    class _InspectingLocalResultScenario(_LocalResultScenario):
        def __init__(self) -> None:
            super().__init__()
            self.seen_metadata: dict[str, Any] = {}

        def on_result(
            self,
            state: _ScenarioState,
            call: PreparedCall,
            result: Any,
        ) -> ScenarioTransition[_ScenarioState, dict[str, Any]]:
            self.seen_metadata = deepcopy(call.metadata)
            return super().on_result(state, call, result)

    run_id = uuid4()
    sink = _LegacyDecisionSink()
    checkpoints: list[Any] = []
    provider_output_items = [
        {
            "type": "reasoning",
            "id": "legacy-reasoning-item",
            "encrypted_content": "encrypted-legacy-reasoning",
            "summary": [],
        },
        {
            "type": "function_call",
            "id": "legacy-function-item",
            "call_id": "legacy-function-call",
            "name": "fixture.query",
            "arguments": json.dumps({"query": "legacy-policy"}),
            "status": "completed",
        },
    ]

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(_TrackingSession()),
            planner=ScriptedPlanner([_call("legacy-policy")]),
            scenario=_NativePreparedScenario(
                {
                    "call_id": "legacy-function-call",
                    "local_rejection": {"reason": "stale-policy-result"},
                    "request_id": "legacy-response",
                    "provider_output_items": provider_output_items,
                }
            ),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=capture_checkpoint,
        ).run(run_id=run_id)

    durable_decision = next(
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.MODEL_DECISION
    )
    assert "local_result" not in durable_decision.payload["prepared_call"]
    snapshot = checkpoints[-1]
    resumed_session = _TrackingSession()
    response_store = _RecordingRemoteResponseStore()
    resumed_planner = ScriptedPlanner([_finish()])
    resumed_scenario = _InspectingLocalResultScenario()
    resumed = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(resumed_session),
        planner=resumed_planner,
        scenario=resumed_scenario,
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert resumed_session.call_calls == 0
    assert resumed.budget.consumed.remote_tool_calls == 0
    assert resumed.observations[0].payload == {
        "query": "legacy-policy",
        "result": {"rejected": True, "reason": "unsafe"},
    }
    assert resumed.remote_responses[0].is_remote is False
    assert response_store.responses == []
    assert "local_rejection" not in resumed_scenario.seen_metadata
    assert resumed_scenario.seen_metadata["request_id"] == "legacy-response"
    resumed_messages = resumed_planner.requests[0].messages
    assert sum(item.get("id") == "legacy-reasoning-item" for item in resumed_messages) == 1
    assert sum(item.get("id") == "legacy-function-item" for item in resumed_messages) == 1
    assert sum(
        item.get("type") == "function_call_output"
        and item.get("call_id") == "legacy-function-call"
        for item in resumed_messages
    ) == 1


@pytest.mark.asyncio
async def test_resume_replays_budget_debit_committed_after_checkpoint() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    checkpoints: list[Any] = []

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    first_runtime = MCPAgentHarnessRuntime(
        connector=_InterruptingConnector(),
        planner=ScriptedPlanner([]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=capture_checkpoint,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    assert len(checkpoints) == 1
    stale_checkpoint = checkpoints[0]
    assert stale_checkpoint.budget.consumed.session_attempts == 0
    tail = await sink.read(run_id, after_sequence=stale_checkpoint.event_version)
    assert [event.kind for event in tail] == [AgentEventKind.BUDGET_DEBITED]
    assert tail[0].payload["provider"] == "fixture-mcp"

    restored_budget = BudgetLedger.from_snapshot(stale_checkpoint.budget)
    connector = ReplayMCPConnector("fixture-mcp", [_session("session-2")])
    result = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(stale_checkpoint, restored_budget=restored_budget)

    assert connector.opened_session_ids == ["session-2"]
    assert result.budget.consumed.session_attempts == 2
    session_debits = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.BUDGET_DEBITED
        and event.payload["amounts"].get("session_attempts") == 1
    ]
    assert [event.payload["consumed"]["session_attempts"] for event in session_debits] == [
        1,
        2,
    ]


@pytest.mark.asyncio
async def test_resume_ignores_same_provider_tail_from_sibling_dispatch_scope() -> None:
    run_id = uuid4()
    current_scope = uuid4()
    sibling_scope = uuid4()
    sink = InMemoryEventSink()
    checkpoints: list[Any] = []

    async def interrupt_initial_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=ReplayMCPConnector("fixture-mcp", [_session("unused")]),
            planner=ScriptedPlanner([]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_initial_checkpoint,
            dispatch_scope_id=current_scope,
        ).run(run_id=run_id)

    snapshot = checkpoints[0]
    sibling_invocation_id = uuid4()
    await sink.append(
        AgentEvent(
            run_id=run_id,
            invocation_id=sibling_invocation_id,
            kind=AgentEventKind.TOOL_INVOCATION_STARTED,
            payload={
                "provider": "fixture-mcp",
                "dispatch_scope_id": str(sibling_scope),
            },
        ),
        expected_version=await sink.current_version(run_id),
    )
    await sink.append(
        AgentEvent(
            run_id=run_id,
            kind=AgentEventKind.BUDGET_DEBITED,
            payload={
                "provider": "fixture-mcp",
                "dispatch_scope_id": str(sibling_scope),
                "amounts": {"session_attempts": 1},
                "consumed": {"session_attempts": 1},
                "remaining": {},
            },
        ),
        expected_version=await sink.current_version(run_id),
    )

    connector = ReplayMCPConnector("fixture-mcp", [_session("current-session")])
    result = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        dispatch_scope_id=current_scope,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert connector.opened_session_ids == ["current-session"]
    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.COMPLETED
    assert result.budget.consumed.session_attempts == 1
    current_events = [
        event
        for event in await sink.read(run_id)
        if event.payload.get("dispatch_scope_id") == str(current_scope)
    ]
    assert current_events
    assert all(event.invocation_id != sibling_invocation_id for event in current_events)


@pytest.mark.asyncio
async def test_terminal_checkpoint_recovers_without_downgrade_or_remote_replay() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    invocation_store = _RecordingInvocationStore()
    captured: list[Any] = []
    first_connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "first"},
                    result={"rows": [1]},
                ),
            )
        ],
    )

    async def interrupt_before_terminal_side_effects(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    first_runtime = MCPAgentHarnessRuntime(
        connector=first_connector,
        planner=ScriptedPlanner([_call("first")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=interrupt_before_terminal_side_effects,
        invocation_store=invocation_store,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = captured[0]
    assert snapshot.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
    assert invocation_store.statuses == [
        ToolInvocationStatus.PENDING,
        ToolInvocationStatus.STARTED,
    ]
    second_connector = ReplayMCPConnector(
        "fixture-mcp",
        [_session("session-2")],
    )
    resumed = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
    ).resume(snapshot, restored_budget=first_runtime.budget)

    assert [item.status for item in resumed.invocations] == [ToolInvocationStatus.SUCCEEDED]
    assert resumed.state.successful_queries == ["first"]
    assert first_connector.opened_session_ids == ["session-1"]
    assert second_connector.opened_session_ids == ["session-2"]
    assert invocation_store.statuses[-1] == ToolInvocationStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_missing_artifact_after_terminal_checkpoint_is_backfilled_without_remote_replay() -> (
    None
):
    run_id = uuid4()
    sink = InMemoryEventSink()
    invocation_store = _RecordingInvocationStore()
    artifact_store = _InterruptBeforeArtifactStore()
    checkpoints: list[Any] = []
    first_connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "session-1",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "artifact-crash"},
                    result={"rows": [1]},
                ),
            )
        ],
    )

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    first_runtime = MCPAgentHarnessRuntime(
        connector=first_connector,
        planner=ScriptedPlanner([_call("artifact-crash")]),
        scenario=_ArtifactScenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=capture_checkpoint,
        invocation_store=invocation_store,
        artifact_store=artifact_store,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = checkpoints[-1]
    assert snapshot.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
    assert snapshot.state.successful_queries == ["artifact-crash"]
    assert invocation_store.statuses[-1] == ToolInvocationStatus.STARTED
    assert snapshot.invocations[-1].artifact_ref is not None
    assert artifact_store.artifacts == []

    second_connector = ReplayMCPConnector("fixture-mcp", [_session("session-2")])
    resumed = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_ArtifactScenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
        artifact_store=artifact_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert resumed.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
    assert len(resumed.invocations) == 1
    assert resumed.state.successful_queries == ["artifact-crash"]
    assert second_connector.opened_session_ids == ["session-2"]
    assert resumed.budget.consumed.remote_tool_calls == 1
    assert invocation_store.statuses[-1] == ToolInvocationStatus.SUCCEEDED
    assert artifact_store.artifacts == [resumed.invocations[-1].artifact_ref]
    terminal_events = [
        event
        for event in await sink.read(run_id)
        if event.kind == AgentEventKind.TOOL_INVOCATION_SUCCEEDED
    ]
    assert len(terminal_events) == 1


@pytest.mark.asyncio
async def test_event_tail_ahead_of_checkpoint_is_reconciled_without_duplicate_event() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    invocation_store = _RecordingInvocationStore()
    terminal_checkpoints: list[Any] = []

    async def interrupt_after_terminal_event(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
        ):
            terminal_checkpoints.append(snapshot)
            if len(terminal_checkpoints) == 2:
                raise asyncio.CancelledError

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-1",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "first"},
                        result={"rows": [1]},
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_call("first")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=interrupt_after_terminal_event,
        invocation_store=invocation_store,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    stale_checkpoint = terminal_checkpoints[0]
    assert await sink.current_version(run_id) > stale_checkpoint.event_version
    result = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("session-2")]),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        invocation_store=invocation_store,
    ).resume(
        stale_checkpoint,
        restored_budget=BudgetLedger.from_snapshot(stale_checkpoint.budget),
    )

    assert result.invocations[0].status == ToolInvocationStatus.SUCCEEDED
    events = await sink.read(run_id)
    assert sum(event.kind == AgentEventKind.TOOL_INVOCATION_SUCCEEDED for event in events) == 1


@pytest.mark.asyncio
async def test_unknown_outcome_checkpoint_survives_interruption_without_replay() -> None:
    run_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []
    disconnect = ReplayErrorFixture(
        code="connection_lost",
        message="Connection closed while awaiting response",
        retryable=True,
        unknown_outcome=True,
    )

    async def interrupt_after_unknown_outcome(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status
            == ToolInvocationStatus.UNKNOWN_OUTCOME
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    first_runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-1",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "retry-me"},
                        outcome=ReplayCallOutcome.DISCONNECT,
                        error=disconnect,
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_call("retry-me")]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=interrupt_after_unknown_outcome,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=run_id)

    snapshot = captured[0]
    assert snapshot.pending_retry is None
    result = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session("session-2")
            ],
        ),
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    ).resume(snapshot, restored_budget=first_runtime.budget)

    assert [item.status for item in result.invocations] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME
    ]
    assert result.budget.consumed.remote_tool_calls == 1
    assert result.pending_retry is None


@pytest.mark.asyncio
async def test_human_escalation_bypasses_evidence_finish_gate() -> None:
    sink = InMemoryEventSink()
    runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", [_session("session-1")]),
        planner=ScriptedPlanner(
            [
                {
                    "action": "request_human_input",
                    "reason": "The target is ambiguous.",
                    "question": "Which database instance is affected?",
                    "required_fields": ["database_instance"],
                }
            ]
        ),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
    )

    result = await runtime.run(run_id=uuid4())

    assert result.finish is not None
    assert result.finish.reason == RuntimeStopReason.HUMAN_INPUT_REQUIRED
    assert result.finish.requires_human is True


@pytest.mark.asyncio
async def test_invocation_and_artifact_hooks_receive_lifecycle_transitions() -> None:
    invocation_store = _RecordingInvocationStore()
    artifact_store = _RecordingArtifactStore()
    runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-1",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "artifact"},
                        result={"rows": [1]},
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_call("artifact"), _finish()]),
        scenario=_ArtifactScenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
        invocation_store=invocation_store,
        artifact_store=artifact_store,
    )

    result = await runtime.run(run_id=uuid4())

    assert invocation_store.statuses == [
        ToolInvocationStatus.PENDING,
        ToolInvocationStatus.STARTED,
        ToolInvocationStatus.SUCCEEDED,
    ]
    assert artifact_store.artifacts == [result.invocations[0].artifact_ref]


async def _capture_staged_remote_response_snapshot() -> tuple[Any, InMemoryEventSink]:
    run_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []

    async def interrupt_after_raw_checkpoint(snapshot: Any) -> None:
        if snapshot.remote_responses:
            captured.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=ReplayMCPConnector(
                "fixture-mcp",
                [
                    _session(
                        "staged-response",
                        ReplayCallFixture(
                            tool_name="fixture.query",
                            expected_arguments={"query": "resume-staged-raw"},
                            result={
                                "_meta": {"api_key": "mcp-owned-secret"},
                                "rows": [{"instance_id": 17}],
                            },
                        ),
                    )
                ],
            ),
            planner=ScriptedPlanner([_call("resume-staged-raw")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_after_raw_checkpoint,
        ).run(run_id=run_id)

    assert len(captured) == 1
    assert len(captured[0].remote_responses) == 1
    return captured[0], sink


async def _capture_successful_remote_response_snapshot() -> tuple[Any, InMemoryEventSink]:
    run_id = uuid4()
    sink = InMemoryEventSink()
    captured: list[Any] = []

    async def interrupt_after_success_checkpoint(snapshot: Any) -> None:
        if (
            snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
            and snapshot.finish is None
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=ReplayMCPConnector(
                "fixture-mcp",
                [
                    _session(
                        "successful-response",
                        ReplayCallFixture(
                            tool_name="fixture.query",
                            expected_arguments={"query": "successful-before-resume"},
                            result={"rows": [{"instance_id": 17}]},
                        ),
                    )
                ],
            ),
            planner=ScriptedPlanner([_call("successful-before-resume")]),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=interrupt_after_success_checkpoint,
        ).run(run_id=run_id)

    assert len(captured) == 1
    assert len(captured[0].remote_responses) == 1
    return captured[0], sink


@pytest.mark.asyncio
async def test_remote_response_is_checkpointed_raw_and_persisted_only_after_finish() -> None:
    response_store = _RecordingRemoteResponseStore()
    staged_before_finish = False

    async def checkpoint(snapshot: Any) -> None:
        nonlocal staged_before_finish
        if snapshot.remote_responses and snapshot.finish is None:
            staged_before_finish = True
            assert response_store.responses == []

    raw_response = {
        "_meta": {"api_key": "mcp-owned-secret"},
        "content": [{"type": "text", "text": "x" * 50_000}],
        "structuredContent": {"rows": [{"instance_id": 17}]},
        "isError": False,
    }
    run_id = uuid4()
    result = await MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector(
            "fixture-mcp",
            [
                _session(
                    "session-1",
                    ReplayCallFixture(
                        tool_name="fixture.query",
                        expected_arguments={"query": "raw"},
                        result=raw_response,
                    ),
                )
            ],
        ),
        planner=ScriptedPlanner([_call("raw"), _finish()]),
        scenario=_Scenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
        checkpoint_hook=checkpoint,
        remote_response_store=response_store,
    ).run(run_id=run_id)

    assert staged_before_finish is True
    assert len(result.remote_responses) == 1
    assert result.remote_responses[0].response == raw_response
    assert response_store.responses == [
        {
            "run_id": run_id,
            "invocation_id": result.invocations[0].invocation_id,
            "tool_name": "fixture.query",
            "arguments": {"query": "raw"},
            "response": raw_response,
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("termination", ["cancel", "outer_timeout"])
async def test_staged_remote_response_is_persisted_after_external_termination(
    termination: str,
) -> None:
    session = _TrackingSession()
    planner = _CallThenBlockingPlanner("raw-before-termination")

    class CloseAwareResponseStore(_RecordingRemoteResponseStore):
        async def save(self, **record: Any) -> None:
            assert session.close_calls == 1
            await super().save(**record)

    response_store = CloseAwareResponseStore()
    run_id = uuid4()
    task = asyncio.create_task(
        MCPAgentHarnessRuntime(
            connector=_SingleSessionConnector(session),
            planner=planner,
            scenario=_Scenario(),
            event_sink=InMemoryEventSink(),
            budget=_budget(),
            remote_response_store=response_store,
        ).run(run_id=run_id)
    )
    await asyncio.wait_for(planner.blocked.wait(), timeout=1)

    if termination == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.01):
                await task

    assert session.close_calls == 1
    assert len(response_store.responses) == 1
    assert response_store.responses[0]["run_id"] == run_id
    assert response_store.responses[0]["tool_name"] == "fixture.query"
    assert response_store.responses[0]["arguments"] == {"query": "raw-before-termination"}
    assert response_store.responses[0]["response"] == {"rows": [1]}


@pytest.mark.asyncio
async def test_staged_remote_response_is_persisted_before_infrastructure_error_propagates() -> (
    None
):
    session = _TrackingSession()
    response_store = _RecordingRemoteResponseStore()

    async def fail_staged_checkpoint(snapshot: Any) -> None:
        if snapshot.remote_responses:
            raise RuntimeError("staged checkpoint failed")

    runtime = MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(session),
        planner=ScriptedPlanner([_call("raw-before-error")]),
        scenario=_Scenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
        checkpoint_hook=fail_staged_checkpoint,
        remote_response_store=response_store,
    )

    with pytest.raises(RuntimeError, match="staged checkpoint failed"):
        await runtime.run(run_id=uuid4())

    assert session.close_calls == 1
    assert len(response_store.responses) == 1
    assert response_store.responses[0]["response"] == {"rows": [1]}


@pytest.mark.asyncio
async def test_terminal_checkpoint_failure_still_persists_response_after_session_close() -> None:
    session = _TrackingSession()

    class CloseAwareResponseStore(_RecordingRemoteResponseStore):
        async def save(self, **record: Any) -> None:
            assert session.close_calls == 1
            await super().save(**record)

    response_store = CloseAwareResponseStore()

    async def fail_terminal_checkpoint(snapshot: Any) -> None:
        if snapshot.finish is not None:
            assert session.close_calls == 1
            raise RuntimeError("terminal checkpoint failed")

    runtime = MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(session),
        planner=ScriptedPlanner([_call("raw-before-terminal-checkpoint"), _finish()]),
        scenario=_Scenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
        checkpoint_hook=fail_terminal_checkpoint,
        remote_response_store=response_store,
    )

    with pytest.raises(RuntimeError, match="terminal checkpoint failed"):
        await runtime.run(run_id=uuid4())

    assert session.close_calls == 1
    assert len(response_store.responses) == 1
    assert response_store.responses[0]["response"] == {"rows": [1]}


@pytest.mark.asyncio
async def test_terminal_checkpoint_error_remains_primary_when_response_persistence_fails() -> (
    None
):
    session = _TrackingSession()

    class FailingResponseStore(_RecordingRemoteResponseStore):
        def __init__(self) -> None:
            super().__init__()
            self.save_calls = 0

        async def save(self, **record: Any) -> None:
            del record
            self.save_calls += 1
            assert session.close_calls == 1
            raise RuntimeError("response artifact failed")

    response_store = FailingResponseStore()

    async def fail_terminal_checkpoint(snapshot: Any) -> None:
        if snapshot.finish is not None:
            raise RuntimeError("terminal checkpoint failed")

    runtime = MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(session),
        planner=ScriptedPlanner([_call("raw-before-double-failure"), _finish()]),
        scenario=_Scenario(),
        event_sink=InMemoryEventSink(),
        budget=_budget(),
        checkpoint_hook=fail_terminal_checkpoint,
        remote_response_store=response_store,
    )

    with pytest.raises(RuntimeError, match="terminal checkpoint failed") as exc_info:
        await runtime.run(run_id=uuid4())

    assert session.close_calls == 1
    assert response_store.save_calls == 1
    assert any(
        "MCP raw-response artifact persistence also failed" in note
        and "HarnessInfrastructureError" in note
        and "failed to persist remote MCP responses" in note
        for note in (exc_info.value.__notes__ or [])
    )


@pytest.mark.asyncio
async def test_partial_remote_response_artifact_flush_is_idempotently_completed_on_resume() -> (
    None
):
    class PartiallyFailingResponseStore:
        def __init__(self) -> None:
            self.records: dict[Any, dict[str, Any]] = {}
            self.failed_once = False

        async def save(self, **record: Any) -> None:
            invocation_id = record["invocation_id"]
            if (
                len(self.records) == 1
                and invocation_id not in self.records
                and not self.failed_once
            ):
                self.failed_once = True
                raise RuntimeError("second response artifact write failed")
            existing = self.records.get(invocation_id)
            if existing is not None and existing != record:
                raise AssertionError("idempotent response artifact changed")
            self.records[invocation_id] = deepcopy(record)

        async def load(self, **identity: Any) -> Any | None:
            record = self.records.get(identity["invocation_id"])
            return deepcopy(record["response"]) if record is not None else None

    run_id = uuid4()
    sink = InMemoryEventSink()
    checkpoints: list[Any] = []
    response_store = PartiallyFailingResponseStore()
    first_connector = ReplayMCPConnector(
        "fixture-mcp",
        [
            _session(
                "partial-flush",
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "first-raw"},
                    result={"rows": [1]},
                ),
                ReplayCallFixture(
                    tool_name="fixture.query",
                    expected_arguments={"query": "second-raw"},
                    result={"rows": [2]},
                ),
            )
        ],
    )

    async def capture(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    with pytest.raises(RuntimeError, match="failed to persist remote MCP responses"):
        await MCPAgentHarnessRuntime(
            connector=first_connector,
            planner=ScriptedPlanner(
                [_call("first-raw"), _call("second-raw"), _finish()]
            ),
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            checkpoint_hook=capture,
            remote_response_store=response_store,
        ).run(run_id=run_id)

    terminal_snapshot = checkpoints[-1]
    assert terminal_snapshot.finish is not None
    assert len(terminal_snapshot.remote_responses) == 2
    assert len(response_store.records) == 1

    second_connector = ReplayMCPConnector("fixture-mcp", [])
    resumed = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=ScriptedPlanner([]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        checkpoint_hook=capture,
        remote_response_store=response_store,
    ).resume(
        terminal_snapshot,
        restored_budget=BudgetLedger.from_snapshot(terminal_snapshot.budget),
    )

    assert resumed.finish == terminal_snapshot.finish
    assert second_connector.opened_session_ids == []
    assert len(response_store.records) == 2
    assert sorted(
        record["response"]["rows"][0] for record in response_store.records.values()
    ) == [1, 2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stage", "method_name"),
    [
        ("reconcile", "_reconcile_durable_invocations"),
        ("trace", "_ensure_observation_trace_events"),
        ("inflight", "_reconcile_inflight"),
        ("checkpoint", "_checkpoint"),
    ],
)
async def test_resume_pre_drive_failure_closes_session_then_flushes_staged_response(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    method_name: str,
) -> None:
    snapshot, sink = await _capture_staged_remote_response_snapshot()
    session = _TrackingSession()

    class CloseAwareResponseStore(_RecordingRemoteResponseStore):
        async def save(self, **record: Any) -> None:
            assert session.close_calls == 1
            await super().save(**record)

    response_store = CloseAwareResponseStore()
    connector = ReplayMCPConnector("fixture-mcp", [])
    runtime = MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    )

    async def fail_pre_drive(ctx: Any, *args: Any) -> None:
        del args
        ctx.session = session
        raise RuntimeError(f"{stage} failed")

    monkeypatch.setattr(runtime, method_name, fail_pre_drive)

    with pytest.raises(RuntimeError, match=f"{stage} failed"):
        await runtime.resume(
            snapshot,
            restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
        )

    assert session.close_calls == 1
    assert connector.opened_session_ids == []
    assert len(response_store.responses) == 1
    assert response_store.responses[0]["response"] == snapshot.remote_responses[0].response


@pytest.mark.asyncio
async def test_resume_pre_drive_error_remains_primary_when_response_flush_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, sink = await _capture_staged_remote_response_snapshot()
    session = _TrackingSession()

    class FailingResponseStore(_RecordingRemoteResponseStore):
        async def save(self, **record: Any) -> None:
            del record
            assert session.close_calls == 1
            raise RuntimeError("resume artifact failed")

    runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", []),
        planner=ScriptedPlanner([]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=FailingResponseStore(),
    )

    async def fail_reconcile(ctx: Any, *args: Any) -> None:
        del args
        ctx.session = session
        raise RuntimeError("resume reconcile failed")

    monkeypatch.setattr(runtime, "_reconcile_durable_invocations", fail_reconcile)

    with pytest.raises(RuntimeError, match="resume reconcile failed") as exc_info:
        await runtime.resume(
            snapshot,
            restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
        )

    assert session.close_calls == 1
    assert any(
        "MCP raw-response artifact persistence also failed" in note
        and "failed to persist remote MCP responses" in note
        for note in (exc_info.value.__notes__ or [])
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("termination", ["cancel", "outer_timeout"])
async def test_resume_pre_drive_external_termination_flushes_staged_response(
    monkeypatch: pytest.MonkeyPatch,
    termination: str,
) -> None:
    snapshot, sink = await _capture_staged_remote_response_snapshot()
    session = _TrackingSession()
    entered = asyncio.Event()

    class CloseAwareResponseStore(_RecordingRemoteResponseStore):
        async def save(self, **record: Any) -> None:
            assert session.close_calls == 1
            await super().save(**record)

    response_store = CloseAwareResponseStore()
    runtime = MCPAgentHarnessRuntime(
        connector=ReplayMCPConnector("fixture-mcp", []),
        planner=ScriptedPlanner([]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    )

    async def block_trace_recovery(ctx: Any) -> None:
        ctx.session = session
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(runtime, "_ensure_observation_trace_events", block_trace_recovery)
    task = asyncio.create_task(
        runtime.resume(
            snapshot,
            restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)

    if termination == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.01):
                await task

    assert task.done()
    assert session.close_calls == 1
    assert len(response_store.responses) == 1
    assert response_store.responses[0]["response"] == snapshot.remote_responses[0].response


@pytest.mark.asyncio
async def test_normal_resume_consumes_staged_response_without_repeating_remote_call() -> None:
    snapshot, sink = await _capture_staged_remote_response_snapshot()
    session = _TrackingSession()
    connector = _SingleSessionConnector(session)
    response_store = _RecordingRemoteResponseStore()

    result = await MCPAgentHarnessRuntime(
        connector=connector,
        planner=ScriptedPlanner([_finish()]),
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    ).resume(
        snapshot,
        restored_budget=BudgetLedger.from_snapshot(snapshot.budget),
    )

    assert connector.open_calls == 1
    assert session.call_calls == 0
    assert result.state.successful_queries == ["resume-staged-raw"]
    assert result.budget.consumed.remote_tool_calls == 1
    assert len(response_store.responses) == 1


@pytest.mark.asyncio
async def test_resume_rejects_successful_legacy_checkpoint_without_raw_response() -> None:
    snapshot, sink = await _capture_successful_remote_response_snapshot()
    legacy_snapshot = replace(snapshot, remote_responses=())
    event_version_before_resume = await sink.current_version(snapshot.run_id)
    planner = ScriptedPlanner([_finish()])
    connector = ReplayMCPConnector("fixture-mcp", [])

    class LegacyResponseStore(_RecordingRemoteResponseStore):
        def __init__(self) -> None:
            super().__init__()
            self.load_calls = 0

        async def load(self, **identity: Any) -> Any | None:
            del identity
            self.load_calls += 1
            return {"rows": "legacy-sanitized"}

    response_store = LegacyResponseStore()

    with pytest.raises(
        RuntimeError,
        match="successful MCP invocation is missing its checkpointed raw response",
    ):
        await MCPAgentHarnessRuntime(
            connector=connector,
            planner=planner,
            scenario=_Scenario(),
            event_sink=sink,
            budget=_budget(),
            remote_response_store=response_store,
        ).resume(
            legacy_snapshot,
            restored_budget=BudgetLedger.from_snapshot(legacy_snapshot.budget),
        )

    assert connector.opened_session_ids == []
    assert planner.requests == []
    assert response_store.load_calls == 0
    assert await sink.current_version(snapshot.run_id) == event_version_before_resume


@pytest.mark.asyncio
async def test_resume_does_not_recover_started_invocation_from_legacy_response_store() -> None:
    snapshot, sink = await _capture_staged_remote_response_snapshot()
    legacy_snapshot = replace(snapshot, remote_responses=())
    session = _TrackingSession()
    planner = ScriptedPlanner([_finish()])

    class LegacyResponseStore(_RecordingRemoteResponseStore):
        def __init__(self) -> None:
            super().__init__()
            self.load_calls = 0

        async def load(self, **identity: Any) -> Any | None:
            del identity
            self.load_calls += 1
            return {"rows": "legacy-sanitized"}

    response_store = LegacyResponseStore()
    result = await MCPAgentHarnessRuntime(
        connector=_SingleSessionConnector(session),
        planner=planner,
        scenario=_Scenario(),
        event_sink=sink,
        budget=_budget(),
        remote_response_store=response_store,
    ).resume(
        legacy_snapshot,
        restored_budget=BudgetLedger.from_snapshot(legacy_snapshot.budget),
    )

    assert response_store.load_calls == 0
    assert result.invocations[0].status == ToolInvocationStatus.UNKNOWN_OUTCOME
    assert result.state.successful_queries == []
    assert session.call_calls == 0
    assert "legacy-sanitized" not in json.dumps(
        planner.requests[0].messages,
        sort_keys=True,
    )
