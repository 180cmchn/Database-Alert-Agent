"""Unified harness for stateful, reconnectable MCP investigations."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid5

from app.agent_runtime.budgets import (
    BudgetAmounts,
    BudgetExceededError,
    BudgetLedger,
    BudgetLimits,
)
from app.agent_runtime.contracts import (
    ArtifactRef,
    CallToolAction,
    FinishAction,
    InvocationError,
    RequestHumanInputAction,
    RuntimeStopReason,
    ToolInvocation,
    ToolInvocationStatus,
    ToolSpec,
    parse_agent_action,
)
from app.agent_runtime.events import (
    AgentEvent,
    AgentEventKind,
    EventSink,
    EventVersionConflictError,
)
from app.mcp_runtime.contracts import (
    ArtifactStore,
    CheckpointHook,
    Finish,
    HarnessObservation,
    InvocationStore,
    MCPConnector,
    MCPHarnessResult,
    MCPHarnessScenario,
    MCPHarnessSnapshot,
    MCPPlanner,
    MCPToolSession,
    PreparedCall,
    RemoteResponseRecord,
    RemoteResponseStore,
    RetryDirective,
    ScenarioTransition,
)

_UNSET = object()
_DURABLE_CALL_CONTEXT_METADATA_KEYS = frozenset(
    {"call_id", "provider_output_items", "request_id", "trace_index"}
)


class HarnessInfrastructureError(RuntimeError):
    """The harness could not durably record its own state transition."""


class _RecoveredUnknownOutcome(RuntimeError):
    code = "recovered_unknown_outcome"
    retryable = True
    unknown_outcome = True


class _HostResultProcessingError(RuntimeError):
    code = "host_result_processing_error"
    retryable = False
    unknown_outcome = False

    def __init__(self, cause: Exception) -> None:
        super().__init__(
            f"The MCP Host could not process a successful transport result: {type(cause).__name__}"
        )
        self.details = {"cause_type": type(cause).__name__}


def event_matches_dispatch_scope(
    event: AgentEvent,
    dispatch_scope_id: UUID | None,
) -> bool:
    """Return whether an MCP event belongs to one logical outer dispatch."""

    expected = str(dispatch_scope_id) if dispatch_scope_id is not None else None
    return event.payload.get("dispatch_scope_id") == expected


@dataclass(slots=True)
class _RunContext[StateT, ObservationT]:
    run_id: UUID
    parent_run_id: UUID | None
    state: StateT
    budget: BudgetLedger
    messages: list[dict[str, Any]]
    observations: list[HarnessObservation[ObservationT]] = field(default_factory=list)
    invocations: list[ToolInvocation] = field(default_factory=list)
    catalog: dict[str, ToolSpec] = field(default_factory=dict)
    fingerprints: set[str] = field(default_factory=set)
    attempts: dict[str, int] = field(default_factory=dict)
    session: MCPToolSession | None = None
    finish: Finish | None = None
    deadline: datetime | None = None
    wall_time_deadline: datetime | None = None
    account_wall_time: bool = True
    event_version: int = 0
    pending_retry: PreparedCall | None = None
    retry_not_before: datetime | None = None
    active_call: PreparedCall | None = None
    remote_debited_invocations: set[UUID] = field(default_factory=set)
    remote_responses: dict[UUID, RemoteResponseRecord] = field(default_factory=dict)


class _BudgetedBootstrapSession:
    def __init__(
        self,
        session: MCPToolSession,
        call_tool: Callable[[str, dict[str, Any]], Awaitable[Any]],
    ) -> None:
        self._session = session
        self._call_tool = call_tool

    @property
    def session_id(self) -> str:
        return self._session.session_id

    async def list_tools(self) -> list[Any]:
        return await self._session.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return await self._call_tool(name, arguments)

    async def close(self) -> None:
        await self._session.close()


class MCPAgentHarnessRuntime[StateT, ObservationT]:
    """Runs a provider scenario without placing another hidden Agent in a tool."""

    def __init__(
        self,
        *,
        connector: MCPConnector,
        planner: MCPPlanner,
        scenario: MCPHarnessScenario[StateT, ObservationT],
        event_sink: EventSink,
        budget: BudgetLedger,
        child_budget_limits: BudgetLimits | dict[str, Any] | None = None,
        checkpoint_hook: CheckpointHook[StateT, ObservationT] | None = None,
        invocation_store: InvocationStore | None = None,
        artifact_store: ArtifactStore | None = None,
        remote_response_store: RemoteResponseStore | None = None,
        planner_timeout_seconds: float = 60,
        session_timeout_seconds: float = 30,
        stream_planner_reasoning: bool = True,
        dispatch_scope_id: UUID | None = None,
    ) -> None:
        if connector.provider != scenario.provider:
            raise ValueError("connector and scenario providers must match")
        if planner_timeout_seconds <= 0 or session_timeout_seconds <= 0:
            raise ValueError("runtime timeouts must be greater than zero")
        self.connector = connector
        self.planner = planner
        self.scenario = scenario
        self.event_sink = event_sink
        self.budget = (
            budget.create_child(child_budget_limits) if child_budget_limits is not None else budget
        )
        self.checkpoint_hook = checkpoint_hook
        self.invocation_store = invocation_store
        self.artifact_store = artifact_store
        self.remote_response_store = remote_response_store
        self.planner_timeout_seconds = planner_timeout_seconds
        self.session_timeout_seconds = session_timeout_seconds
        self.stream_planner_reasoning = stream_planner_reasoning
        self.dispatch_scope_id = dispatch_scope_id

    async def run(
        self,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        initial_state: StateT | object = _UNSET,
        initial_messages: list[dict[str, Any]] | None = None,
        deadline: datetime | None = None,
    ) -> MCPHarnessResult[StateT, ObservationT]:
        if deadline is not None and deadline.tzinfo is None:
            raise ValueError("deadline must be timezone-aware")
        now = datetime.now(UTC)
        budget_snapshot = self.budget.snapshot()
        if budget_snapshot.reserved.wall_time_seconds:
            raise ValueError("MCP runtime cannot start with reserved wall-time budget")
        wall_time_remaining = budget_snapshot.remaining.wall_time_seconds
        wall_time_deadline = (
            now + timedelta(seconds=wall_time_remaining)
            if wall_time_remaining is not None
            else None
        )
        effective_deadline = (
            min(candidate for candidate in (deadline, wall_time_deadline) if candidate is not None)
            if deadline is not None or wall_time_deadline is not None
            else None
        )
        state = self.scenario.initial_state() if initial_state is _UNSET else initial_state
        typed_state = state  # Narrow the sentinel union for type checkers.
        assert typed_state is not _UNSET
        messages = (
            deepcopy(initial_messages)
            if initial_messages is not None
            else deepcopy(self.scenario.initial_messages(typed_state))
        )
        ctx = _RunContext[StateT, ObservationT](
            run_id=run_id,
            parent_run_id=parent_run_id,
            state=typed_state,
            budget=self.budget,
            messages=messages,
            deadline=effective_deadline,
            wall_time_deadline=wall_time_deadline,
            event_version=await self.event_sink.current_version(run_id),
        )
        await self._emit(ctx, AgentEventKind.RUN_STARTED, {"provider": self.scenario.provider})
        await self._checkpoint(ctx)
        return await self._drive(ctx)

    async def resume(
        self,
        snapshot: MCPHarnessSnapshot[StateT, ObservationT],
        *,
        restored_budget: BudgetLedger,
    ) -> MCPHarnessResult[StateT, ObservationT]:
        """Resume a checkpoint without replaying RUN_STARTED or resetting run memory.

        Budget reservations and consumption are deliberately not reconstructed
        from numbers alone. The caller must restore the ledger hierarchy and
        provide a ledger whose complete snapshot matches the checkpoint.
        """

        if restored_budget.snapshot() != snapshot.budget:
            raise ValueError("restored BudgetLedger does not match the checkpoint snapshot")
        if snapshot.retry_not_before is not None and snapshot.retry_not_before.tzinfo is None:
            raise ValueError("retry_not_before must be timezone-aware")
        if snapshot.deadline is not None and snapshot.deadline.tzinfo is None:
            raise ValueError("restored deadline must be timezone-aware")
        if snapshot.wall_time_deadline is not None and snapshot.wall_time_deadline.tzinfo is None:
            raise ValueError("restored wall-time deadline must be timezone-aware")
        if (
            snapshot.deadline is not None
            and snapshot.wall_time_deadline is not None
            and snapshot.deadline > snapshot.wall_time_deadline
        ):
            raise ValueError("restored deadline exceeds the wall-time budget deadline")
        actual_event_version = await self.event_sink.current_version(snapshot.run_id)
        if actual_event_version < snapshot.event_version:
            raise ValueError(
                "event stream is behind the checkpoint: "
                f"expected={snapshot.event_version}, actual={actual_event_version}"
            )
        attempts: dict[str, int] = {}
        for invocation in snapshot.invocations:
            attempts[invocation.fingerprint] = max(
                attempts.get(invocation.fingerprint, 0),
                invocation.attempt,
            )
        ctx = _RunContext[StateT, ObservationT](
            run_id=snapshot.run_id,
            parent_run_id=snapshot.parent_run_id,
            state=deepcopy(snapshot.state),
            budget=restored_budget,
            messages=list(deepcopy(snapshot.messages)),
            observations=list(deepcopy(snapshot.observations)),
            invocations=[item.model_copy(deep=True) for item in snapshot.invocations],
            catalog={item.name: item.model_copy(deep=True) for item in snapshot.tool_specs},
            fingerprints=set(snapshot.fingerprints),
            attempts=attempts,
            finish=snapshot.finish.model_copy(deep=True) if snapshot.finish is not None else None,
            deadline=snapshot.deadline,
            wall_time_deadline=snapshot.wall_time_deadline,
            account_wall_time=snapshot.finish is None,
            event_version=actual_event_version,
            pending_retry=(
                snapshot.pending_retry.model_copy(deep=True)
                if snapshot.pending_retry is not None
                else None
            ),
            retry_not_before=snapshot.retry_not_before,
            active_call=(
                snapshot.active_call.model_copy(deep=True)
                if snapshot.active_call is not None
                else None
            ),
            remote_responses={
                item.invocation_id: RemoteResponseRecord(
                    invocation_id=item.invocation_id,
                    tool_name=item.tool_name,
                    arguments=deepcopy(item.arguments),
                    response=deepcopy(item.response),
                    is_remote=bool(getattr(item, "is_remote", True)),
                )
                for item in snapshot.remote_responses
            },
        )
        try:
            self._validate_recovered_remote_response_lineage(ctx)
            persisted_events = await self.event_sink.read(snapshot.run_id)
            self._reconcile_budget_tail(
                ctx,
                persisted_events,
                after_sequence=snapshot.event_version,
            )
            await self._reconcile_durable_invocations(ctx, persisted_events)
            self._validate_recovered_remote_response_lineage(ctx)
            await self._ensure_observation_trace_events(ctx)
            if ctx.finish is not None:
                await self._persist_deferred_remote_responses(ctx)
                await self._ensure_run_completed_event(ctx, persisted_events)
                await self._checkpoint(ctx)
                return await self._result(ctx)
            await self._reconcile_inflight(ctx)
            await self._checkpoint(ctx)
        except BaseException as resume_error:
            await self._cleanup_interrupted_resume(ctx, resume_error)
            raise
        return await self._drive(ctx)

    async def _cleanup_interrupted_resume(
        self,
        ctx: _RunContext[StateT, ObservationT],
        resume_error: BaseException,
    ) -> None:
        """Close recovery resources and flush staged responses before re-raising."""

        try:
            await self._close_session(ctx)
        except BaseException as close_error:
            resume_error.add_note(
                "MCP resume session cleanup also failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        try:
            await self._persist_deferred_remote_responses(ctx)
        except BaseException as persist_error:
            resume_error.add_note(
                "MCP raw-response artifact persistence also failed: "
                f"{type(persist_error).__name__}: {persist_error}"
            )

    async def _drive(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> MCPHarnessResult[StateT, ObservationT]:

        run_loop_completed = False
        termination_error: BaseException | None = None
        try:
            finish = await self._run_loop(ctx)
        except BudgetExceededError as exc:
            finish = self._budget_finish(exc)
            run_loop_completed = True
        except Exception as exc:
            await self._emit(
                ctx,
                AgentEventKind.RUN_FAILED,
                {"error_code": type(exc).__name__, "message": str(exc)},
            )
            termination_error = exc
            raise
        except BaseException as exc:
            termination_error = exc
            raise
        else:
            run_loop_completed = True
        finally:
            session_closed = False
            try:
                await self._close_session(ctx)
                session_closed = True
            finally:
                if not run_loop_completed or not session_closed:
                    # A caller-side timeout or cancellation terminates the MCP
                    # investigation without producing a Finish. Flush every
                    # staged response before propagating that termination.
                    try:
                        await self._persist_deferred_remote_responses(ctx)
                    except BaseException as persist_error:
                        if termination_error is None:
                            raise
                        termination_error.add_note(
                            "MCP raw-response artifact persistence also failed: "
                            f"{type(persist_error).__name__}: {persist_error}"
                        )

        ctx.finish = finish
        try:
            await self._checkpoint(ctx)
        except BaseException as checkpoint_error:
            ctx.account_wall_time = False
            try:
                await self._persist_deferred_remote_responses(ctx)
            except BaseException as persist_error:
                checkpoint_error.add_note(
                    "MCP raw-response artifact persistence also failed: "
                    f"{type(persist_error).__name__}: {persist_error}"
                )
            raise
        ctx.account_wall_time = False
        await self._persist_deferred_remote_responses(ctx)
        await self._emit(
            ctx,
            AgentEventKind.RUN_COMPLETED,
            {
                "reason": finish.reason.value,
                "requires_human": finish.requires_human,
                "summary": finish.summary,
                "provider": self.scenario.provider,
            },
        )
        await self._checkpoint(ctx)
        return await self._result(ctx)

    async def _run_loop(self, ctx: _RunContext[StateT, ObservationT]) -> Finish:
        scenario_finish = self.scenario.completion(ctx.state, tuple(ctx.observations))
        if scenario_finish is not None:
            return scenario_finish
        settled_local_pending, local_finish = await self._settle_pending_local_call(ctx)
        if local_finish is not None:
            return local_finish
        if self._deadline_reached(ctx):
            return self._deadline_finish(
                "The MCP investigation deadline was reached before session setup."
            )
        if not settled_local_pending:
            session_finish = await self._ensure_session(ctx)
            if session_finish is not None:
                return session_finish
        while True:
            if self._deadline_reached(ctx):
                return Finish(
                    reason=RuntimeStopReason.DEADLINE_EXCEEDED,
                    summary="The MCP investigation deadline was reached.",
                    requires_human=True,
                )
            scenario_finish = self.scenario.completion(ctx.state, tuple(ctx.observations))
            if scenario_finish is not None:
                return scenario_finish

            durable_pending = self._pending_invocation(ctx)
            if durable_pending is not None:
                prepared = self._active_or_reconstructed_call(ctx, durable_pending)
            elif ctx.pending_retry is None:
                prepared_or_finish = await self._next_action(ctx)
                if isinstance(prepared_or_finish, Finish):
                    return prepared_or_finish
                prepared = prepared_or_finish
            else:
                retry_finish = await self._wait_for_pending_retry(ctx)
                if retry_finish is not None:
                    return retry_finish
                assert ctx.pending_retry is not None
                prepared = ctx.pending_retry.model_copy(deep=True)

            if prepared.local_result is None and ctx.session is None:
                session_finish = await self._ensure_session(ctx)
                if session_finish is not None:
                    return session_finish
            finish, retry = await self._execute_call(ctx, prepared)
            if finish is not None:
                return finish
            if retry is not None and ctx.pending_retry is None:
                raise HarnessInfrastructureError(
                    "retry directive was returned without a durable pending retry"
                )

    async def _settle_pending_local_call(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> tuple[bool, Finish | None]:
        """Complete a policy-rejected pending call before opening a new session."""

        invocation = self._pending_invocation(ctx)
        if invocation is None:
            return False, None
        prepared = self._active_or_reconstructed_call(ctx, invocation)
        if prepared.local_result is None:
            return False, None
        finish, retry = await self._execute_call(ctx, prepared)
        if retry is not None and ctx.pending_retry is None:
            raise HarnessInfrastructureError(
                "retry directive was returned without a durable pending retry"
            )
        return True, finish

    async def _ensure_session(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> Finish | None:
        await self._close_session(ctx)
        while True:
            if self._deadline_reached(ctx):
                return Finish(
                    reason=RuntimeStopReason.DEADLINE_EXCEEDED,
                    summary="The MCP investigation deadline was reached while connecting.",
                    requires_human=True,
                )
            await self._debit(ctx, session_attempts=1)
            try:
                candidate = await self._await_bounded(
                    self.connector.open_session(),
                    ctx,
                    cap_seconds=self.session_timeout_seconds,
                )
            except Exception as exc:
                if self._deadline_reached(ctx):
                    return self._deadline_finish(
                        "The MCP investigation deadline was reached while connecting."
                    )
                finish = await self._record_session_failure(ctx, None, exc)
                if finish is not None:
                    return finish
                continue

            bootstrap_session = _BudgetedBootstrapSession(
                candidate,
                partial(self._bootstrap_tool_call, ctx, candidate),
            )
            try:
                discovered = await self._await_bounded(
                    candidate.list_tools(),
                    ctx,
                    cap_seconds=self.session_timeout_seconds,
                )
                specs = self.scenario.build_tool_specs(discovered)
                catalog = self._catalog(specs)
                bootstrapped_state = await self._await_bounded(
                    self.scenario.bootstrap(bootstrap_session, ctx.state),
                    ctx,
                    cap_seconds=self.session_timeout_seconds,
                )
            except (BudgetExceededError, HarnessInfrastructureError):
                await self._safe_close(candidate)
                raise
            except Exception as exc:
                if self._deadline_reached(ctx):
                    await self._safe_close(candidate)
                    return self._deadline_finish(
                        "The MCP investigation deadline was reached during session setup."
                    )
                finish = await self._record_session_failure(ctx, candidate, exc)
                if finish is not None:
                    return finish
                continue
            except BaseException:
                await self._close_candidate_after_interruption(candidate)
                raise

            ctx.state = bootstrapped_state
            ctx.session = candidate
            # Keep every previously discovered ToolSpec for audit/recovery while
            # refreshing descriptions for tools still advertised by the server.
            # Missing/unknown names are never a Host-side execution gate.
            ctx.catalog.update(catalog)
            await self._emit(
                ctx,
                AgentEventKind.MCP_SESSION_STARTED,
                {"session_id": candidate.session_id, "provider": self.scenario.provider},
            )
            await self._emit(
                ctx,
                AgentEventKind.MCP_TOOLS_DISCOVERED,
                {
                    "session_id": candidate.session_id,
                    "tools": sorted(catalog),
                },
            )
            await self._checkpoint(ctx)
            return None

    async def _bootstrap_tool_call(
        self,
        ctx: _RunContext[StateT, ObservationT],
        session: MCPToolSession,
        name: str,
        arguments: dict[str, Any],
    ) -> Any:
        await self._debit(ctx, host_bootstrap_calls=1)
        return await self._await_bounded(
            session.call_tool(name, arguments),
            ctx,
            cap_seconds=self.session_timeout_seconds,
        )

    async def _record_session_failure(
        self,
        ctx: _RunContext[StateT, ObservationT],
        session: MCPToolSession | None,
        exc: Exception,
    ) -> Finish | None:
        if session is not None:
            await self._safe_close(session)
        directive = self.scenario.retry_directive(ctx.state, None, exc)
        await self._emit(
            ctx,
            AgentEventKind.MCP_SESSION_FAILED,
            {
                "error_code": getattr(exc, "code", type(exc).__name__),
                "message": str(exc),
                "reconnect": directive.reconnect,
            },
        )
        await self._checkpoint(ctx)
        if directive.continue_run and directive.reconnect:
            return None
        return Finish(
            reason=RuntimeStopReason.FAILED,
            summary=f"MCP session could not be established: {directive.reason}",
            requires_human=True,
        )

    async def _next_action(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> PreparedCall | Finish:
        last_error = "planner returned no action"
        while True:
            action = None
            prepared: PreparedCall | None = None
            reasoning: str | None = None
            streamed_reasoning = False
            decision_key = self._decision_key(ctx)
            recovered = await self._load_durable_decision(ctx, decision_key)
            if recovered is None:
                await self._debit(ctx, planner_requests=1)
                try:
                    reasoning_stream_id = (
                        f"{self.scenario.provider}-agent:decision:{decision_key}"
                    )

                    async def emit_reasoning_delta(
                        content: str,
                        delta_index: int,
                        *,
                        _stream_id: str = reasoning_stream_id,
                        _decision_key: str = decision_key,
                    ) -> None:
                        nonlocal streamed_reasoning
                        emitted = await self._emit_provider_reasoning_delta(
                            ctx,
                            content=content,
                            stream_id=_stream_id,
                            delta_index=delta_index,
                            trace_key=(
                                f"decision:{_decision_key}:reasoning:delta:{delta_index}"
                            ),
                        )
                        streamed_reasoning = streamed_reasoning or emitted is not None

                    planner_kwargs = {
                        "messages": deepcopy(ctx.messages),
                        "tools": [
                            ctx.catalog[name].model_copy(deep=True)
                            for name in sorted(ctx.catalog)
                        ],
                    }
                    # Streaming every reasoning delta durably (one event
                    # insert plus a version read per delta) dominates planner
                    # wall time for long reasoning outputs and can exhaust
                    # planner_timeout_seconds before the decision returns.
                    # Providers that disable streaming still record the
                    # complete reasoning once per decision through
                    # MODEL_DECISION and TRACE_REASONING.
                    if (
                        self.stream_planner_reasoning
                        and self._accepts_keyword_argument(
                            self.planner.plan,
                            "reasoning_callback",
                        )
                    ):
                        planner_kwargs["reasoning_callback"] = emit_reasoning_delta
                    raw = await self._await_bounded(
                        self.planner.plan(**planner_kwargs),
                        ctx,
                        cap_seconds=self.planner_timeout_seconds,
                    )
                    raw_reasoning = getattr(self.planner, "last_reasoning_content", None)
                    reasoning = (
                        raw_reasoning
                        if not streamed_reasoning
                        and isinstance(raw_reasoning, str)
                        and raw_reasoning.strip()
                        else None
                    )
                    action = parse_agent_action(raw)
                except Exception as exc:
                    last_error = str(exc) or type(exc).__name__
                    if self._deadline_reached(ctx):
                        return self._deadline_finish(
                            "The MCP investigation deadline was reached while planning."
                        )
                else:
                    await self._debit(ctx, accepted_decisions=1)
                    if isinstance(action, CallToolAction):
                        prepared = self._prepare_call(ctx, action)
                    await self._emit_idempotent(
                        ctx,
                        AgentEventKind.MODEL_DECISION,
                        {
                            "action": action.action,
                            "tool_name": getattr(action, "tool_name", None),
                            "decision": action.model_dump(mode="json"),
                            "reasoning": reasoning,
                            "decision_key": decision_key,
                            "prepared_call": (
                                prepared.model_dump(mode="json")
                                if prepared is not None
                                else None
                            ),
                        },
                        idempotency_key=f"decision:{decision_key}",
                    )
            else:
                action, reasoning, prepared = recovered

            if action is not None:
                if reasoning is not None:
                    await self._emit_provider_reasoning(
                        ctx,
                        content=reasoning,
                        trace_key=f"decision:{decision_key}:reasoning",
                    )
                await self._emit_trace(
                    ctx,
                    AgentEventKind.TRACE_ACTION,
                    actor=f"{self.scenario.provider}_agent",
                    content=json.dumps(
                        action.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                        default=str,
                    ),
                    trace_key=f"decision:{decision_key}:action",
                )
                ctx.messages.append(
                    {
                        "role": "assistant",
                        "content": json.dumps(
                            action.model_dump(mode="json"),
                            ensure_ascii=True,
                            sort_keys=True,
                        ),
                    }
                )
                if isinstance(action, CallToolAction):
                    if prepared is None:
                        raise HarnessInfrastructureError(
                            "durable MCP call decision has no prepared invocation"
                        )
                    return prepared
                if isinstance(action, FinishAction):
                    return Finish(
                        reason=action.reason,
                        summary=action.summary,
                        requires_human=action.reason
                        in {
                            RuntimeStopReason.HUMAN_INPUT_REQUIRED,
                            RuntimeStopReason.AMBIGUOUS_TARGET,
                            RuntimeStopReason.NO_SAFE_ACTION,
                        },
                        model_requested=True,
                    )
                assert isinstance(action, RequestHumanInputAction)
                return Finish(
                    reason=RuntimeStopReason.HUMAN_INPUT_REQUIRED,
                    summary=f"{action.reason} {action.question}",
                    requires_human=True,
                    model_requested=True,
                )

            repair_message = {
                "role": "user",
                "content": (
                    "Return exactly one valid Agent action: call_tool, finish, or "
                    f"request_human_input. Previous response was invalid: {last_error}"
                ),
            }
            ctx.messages.append(repair_message)
            await self._emit(
                ctx,
                AgentEventKind.PLANNER_REPAIR_REQUESTED,
                {"error": last_error},
            )
            await self._checkpoint(ctx)

    async def _execute_call(
        self,
        ctx: _RunContext[StateT, ObservationT],
        prepared: PreparedCall,
    ) -> tuple[Finish | None, RetryDirective | None]:
        spec = self._tool_spec(ctx, prepared)
        fingerprint = ToolInvocation.build_fingerprint(
            tool_name=prepared.tool_name,
            effective_arguments=prepared.effective_arguments,
        )
        if ctx.pending_retry is not None:
            pending_fingerprint = ToolInvocation.build_fingerprint(
                tool_name=ctx.pending_retry.tool_name,
                effective_arguments=ctx.pending_retry.effective_arguments,
            )
            if pending_fingerprint != fingerprint:
                raise HarnessInfrastructureError(
                    "pending retry does not match the prepared invocation"
                )
        timeout_seconds = min(spec.timeout, prepared.timeout_seconds or spec.timeout)
        invocation = self._pending_invocation(ctx)
        if invocation is not None:
            if invocation.fingerprint != fingerprint:
                raise HarnessInfrastructureError(
                    "checkpoint PENDING invocation does not match the prepared call"
                )
            invocation_index = self._invocation_index(ctx, invocation.invocation_id)
        else:
            attempt = ctx.attempts.get(fingerprint, 0) + 1
            now = datetime.now(UTC)
            call_deadline = now + timedelta(seconds=timeout_seconds)
            if ctx.deadline is not None:
                call_deadline = min(call_deadline, ctx.deadline)
            invocation = ToolInvocation(
                run_id=ctx.run_id,
                parent_run_id=ctx.parent_run_id,
                tool_name=prepared.tool_name,
                provider=spec.provider,
                objective=prepared.objective,
                hypothesis_ids=prepared.hypothesis_ids,
                model_arguments=prepared.model_arguments,
                effective_arguments=prepared.effective_arguments,
                fingerprint=fingerprint,
                attempt=attempt,
                deadline=call_deadline,
            )
            ctx.invocations.append(invocation)
            invocation_index = len(ctx.invocations) - 1
            ctx.fingerprints.add(fingerprint)
            ctx.attempts[fingerprint] = attempt
            ctx.active_call = prepared.model_copy(deep=True)
            # The checkpoint owns invocation identity before any remote-call
            # budget can be consumed. Recovery can therefore always explain
            # and continue a crash that occurs before the transport boundary.
            await self._checkpoint(ctx)
            await self._persist_invocation(ctx, invocation)

        ctx.active_call = prepared.model_copy(deep=True)
        if (
            prepared.local_result is None
            and invocation.invocation_id not in ctx.remote_debited_invocations
        ):
            await self._debit(
                ctx,
                invocation_id=invocation.invocation_id,
                remote_tool_calls=1,
            )
        started = self._transition_invocation(
            invocation,
            status=ToolInvocationStatus.STARTED,
            started_at=datetime.now(UTC),
        )
        ctx.invocations[invocation_index] = started
        await self._persist_invocation(ctx, started)
        await self._emit_invocation(ctx, started, AgentEventKind.TOOL_INVOCATION_STARTED)
        ctx.pending_retry = None
        ctx.retry_not_before = None
        await self._checkpoint(ctx)

        if prepared.local_result is not None:
            await self._stage_response_lineage(
                ctx,
                invocation=started,
                prepared=prepared,
                response=prepared.local_result,
                is_remote=False,
            )
            return await self._complete_response(
                ctx,
                prepared=prepared,
                started=started,
                fingerprint=fingerprint,
                raw_result=deepcopy(prepared.local_result),
            )

        try:
            assert ctx.session is not None
            raw_result = await self._await_bounded(
                ctx.session.call_tool(prepared.tool_name, prepared.effective_arguments),
                ctx,
                cap_seconds=timeout_seconds,
            )
        except Exception as exc:
            return await self._complete_failure(ctx, prepared, started, fingerprint, exc)

        await self._stage_response_lineage(
            ctx,
            invocation=started,
            prepared=prepared,
            response=raw_result,
            is_remote=True,
        )

        return await self._complete_response(
            ctx,
            prepared=prepared,
            started=started,
            fingerprint=fingerprint,
            raw_result=raw_result,
        )

    async def _complete_response(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        prepared: PreparedCall,
        started: ToolInvocation,
        fingerprint: str,
        raw_result: Any,
    ) -> tuple[Finish | None, RetryDirective | None]:
        """Apply one durable response without crossing the transport again."""

        prepared.metadata["mcp_raw_response"] = self._portable_remote_response(raw_result)

        try:
            transition = self.scenario.on_result(ctx.state, prepared, raw_result)
            if transition.status not in {
                ToolInvocationStatus.SUCCEEDED,
                ToolInvocationStatus.NO_DATA,
            }:
                raise ValueError("successful scenario transition must be SUCCEEDED or NO_DATA")
        except Exception as exc:
            try:
                result_error_directive = self.scenario.result_error_directive(
                    ctx.state,
                    prepared,
                    exc,
                )
            except Exception as directive_exc:
                processing_error = _HostResultProcessingError(directive_exc)
                return await self._complete_failure(
                    ctx,
                    prepared,
                    started,
                    fingerprint,
                    processing_error,
                    directive=RetryDirective(
                        reason=str(processing_error),
                        reconnect=False,
                        retry_call=False,
                        continue_run=False,
                        unknown_outcome=False,
                    ),
                )
            if result_error_directive is not None:
                return await self._complete_failure(
                    ctx,
                    prepared,
                    started,
                    fingerprint,
                    exc,
                    directive=result_error_directive,
                )
            processing_error = _HostResultProcessingError(exc)
            return await self._complete_failure(
                ctx,
                prepared,
                started,
                fingerprint,
                processing_error,
                directive=RetryDirective(
                    reason=str(processing_error),
                    reconnect=False,
                    retry_call=False,
                    continue_run=False,
                    unknown_outcome=False,
                ),
            )

        completed = self._transition_invocation(
            started,
            status=transition.status,
            completed_at=datetime.now(UTC),
            artifact_ref=transition.artifact_ref,
        )
        invocation_index = self._invocation_index(ctx, started.invocation_id)
        ctx.invocations[invocation_index] = completed
        ctx.state = transition.state
        ctx.observations.append(
            HarnessObservation(
                invocation_id=completed.invocation_id,
                fingerprint=fingerprint,
                status=completed.status,
                payload=transition.observation,
            )
        )
        self._append_observation_message(ctx, transition, completed)
        ctx.active_call = None
        # The first checkpoint is the recovery source of truth. A crash after
        # it can backfill the artifact, invocation row, and terminal event
        # without calling the remote MCP tool again.
        await self._checkpoint(ctx)
        await self._emit_observation_trace(ctx, completed, transition.observation)
        await self._persist_artifact(ctx, completed)
        await self._persist_invocation(ctx, completed)
        kind = (
            AgentEventKind.TOOL_INVOCATION_NO_DATA
            if completed.status == ToolInvocationStatus.NO_DATA
            else AgentEventKind.TOOL_INVOCATION_SUCCEEDED
        )
        await self._emit_invocation(ctx, completed, kind)
        await self._checkpoint(ctx)
        return None, None

    async def _complete_failure(
        self,
        ctx: _RunContext[StateT, ObservationT],
        prepared: PreparedCall,
        started: ToolInvocation,
        fingerprint: str,
        exc: Exception,
        *,
        directive: RetryDirective | None = None,
    ) -> tuple[Finish | None, RetryDirective | None]:
        directive = directive or self.scenario.retry_directive(ctx.state, prepared, exc)
        error = self._invocation_error(exc, directive)
        status = (
            ToolInvocationStatus.UNKNOWN_OUTCOME
            if directive.unknown_outcome
            else ToolInvocationStatus.TIMED_OUT
            if isinstance(exc, TimeoutError)
            else ToolInvocationStatus.FAILED
        )
        completed = self._transition_invocation(
            started,
            status=status,
            completed_at=datetime.now(UTC),
            error=error,
        )
        ctx.invocations[self._invocation_index(ctx, started.invocation_id)] = completed
        try:
            transition = self.scenario.on_failure(ctx.state, prepared, error, status)
        except Exception:
            transition = ScenarioTransition(state=ctx.state)
        ctx.state = transition.state
        ctx.observations.append(
            HarnessObservation(
                invocation_id=completed.invocation_id,
                fingerprint=fingerprint,
                status=status,
                payload=transition.observation,
                error=error,
            )
        )
        ctx.active_call = None
        retry_scheduled = self._schedule_retry(
            ctx,
            prepared=prepared,
            invocation=completed,
            error=error,
            directive=directive,
        )
        if not retry_scheduled:
            self._append_observation_message(ctx, transition, completed)
        await self._checkpoint(ctx)
        await self._emit_observation_trace(ctx, completed, transition.observation)
        await self._persist_invocation(ctx, completed)
        await self._emit_invocation(
            ctx,
            completed,
            AgentEventKind.TOOL_INVOCATION_UNKNOWN_OUTCOME
            if status == ToolInvocationStatus.UNKNOWN_OUTCOME
            else AgentEventKind.TOOL_INVOCATION_TIMED_OUT
            if status == ToolInvocationStatus.TIMED_OUT
            else AgentEventKind.TOOL_INVOCATION_FAILED,
        )
        await self._checkpoint(ctx)

        if self._deadline_reached(ctx):
            return (
                self._deadline_finish(
                    "The MCP investigation deadline was reached during a tool call."
                ),
                None,
            )

        scenario_finish = self.scenario.completion(ctx.state, tuple(ctx.observations))
        if scenario_finish is not None:
            return scenario_finish, None
        if not directive.continue_run:
            return (
                Finish(
                    reason=RuntimeStopReason.FAILED,
                    summary=directive.reason,
                    requires_human=True,
                ),
                None,
            )
        if directive.reconnect:
            session_finish = await self._ensure_session(ctx)
            if session_finish is not None:
                return session_finish, None
        if retry_scheduled:
            return None, directive
        return None, None

    async def _reconcile_inflight(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> None:
        observed_invocations = {item.invocation_id for item in ctx.observations}
        for index, invocation in enumerate(ctx.invocations):
            if invocation.status != ToolInvocationStatus.STARTED:
                continue
            prepared = self._active_or_reconstructed_call(ctx, invocation)
            if prepared.local_result is not None:
                await self._stage_response_lineage(
                    ctx,
                    invocation=invocation,
                    prepared=prepared,
                    response=prepared.local_result,
                    is_remote=False,
                )
                finish, _retry = await self._complete_response(
                    ctx,
                    prepared=prepared,
                    started=invocation,
                    fingerprint=invocation.fingerprint,
                    raw_result=deepcopy(prepared.local_result),
                )
                if finish is not None:
                    ctx.finish = finish
                observed_invocations.add(invocation.invocation_id)
                continue
            recovered_response = await self._load_remote_response(
                ctx,
                invocation=invocation,
                prepared=prepared,
            )
            if recovered_response is not None:
                finish, _retry = await self._complete_response(
                    ctx,
                    prepared=prepared,
                    started=invocation,
                    fingerprint=invocation.fingerprint,
                    raw_result=recovered_response,
                )
                if finish is not None:
                    ctx.finish = finish
                observed_invocations.add(invocation.invocation_id)
                continue
            recovered = _RecoveredUnknownOutcome(
                "The process stopped while the MCP invocation was in flight."
            )
            directive = self.scenario.retry_directive(ctx.state, prepared, recovered)
            error = self._invocation_error(recovered, directive)
            completed = self._transition_invocation(
                invocation,
                status=ToolInvocationStatus.UNKNOWN_OUTCOME,
                completed_at=max(datetime.now(UTC), invocation.started_at or datetime.now(UTC)),
                error=error,
            )
            ctx.invocations[index] = completed
            ctx.fingerprints.add(completed.fingerprint)
            if completed.invocation_id not in observed_invocations:
                try:
                    transition = self.scenario.on_failure(
                        ctx.state,
                        prepared,
                        error,
                        ToolInvocationStatus.UNKNOWN_OUTCOME,
                    )
                except Exception:
                    transition = ScenarioTransition(state=ctx.state)
                ctx.state = transition.state
                ctx.observations.append(
                    HarnessObservation(
                        invocation_id=completed.invocation_id,
                        fingerprint=completed.fingerprint,
                        status=ToolInvocationStatus.UNKNOWN_OUTCOME,
                        payload=transition.observation,
                        error=error,
                    )
                )
            if self._call_fingerprint(prepared) == completed.fingerprint:
                ctx.active_call = None
            retry_scheduled = self._schedule_retry(
                ctx,
                prepared=prepared,
                invocation=completed,
                error=error,
                directive=directive,
            )
            if completed.invocation_id not in observed_invocations and not retry_scheduled:
                self._append_observation_message(ctx, transition, completed)
            await self._checkpoint(ctx)
            await self._persist_invocation(ctx, completed)
            await self._emit_invocation(
                ctx,
                completed,
                AgentEventKind.TOOL_INVOCATION_UNKNOWN_OUTCOME,
            )
            await self._checkpoint(ctx)
            if retry_scheduled and directive.reconnect:
                # _run_loop establishes a fresh session before consuming the
                # durable retry, so recovery does not reconnect twice here.
                continue

    async def _reconcile_durable_invocations(
        self,
        ctx: _RunContext[StateT, ObservationT],
        events: list[AgentEvent],
    ) -> None:
        """Reconcile a checkpoint with invocation rows and an event-stream tail."""

        terminal_events = {
            event.invocation_id: event
            for event in events
            if event.invocation_id is not None
            and event.payload.get("provider") == self.scenario.provider
            and event_matches_dispatch_scope(event, self.dispatch_scope_id)
            and event.kind
            in {
                AgentEventKind.TOOL_INVOCATION_SUCCEEDED,
                AgentEventKind.TOOL_INVOCATION_NO_DATA,
                AgentEventKind.TOOL_INVOCATION_FAILED,
                AgentEventKind.TOOL_INVOCATION_TIMED_OUT,
                AgentEventKind.TOOL_INVOCATION_UNKNOWN_OUTCOME,
                AgentEventKind.TOOL_INVOCATION_CANCELLED,
                AgentEventKind.TOOL_INVOCATION_SKIPPED,
            }
        }
        started_events = {
            event.invocation_id: event
            for event in events
            if event.invocation_id is not None
            and event.payload.get("provider") == self.scenario.provider
            and event_matches_dispatch_scope(event, self.dispatch_scope_id)
            and event.kind == AgentEventKind.TOOL_INVOCATION_STARTED
        }
        observed_ids = {item.invocation_id for item in ctx.observations}
        known_ids = {item.invocation_id for item in ctx.invocations}

        unknown_started_ids = set(started_events) - known_ids
        if unknown_started_ids:
            raise HarnessInfrastructureError(
                "durable STARTED event has no invocation identity in the checkpoint"
            )

        # A previous process may have committed a terminal row/event after the
        # last checkpoint. Import it before deciding that a STARTED call has an
        # unknown outcome, and never issue the same fingerprint again.
        for invocation_id, event in terminal_events.items():
            if invocation_id in known_ids:
                continue
            persisted = await self._load_invocation(invocation_id)
            if persisted is not None and self._is_terminal_status(persisted.status):
                if persisted.run_id != ctx.run_id:
                    raise HarnessInfrastructureError("persisted invocation belongs to another run")
                ctx.invocations.append(persisted)
                known_ids.add(invocation_id)
                ctx.fingerprints.add(persisted.fingerprint)
                ctx.attempts[persisted.fingerprint] = max(
                    ctx.attempts.get(persisted.fingerprint, 0),
                    persisted.attempt,
                )
                if invocation_id not in observed_ids:
                    ctx.observations.append(
                        HarnessObservation(
                            invocation_id=invocation_id,
                            fingerprint=persisted.fingerprint,
                            status=persisted.status,
                            error=persisted.error,
                        )
                    )
                    observed_ids.add(invocation_id)
            else:
                fingerprint = event.payload.get("fingerprint")
                if isinstance(fingerprint, str) and fingerprint:
                    ctx.fingerprints.add(fingerprint)

        for index, invocation in enumerate(ctx.invocations):
            if self._is_terminal_status(invocation.status):
                continue
            persisted = await self._load_invocation(invocation.invocation_id)
            if persisted is not None:
                self._validate_recovered_invocation(invocation, persisted)
            if persisted is not None and (
                self._is_terminal_status(persisted.status)
                or persisted.status == ToolInvocationStatus.STARTED
            ):
                recovered = persisted
            else:
                recovered = self._invocation_from_terminal_event(
                    invocation,
                    terminal_events.get(invocation.invocation_id),
                )
                if recovered is None and invocation.status == ToolInvocationStatus.PENDING:
                    started_event = started_events.get(invocation.invocation_id)
                    if started_event is not None:
                        recovered = self._transition_invocation(
                            invocation,
                            status=ToolInvocationStatus.STARTED,
                            started_at=max(started_event.occurred_at, invocation.created_at),
                        )
            if invocation.status == ToolInvocationStatus.PENDING and (
                recovered is None
                or (
                    recovered.status == ToolInvocationStatus.STARTED
                    and invocation.invocation_id not in ctx.remote_debited_invocations
                )
            ):
                self._refresh_pending_call_policy(ctx, invocation)
            if recovered is None:
                continue
            self._validate_recovered_invocation(invocation, recovered)
            if (
                invocation.status == ToolInvocationStatus.PENDING
                and recovered.status == ToolInvocationStatus.STARTED
                and invocation.invocation_id not in ctx.remote_debited_invocations
                and not self._is_local_invocation(ctx, invocation)
            ):
                raise HarnessInfrastructureError(
                    "durable STARTED invocation has no correlated remote tool debit"
                )
            ctx.invocations[index] = recovered
            ctx.fingerprints.add(recovered.fingerprint)
            ctx.attempts[recovered.fingerprint] = max(
                ctx.attempts.get(recovered.fingerprint, 0),
                recovered.attempt,
            )
            if (
                self._is_terminal_status(recovered.status)
                and recovered.invocation_id not in observed_ids
            ):
                ctx.observations.append(
                    HarnessObservation(
                        invocation_id=recovered.invocation_id,
                        fingerprint=recovered.fingerprint,
                        status=recovered.status,
                        error=recovered.error,
                    )
                )
                observed_ids.add(recovered.invocation_id)

        terminal_event_ids = set(terminal_events)
        for invocation in ctx.invocations:
            if (
                not self._is_terminal_status(invocation.status)
                or invocation.invocation_id in terminal_event_ids
            ):
                continue
            await self._persist_artifact(ctx, invocation)
            await self._persist_invocation(ctx, invocation)
            await self._emit_invocation(
                ctx,
                invocation,
                self._terminal_event_kind(invocation.status),
            )

    def _reconcile_budget_tail(
        self,
        ctx: _RunContext[StateT, ObservationT],
        events: list[AgentEvent],
        *,
        after_sequence: int,
    ) -> None:
        """Replay durable debits emitted after the latest provider checkpoint."""

        provider_debits = self._provider_remote_debit_events(
            events,
        )
        for invocation_id, event in provider_debits.items():
            if event.sequence <= after_sequence and event_matches_dispatch_scope(
                event, self.dispatch_scope_id
            ):
                ctx.remote_debited_invocations.add(invocation_id)

        for event in events:
            if (
                event.sequence <= after_sequence
                or event.kind != AgentEventKind.BUDGET_DEBITED
                or event.payload.get("provider") != self.scenario.provider
                or not event_matches_dispatch_scope(event, self.dispatch_scope_id)
            ):
                continue
            raw_amounts = event.payload.get("amounts")
            raw_consumed = event.payload.get("consumed")
            if not isinstance(raw_amounts, dict) or not isinstance(raw_consumed, dict):
                raise HarnessInfrastructureError(
                    "budget debit event is missing its durable accounting payload"
                )
            try:
                amounts = BudgetAmounts.model_validate(raw_amounts)
                expected_consumed = BudgetAmounts.model_validate(raw_consumed)
                if amounts.remote_tool_calls:
                    if amounts.remote_tool_calls != 1 or event.invocation_id is None:
                        raise HarnessInfrastructureError(
                            "remote tool debit must identify exactly one invocation"
                        )
                    if event.invocation_id in ctx.remote_debited_invocations:
                        raise HarnessInfrastructureError(
                            "duplicate remote tool debit exists for one invocation"
                        )
                    ctx.remote_debited_invocations.add(event.invocation_id)
                actual = ctx.budget.debit(**amounts.model_dump(mode="python"))
            except Exception as exc:
                if isinstance(exc, HarnessInfrastructureError):
                    raise
                raise HarnessInfrastructureError("failed to replay a durable budget debit") from exc
            if actual.consumed != expected_consumed:
                raise HarnessInfrastructureError(
                    "durable budget debit does not continue the checkpoint ledger"
                )

    async def _ensure_run_completed_event(
        self,
        ctx: _RunContext[StateT, ObservationT],
        events: list[AgentEvent],
    ) -> None:
        if ctx.finish is None:
            return
        if any(
            event.kind == AgentEventKind.RUN_COMPLETED
            and event.payload.get("provider") in {None, self.scenario.provider}
            and event_matches_dispatch_scope(event, self.dispatch_scope_id)
            for event in events
        ):
            return
        await self._emit(
            ctx,
            AgentEventKind.RUN_COMPLETED,
            {
                "reason": ctx.finish.reason.value,
                "requires_human": ctx.finish.requires_human,
                "summary": ctx.finish.summary,
                "provider": self.scenario.provider,
            },
        )

    async def _load_invocation(self, invocation_id: UUID) -> ToolInvocation | None:
        if self.invocation_store is None:
            return None
        loader = getattr(self.invocation_store, "load", None)
        if loader is None:
            return None
        loaded = await loader(invocation_id)
        return loaded.model_copy(deep=True) if loaded is not None else None

    def _schedule_retry(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        prepared: PreparedCall,
        invocation: ToolInvocation,
        error: InvocationError,
        directive: RetryDirective,
    ) -> bool:
        if not directive.retry_call:
            return False
        if directive.unknown_outcome and not directive.allow_unknown_outcome_retry:
            raise HarnessInfrastructureError(
                "unknown-outcome retry requires explicit authorization"
            )
        delay = 0
        retry_not_before = datetime.now(UTC) + timedelta(seconds=delay)
        if ctx.deadline is not None and retry_not_before >= ctx.deadline:
            self._append_retry_suppressed_message(
                ctx,
                code="retry_exceeds_deadline",
                detail="Retry backoff would exceed the MCP investigation deadline.",
            )
            return False
        if ctx.pending_retry is not None:
            existing = ToolInvocation.build_fingerprint(
                tool_name=ctx.pending_retry.tool_name,
                effective_arguments=ctx.pending_retry.effective_arguments,
            )
            if existing != invocation.fingerprint:
                raise HarnessInfrastructureError(
                    "multiple pending retries are not supported in one sequential MCP run"
                )
        ctx.pending_retry = prepared.model_copy(deep=True)
        ctx.retry_not_before = retry_not_before
        ctx.fingerprints.discard(invocation.fingerprint)
        return True

    async def _wait_for_pending_retry(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> Finish | None:
        if ctx.retry_not_before is None:
            return None
        delay = (ctx.retry_not_before - datetime.now(UTC)).total_seconds()
        if delay <= 0:
            return None
        if (
            ctx.deadline is not None
            and datetime.now(UTC) + timedelta(seconds=delay) >= ctx.deadline
        ):
            return Finish(
                reason=RuntimeStopReason.DEADLINE_EXCEEDED,
                summary="The MCP investigation deadline was reached before a policy retry.",
                requires_human=True,
            )
        await asyncio.sleep(delay)
        return None

    @staticmethod
    def _append_retry_suppressed_message(
        ctx: _RunContext[StateT, ObservationT],
        *,
        code: str,
        detail: str,
    ) -> None:
        ctx.messages.append(
            {
                "role": "user",
                "content": json.dumps(
                    {"host_event": "retry_suppressed", "code": code, "detail": detail},
                    ensure_ascii=True,
                    sort_keys=True,
                ),
            }
        )

    @staticmethod
    def _is_terminal_status(status: ToolInvocationStatus) -> bool:
        return status in {
            ToolInvocationStatus.SUCCEEDED,
            ToolInvocationStatus.NO_DATA,
            ToolInvocationStatus.FAILED,
            ToolInvocationStatus.TIMED_OUT,
            ToolInvocationStatus.UNKNOWN_OUTCOME,
            ToolInvocationStatus.CANCELLED,
            ToolInvocationStatus.SKIPPED,
        }

    @staticmethod
    def _terminal_event_kind(status: ToolInvocationStatus) -> AgentEventKind:
        mapping = {
            ToolInvocationStatus.SUCCEEDED: AgentEventKind.TOOL_INVOCATION_SUCCEEDED,
            ToolInvocationStatus.NO_DATA: AgentEventKind.TOOL_INVOCATION_NO_DATA,
            ToolInvocationStatus.FAILED: AgentEventKind.TOOL_INVOCATION_FAILED,
            ToolInvocationStatus.TIMED_OUT: AgentEventKind.TOOL_INVOCATION_TIMED_OUT,
            ToolInvocationStatus.UNKNOWN_OUTCOME: (AgentEventKind.TOOL_INVOCATION_UNKNOWN_OUTCOME),
            ToolInvocationStatus.CANCELLED: AgentEventKind.TOOL_INVOCATION_CANCELLED,
            ToolInvocationStatus.SKIPPED: AgentEventKind.TOOL_INVOCATION_SKIPPED,
        }
        try:
            return mapping[status]
        except KeyError as exc:
            raise HarnessInfrastructureError(
                f"terminal invocation status has no event mapping: {status.value}"
            ) from exc

    def _invocation_from_terminal_event(
        self,
        invocation: ToolInvocation,
        event: AgentEvent | None,
    ) -> ToolInvocation | None:
        if event is None:
            return None
        try:
            status = ToolInvocationStatus(str(event.payload.get("status")))
        except ValueError:
            return None
        if not self._is_terminal_status(status):
            return None
        raw_error = event.payload.get("error")
        error = InvocationError.model_validate(raw_error) if isinstance(raw_error, dict) else None
        if (
            status
            in {
                ToolInvocationStatus.FAILED,
                ToolInvocationStatus.TIMED_OUT,
                ToolInvocationStatus.UNKNOWN_OUTCOME,
                ToolInvocationStatus.CANCELLED,
            }
            and error is None
        ):
            error = InvocationError(
                code="recovered_terminal_event",
                message="Recovered a terminal invocation from the Agent event stream.",
                details={"event_id": str(event.event_id)},
            )
        raw_artifact = event.payload.get("artifact_ref")
        artifact = (
            ArtifactRef.model_validate(raw_artifact) if isinstance(raw_artifact, dict) else None
        )
        return self._transition_invocation(
            invocation,
            status=status,
            completed_at=max(event.occurred_at, invocation.started_at or event.occurred_at),
            error=error,
            artifact_ref=artifact,
        )

    @staticmethod
    def _validate_recovered_invocation(
        expected: ToolInvocation,
        recovered: ToolInvocation,
    ) -> None:
        if (
            recovered.invocation_id != expected.invocation_id
            or recovered.run_id != expected.run_id
            or recovered.tool_name != expected.tool_name
            or recovered.fingerprint != expected.fingerprint
        ):
            raise HarnessInfrastructureError(
                "persisted invocation identity does not match the checkpoint"
            )

    async def _debit(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        invocation_id: UUID | None = None,
        **amounts: int | float,
    ) -> None:
        remote_tool_calls = amounts.get("remote_tool_calls", 0)
        if remote_tool_calls:
            if remote_tool_calls != 1 or invocation_id is None:
                raise HarnessInfrastructureError(
                    "remote tool debit must identify exactly one invocation"
                )
            if invocation_id in ctx.remote_debited_invocations:
                raise HarnessInfrastructureError(
                    "remote tool budget was already debited for this invocation"
                )
            await self._debit_remote_tool_call(ctx, invocation_id=invocation_id)
            return
        elif invocation_id is not None:
            raise HarnessInfrastructureError("invocation_id is valid only for a remote tool debit")
        snapshot = ctx.budget.debit(**amounts)
        try:
            await self._emit(
                ctx,
                AgentEventKind.BUDGET_DEBITED,
                {
                    "amounts": amounts,
                    "consumed": snapshot.consumed.model_dump(mode="json"),
                    "remaining": snapshot.remaining.model_dump(mode="json"),
                },
                invocation_id=invocation_id,
            )
        except Exception as exc:
            raise HarnessInfrastructureError("failed to record budget debit") from exc
        if invocation_id is not None:
            ctx.remote_debited_invocations.add(invocation_id)

    async def _debit_remote_tool_call(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        invocation_id: UUID,
    ) -> None:
        """Atomically record one run/provider remote call before transport.

        The scope-local ledger remains the checkpoint authority for this MCP
        investigation. The append-only run event stream serializes audit usage
        shared by sibling dispatch scopes and processes; it never caps calls.
        """

        before = ctx.budget.snapshot()
        reservation = ctx.budget.reserve(remote_tool_calls=1)
        reserved = ctx.budget.snapshot()
        expected_consumed = before.consumed.model_copy(
            update={
                "remote_tool_calls": before.consumed.remote_tool_calls + 1,
            }
        )
        settled = False
        try:
            while True:
                events = await self.event_sink.read(ctx.run_id)
                observed_version = max((event.version for event in events), default=0)
                if observed_version < ctx.event_version:
                    raise HarnessInfrastructureError(
                        "event stream is behind the MCP runtime context"
                    )
                ctx.event_version = observed_version
                provider_debits = self._provider_remote_debit_events(
                    events,
                )
                if invocation_id in provider_debits:
                    # Another live/resuming executor already recorded this
                    # invocation. Only resume reconciliation may adopt it.
                    raise HarnessInfrastructureError(
                        "remote tool budget debit was claimed concurrently for this invocation"
                    )
                provider_consumed = len(provider_debits)

                payload = {
                    "provider": self.scenario.provider,
                    "amounts": {"remote_tool_calls": 1},
                    "consumed": expected_consumed.model_dump(mode="json"),
                    "remaining": reserved.remaining.model_dump(mode="json"),
                    "provider_remote_tool_calls": {
                        "consumed": provider_consumed + 1,
                    },
                }
                if self.dispatch_scope_id is not None:
                    payload["dispatch_scope_id"] = str(self.dispatch_scope_id)
                event = AgentEvent(
                    run_id=ctx.run_id,
                    parent_run_id=ctx.parent_run_id,
                    invocation_id=invocation_id,
                    kind=AgentEventKind.BUDGET_DEBITED,
                    payload=payload,
                    correlation_id=ctx.run_id,
                )
                try:
                    committed = await self.event_sink.append(
                        event,
                        expected_version=observed_version,
                    )
                except EventVersionConflictError:
                    # Serialize audit usage with the conflicting writer before
                    # making the transport call.
                    continue
                except Exception as exc:
                    raise HarnessInfrastructureError(
                        "failed to record remote tool budget debit"
                    ) from exc

                snapshot = ctx.budget.debit(reservation)
                settled = True
                if snapshot.consumed != expected_consumed:
                    raise HarnessInfrastructureError(
                        "scope budget changed while committing a remote tool debit"
                    )
                ctx.event_version = committed.version
                ctx.remote_debited_invocations.add(invocation_id)
                return
        finally:
            if not settled:
                ctx.budget.release(reservation)

    def _provider_remote_debit_events(
        self,
        events: list[AgentEvent],
    ) -> dict[UUID, AgentEvent]:
        debits: dict[UUID, AgentEvent] = {}
        for event in events:
            if (
                event.kind != AgentEventKind.BUDGET_DEBITED
                or event.payload.get("provider") != self.scenario.provider
            ):
                continue
            raw_amounts = event.payload.get("amounts")
            if not isinstance(raw_amounts, dict):
                raise HarnessInfrastructureError(
                    "provider budget debit event is missing its amounts payload"
                )
            try:
                amounts = BudgetAmounts.model_validate(raw_amounts)
            except Exception as exc:
                raise HarnessInfrastructureError(
                    "provider budget debit event has an invalid amounts payload"
                ) from exc
            if not amounts.remote_tool_calls:
                continue
            if amounts.remote_tool_calls != 1 or event.invocation_id is None:
                raise HarnessInfrastructureError(
                    "remote tool debit must identify exactly one invocation"
                )
            if event.invocation_id in debits:
                raise HarnessInfrastructureError(
                    "duplicate remote tool debit exists for one invocation"
                )
            provider_budget = event.payload.get("provider_remote_tool_calls")
            if provider_budget is not None:
                if not isinstance(provider_budget, dict):
                    raise HarnessInfrastructureError(
                        "provider remote tool usage metadata is invalid"
                    )
            debits[event.invocation_id] = event
        return debits

    async def _emit_invocation(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
        kind: AgentEventKind,
    ) -> None:
        payload: dict[str, Any] = {
            "attempt": invocation.attempt,
            "fingerprint": invocation.fingerprint,
            "status": invocation.status.value,
            "tool_name": invocation.tool_name,
        }
        if invocation.error is not None:
            payload["error"] = invocation.error.model_dump(mode="json")
            payload["evidence_disposition"] = "MISSING"
            payload["is_contradiction"] = False
        if invocation.artifact_ref is not None:
            payload["artifact_ref"] = invocation.artifact_ref.model_dump(mode="json")
        await self._emit(ctx, kind, payload, invocation_id=invocation.invocation_id)

    async def _emit(
        self,
        ctx: _RunContext[StateT, ObservationT],
        kind: AgentEventKind,
        payload: dict[str, Any],
        *,
        invocation_id: UUID | None = None,
        event_id: UUID | None = None,
    ) -> AgentEvent:
        event_payload = {**payload, "provider": self.scenario.provider}
        if self.dispatch_scope_id is not None:
            event_payload["dispatch_scope_id"] = str(self.dispatch_scope_id)
        committed = await self.event_sink.append(
            AgentEvent(
                **({"event_id": event_id} if event_id is not None else {}),
                run_id=ctx.run_id,
                parent_run_id=ctx.parent_run_id,
                invocation_id=invocation_id,
                kind=kind,
                payload=event_payload,
                correlation_id=ctx.run_id,
            ),
            expected_version=ctx.event_version,
        )
        ctx.event_version = committed.version
        return committed

    def _decision_key(self, ctx: _RunContext[StateT, ObservationT]) -> str:
        payload = {
            "dispatch_scope_id": (
                str(self.dispatch_scope_id) if self.dispatch_scope_id is not None else None
            ),
            "messages": ctx.messages,
            "provider": self.scenario.provider,
            "tools": [
                ctx.catalog[name].model_dump(mode="json") for name in sorted(ctx.catalog)
            ],
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

    def _prepare_call(
        self,
        ctx: _RunContext[StateT, ObservationT],
        action: CallToolAction,
    ) -> PreparedCall:
        scenario_prepared = self.scenario.prepare_call(action, state=ctx.state)
        return scenario_prepared.model_copy(
            update={
                "tool_name": action.tool_name,
                "objective": action.objective,
                "hypothesis_ids": list(action.hypothesis_ids),
                "model_arguments": deepcopy(action.arguments),
                "effective_arguments": deepcopy(action.arguments),
            },
            deep=True,
        )

    async def _load_durable_decision(
        self,
        ctx: _RunContext[StateT, ObservationT],
        decision_key: str,
    ) -> tuple[Any, str | None, PreparedCall | None] | None:
        for event in reversed(await self.event_sink.read(ctx.run_id)):
            if (
                event.kind != AgentEventKind.MODEL_DECISION
                or event.payload.get("provider") != self.scenario.provider
                or event.payload.get("decision_key") != decision_key
                or not event_matches_dispatch_scope(event, self.dispatch_scope_id)
            ):
                continue
            raw_decision = event.payload.get("decision")
            try:
                action = parse_agent_action(raw_decision)
            except Exception as exc:
                raise HarnessInfrastructureError(
                    "durable MCP decision payload is invalid"
                ) from exc
            raw_reasoning = event.payload.get("reasoning")
            reasoning = (
                raw_reasoning
                if isinstance(raw_reasoning, str) and raw_reasoning.strip()
                else None
            )
            raw_prepared = event.payload.get("prepared_call")
            if isinstance(action, CallToolAction):
                if raw_prepared is None:
                    # Checkpoints written before prepared_call became durable can
                    # still resume, albeit without provider-native call context.
                    prepared = self._prepare_call(ctx, action)
                else:
                    try:
                        prepared = PreparedCall.model_validate(raw_prepared)
                    except Exception as exc:
                        raise HarnessInfrastructureError(
                            "durable MCP prepared-call payload is invalid"
                        ) from exc
                    if (
                        prepared.tool_name != action.tool_name
                        or prepared.objective != action.objective
                        or prepared.hypothesis_ids != list(action.hypothesis_ids)
                        or prepared.model_arguments != action.arguments
                        or prepared.effective_arguments != action.arguments
                    ):
                        raise HarnessInfrastructureError(
                            "durable MCP prepared call does not match its decision"
                        )
                    # Reapply current Host policy while retaining durable
                    # provider-native context such as response item IDs.
                    current_prepared = self._prepare_call(ctx, action)
                    durable_context_metadata = {
                        key: deepcopy(prepared.metadata[key])
                        for key in _DURABLE_CALL_CONTEXT_METADATA_KEYS
                        if key in prepared.metadata
                    }
                    prepared = current_prepared.model_copy(
                        update={
                            "metadata": {
                                **deepcopy(current_prepared.metadata),
                                **durable_context_metadata,
                            }
                        },
                        deep=True,
                    )
            else:
                if raw_prepared is not None:
                    raise HarnessInfrastructureError(
                        "non-call durable MCP decision contains a prepared invocation"
                    )
                prepared = None
            return action, reasoning, prepared
        return None

    async def _emit_trace(
        self,
        ctx: _RunContext[StateT, ObservationT],
        kind: AgentEventKind,
        *,
        actor: str,
        content: str,
        trace_key: str,
        invocation_id: UUID | None = None,
    ) -> AgentEvent:
        if kind not in {
            AgentEventKind.TRACE_REASONING,
            AgentEventKind.TRACE_ACTION,
            AgentEventKind.TRACE_OBSERVATION,
        }:
            raise ValueError("_emit_trace accepts only UI trace event kinds")
        return await self._emit_idempotent(
            ctx,
            kind,
            {
                "actor": actor,
                "content": content,
                "scope": "mcp_internal",
                "trace_key": trace_key,
            },
            idempotency_key=f"trace:{kind.value}:{trace_key}",
            invocation_id=invocation_id,
        )

    async def _emit_provider_reasoning(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        content: str,
        trace_key: str,
    ) -> AgentEvent | None:
        from app.agent_runtime.trace import AgentTraceEmitter, AgentTraceScope

        emitter = AgentTraceEmitter(
            self.event_sink,
            run_id=ctx.run_id,
            actor=f"{self.scenario.provider}_agent",
            provider=self.scenario.provider,
            scope=AgentTraceScope.MCP_INTERNAL,
        )
        event = await emitter.emit_reasoning(content, trace_key=trace_key)
        ctx.event_version = await self.event_sink.current_version(ctx.run_id)
        return event

    async def _emit_provider_reasoning_delta(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        content: str,
        stream_id: str,
        delta_index: int,
        trace_key: str,
    ) -> AgentEvent | None:
        from app.agent_runtime.trace import AgentTraceEmitter, AgentTraceScope

        emitter = AgentTraceEmitter(
            self.event_sink,
            run_id=ctx.run_id,
            actor=f"{self.scenario.provider}_agent",
            provider=self.scenario.provider,
            scope=AgentTraceScope.MCP_INTERNAL,
        )
        event = await emitter.emit_reasoning_delta(
            content,
            stream_id=stream_id,
            delta_index=delta_index,
            trace_key=trace_key,
        )
        ctx.event_version = await self.event_sink.current_version(ctx.run_id)
        return event

    async def _emit_observation_trace(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
        observation: ObservationT | None,
    ) -> AgentEvent | None:
        if observation is None:
            return None
        return await self._emit_trace(
            ctx,
            AgentEventKind.TRACE_OBSERVATION,
            actor=invocation.tool_name,
            content=json.dumps(
                observation,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ),
            trace_key=f"invocation:{invocation.invocation_id}:{invocation.status.value}",
            invocation_id=invocation.invocation_id,
        )

    async def _ensure_observation_trace_events(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> None:
        invocations = {item.invocation_id: item for item in ctx.invocations}
        for observation in ctx.observations:
            invocation = invocations.get(observation.invocation_id)
            if invocation is None or observation.payload is None:
                continue
            await self._emit_observation_trace(ctx, invocation, observation.payload)

    async def _emit_idempotent(
        self,
        ctx: _RunContext[StateT, ObservationT],
        kind: AgentEventKind,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        invocation_id: UUID | None = None,
    ) -> AgentEvent:
        scope = str(self.dispatch_scope_id) if self.dispatch_scope_id is not None else "root"
        event_id = uuid5(
            ctx.run_id,
            f"mcp-runtime-v1:{self.scenario.provider}:{scope}:{idempotency_key}",
        )
        expected_payload = {**payload, "provider": self.scenario.provider}
        if self.dispatch_scope_id is not None:
            expected_payload["dispatch_scope_id"] = str(self.dispatch_scope_id)
        events = await self.event_sink.read(ctx.run_id)
        existing = next((event for event in events if event.event_id == event_id), None)
        if existing is not None:
            existing_payload = existing.payload
            if (
                kind
                in {
                    AgentEventKind.TRACE_REASONING,
                    AgentEventKind.TRACE_ACTION,
                    AgentEventKind.TRACE_OBSERVATION,
                }
                and "scope" not in existing_payload
            ):
                existing_payload = {**existing_payload, "scope": "mcp_internal"}
            if (
                existing.kind != kind
                or existing.invocation_id != invocation_id
                or existing_payload != expected_payload
            ):
                raise HarnessInfrastructureError(
                    f"idempotent MCP event {event_id} conflicts with durable history"
                )
            ctx.event_version = max(ctx.event_version, max(item.version for item in events))
            return existing
        actual_version = max((event.version for event in events), default=0)
        if actual_version > ctx.event_version:
            ctx.event_version = actual_version
        return await self._emit(
            ctx,
            kind,
            payload,
            invocation_id=invocation_id,
            event_id=event_id,
        )

    async def _checkpoint(self, ctx: _RunContext[StateT, ObservationT]) -> None:
        await self._sync_wall_time(ctx)
        if self.checkpoint_hook is None:
            return
        await self.checkpoint_hook(await self._snapshot(ctx))

    async def _persist_invocation(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
    ) -> None:
        try:
            if self.invocation_store is not None:
                await self.invocation_store.save(invocation.model_copy(deep=True))
        except Exception as exc:
            raise HarnessInfrastructureError(
                f"failed to persist invocation {invocation.invocation_id}"
            ) from exc

    async def _persist_artifact(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
    ) -> None:
        if invocation.artifact_ref is None or self.artifact_store is None:
            return
        try:
            await self.artifact_store.save(
                run_id=ctx.run_id,
                invocation_id=invocation.invocation_id,
                artifact=invocation.artifact_ref.model_copy(deep=True),
            )
        except Exception as exc:
            raise HarnessInfrastructureError(
                f"failed to persist artifact {invocation.artifact_ref.artifact_id}"
            ) from exc

    async def _stage_response_lineage(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        invocation: ToolInvocation,
        prepared: PreparedCall,
        response: Any,
        is_remote: bool,
    ) -> None:
        record = RemoteResponseRecord(
            invocation_id=invocation.invocation_id,
            tool_name=prepared.tool_name,
            arguments=deepcopy(prepared.effective_arguments),
            response=self._portable_remote_response(response),
            is_remote=is_remote,
        )
        existing = ctx.remote_responses.get(invocation.invocation_id)
        if existing is not None and existing != record:
            raise HarnessInfrastructureError(
                "checkpoint response lineage conflicts with the completed invocation"
            )
        ctx.remote_responses[invocation.invocation_id] = record
        # Checkpoint before scenario processing so recovery can apply the same
        # response without repeating either transport or local policy work.
        await self._checkpoint(ctx)

    async def _persist_deferred_remote_responses(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> None:
        if self.remote_response_store is None:
            return
        for invocation in ctx.invocations:
            record = ctx.remote_responses.get(invocation.invocation_id)
            if record is None or not record.is_remote:
                continue
            try:
                await self.remote_response_store.save(
                    run_id=ctx.run_id,
                    invocation_id=record.invocation_id,
                    tool_name=record.tool_name,
                    arguments=deepcopy(record.arguments),
                    response=deepcopy(record.response),
                )
            except Exception as exc:
                raise HarnessInfrastructureError(
                    "failed to persist remote MCP responses after investigation completion"
                ) from exc

    async def _load_remote_response(
        self,
        ctx: _RunContext[StateT, ObservationT],
        *,
        invocation: ToolInvocation,
        prepared: PreparedCall,
    ) -> Any | None:
        staged = ctx.remote_responses.get(invocation.invocation_id)
        if staged is not None:
            if (
                not staged.is_remote
                or prepared.local_result is not None
                or staged.tool_name != prepared.tool_name
                or staged.arguments != prepared.effective_arguments
            ):
                raise HarnessInfrastructureError(
                    "checkpoint remote MCP response does not match its invocation"
                )
            return deepcopy(staged.response)
        # Audit stores have no response-format discriminator and may contain
        # legacy sanitized artifacts. Only a response carried by the same
        # checkpoint can safely complete an interrupted invocation.
        return None

    def _validate_recovered_remote_response_lineage(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> None:
        if self.remote_response_store is None:
            return
        for invocation in ctx.invocations:
            if invocation.status not in {
                ToolInvocationStatus.SUCCEEDED,
                ToolInvocationStatus.NO_DATA,
            }:
                continue
            record = ctx.remote_responses.get(invocation.invocation_id)
            if record is None:
                raise HarnessInfrastructureError(
                    "successful MCP invocation is missing its checkpointed raw response"
                )
            if (
                record.tool_name != invocation.tool_name
                or record.arguments != invocation.effective_arguments
            ):
                raise HarnessInfrastructureError(
                    "checkpoint raw response does not match its successful invocation"
                )

    @staticmethod
    def _accepts_keyword_argument(callable_object: Any, keyword: str) -> bool:
        try:
            parameters = inspect.signature(callable_object).parameters.values()
        except (TypeError, ValueError):
            return False
        return any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            or (
                parameter.name == keyword
                and parameter.kind
                in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            )
            for parameter in parameters
        )

    async def _snapshot(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> MCPHarnessSnapshot[StateT, ObservationT]:
        return MCPHarnessSnapshot(
            run_id=ctx.run_id,
            parent_run_id=ctx.parent_run_id,
            state=deepcopy(ctx.state),
            messages=tuple(deepcopy(ctx.messages)),
            observations=tuple(deepcopy(ctx.observations)),
            invocations=tuple(item.model_copy(deep=True) for item in ctx.invocations),
            tool_specs=tuple(
                ctx.catalog[name].model_copy(deep=True) for name in sorted(ctx.catalog)
            ),
            fingerprints=frozenset(ctx.fingerprints),
            budget=ctx.budget.snapshot(),
            finish=ctx.finish.model_copy(deep=True) if ctx.finish is not None else None,
            event_version=ctx.event_version,
            deadline=ctx.deadline,
            wall_time_deadline=ctx.wall_time_deadline,
            pending_retry=(
                ctx.pending_retry.model_copy(deep=True) if ctx.pending_retry is not None else None
            ),
            retry_not_before=ctx.retry_not_before,
            active_call=(
                ctx.active_call.model_copy(deep=True) if ctx.active_call is not None else None
            ),
            remote_responses=tuple(
                RemoteResponseRecord(
                    invocation_id=record.invocation_id,
                    tool_name=record.tool_name,
                    arguments=deepcopy(record.arguments),
                    response=deepcopy(record.response),
                    is_remote=record.is_remote,
                )
                for record in (
                    ctx.remote_responses[invocation_id]
                    for invocation_id in sorted(ctx.remote_responses, key=str)
                )
            ),
        )

    async def _result(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> MCPHarnessResult[StateT, ObservationT]:
        snapshot = await self._snapshot(ctx)
        return MCPHarnessResult(
            run_id=snapshot.run_id,
            parent_run_id=snapshot.parent_run_id,
            state=snapshot.state,
            messages=snapshot.messages,
            observations=snapshot.observations,
            invocations=snapshot.invocations,
            tool_specs=snapshot.tool_specs,
            fingerprints=snapshot.fingerprints,
            budget=snapshot.budget,
            finish=snapshot.finish,
            event_version=snapshot.event_version,
            deadline=snapshot.deadline,
            wall_time_deadline=snapshot.wall_time_deadline,
            pending_retry=snapshot.pending_retry,
            retry_not_before=snapshot.retry_not_before,
            active_call=snapshot.active_call,
            remote_responses=snapshot.remote_responses,
        )

    @staticmethod
    def _portable_remote_response(response: Any) -> Any:
        if hasattr(response, "model_dump"):
            return response.model_dump(mode="json", by_alias=True)
        return deepcopy(response)

    async def _await_bounded(
        self,
        awaitable: Any,
        ctx: _RunContext[StateT, ObservationT],
        *,
        cap_seconds: float,
    ) -> Any:
        seconds = cap_seconds
        if ctx.deadline is not None:
            seconds = min(seconds, max(0, (ctx.deadline - datetime.now(UTC)).total_seconds()))
        if seconds <= 0:
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise TimeoutError("MCP investigation deadline exceeded")
        try:
            async with asyncio.timeout(seconds):
                return await awaitable
        except TimeoutError as exc:
            reason = (
                "MCP investigation deadline exceeded"
                if self._deadline_reached(ctx)
                else f"MCP operation timed out after {seconds:.3f} seconds"
            )
            raise TimeoutError(reason) from exc

    async def _close_session(self, ctx: _RunContext[StateT, ObservationT]) -> None:
        session = ctx.session
        ctx.session = None
        if session is not None:
            await self._safe_close(session)

    @staticmethod
    async def _safe_close(session: MCPToolSession) -> None:
        try:
            async with asyncio.timeout(5):
                await session.close()
        except Exception:
            pass

    @staticmethod
    async def _close_candidate_after_interruption(session: MCPToolSession) -> None:
        try:
            async with asyncio.timeout(5):
                await session.close()
        except BaseException:
            pass

    async def _sync_wall_time(
        self,
        ctx: _RunContext[StateT, ObservationT],
    ) -> None:
        if not ctx.account_wall_time or ctx.wall_time_deadline is None:
            return
        snapshot = ctx.budget.snapshot()
        limit = snapshot.limits.wall_time_seconds
        if limit is None:
            return
        clock_remaining = max(
            0.0,
            (ctx.wall_time_deadline - datetime.now(UTC)).total_seconds(),
        )
        target_consumed = min(limit, max(0.0, limit - clock_remaining))
        delta = target_consumed - snapshot.consumed.wall_time_seconds
        if delta <= 0:
            return
        await self._debit(ctx, wall_time_seconds=delta)

    @staticmethod
    def _call_fingerprint(call: PreparedCall) -> str:
        return ToolInvocation.build_fingerprint(
            tool_name=call.tool_name,
            effective_arguments=call.effective_arguments,
        )

    def _is_local_invocation(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
    ) -> bool:
        return self._active_or_reconstructed_call(ctx, invocation).local_result is not None

    def _refresh_pending_call_policy(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
    ) -> None:
        """Apply current Host policy before a checkpointed call crosses transport."""

        durable = self._active_or_reconstructed_call(ctx, invocation)
        # A durable local decision is already the conservative side of the
        # transport boundary. Policy upgrades may further restrict a pending
        # remote call, but must never turn a checkpointed local rejection into
        # a remote execution.
        if durable.local_result is not None:
            return
        action = CallToolAction(
            tool_name=invocation.tool_name,
            objective=invocation.objective,
            hypothesis_ids=list(invocation.hypothesis_ids),
            arguments=deepcopy(invocation.model_arguments),
        )
        # The checkpoint already contains prepare_call's deterministic state
        # effects. Re-evaluate policy against an isolated copy so recovery does
        # not append duplicate traces or advance scenario state twice.
        isolated_state = deepcopy(ctx.state)
        restore_state = getattr(self.scenario, "restore_state", None)
        try:
            scenario_prepared = self.scenario.prepare_call(action, state=isolated_state)
        finally:
            # Stateful scenarios may retain the state object passed to
            # prepare_call. Never leave that pointer on the isolated policy
            # copy, including when policy evaluation raises.
            if callable(restore_state):
                restore_state(ctx.state)
        current = scenario_prepared.model_copy(
            update={
                "tool_name": action.tool_name,
                "objective": action.objective,
                "hypothesis_ids": list(action.hypothesis_ids),
                "model_arguments": deepcopy(action.arguments),
                "effective_arguments": deepcopy(action.arguments),
            },
            deep=True,
        )
        if self._call_fingerprint(current) != invocation.fingerprint:
            raise HarnessInfrastructureError(
                "current Host policy changed a checkpointed invocation identity"
            )
        durable_context_metadata = {
            key: deepcopy(durable.metadata[key])
            for key in _DURABLE_CALL_CONTEXT_METADATA_KEYS
            if key in durable.metadata
        }
        ctx.active_call = current.model_copy(
            update={
                "metadata": {
                    **deepcopy(current.metadata),
                    **durable_context_metadata,
                }
            },
            deep=True,
        )

    def _active_or_reconstructed_call(
        self,
        ctx: _RunContext[StateT, ObservationT],
        invocation: ToolInvocation,
    ) -> PreparedCall:
        if ctx.active_call is not None:
            if self._call_fingerprint(ctx.active_call) != invocation.fingerprint:
                raise HarnessInfrastructureError(
                    "active PreparedCall does not match its checkpoint invocation"
                )
            return ctx.active_call.model_copy(deep=True)
        return PreparedCall(
            tool_name=invocation.tool_name,
            objective=invocation.objective,
            hypothesis_ids=list(invocation.hypothesis_ids),
            model_arguments=deepcopy(invocation.model_arguments),
            effective_arguments=deepcopy(invocation.effective_arguments),
        )

    @staticmethod
    def _pending_invocation(
        ctx: _RunContext[StateT, ObservationT],
    ) -> ToolInvocation | None:
        pending = [
            invocation
            for invocation in ctx.invocations
            if invocation.status == ToolInvocationStatus.PENDING
        ]
        if len(pending) > 1:
            raise HarnessInfrastructureError(
                "sequential MCP run contains multiple PENDING invocations"
            )
        return pending[0] if pending else None

    @staticmethod
    def _invocation_index(
        ctx: _RunContext[StateT, ObservationT],
        invocation_id: UUID,
    ) -> int:
        matches = [
            index
            for index, invocation in enumerate(ctx.invocations)
            if invocation.invocation_id == invocation_id
        ]
        if len(matches) != 1:
            raise HarnessInfrastructureError(
                "invocation identity is missing or duplicated in the run checkpoint"
            )
        return matches[0]

    def _catalog(self, specs: list[ToolSpec]) -> dict[str, ToolSpec]:
        catalog: dict[str, ToolSpec] = {}
        for spec in specs:
            if spec.name in catalog:
                raise ValueError(f"Duplicate MCP ToolSpec: {spec.name}")
            if spec.provider != self.scenario.provider:
                raise ValueError(
                    f"MCP ToolSpec {spec.name!r} does not belong to {self.scenario.provider!r}"
                )
            catalog[spec.name] = spec
        return catalog

    def _tool_spec(
        self,
        ctx: _RunContext[StateT, ObservationT],
        call: PreparedCall,
    ) -> ToolSpec:
        discovered = ctx.catalog.get(call.tool_name)
        if discovered is not None:
            return discovered
        return ToolSpec(
            name=call.tool_name,
            provider=self.scenario.provider,
            capability=call.tool_name,
            input_schema={"type": "object", "additionalProperties": True},
            policy_version="mcp-server-key-v1",
            schema_version="dynamic-mcp-schema-v1",
            timeout=call.timeout_seconds or self.session_timeout_seconds,
        )

    @staticmethod
    def _transition_invocation(invocation: ToolInvocation, **updates: Any) -> ToolInvocation:
        payload = invocation.model_dump(mode="python")
        payload.update(updates)
        return ToolInvocation.model_validate(payload)

    @staticmethod
    def _append_observation_message(
        ctx: _RunContext[StateT, ObservationT],
        transition: ScenarioTransition[StateT, ObservationT],
        invocation: ToolInvocation,
    ) -> None:
        if transition.message is not None:
            if isinstance(transition.message, list):
                ctx.messages.extend(deepcopy(transition.message))
            else:
                ctx.messages.append(deepcopy(transition.message))
            return
        ctx.messages.append(
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "invocation_id": str(invocation.invocation_id),
                        "status": invocation.status.value,
                        "tool_name": invocation.tool_name,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                ),
            }
        )

    @staticmethod
    def _invocation_error(exc: Exception, directive: RetryDirective) -> InvocationError:
        extra_details = getattr(exc, "details", {})
        if not isinstance(extra_details, dict):
            extra_details = {}
        return InvocationError(
            code=str(getattr(exc, "code", type(exc).__name__)),
            message=str(exc) or type(exc).__name__,
            retryable=bool(getattr(exc, "retryable", directive.continue_run)),
            details={"unknown_outcome": directive.unknown_outcome, **extra_details},
        )

    @staticmethod
    def _deadline_reached(ctx: _RunContext[StateT, ObservationT]) -> bool:
        return ctx.deadline is not None and datetime.now(UTC) >= ctx.deadline

    @staticmethod
    def _deadline_finish(summary: str) -> Finish:
        return Finish(
            reason=RuntimeStopReason.DEADLINE_EXCEEDED,
            summary=summary,
            requires_human=True,
        )

    @staticmethod
    def _budget_finish(exc: BudgetExceededError) -> Finish:
        return Finish(
            reason=RuntimeStopReason.BUDGET_EXHAUSTED,
            summary=f"MCP investigation budget exhausted: {exc.dimension}",
            requires_human=True,
        )
