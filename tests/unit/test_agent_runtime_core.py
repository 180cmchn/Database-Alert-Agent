from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    AgentTraceEmitter,
    AgentTraceScope,
    ArtifactRef,
    BudgetLedger,
    BudgetLimits,
    CallToolAction,
    EventVersionConflictError,
    EvidenceDisposition,
    FinishAction,
    InMemoryEventSink,
    InvalidBudgetReservationError,
    InvocationExecutionOutput,
    InvocationExecutionResult,
    InvocationExecutor,
    RequestHumanInputAction,
    RuntimeStopReason,
    ToolInvocation,
    ToolInvocationStatus,
    parse_agent_action,
    provider_reasoning_text,
    trace_entry_from_event,
)


def _invocation(**updates: object) -> ToolInvocation:
    arguments = {"query": "up"}
    values = {
        "run_id": uuid4(),
        "tool_name": "prometheus.query_range",
        "provider": "prometheus",
        "objective": "Check whether CPU saturation coincides with the alert window",
        "hypothesis_ids": ["cpu-saturation"],
        "model_arguments": arguments,
        "effective_arguments": arguments,
        "fingerprint": ToolInvocation.build_fingerprint(
            tool_name="prometheus.query_range",
            effective_arguments=arguments,
        ),
    }
    values.update(updates)
    return ToolInvocation.model_validate(values)


def test_agent_action_uses_a_strict_discriminator() -> None:
    call = parse_agent_action(
        {
            "action": "call_tool",
            "tool_name": "archery.sql_query",
            "objective": "Collect the slow-query distribution",
            "hypothesis_ids": ["expensive-query-shape"],
            "arguments": {"window_minutes": 5},
        }
    )
    finish = parse_agent_action(
        {
            "action": "finish",
            "reason": "EVIDENCE_SUFFICIENT",
            "summary": "Live evidence distinguishes the leading cause.",
        }
    )
    human = parse_agent_action(
        {
            "action": "request_human_input",
            "reason": "The affected instance is ambiguous.",
            "question": "Which database instance emitted this alert?",
            "required_fields": ["database.instance"],
        }
    )

    assert isinstance(call, CallToolAction)
    assert isinstance(finish, FinishAction)
    assert isinstance(human, RequestHumanInputAction)
    with pytest.raises(ValidationError):
        parse_agent_action({"action": "unknown", "summary": "invalid"})
    with pytest.raises(ValidationError, match="extra_forbidden"):
        parse_agent_action(
            {
                "action": "finish",
                "reason": "COMPLETED",
                "summary": "done",
                "tool_name": "unexpected",
            }
        )


def test_count_limit_input_is_normalized_to_unlimited_usage_accounting() -> None:
    ledger = BudgetLedger(BudgetLimits(remote_tool_calls=2))
    first = ledger.reserve(remote_tool_calls=2)
    second = ledger.reserve(remote_tool_calls=1)

    ledger.debit(first)
    snapshot = ledger.debit(second)
    assert snapshot.consumed.remote_tool_calls == 3
    assert snapshot.reserved.remote_tool_calls == 0
    assert snapshot.limits.remote_tool_calls is None
    assert snapshot.remaining.remote_tool_calls is None


def test_released_budget_can_be_reserved_again() -> None:
    ledger = BudgetLedger({"planner_requests": 1})
    reservation = ledger.reserve(planner_requests=1)

    ledger.release(reservation)
    ledger.debit(planner_requests=1)

    assert ledger.snapshot().consumed.planner_requests == 1


def test_budget_snapshot_restores_count_usage_without_a_count_limit() -> None:
    ledger = BudgetLedger(BudgetLimits(remote_tool_calls=3, planner_requests=4))
    ledger.debit(remote_tool_calls=2)
    ledger.debit(planner_requests=1)

    restored = BudgetLedger.from_snapshot(ledger.snapshot())

    assert restored.snapshot() == ledger.snapshot()
    restored.debit(remote_tool_calls=1)
    restored.debit(remote_tool_calls=1)
    assert restored.snapshot().consumed.remote_tool_calls == 4


def test_budget_snapshot_with_live_reservation_is_not_resumable() -> None:
    ledger = BudgetLedger(BudgetLimits(remote_tool_calls=2))
    ledger.reserve(remote_tool_calls=1)

    with pytest.raises(InvalidBudgetReservationError, match="unsettled"):
        BudgetLedger.from_snapshot(ledger.snapshot())


def test_child_count_usage_is_unbounded_and_debits_parent() -> None:
    parent = BudgetLedger({"remote_tool_calls": 3, "model_tokens": 100})
    parent.debit(remote_tool_calls=1)

    child = parent.create_child({"remote_tool_calls": 2, "model_tokens": 40})
    reservation = child.reserve(remote_tool_calls=2, model_tokens=25)

    assert parent.snapshot().reserved.remote_tool_calls == 2
    child.debit(reservation)

    assert child.snapshot().consumed.remote_tool_calls == 2
    assert parent.snapshot().consumed.remote_tool_calls == 3
    assert parent.snapshot().consumed.model_tokens == 25
    child.debit(remote_tool_calls=1)
    assert parent.snapshot().consumed.remote_tool_calls == 4


def test_child_budget_restore_requires_and_reuses_the_same_parent_ledger() -> None:
    parent = BudgetLedger({"remote_tool_calls": 4})
    child = parent.create_child({"remote_tool_calls": 3})
    child.debit(remote_tool_calls=1)
    parent_snapshot = parent.snapshot()
    child_snapshot = child.snapshot()

    with pytest.raises(ValueError, match="parent"):
        BudgetLedger.from_snapshot(child_snapshot)
    with pytest.raises(ValueError, match="parent"):
        BudgetLedger.from_snapshot(
            child_snapshot,
            parent=BudgetLedger({"remote_tool_calls": 4}),
        )

    # A recovered hierarchy must retain the persisted ledger identity. Future
    # child consumption is propagated once; historical consumption is not
    # charged to the parent a second time.
    restored_parent = BudgetLedger.from_snapshot(parent_snapshot)
    restored_child = BudgetLedger.from_snapshot(
        child_snapshot,
        parent=restored_parent,
    )
    assert restored_child.snapshot() == child_snapshot
    restored_child.debit(remote_tool_calls=1)
    assert restored_parent.snapshot().consumed.remote_tool_calls == 2


def test_budget_ledger_is_thread_safe() -> None:
    from concurrent.futures import ThreadPoolExecutor

    ledger = BudgetLedger({"accepted_decisions": 100})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: ledger.debit(accepted_decisions=1), range(100)))

    assert ledger.snapshot().consumed.accepted_decisions == 100


@pytest.mark.asyncio
async def test_event_sink_assigns_sequence_and_rejects_stale_version() -> None:
    sink = InMemoryEventSink()
    run_id = uuid4()
    first = await sink.append(
        AgentEvent(run_id=run_id, kind=AgentEventKind.RUN_STARTED),
        expected_version=0,
    )
    second = await sink.append(
        AgentEvent(run_id=run_id, kind=AgentEventKind.MODEL_DECISION),
        expected_version=1,
    )

    assert (first.sequence, first.version) == (1, 1)
    assert (second.sequence, second.version) == (2, 2)
    with pytest.raises(EventVersionConflictError) as caught:
        await sink.append(
            AgentEvent(run_id=run_id, kind=AgentEventKind.CHECKPOINT_SAVED),
            expected_version=1,
        )
    assert caught.value.actual_version == 2
    assert [event.kind for event in await sink.read(run_id)] == [
        AgentEventKind.RUN_STARTED,
        AgentEventKind.MODEL_DECISION,
    ]


@pytest.mark.asyncio
async def test_event_sink_serializes_concurrent_appends() -> None:
    sink = InMemoryEventSink()
    run_id = uuid4()

    await asyncio.gather(
        *(
            sink.append(AgentEvent(run_id=run_id, kind=AgentEventKind.MODEL_DECISION))
            for _ in range(20)
        )
    )

    events = await sink.read(run_id)
    assert [event.sequence for event in events] == list(range(1, 21))


@pytest.mark.asyncio
async def test_agent_trace_emitter_preserves_real_provider_content_and_order() -> None:
    sink = InMemoryEventSink()
    run_id = uuid4()
    emitter = AgentTraceEmitter(
        sink,
        run_id=run_id,
        actor="main-agent",
        provider="openai-compatible",
    )

    assert await emitter.emit_provider_reasoning({"content": "answer only"}) is None
    reasoning = "真实 reasoning_content，不是宿主摘要。"
    await emitter.emit_provider_reasoning(
        {"reasoning_content": reasoning, "reasoning": "lower-priority reasoning"}
    )
    await emitter.emit_action('call_tool archery.query {"read_only":true}')
    await emitter.emit_observation(
        "query returned 3 rows",
        actor="archery-mcp",
        provider="archery",
    )

    entries = [
        entry
        for event in await sink.read(run_id)
        if (entry := trace_entry_from_event(event)) is not None
    ]
    assert [entry.sequence for entry in entries] == [1, 2, 3]
    assert [entry.kind.value for entry in entries] == [
        "REASONING",
        "ACTION",
        "OBSERVATION",
    ]
    assert entries[0].content == reasoning
    assert [entry.scope for entry in entries] == [
        AgentTraceScope.MAIN_AGENT,
        AgentTraceScope.MAIN_AGENT,
        AgentTraceScope.MAIN_AGENT,
    ]
    assert entries[0].actor == "main-agent"
    assert entries[2].actor == "archery-mcp"
    assert entries[2].provider == "archery"


def test_provider_reasoning_text_reads_model_extra_without_fabricating_fallback() -> None:
    class Message:
        reasoning_content = None
        reasoning = None
        model_extra = {"reasoning": "provider reasoning"}

    assert provider_reasoning_text(Message()) == "provider reasoning"
    assert provider_reasoning_text({"content": "ordinary answer"}) is None


def test_trace_projection_skips_malformed_historical_event() -> None:
    malformed = AgentEvent(
        run_id=uuid4(),
        sequence=1,
        version=1,
        kind=AgentEventKind.TRACE_ACTION,
        payload={"actor": "main-agent", "provider": "fixture"},
    )

    assert trace_entry_from_event(malformed) is None


def test_trace_projection_infers_scopes_for_legacy_events() -> None:
    run_id = uuid4()
    main_entry = trace_entry_from_event(
        AgentEvent(
            run_id=run_id,
            sequence=1,
            version=1,
            kind=AgentEventKind.TRACE_REASONING,
            payload={
                "actor": "main_agent",
                "provider": "openai-compatible",
                "content": "main thought",
            },
        )
    )
    mcp_entry = trace_entry_from_event(
        AgentEvent(
            run_id=run_id,
            sequence=2,
            version=2,
            kind=AgentEventKind.TRACE_REASONING,
            payload={
                "actor": "archery_mcp_agent",
                "provider": "archery",
                "content": "internal thought",
            },
        )
    )

    assert main_entry is not None and main_entry.scope == AgentTraceScope.MAIN_AGENT
    assert mcp_entry is not None and mcp_entry.scope == AgentTraceScope.MCP_INTERNAL


@pytest.mark.asyncio
async def test_executor_emits_started_then_success_with_artifact() -> None:
    sink = InMemoryEventSink()
    executor = InvocationExecutor(sink)
    artifact = ArtifactRef(kind="mcp-result", uri="memory://artifact/1")

    async def handler(invocation: ToolInvocation) -> InvocationExecutionOutput:
        assert invocation.status == ToolInvocationStatus.STARTED
        return InvocationExecutionOutput(
            result={"series_count": 3},
            artifact_ref=artifact,
        )

    result = await executor.execute(_invocation(), handler, timeout_seconds=1)
    events = await sink.read(result.invocation.run_id)

    assert result.invocation.status == ToolInvocationStatus.SUCCEEDED
    assert result.invocation.artifact_ref == artifact
    assert result.evidence_disposition == EvidenceDisposition.AVAILABLE
    assert [event.kind for event in events] == [
        AgentEventKind.TOOL_INVOCATION_STARTED,
        AgentEventKind.TOOL_INVOCATION_SUCCEEDED,
    ]


@pytest.mark.asyncio
async def test_executor_failure_is_missing_evidence_not_contradiction() -> None:
    sink = InMemoryEventSink()
    executor = InvocationExecutor(sink)

    async def handler(_: ToolInvocation) -> None:
        raise RuntimeError("backend unavailable")

    result = await executor.execute(_invocation(), handler)
    events = await sink.read(result.invocation.run_id)

    assert result.invocation.status == ToolInvocationStatus.FAILED
    assert result.evidence_disposition == EvidenceDisposition.MISSING
    assert result.is_contradiction is False
    assert result.result == {}
    assert events[-1].kind == AgentEventKind.TOOL_INVOCATION_FAILED
    assert events[-1].payload["evidence_disposition"] == "MISSING"
    assert events[-1].payload["is_contradiction"] is False

    with pytest.raises(ValidationError, match="cannot be represented as contradiction"):
        InvocationExecutionResult(
            invocation=result.invocation,
            evidence_disposition=EvidenceDisposition.MISSING,
            is_contradiction=True,
        )


@pytest.mark.asyncio
async def test_executor_uses_earliest_deadline_and_marks_timeout_missing() -> None:
    sink = InMemoryEventSink()
    executor = InvocationExecutor(sink)

    async def handler(_: ToolInvocation) -> dict[str, object]:
        await asyncio.sleep(0.05)
        return {"unexpected": True}

    result = await executor.execute(
        _invocation(deadline=datetime.now(UTC) + timedelta(milliseconds=5)),
        handler,
        timeout_seconds=1,
    )

    assert result.invocation.status == ToolInvocationStatus.TIMED_OUT
    assert result.invocation.error is not None
    assert result.invocation.error.code == "invocation_timeout"
    assert result.evidence_disposition == EvidenceDisposition.MISSING
    assert (await sink.read(result.invocation.run_id))[-1].kind == (
        AgentEventKind.TOOL_INVOCATION_TIMED_OUT
    )


@pytest.mark.asyncio
async def test_executor_does_not_call_handler_after_deadline() -> None:
    sink = InMemoryEventSink()
    executor = InvocationExecutor(sink)
    called = False

    async def handler(_: ToolInvocation) -> dict[str, object]:
        nonlocal called
        called = True
        return {"unexpected": True}

    result = await executor.execute(
        _invocation(deadline=datetime.now(UTC) - timedelta(seconds=1)),
        handler,
    )

    assert called is False
    assert result.invocation.status == ToolInvocationStatus.TIMED_OUT
    assert result.invocation.error is not None
    assert result.invocation.error.code == "invocation_deadline_exceeded"


def test_manifest_digest_is_stable_for_equivalent_content() -> None:
    from app.agent_runtime import RunManifest

    run_id = uuid4()
    created_at = datetime.now(UTC)
    first = RunManifest(
        run_id=run_id,
        agent_name="database-alert-agent",
        code_version="abc123",
        tool_schema_versions={"prometheus": "v1", "archery": "v2"},
        configuration={"react": True, "sources": ["local_pdf"]},
        created_at=created_at,
    )
    second = RunManifest(
        run_id=run_id,
        agent_name="database-alert-agent",
        code_version="abc123",
        tool_schema_versions={"archery": "v2", "prometheus": "v1"},
        configuration={"sources": ["local_pdf"], "react": True},
        created_at=created_at,
    )

    assert first.digest() == second.digest()
    assert RuntimeStopReason.EVIDENCE_SUFFICIENT.value == "EVIDENCE_SUFFICIENT"


def test_unknown_outcome_requires_error_and_is_terminal() -> None:
    created_at = datetime.now(UTC)
    invocation = _invocation(
        status=ToolInvocationStatus.UNKNOWN_OUTCOME,
        created_at=created_at,
        started_at=created_at,
        completed_at=created_at,
        error={
            "code": "connection_lost",
            "message": "Connection closed while awaiting the MCP response",
            "retryable": True,
        },
    )

    assert invocation.status == ToolInvocationStatus.UNKNOWN_OUTCOME
    with pytest.raises(ValidationError, match="requires error details"):
        _invocation(
            status=ToolInvocationStatus.UNKNOWN_OUTCOME,
            created_at=created_at,
            started_at=created_at,
            completed_at=created_at,
        )
