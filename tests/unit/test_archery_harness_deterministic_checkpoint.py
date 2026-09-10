from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any
from uuid import uuid4

import pytest

from app.adapters import archery_harness as archery_harness_module
from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
    ARCHERY_HISTORY_PAYLOAD_CONTRACT_VERSION,
)
from app.adapters.archery_mcp import (
    ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcherySlowLogQueryResult,
)
from app.agent_runtime import (
    BudgetLedger,
    BudgetLimits,
    InMemoryEventSink,
    ToolInvocationStatus,
)
from app.mcp_runtime import (
    MCPAgentHarnessRuntime,
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    ALERT_CONTEXT,
    OCCURRED_AT,
    TARGET_ARGUMENTS,
    _analysis_tools,
    _client,
    _ScriptedModel,
)


def _pipeline_scenario(connector: ReplayMCPConnector):
    client = _client(_ScriptedModel([]), connector)
    state = archery_harness_module.ArcheryHarnessState(
        window_start=OCCURRED_AT,
        window_end=OCCURRED_AT,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
        history_pipeline_enabled=True,
    )
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.slow_log_tables[target] = {ARCHERY_SLOW_QUERY_REVIEW_TABLE}
    state.table_columns[target] = {
        ARCHERY_SLOW_QUERY_REVIEW_TABLE: {
            "id",
            "hostname_max",
            "db_max",
            "checksum",
            "ts_min",
            "ts_max",
            "query_time_max",
            "query_time_sum",
            "sample",
        }
    }
    state.resolved_endpoints[target] = {"db-1.example:3306"}
    scenario = archery_harness_module.ArcheryHarnessScenario(
        client,
        state,
        archery_harness_module._PlannerCallRegistry(),
    )
    return scenario, state


def _restored_scenario(snapshot, connector: ReplayMCPConnector):
    client = _client(_ScriptedModel([]), connector)
    state = deepcopy(snapshot.state)
    scenario = archery_harness_module.ArcheryHarnessScenario(
        client,
        state,
        archery_harness_module._PlannerCallRegistry(),
    )
    scenario.restore_state(state)
    return scenario, state


def _runtime(
    scenario,
    connector: ReplayMCPConnector,
    sink: InMemoryEventSink,
    *,
    checkpoint_hook=None,
    budget: BudgetLedger | None = None,
):
    return MCPAgentHarnessRuntime(
        connector=connector,
        planner=archery_harness_module.ArcheryHarnessPlanner(
            scenario.client,
            scenario,
            scenario.registry,
        ),
        scenario=scenario,
        event_sink=sink,
        budget=budget or BudgetLedger(BudgetLimits()),
        checkpoint_hook=checkpoint_hook,
    )


def _query_result(call, rows: list[dict[str, Any]]) -> ReplayCallFixture:
    sql = call.arguments["sql_content"]
    return ReplayCallFixture(
        tool_name=call.name,
        expected_arguments=dict(call.arguments),
        result={
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": rows,
            }
        },
    )


def _compact_row(
    row_id: int,
    *,
    checksum: str | None = None,
    sample_full_length: int = 64,
) -> dict[str, Any]:
    return {
        "id": row_id,
        "hostname_max": "db-1.example:3306",
        "db_max": "orders_prod",
        "checksum": checksum or f"checksum-{row_id}",
        "ts_min": "2026-07-23 15:59:00",
        "ts_max": "2026-07-23 16:00:00",
        "Query_time_max": float(row_id),
        "Query_time_sum": float(row_id * 10),
        ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS: sample_full_length,
    }


def _prime_enrichment(scenario, state, rows: list[dict[str, Any]]) -> None:
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.history_pipeline_target = target
    state.history_result_target = target
    state.history_pipeline_endpoint = "db-1.example:3306"
    state.history_ranking_rows = {
        row["id"]: {
            "id": row["id"],
            "Query_time_max": row["Query_time_max"],
            "Query_time_sum": row["Query_time_sum"],
        }
        for row in rows
    }
    state.history_compact_rows = {row["id"]: dict(row) for row in rows}
    state.history_ranking_scan_complete = True
    state.history_compact_scan_complete = True
    scenario._finalize_history_pipeline_scan(state)


def _analysis_binding(state, *, instance_id: int = 3, db_name: str = "orders_prod"):
    state.analysis_instance_endpoints[instance_id] = {"db-1.example:3306"}
    state.analysis_database_names[instance_id] = {db_name}
    state.slow_query_table_structure_results.append(
        {
            "stage": "table_structure",
            "target": {
                "instance_id": instance_id,
                "db_name": db_name,
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [{"COLUMN_NAME": "id"}]},
        }
    )
    state.slow_query_index_results.append(
        {
            "stage": "indexes",
            "target": {
                "instance_id": instance_id,
                "db_name": db_name,
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [{"INDEX_NAME": "PRIMARY"}]},
        }
    )


def test_legacy_compact_checkpoint_restarts_lossless_read_only_materialization() -> None:
    connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    scenario, state = _pipeline_scenario(connector)
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.history_payload_contract_version = ""
    state.history_pipeline_phase = "COMPLETED"
    state.history_pipeline_target = target
    state.history_pipeline_endpoint = "db-1.example:3306"
    state.history_ranking_rows = {1: {"id": 1}}
    state.history_compact_rows = {1: _compact_row(1)}
    state.history_id_rows = {1: {"id": 1, "sample": "SELECT prefix"}}
    state.history_sample_prefix_ids = {1}
    state.history_full_row_ids = {1}
    state.history_sample_states = {1: "ANALYZED"}
    state.slow_query_explain_results = [{"stage": "explain", "result": {"rows": []}}]
    state.finish_accepted = True
    state.final_result = ArcherySlowLogQueryResult(
        payload={"rows": [{"id": 1, "sample": "SELECT prefix"}], "row_count": 1},
        requested_sql="SELECT compact_columns FROM mysql_slow_query_review_history",
        window_start=state.window_start,
        window_end=state.window_end,
    )
    durable_host_calls = [{"tool_name": "sql_query_gymJPA", "artifact_id": "durable"}]
    state.executed_host_calls = deepcopy(durable_host_calls)

    scenario.restore_state(state)

    assert state.history_payload_contract_version == ARCHERY_HISTORY_PAYLOAD_CONTRACT_VERSION
    assert state.history_pipeline_phase == "IDLE"
    assert state.history_pipeline_target is None
    assert state.history_ranking_rows == {}
    assert state.history_compact_rows == {}
    assert state.history_id_rows == {}
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == set()
    assert state.slow_query_explain_results == []
    assert state.final_result is None
    assert state.finish_accepted is False
    assert state.executed_host_calls == durable_host_calls
    ranking = scenario.next_host_call(scenario.build_tool_specs(_analysis_tools()))
    assert ranking is not None
    assert "SELECT id, Query_time_max, Query_time_sum" in ranking.arguments["sql_content"]


@pytest.mark.parametrize("phase", ["RANKING", "COMPACT"])
@pytest.mark.asyncio
async def test_keyset_page_checkpoint_resumes_with_accumulated_rows_and_cursor(
    phase: str,
) -> None:
    planning_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    scenario, state = _pipeline_scenario(planning_connector)
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.history_pipeline_phase = phase
    state.history_pipeline_target = target
    state.history_result_target = target
    state.history_pipeline_endpoint = "db-1.example:3306"
    state.history_snapshot_max_id = 4
    state.history_page_cursor = 3
    state.history_page_size = 2
    state.history_ranking_rows = {
        row_id: {
            "id": row_id,
            "Query_time_max": float(row_id),
            "Query_time_sum": float(row_id * 10),
        }
        for row_id in (4, 3, 2, 1)
        if phase == "COMPACT" or row_id in (4, 3)
    }
    state.history_ranking_page_count = 1
    if phase == "COMPACT":
        state.history_ranking_scan_complete = True
        state.history_compact_rows = {row_id: _compact_row(row_id) for row_id in (4, 3)}
        state.history_compact_page_count = 1

    specs = scenario.build_tool_specs(_analysis_tools())
    page_call = scenario.next_host_call(specs)
    assert page_call is not None
    page_rows = (
        [
            {"id": row_id, "Query_time_max": float(row_id), "Query_time_sum": row_id * 10.0}
            for row_id in (2, 1)
        ]
        if phase == "RANKING"
        else [_compact_row(row_id) for row_id in (2, 1)]
    )
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id=f"{phase.casefold()}-before-checkpoint",
                tools=_analysis_tools(),
                calls=[_query_result(page_call, page_rows)],
            )
        ],
    )
    captured = []

    async def interrupt_after_page(snapshot) -> None:
        page_count = (
            snapshot.state.history_ranking_page_count
            if phase == "RANKING"
            else snapshot.state.history_compact_page_count
        )
        if (
            snapshot.active_call is None
            and snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.SUCCEEDED
            and page_count == 2
            and snapshot.state.history_page_cursor == 1
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    sink = InMemoryEventSink()
    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            scenario,
            first_connector,
            sink,
            checkpoint_hook=interrupt_after_page,
        ).run(run_id=uuid4(), initial_state=state)

    checkpoint = captured[-1]
    second_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id=f"{phase.casefold()}-after-checkpoint",
                tools=_analysis_tools(),
                calls=[],
            )
        ],
    )
    resumed_scenario, _ = _restored_scenario(checkpoint, second_connector)
    pending = []

    async def interrupt_next_page(snapshot) -> None:
        if (
            snapshot.active_call is not None
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
            and "id < 1" in str(snapshot.active_call.effective_arguments.get("sql_content") or "")
        ):
            pending.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            resumed_scenario,
            second_connector,
            sink,
            checkpoint_hook=interrupt_next_page,
        ).resume(
            checkpoint,
            restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
        )

    resumed = pending[-1]
    accumulated = (
        resumed.state.history_ranking_rows
        if phase == "RANKING"
        else resumed.state.history_compact_rows
    )
    assert set(accumulated) == {1, 2, 3, 4}
    assert resumed.state.history_snapshot_max_id == 4
    assert "id <= 4" in resumed.active_call.effective_arguments["sql_content"]


@pytest.mark.asyncio
async def test_sample_chunk_checkpoint_resumes_at_next_offset() -> None:
    sample = "SELECT * FROM orders WHERE id = 123 AND status = 'open'"
    planning_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    scenario, state = _pipeline_scenario(planning_connector)
    _prime_enrichment(
        scenario,
        state,
        [_compact_row(81, sample_full_length=len(sample.encode("utf-8")))],
    )
    scenario._start_history_chunk_recovery(state, 81)
    state.history_current_id = 81
    state.history_chunk_size = 10
    specs = scenario.build_tool_specs(_analysis_tools())
    chunk_call = scenario.next_host_call(specs)
    assert chunk_call is not None
    first_chunk = sample[:10]
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="chunk-before-checkpoint",
                tools=_analysis_tools(),
                calls=[_query_result(chunk_call, [{"sample_chunk": first_chunk}])],
            )
        ],
    )
    captured = []

    async def interrupt_after_chunk(snapshot) -> None:
        if (
            snapshot.active_call is None
            and snapshot.state.history_chunk_offset == 11
            and snapshot.state.history_chunk_parts == [first_chunk]
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    sink = InMemoryEventSink()
    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            scenario,
            first_connector,
            sink,
            checkpoint_hook=interrupt_after_chunk,
        ).run(run_id=uuid4(), initial_state=state)

    checkpoint = captured[-1]
    second_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="chunk-after-checkpoint",
                tools=_analysis_tools(),
                calls=[],
            )
        ],
    )
    resumed_scenario, _ = _restored_scenario(checkpoint, second_connector)
    pending = []

    async def interrupt_next_chunk(snapshot) -> None:
        if (
            snapshot.active_call is not None
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
            and "SUBSTRING(sample, 11, 10)"
            in str(snapshot.active_call.effective_arguments.get("sql_content") or "")
        ):
            pending.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            resumed_scenario,
            second_connector,
            sink,
            checkpoint_hook=interrupt_next_chunk,
        ).resume(
            checkpoint,
            restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
        )

    assert pending[-1].state.history_chunk_parts == [first_chunk]
    assert pending[-1].state.history_chunk_offset == 11


@pytest.mark.asyncio
async def test_complete_sample_checkpoint_resumes_with_exact_explain_sql() -> None:
    sample = "SELECT * FROM orders WHERE customer_id = 42"
    planning_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    scenario, state = _pipeline_scenario(planning_connector)
    _prime_enrichment(
        scenario,
        state,
        [_compact_row(42, sample_full_length=len(sample.encode("utf-8")))],
    )
    _analysis_binding(state)
    specs = scenario.build_tool_specs(_analysis_tools())
    sample_call = scenario.next_host_call(specs)
    assert sample_call is not None
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="sample-before-explain-checkpoint",
                tools=_analysis_tools(),
                calls=[_query_result(sample_call, [{"sample": sample}])],
            )
        ],
    )
    captured = []

    async def interrupt_after_sample(snapshot) -> None:
        final_result = snapshot.state.final_result
        if (
            snapshot.active_call is None
            and snapshot.state.history_sample_states.get(42) == "READY"
            and final_result is not None
            and final_result.history_complete is True
            and final_result.payload["rows"][0]["sample"] == sample
            and not snapshot.state.slow_query_explain_results
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    sink = InMemoryEventSink()
    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            scenario,
            first_connector,
            sink,
            checkpoint_hook=interrupt_after_sample,
        ).run(run_id=uuid4(), initial_state=state)

    checkpoint = captured[-1]
    second_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="sample-after-explain-checkpoint",
                tools=_analysis_tools(),
                calls=[],
            )
        ],
    )
    resumed_scenario, _ = _restored_scenario(checkpoint, second_connector)
    pending = []

    async def interrupt_explain(snapshot) -> None:
        if (
            snapshot.active_call is not None
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
            and snapshot.active_call.effective_arguments.get("sql_content") == f"EXPLAIN {sample}"
        ):
            pending.append(snapshot)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            resumed_scenario,
            second_connector,
            sink,
            checkpoint_hook=interrupt_explain,
        ).resume(
            checkpoint,
            restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
        )

    assert pending[-1].state.history_exact_sample == sample
    assert pending[-1].state.history_exact_sample_id == 42


@pytest.mark.asyncio
async def test_staged_explain_response_is_applied_on_resume_without_replay() -> None:
    exact_sample = (
        "SELECT * FROM orders WHERE id IN (" + ",".join(str(value) for value in range(6000)) + ")"
    )
    planning_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    scenario, state = _pipeline_scenario(planning_connector)
    _prime_enrichment(
        scenario,
        state,
        [_compact_row(91, sample_full_length=len(exact_sample.encode("utf-8")))],
    )
    state.history_current_id = 91
    scenario._accept_reconstructed_sample(state, 91, exact_sample)
    _analysis_binding(state)
    specs = scenario.build_tool_specs(_analysis_tools())
    explain_call = scenario.next_host_call(specs)
    assert explain_call is not None
    assert explain_call.arguments["sql_content"] == f"EXPLAIN {exact_sample}"
    state.history_host_stage_attempts.discard("explain:91")
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="explain-response-staged",
                tools=_analysis_tools(),
                calls=[
                    _query_result(
                        explain_call,
                        [{"id": 1, "table": "orders", "type": "range"}],
                    )
                ],
            )
        ],
    )
    captured = []

    async def interrupt_staged_response(snapshot) -> None:
        if (
            snapshot.active_call is not None
            and snapshot.invocations[-1].status == ToolInvocationStatus.STARTED
            and snapshot.remote_responses
            and snapshot.active_call.effective_arguments.get("sql_content")
            == f"EXPLAIN {exact_sample}"
            and not snapshot.state.slow_query_explain_results
        ):
            captured.append(snapshot)
            raise asyncio.CancelledError

    sink = InMemoryEventSink()
    with pytest.raises(asyncio.CancelledError):
        await _runtime(
            scenario,
            first_connector,
            sink,
            checkpoint_hook=interrupt_staged_response,
        ).run(run_id=uuid4(), initial_state=state)

    checkpoint = captured[-1]
    second_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="explain-response-recovered",
                tools=_analysis_tools(),
                calls=[],
            )
        ],
    )
    resumed_scenario, _ = _restored_scenario(checkpoint, second_connector)
    resumed = await _runtime(
        resumed_scenario,
        second_connector,
        sink,
    ).resume(
        checkpoint,
        restored_budget=BudgetLedger.from_snapshot(checkpoint.budget),
    )

    assert len(resumed.state.slow_query_explain_results) == 1
    assert exact_sample in str(resumed.state.slow_query_explain_results)
    assert resumed.budget.consumed.remote_tool_calls == 1
    assert resumed.state.history_sample_states[91] == "ANALYZED"
    assert resumed.state.history_sample_metadata[91]["explain_status"] == "succeeded"
    assert resumed.state.history_sample_metadata[91].get("explain_reused_from_history_id") is None


@pytest.mark.asyncio
async def test_budget_stop_checkpoint_rematerializes_same_partial_result() -> None:
    connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    scenario, state = _pipeline_scenario(connector)
    _prime_enrichment(scenario, state, [_compact_row(7, sample_full_length=20_000)])
    checkpoints = []

    async def capture_checkpoint(snapshot) -> None:
        checkpoints.append(snapshot)

    sink = InMemoryEventSink()
    runtime_result = await _runtime(
        scenario,
        connector,
        sink,
        checkpoint_hook=capture_checkpoint,
        budget=BudgetLedger(BudgetLimits(wall_time_seconds=0)),
    ).run(run_id=uuid4(), initial_state=state)
    first = archery_harness_module._query_result(scenario.client, runtime_result)
    terminal_checkpoint = next(
        snapshot for snapshot in reversed(checkpoints) if snapshot.finish is not None
    )

    assert terminal_checkpoint.state.history_pipeline_phase == "ENRICHMENT"
    assert first.history_complete is False
    assert "history_lossless_recovery_incomplete" in first.history_incomplete_reasons
    assert first.enrichment_unfinished_ids == ()
    assert "sample_recovery_status" not in first.payload["rows"][0]

    resumed_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    resumed_scenario, _ = _restored_scenario(terminal_checkpoint, resumed_connector)
    resumed_runtime_result = await _runtime(
        resumed_scenario,
        resumed_connector,
        sink,
    ).resume(
        terminal_checkpoint,
        restored_budget=BudgetLedger.from_snapshot(terminal_checkpoint.budget),
    )
    second = archery_harness_module._query_result(
        resumed_scenario.client,
        resumed_runtime_result,
    )

    assert second.payload == first.payload
    assert second.history_complete is False
    assert second.history_incomplete_reasons == first.history_incomplete_reasons
    assert isinstance(second.history_incomplete_reasons, tuple)
    assert second.enrichment_unfinished_ids == first.enrichment_unfinished_ids
    assert isinstance(second.enrichment_unfinished_ids, tuple)
    assert resumed_connector.opened_session_ids == []
    assert (
        sum(
            item.get("reason_code") == "history_lossless_recovery_incomplete"
            for item in resumed_runtime_result.state.slow_query_analysis_failures
        )
        == 1
    )
