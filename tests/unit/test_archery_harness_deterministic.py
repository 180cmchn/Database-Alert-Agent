from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.adapters import archery_harness as archery_harness_module
from app.adapters.archery_mcp import (
    ARCHERY_SAMPLE_CHUNK_RESULT_CHARS,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcherySlowLogEvidenceTool,
)
from tests.unit.archery_harness_support import (
    TARGET_ARGUMENTS,
    _analysis_tools,
    _scenario,
    _success,
)


def _prepare_host_call(scenario, state, call):
    scenario.registry.pending.append(call)
    return scenario.prepare_call(
        SimpleNamespace(
            tool_name=call.name,
            objective="Execute deterministic Archery work",
            hypothesis_ids=(),
            arguments=call.arguments,
        ),
        state=state,
    )


def _apply_query_result(scenario, state, call, rows):
    prepared = _prepare_host_call(scenario, state, call)
    assert "local_rejection" not in prepared.metadata
    fixture = _success(
        call.arguments["sql_content"],
        rows=rows,
        max_result_chars=call.arguments.get("max_result_chars"),
    )
    return scenario.on_result(state, prepared, fixture.result)


def _pipeline_scenario():
    scenario = _scenario()
    state = scenario.state
    state.history_pipeline_enabled = True
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
    specs = scenario.build_tool_specs(_analysis_tools())
    return scenario, state, specs


def test_pipeline_starts_after_verified_archery_target_without_table_discovery() -> None:
    scenario, state, specs = _pipeline_scenario()
    state.slow_log_tables.clear()
    state.table_columns.clear()

    ranking = scenario.next_host_call(specs)

    assert ranking is not None
    assert ranking.arguments["instance_id"] == TARGET_ARGUMENTS["instance_id"]
    assert ranking.arguments["db_name"] == "archery"
    assert "SELECT id, Query_time_max, Query_time_sum" in ranking.arguments["sql_content"]
    assert "hostname_max = 'db-1.example:3306'" in ranking.arguments["sql_content"]


def test_history_priority_uses_union_of_both_top_twenty_percent_rankings() -> None:
    scenario, _, _ = _pipeline_scenario()
    rows = [
        {
            "id": row_id,
            "Query_time_max": 1000 - row_id,
            "Query_time_sum": row_id,
        }
        for row_id in range(1, 41)
    ]

    priority = scenario.client.prioritize_history_rows(rows)

    assert len(priority["high_priority_ids"]) == 16
    assert set(priority["high_priority_ids"]) == {
        *range(1, 9),
        *range(33, 41),
    }
    assert set(priority["ordered_ids"][:16]) == set(priority["high_priority_ids"])
    assert priority["ranks"]["1"]["priority"] == "high"
    assert priority["ranks"]["20"]["priority"] == "normal"


@pytest.mark.asyncio
async def test_host_pipeline_planning_does_not_invoke_the_model() -> None:
    scenario, state, specs = _pipeline_scenario()
    planner = archery_harness_module.ArcheryHarnessPlanner(
        scenario.client,
        scenario,
        scenario.registry,
    )

    action = await planner.plan(messages=[], tools=specs)

    assert action["tool_name"] == "sql_query_gymJPA"
    assert scenario.client.model.requests == []
    model_call = scenario.registry.pending[-1]
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=model_call.name,
            objective=action["objective"],
            hypothesis_ids=(),
            arguments=model_call.arguments,
        ),
        state=state,
    )
    assert prepared.metadata["host_generated"] is True
    assert prepared.metadata["internal_only"] is True


def test_missing_compact_id_is_reconciled_before_global_ranking() -> None:
    scenario, state, specs = _pipeline_scenario()
    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    _apply_query_result(
        scenario,
        state,
        ranking,
        [
            {"id": 2, "Query_time_max": 8.0, "Query_time_sum": 9.0},
            {"id": 1, "Query_time_max": 4.0, "Query_time_sum": 5.0},
        ],
    )
    compact = scenario.next_host_call(specs)
    assert compact is not None
    shared = {
        "hostname_max": "db-1.example:3306",
        "db_max": "orders_prod",
        "ts_min": "2026-07-23 15:59:00",
        "ts_max": "2026-07-23 16:00:00",
        "Query_time_max": 8.0,
        "Query_time_sum": 9.0,
        "sample_full_length": 8,
    }
    _apply_query_result(
        scenario,
        state,
        compact,
        [{"id": 2, "checksum": "checksum-2", **shared}],
    )

    reconciliation = scenario.next_host_call(specs)
    assert reconciliation is not None
    assert "id = 1" in reconciliation.arguments["sql_content"]
    _apply_query_result(
        scenario,
        state,
        reconciliation,
        [
            {
                "id": 1,
                "checksum": "checksum-1",
                **{
                    **shared,
                    "Query_time_max": 4.0,
                    "Query_time_sum": 5.0,
                },
            }
        ],
    )

    assert state.history_pipeline_phase == "ENRICHMENT"
    assert state.final_result.payload["history_snapshot_consistent"] is True
    assert state.history_processing_order == [2, 1]


def test_budget_stop_materializes_completed_ranking_rows_before_compact_scan() -> None:
    scenario, state, specs = _pipeline_scenario()
    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    _apply_query_result(
        scenario,
        state,
        ranking,
        [{"id": 1, "Query_time_max": 4.0, "Query_time_sum": 7.0}],
    )
    assert state.history_pipeline_phase == "COMPACT"
    assert state.final_result is None

    archery_harness_module._finalize_deterministic_pipeline_stop(
        scenario.client,
        state,
        stop_reason="BUDGET_EXHAUSTED",
    )

    assert state.final_result is not None
    assert state.final_result.payload["history_scan_complete"] is False
    assert state.final_result.payload["result_incomplete"] is True
    assert state.final_result.payload["rows"][0]["id"] == 1
    assert state.final_result.payload["enrichment_unfinished_ids"] == [1]


def test_budget_stop_keeps_complete_compact_history_root_cause_eligible() -> None:
    scenario, state, specs = _pipeline_scenario()
    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    _apply_query_result(
        scenario,
        state,
        ranking,
        [{"id": 1, "Query_time_max": 4.0, "Query_time_sum": 7.0}],
    )
    compact = scenario.next_host_call(specs)
    assert compact is not None
    _apply_query_result(
        scenario,
        state,
        compact,
        [
            {
                "id": 1,
                "hostname_max": "db-1.example:3306",
                "db_max": "orders_prod",
                "checksum": "checksum-1",
                "ts_min": "2026-07-23 15:59:00",
                "ts_max": "2026-07-23 16:00:00",
                "Query_time_max": 4.0,
                "Query_time_sum": 7.0,
                "sample_full_length": 20_000,
            }
        ],
    )

    archery_harness_module._finalize_deterministic_pipeline_stop(
        scenario.client,
        state,
        stop_reason="budget_exhausted",
    )

    assert state.final_result.payload["result_incomplete"] is False
    assert state.final_result.payload["enrichment_partial"] is True
    assert state.final_result.payload["enrichment_unfinished_ids"] == [1]
    assert state.history_sample_states[1] == "BUDGET_EXHAUSTED"
    evidence = ArcherySlowLogEvidenceTool(scenario.client)._build_slow_query_evidence(
        state.final_result,
        session_attempts=1,
        root_cause_ineligible_reason="",
        parsed_rows=scenario.client._tabular_rows(state.final_result.payload),
    )
    assert evidence["partial"] is False
    assert evidence["enrichment_partial"] is True
    assert evidence["root_cause_eligible"] is True


def test_host_generated_calls_use_separate_audit_counters() -> None:
    scenario, state, specs = _pipeline_scenario()
    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    prepared = _prepare_host_call(scenario, state, ranking)
    assert prepared.metadata["host_generated"] is True

    scenario._record_remote_call(state, prepared)
    diagnostics = scenario._diagnostics(
        state,
        target=(TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"]),
        completed=False,
    )

    assert diagnostics["model_executed_tool_calls"] == []
    assert diagnostics["host_executed_tool_calls"] == [ranking.name]
    assert diagnostics["host_request_ids"] == [prepared.metadata["request_id"]]
    assert diagnostics["mcp_tool_call_count"] == 1
    assert state.model_request_ids == []


def test_oversized_sample_is_chunked_but_exact_sql_is_used_for_explain() -> None:
    scenario, state, specs = _pipeline_scenario()
    sample = (
        "SELECT * FROM orders WHERE id IN ("
        + ",".join(str(value) for value in range(6000))
        + ") AND status = 'open'"
    )
    assert len(sample.encode("utf-8")) > 12_000

    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    _apply_query_result(
        scenario,
        state,
        ranking,
        [{"id": 81, "Query_time_max": 8.5, "Query_time_sum": 91.0}],
    )

    compact = scenario.next_host_call(specs)
    assert compact is not None
    compact_row = {
        "id": 81,
        "hostname_max": "db-1.example:3306",
        "db_max": "orders_prod",
        "checksum": "checksum-81",
        "ts_min": "2026-07-23 15:59:00",
        "ts_max": "2026-07-23 16:00:00",
        "Query_time_max": 8.5,
        "Query_time_sum": 91.0,
        "sample_full_length": len(sample.encode("utf-8")),
    }
    _apply_query_result(scenario, state, compact, [compact_row])

    recovered = ""
    chunk_calls = 0
    while state.history_sample_states[81] != "READY":
        chunk_call = scenario.next_host_call(specs)
        assert chunk_call is not None
        assert chunk_call.arguments["max_result_chars"] == (ARCHERY_SAMPLE_CHUNK_RESULT_CHARS)
        retrieval = scenario.client.history_sample_chunk_retrieval(
            chunk_call.arguments["sql_content"]
        )
        assert retrieval is not None
        _, offset, size = retrieval
        chunk = sample[offset - 1 : offset - 1 + size]
        recovered += chunk
        _apply_query_result(
            scenario,
            state,
            chunk_call,
            [{"sample_chunk": chunk}],
        )
        chunk_calls += 1

    assert chunk_calls < len(sample) // 4000
    assert recovered == sample
    projected = state.history_id_rows[81]
    assert projected["sample_representation"] == "structured"
    assert projected["sample_source_reconstructed"] is True
    assert projected["sample_structure_executable"] is True
    assert len(projected["sample"]) <= 12_000
    assert projected["sample"] != sample
    assert "IN (0," in projected["sample"]
    assert "5999)" in projected["sample"]
    assert projected["sample_in_lists"][0]["head_value_count"] > 0
    assert projected["sample_in_lists"][0]["tail_value_count"] > 0
    assert (
        scenario.client.history_row_for_explain(
            f"EXPLAIN {projected['sample']}",
            state.final_result.payload,
        )
        is None
    )

    state.analysis_instance_endpoints[3] = {"db-1.example:3306"}
    state.analysis_database_names[3] = {"orders_prod"}
    state.slow_query_table_structure_results.append(
        {
            "stage": "table_structure",
            "target": {
                "instance_id": 3,
                "db_name": "orders_prod",
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [{"COLUMN_NAME": "id"}]},
        }
    )

    explain = scenario.next_host_call(specs)
    assert explain is not None
    assert explain.arguments["sql_content"] == f"EXPLAIN {sample}"
    assert explain.arguments["max_result_chars"] >= len(sample) + 12_000
    assert sample not in projected["sample"]

    _apply_query_result(
        scenario,
        state,
        explain,
        [{"id": 1, "select_type": "SIMPLE", "table": "orders", "type": "range"}],
    )
    assert (
        state.slow_query_explain_results[0]["source_history_row"]["sample"] == (projected["sample"])
    )
    assert sample not in str(state.slow_query_explain_results[0])

    state.slow_query_index_results.append(
        {
            "stage": "indexes",
            "target": {
                "instance_id": 3,
                "db_name": "orders_prod",
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [{"INDEX_NAME": "PRIMARY"}]},
        }
    )
    finish = scenario.next_host_call(specs)
    assert finish is not None
    assert finish.name == "finish_archery_investigation"
    prepared_finish = _prepare_host_call(scenario, state, finish)
    scenario.on_result(state, prepared_finish, prepared_finish.local_result)
    assert state.history_sample_states[81] == "ANALYZED"
    assert state.history_exact_sample is None
    assert state.finish_accepted is True
    final_row = state.final_result.payload["rows"][0]
    assert final_row["sample"] == projected["sample"]
    assert sample not in str(state.final_result.payload)
