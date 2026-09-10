from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.adapters import archery_harness as archery_harness_module
from app.adapters.archery_mcp import (
    ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS,
    ARCHERY_SAMPLE_CHUNK_MIN_CHARS,
    ARCHERY_SAMPLE_CHUNK_RESULT_CHARS,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcherySlowLogEvidenceTool,
)
from app.agent_runtime import InvocationError, ToolInvocationStatus
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


def _apply_query_failure(
    scenario,
    state,
    call,
    *,
    code: str = "remote_query_failed",
):
    prepared = _prepare_host_call(scenario, state, call)
    assert "local_rejection" not in prepared.metadata
    return scenario.on_failure(
        state,
        prepared,
        InvocationError(
            code=code,
            message="sanitized remote query failure",
            retryable=False,
        ),
        ToolInvocationStatus.FAILED,
    )


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
            "raw",
            "raw_metric",
            "artifact_count",
            "hash",
            "content_hash",
            "request_id",
            "usage",
            "sha256",
            "sample_sha256",
            "business_blob",
            "sample",
        }
    }
    state.resolved_endpoints[target] = {"db-1.example:3306"}
    specs = scenario.build_tool_specs(_analysis_tools())
    return scenario, state, specs


def _history_compact_row(
    row_id: int,
    *,
    endpoint: str = "db-1.example:3306",
    db_name: str = "orders_prod",
    checksum: str | None = None,
    sample_full_length: int = 64,
):
    return {
        "id": row_id,
        "hostname_max": endpoint,
        "db_max": db_name,
        "checksum": checksum or f"checksum-{row_id}",
        "ts_min": "2026-07-23 15:59:00",
        "ts_max": "2026-07-23 16:00:00",
        "Query_time_max": float(row_id),
        "Query_time_sum": float(row_id * 10),
        ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS: sample_full_length,
        "raw": {"nested": ["value", {"raw": True}]},
        "raw_metric": row_id * 7,
        "artifact_count": row_id,
        "hash": f"business-hash-{row_id}",
        "content_hash": f"business-content-hash-{row_id}",
        "request_id": f"business-request-{row_id}",
        "usage": {"business_units": row_id},
        "sha256": f"business-sha256-{row_id}",
        "sample_sha256": f"business-sample-sha256-{row_id}",
        "business_blob": f"business-value-{row_id}",
    }


def _prime_enrichment(scenario, state, rows):
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


def _prime_reuse_candidate(
    scenario,
    state,
    *,
    current_instance_id: int,
    current_db_name: str = "orders_prod",
    prior_instance_id: int = 3,
    prior_db_name: str = "orders_prod",
):
    endpoint = "db-1.example:3306"
    prior_sample = "SELECT * FROM orders WHERE id = 2"
    exact_sample = (
        "SELECT * FROM orders WHERE id IN ("
        + ",".join(str(value) for value in range(6000))
        + ")"
    )
    rows = [
        _history_compact_row(
            2,
            db_name=prior_db_name,
            checksum="shared-checksum",
            sample_full_length=len(prior_sample),
        ),
        _history_compact_row(
            1,
            db_name=current_db_name,
            checksum="shared-checksum",
            sample_full_length=len(exact_sample),
        ),
    ]
    _prime_enrichment(scenario, state, rows)
    scenario._accept_reconstructed_sample(state, 2, prior_sample)
    prior_source = dict(state.history_id_rows[2])
    state.history_sample_states[2] = "ANALYZED"
    state.history_exact_sample_id = None
    state.history_exact_sample = None
    scenario._accept_reconstructed_sample(state, 1, exact_sample)
    state.history_processing_order = [2, 1]
    state.history_current_id = 1
    state.analysis_instance_endpoints = {current_instance_id: {endpoint}}
    state.analysis_database_names = {current_instance_id: {current_db_name}}
    state.slow_query_table_structure_results.append(
        {
            "stage": "table_structure",
            "target": {
                "instance_id": current_instance_id,
                "db_name": current_db_name,
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [{"COLUMN_NAME": "id"}]},
        }
    )
    state.slow_query_index_results.append(
        {
            "stage": "indexes",
            "target": {
                "instance_id": current_instance_id,
                "db_name": current_db_name,
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [{"INDEX_NAME": "PRIMARY"}]},
        }
    )
    state.slow_query_explain_results.append(
        {
            "stage": "explain",
            "source_history_row": prior_source,
            "target": {
                "instance_id": prior_instance_id,
                "db_name": prior_db_name,
            },
            "statement_type": "select",
            "result": {"row_count": 1, "rows": [{"table": "orders"}]},
        }
    )
    scenario._refresh_history_pipeline_result(state)
    return exact_sample


def test_pipeline_requires_discovered_complete_history_schema_before_start() -> None:
    scenario, state, specs = _pipeline_scenario()
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    discovered_tables = state.slow_log_tables.pop(target)
    discovered_columns = state.table_columns.pop(target)

    assert scenario.next_host_call(specs) is None

    state.slow_log_tables[target] = discovered_tables
    state.table_columns[target] = discovered_columns
    ranking = scenario.next_host_call(specs)

    assert ranking is not None
    assert ranking.arguments["instance_id"] == TARGET_ARGUMENTS["instance_id"]
    assert ranking.arguments["db_name"] == "archery"
    assert "SELECT id, Query_time_max, Query_time_sum" in ranking.arguments["sql_content"]
    assert "hostname_max = 'db-1.example:3306'" in ranking.arguments["sql_content"]



@pytest.mark.parametrize("suffix", ["", " LIMIT 0", " LIMIT 1", " LIMIT 1000"])
def test_history_scope_ignores_plain_limit_presence_and_value(suffix: str) -> None:
    scenario, state, specs = _pipeline_scenario()
    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    without_limit = ranking.arguments["sql_content"].rsplit(" LIMIT ", 1)[0]

    assert scenario._is_scoped_history_ranking_query(state, without_limit + suffix)


def test_pipeline_uses_executed_limit_only_for_page_progress() -> None:
    scenario, state, specs = _pipeline_scenario()
    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    prepared = _prepare_host_call(scenario, state, ranking)
    actual_sql = ranking.arguments["sql_content"].rsplit(" LIMIT ", 1)[0] + " LIMIT 2"
    scenario.on_result(
        state,
        prepared,
        _success(
            actual_sql,
            rows=[
                {"id": 2, "Query_time_max": 8.0, "Query_time_sum": 9.0},
                {"id": 1, "Query_time_max": 4.0, "Query_time_sum": 5.0},
            ],
        ).result,
    )

    assert state.history_pipeline_phase == "RANKING"
    assert state.history_page_cursor == 1
    next_page = scenario.next_host_call(specs)
    assert next_page is not None
    assert "id < 1" in next_page.arguments["sql_content"]

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
    row_two = _history_compact_row(2, sample_full_length=8)
    row_two["Query_time_max"] = 8.0
    row_two["Query_time_sum"] = 9.0
    _apply_query_result(scenario, state, compact, [row_two])

    reconciliation = scenario.next_host_call(specs)
    assert reconciliation is not None
    assert "id = 1" in reconciliation.arguments["sql_content"]
    row_one = _history_compact_row(1, sample_full_length=8)
    row_one["Query_time_max"] = 4.0
    row_one["Query_time_sum"] = 5.0
    _apply_query_result(scenario, state, reconciliation, [row_one])

    assert state.history_pipeline_phase == "ENRICHMENT"
    assert state.final_result.history_incomplete_reasons == (
        "history_lossless_recovery_incomplete",
    )
    assert state.history_processing_order == [2, 1]
    assert [row["id"] for row in state.final_result.payload["rows"]] == [2, 1]
    assert ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS not in state.final_result.payload["rows"][0]


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
    assert state.final_result.history_complete is False
    assert "history_scan_incomplete" in state.final_result.history_incomplete_reasons
    assert state.final_result.payload["rows"][0]["id"] == 1
    assert "result_incomplete" not in state.final_result.payload
    assert "enrichment_unfinished_ids" not in state.final_result.payload


def test_budget_stop_before_sample_recovery_makes_history_ineligible() -> None:
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
        [_history_compact_row(1, sample_full_length=20_000)],
    )

    archery_harness_module._finalize_deterministic_pipeline_stop(
        scenario.client,
        state,
        stop_reason="budget_exhausted",
    )

    assert state.final_result.history_complete is False
    assert "history_lossless_recovery_incomplete" in state.final_result.history_incomplete_reasons
    assert state.final_result.enrichment_partial is False
    assert state.final_result.enrichment_unfinished_ids == ()
    assert state.history_sample_states[1] == "BUDGET_EXHAUSTED"
    assert "sample_recovery_status" not in state.final_result.payload["rows"][0]
    evidence = ArcherySlowLogEvidenceTool(scenario.client)._build_slow_query_evidence(
        state.final_result,
        session_attempts=1,
        root_cause_ineligible_reason="",
        parsed_rows=scenario.client._tabular_rows(state.final_result.payload),
    )
    assert evidence["partial"] is True
    assert evidence["history_scan_complete"] is False
    assert evidence["root_cause_eligible"] is False


def test_budget_stop_after_lossless_history_only_marks_supplemental_partial() -> None:
    scenario, state, _ = _pipeline_scenario()
    sample = "SELECT * FROM orders WHERE id = 1"
    _prime_enrichment(
        scenario,
        state,
        [_history_compact_row(1, sample_full_length=len(sample.encode("utf-8")))],
    )
    scenario._accept_reconstructed_sample(state, 1, sample)
    clean_payload = deepcopy(state.final_result.payload)

    archery_harness_module._finalize_deterministic_pipeline_stop(
        scenario.client,
        state,
        stop_reason="BUDGET_EXHAUSTED",
    )

    assert state.final_result.payload == clean_payload
    assert state.final_result.history_complete is True
    assert state.final_result.history_incomplete_reasons == ()
    assert state.final_result.enrichment_partial is True
    assert state.final_result.enrichment_unfinished_ids == (1,)
    assert "sample_recovery_status" not in state.final_result.payload["rows"][0]
    evidence = ArcherySlowLogEvidenceTool(scenario.client)._build_slow_query_evidence(
        state.final_result,
        session_attempts=1,
        root_cause_ineligible_reason="",
        parsed_rows=scenario.client._tabular_rows(state.final_result.payload),
    )
    assert evidence["partial"] is False
    assert evidence["history_scan_complete"] is True
    assert evidence["root_cause_eligible"] is True
    assert evidence["enrichment_partial"] is True


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
    compact_row = _history_compact_row(
        81,
        sample_full_length=len(sample.encode("utf-8")),
    )
    compact_row["Query_time_max"] = 8.5
    compact_row["Query_time_sum"] = 91.0
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
    assert projected["sample"] == sample
    assert projected["raw"] == {"nested": ["value", {"raw": True}]}
    assert projected["request_id"] == "business-request-81"
    assert projected["usage"] == {"business_units": 81}
    assert projected["sample_sha256"] == "business-sample-sha256-81"
    assert "sample_recovery_status" not in projected
    assert "sample_source_reconstructed" not in projected
    assert state.history_sample_metadata[81]["sample_source_reconstructed"] is True
    assert state.history_sample_metadata[81]["sample_sha256"] != projected["sample_sha256"]
    explainable = scenario.client.history_row_for_explain(
        f"EXPLAIN {sample}",
        state.final_result.payload,
    )
    assert explainable is not None
    assert explainable["id"] == 81
    assert state.final_result.history_complete is True

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
    indexes = scenario.next_host_call(specs)
    assert indexes is not None
    assert "information_schema.STATISTICS" in indexes.arguments["sql_content"]
    assert sample not in indexes.arguments["sql_content"]
    _apply_query_result(
        scenario,
        state,
        indexes,
        [{"INDEX_NAME": "PRIMARY", "COLUMN_NAME": "id"}],
    )

    explain = scenario.next_host_call(specs)
    assert explain is not None
    assert explain.arguments["sql_content"] == f"EXPLAIN {sample}"
    assert explain.arguments["max_result_chars"] >= len(sample) + 12_000
    assert projected["sample"] == sample

    _apply_query_result(
        scenario,
        state,
        explain,
        [{"id": 1, "select_type": "SIMPLE", "table": "orders", "type": "range"}],
    )
    assert state.slow_query_explain_results[0]["source_history_row"]["sample"] == sample
    assert sample in str(state.slow_query_explain_results[0])

    finish = scenario.next_host_call(specs)
    assert finish is not None
    assert finish.name == "finish_archery_investigation"
    prepared_finish = _prepare_host_call(scenario, state, finish)
    scenario.on_result(state, prepared_finish, prepared_finish.local_result)
    assert state.history_sample_states[81] == "ANALYZED"
    assert state.history_exact_sample is None
    assert state.finish_accepted is True
    final_row = state.final_result.payload["rows"][0]
    assert {key.casefold(): value for key, value in final_row.items()} == {
        key.casefold(): value for key, value in projected.items()
    }
    assert final_row["sample"] == sample
    assert sample in str(state.final_result.payload)


def test_explain_reuse_is_bound_to_instance_database_and_checksum() -> None:
    scenario, state, specs = _pipeline_scenario()
    exact_sample = _prime_reuse_candidate(
        scenario,
        state,
        current_instance_id=3,
    )

    finish = scenario.next_host_call(specs)

    assert finish is not None
    assert finish.name == "finish_archery_investigation"
    assert state.history_sample_states[1] == "ANALYZED"
    assert state.history_sample_metadata[1]["explain_status"] == "reused"
    assert state.history_sample_metadata[1]["explain_reused_from_history_id"] == 2
    assert state.history_exact_sample is None
    assert exact_sample in str(state.final_result.payload)
    assert exact_sample not in str(state.slow_query_explain_results)


@pytest.mark.parametrize(
    ("current_instance_id", "current_db_name"),
    [
        (4, "orders_prod"),
        (3, "payments_prod"),
    ],
)
def test_explain_is_not_reused_across_instance_or_database(
    current_instance_id: int,
    current_db_name: str,
) -> None:
    scenario, state, specs = _pipeline_scenario()
    exact_sample = _prime_reuse_candidate(
        scenario,
        state,
        current_instance_id=current_instance_id,
        current_db_name=current_db_name,
    )

    explain = scenario.next_host_call(specs)

    assert explain is not None
    assert explain.name == "sql_query_gymJPA"
    assert explain.arguments["instance_id"] == current_instance_id
    assert explain.arguments["db_name"] == current_db_name
    assert explain.arguments["sql_content"] == f"EXPLAIN {exact_sample}"
    assert state.history_sample_metadata[1].get("explain_reused_from_history_id") is None


@pytest.mark.parametrize("phase", ["RANKING", "COMPACT"])
def test_history_page_failure_retains_available_partial_rows(phase: str) -> None:
    scenario, state, specs = _pipeline_scenario()
    initial = scenario.next_host_call(specs)
    assert initial is not None
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.history_pipeline_phase = phase
    state.history_pipeline_target = target
    state.history_result_target = target
    state.history_pipeline_endpoint = "db-1.example:3306"
    state.history_snapshot_max_id = 3
    state.history_page_cursor = 2
    state.history_ranking_rows = {
        row_id: {
            "id": row_id,
            "Query_time_max": float(row_id),
            "Query_time_sum": float(row_id * 10),
        }
        for row_id in (3, 2)
    }
    state.history_ranking_page_count = 1
    if phase == "COMPACT":
        state.history_ranking_scan_complete = True
        state.history_compact_rows = {3: _history_compact_row(3)}
        state.history_compact_page_count = 1

    failed_page = scenario.next_host_call(specs)
    assert failed_page is not None
    _apply_query_failure(scenario, state, failed_page)
    archery_harness_module._finalize_deterministic_pipeline_stop(
        scenario.client,
        state,
        stop_reason="FAILED",
    )

    assert state.history_pipeline_phase == "COMPLETED"
    assert state.final_result is not None
    assert state.final_result.history_complete is False
    assert "history_scan_incomplete" in state.final_result.history_incomplete_reasons
    expected_ids = [3, 2] if phase == "RANKING" else [3]
    assert [row["id"] for row in state.final_result.payload["rows"]] == expected_ids
    assert "result_incomplete" not in state.final_result.payload
    assert "enrichment_unfinished_ids" not in state.final_result.payload
    assert all(
        "sample_recovery_status" not in row for row in state.final_result.payload["rows"]
    )


def test_direct_sample_failure_switches_to_chunk_recovery() -> None:
    scenario, state, specs = _pipeline_scenario()
    sample = "SELECT * FROM orders WHERE id = 1"
    _prime_enrichment(
        scenario,
        state,
        [_history_compact_row(1, sample_full_length=len(sample))],
    )

    direct_sample = scenario.next_host_call(specs)
    assert direct_sample is not None
    assert "SELECT sample FROM" in direct_sample.arguments["sql_content"]
    _apply_query_failure(scenario, state, direct_sample)

    assert state.history_sample_states[1] == "CHUNK_PENDING"
    assert state.history_chunk_offset == 1
    chunk = scenario.next_host_call(specs)
    assert chunk is not None
    assert "SUBSTRING(sample, 1," in chunk.arguments["sql_content"]


def test_minimum_chunk_failure_marks_one_row_failed_and_continues_next_id() -> None:
    scenario, state, specs = _pipeline_scenario()
    _prime_enrichment(
        scenario,
        state,
        [
            _history_compact_row(2, sample_full_length=20_000),
            _history_compact_row(1, sample_full_length=20),
        ],
    )
    state.history_current_id = 2
    scenario._start_history_chunk_recovery(state, 2)
    state.history_chunk_size = ARCHERY_SAMPLE_CHUNK_MIN_CHARS

    final_chunk_attempt = scenario.next_host_call(specs)
    assert final_chunk_attempt is not None
    _apply_query_failure(scenario, state, final_chunk_attempt)
    next_sample = scenario.next_host_call(specs)

    assert state.history_sample_states[2] == "FAILED"
    assert state.history_sample_metadata[2]["sample_recovery_failure"] == (
        "history_sample_chunk_tool_failure"
    )
    assert next_sample is not None
    assert "id = 1" in next_sample.arguments["sql_content"]
    assert state.history_current_id == 1


def test_structure_and_index_failures_do_not_block_exact_explain() -> None:
    scenario, state, specs = _pipeline_scenario()
    sample = "SELECT * FROM orders WHERE customer_id = 42"
    _prime_enrichment(
        scenario,
        state,
        [_history_compact_row(42, sample_full_length=len(sample))],
    )
    state.history_current_id = 42
    scenario._accept_reconstructed_sample(state, 42, sample)
    state.analysis_instance_endpoints[3] = {"db-1.example:3306"}
    state.analysis_database_names[3] = {"orders_prod"}

    columns = scenario.next_host_call(specs)
    assert columns is not None
    assert columns.name == "list_table_columns_gymJPA"
    _apply_query_failure(scenario, state, columns, code="columns_unavailable")

    indexes = scenario.next_host_call(specs)
    assert indexes is not None
    assert "information_schema.STATISTICS" in indexes.arguments["sql_content"]
    _apply_query_failure(scenario, state, indexes, code="indexes_unavailable")

    explain = scenario.next_host_call(specs)
    assert explain is not None
    assert explain.arguments["sql_content"] == f"EXPLAIN {sample}"
    assert {
        failure["stage"] for failure in state.slow_query_analysis_failures
    } >= {"table_structure", "indexes"}


def test_explain_failure_finishes_current_row_and_continues_next_id() -> None:
    scenario, state, specs = _pipeline_scenario()
    samples = {
        2: "SELECT * FROM orders WHERE id = 2",
        1: "SELECT * FROM orders WHERE id = 1",
    }
    _prime_enrichment(
        scenario,
        state,
        [
            _history_compact_row(
                row_id,
                sample_full_length=len(sample),
            )
            for row_id, sample in samples.items()
        ],
    )
    state.history_current_id = 2
    scenario._accept_reconstructed_sample(state, 2, samples[2])
    state.analysis_instance_endpoints[3] = {"db-1.example:3306"}
    state.analysis_database_names[3] = {"orders_prod"}
    for stage, result in (
        ("table_structure", {"COLUMN_NAME": "id"}),
        ("indexes", {"INDEX_NAME": "PRIMARY"}),
    ):
        target_result = {
            "stage": stage,
            "target": {
                "instance_id": 3,
                "db_name": "orders_prod",
                "table_name": "orders",
            },
            "result": {"row_count": 1, "rows": [result]},
        }
        (
            state.slow_query_table_structure_results
            if stage == "table_structure"
            else state.slow_query_index_results
        ).append(target_result)

    next_recovery = scenario.next_host_call(specs)
    assert next_recovery is not None
    assert "SELECT sample FROM" in next_recovery.arguments["sql_content"]
    assert "id = 1" in next_recovery.arguments["sql_content"]
    assert not next_recovery.arguments["sql_content"].startswith("EXPLAIN")
    _apply_query_result(
        scenario,
        state,
        next_recovery,
        [{"sample": samples[1]}],
    )
    assert state.final_result.history_complete is True

    explain = scenario.next_host_call(specs)
    assert explain is not None
    assert explain.arguments["sql_content"] == f"EXPLAIN {samples[2]}"
    _apply_query_failure(scenario, state, explain, code="explain_unavailable")
    next_sample = scenario.next_host_call(specs)

    assert state.history_sample_states[2] == "ANALYZED"
    assert state.history_sample_metadata[2]["explain_status"] == "failed"
    assert next_sample is not None
    assert next_sample.arguments["sql_content"] == f"EXPLAIN {samples[1]}"
    assert state.history_current_id == 1
