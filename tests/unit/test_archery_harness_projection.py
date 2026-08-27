from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest

import app.adapters.archery_harness as archery_harness_module
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
)
from tests.unit.archery_harness_support import (
    _MERGE_IDS_SQL,
    _MERGE_RECOVERED_ROW,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    FINAL_SQL,
    INSTANCE_SQL,
    MEMBER_SQL,
    OCCURRED_AT,
    TARGET_ARGUMENTS,
    _assess_pending_result,
    _bound_history_scenario,
    _scenario,
)


@pytest.mark.parametrize(
    ("result", "reason_code"),
    [
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": INSTANCE_SQL,
                    "rows": [{"f_instance_id": 53}],
                }
            },
            "actual_sql_mismatch",
        ),
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": MEMBER_SQL,
                    "instance_id": 99,
                    "db_name": "archery",
                    "rows": [{"f_instance_id": 53}],
                }
            },
            "actual_target_mismatch",
        ),
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": MEMBER_SQL,
                    "instance_id": 17,
                    "db_name": "Archery",
                    "rows": [{"f_instance_id": 53}],
                }
            },
            "actual_target_mismatch",
        ),
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": MEMBER_SQL,
                    "instance_id": 17,
                    "db_name": "archery",
                    "rows": [{"f_instance_id": 53}],
                },
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "full_sql": MEMBER_SQL,
                                "instance_id": 99,
                                "db_name": "archery",
                            }
                        ),
                    }
                ],
            },
            "actual_target_mismatch",
        ),
    ],
)
def test_pre_history_response_mismatch_does_not_authorize_metadata_lineage(
    result: dict[str, Any],
    reason_code: str,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Resolve the alert instance",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
        ),
        state=state,
    )

    scenario.on_result(state, prepared, result)

    assert state.member_instance_ids == {}
    assert state.resolved_endpoints == {}
    assert state.history_result_target is None
    assert state.slow_query_analysis_failures == []
    assert state.query_trace[-1]["outcome"] == "result_mismatch"
    assert state.query_trace[-1]["reason_code"] == reason_code


def test_pre_history_instance_allowlist_is_reused_only_for_database_discovery() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    instances_text = (
        "实例清单（第 1 页）：\n"
        "1. [ID:3] pcm orders-db.example:3306 资源组:[1]"
    )
    catalog = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Discover the MCP instance catalog",
            hypothesis_ids=(),
            arguments={},
        ),
        state=state,
    )
    result = {
        "structuredContent": {"result": instances_text},
        "content": [{"type": "text", "text": instances_text}],
    }

    scenario.on_result(state, catalog, result)

    assert state.analysis_instance_endpoints == {}
    allowlist = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Resolve one execution-allowlisted instance",
            hypothesis_ids=(),
            arguments={"instance_ref": "pcm"},
        ),
        state=state,
    )
    scenario.on_result(state, allowlist, result)

    assert state.analysis_instance_endpoints == {3: {"orders-db.example:3306"}}
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1040,
                    "checksum": "pre-history-discovery",
                    "sample": "SELECT * FROM orders WHERE id = 1",
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    databases = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            objective="Discover databases for the bound instance",
            hypothesis_ids=(),
            arguments={"instance_id": 3},
        ),
        state=state,
    )
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    columns = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Do not authorize SQL before database discovery",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": columns_sql,
            },
        ),
        state=state,
    )

    assert "local_rejection" not in databases.metadata
    assert columns.metadata["local_rejection"]["reason_code"] == (
        "database_not_allowlisted"
    )


def test_successful_history_response_without_deferred_target_binding_is_not_adopted() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.window_start, state.window_end = archery_harness_module.client_window(
        scenario.client,
        OCCURRED_AT,
    )
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.resolved_endpoints[target] = {"db-1.example:3306"}
    arguments = {
        "db_name": TARGET_ARGUMENTS["db_name"],
        "sql_content": FINAL_SQL,
    }
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Let the remote Schema validate the missing instance id",
            hypothesis_ids=(),
            arguments=arguments,
        ),
        state=state,
    )

    assert "local_rejection" not in prepared.metadata
    assert prepared.metadata["deferred_target_binding"][
        "missing_or_invalid_fields"
    ] == ["instance_id"]
    transition = scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": FINAL_SQL,
                "rows": [{"id": 999, "sample": "RAW_BINDING_SENTINEL"}],
            }
        },
    )

    assert state.final_result is None
    assert state.history_id_rows == {}
    assert state.history_window_state == "FAILED_TERMINAL"
    assert state.pending_result_assessment is None
    rendered = json.dumps(transition.message, ensure_ascii=False)
    assert "target_binding_unavailable" in rendered
    assert "RAW_BINDING_SENTINEL" not in rendered


def test_successful_history_baseline_resets_prior_terminal_failure() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.window_start, state.window_end = archery_harness_module.client_window(
        scenario.client,
        OCCURRED_AT,
    )
    target = (TARGET_ARGUMENTS["instance_id"], TARGET_ARGUMENTS["db_name"])
    state.resolved_endpoints[target] = {"db-1.example:3306"}
    state.history_window_state = "FAILED_TERMINAL"
    state.history_window_failure = {"reason_code": "prior_tool_failure"}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Retry a complete history baseline",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
        ),
        state=state,
    )

    assert "local_rejection" not in prepared.metadata
    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": FINAL_SQL,
                "rows": [],
            }
        },
    )
    assert state.history_window_state == "PENDING"
    assert state.history_window_failure is None
    _assess_pending_result(scenario, state, content_state="complete")

    assert state.history_window_state == "NO_DATA"
    assert state.history_window_failure is None
    assert state.final_result is not None


def test_successful_supplemental_sql_without_deferred_binding_does_not_mutate_work_item() -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 2051,
                "checksum": "deferred-columns",
                "sample": "SELECT * FROM orders WHERE id = 1",
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    scenario._initialize_supplemental_stage_states(state)
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Let the remote Schema validate the missing instance id",
            hypothesis_ids=(),
            arguments={"db_name": "orders_prod", "sql_content": columns_sql},
        ),
        state=state,
    )

    assert "local_rejection" not in prepared.metadata
    before_work_items = {
        key: dict(item) for key, item in state.supplemental_work_items.items()
    }
    transition = scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": columns_sql,
                "rows": [{"COLUMN_NAME": "RAW_BINDING_SENTINEL"}],
            }
        },
    )

    assert state.slow_query_table_structure_results == []
    assert state.supplemental_work_items == before_work_items
    assert state.pending_result_assessment is None
    rendered = json.dumps(transition.message, ensure_ascii=False)
    assert "target_binding_unavailable" in rendered
    assert "RAW_BINDING_SENTINEL" not in rendered


@pytest.mark.parametrize(
    ("tool_name", "arguments", "stage"),
    [
        (ARCHERY_MCP_DATABASES_TOOL_NAME, {}, "target_resolution"),
        (
            ARCHERY_MCP_TABLES_TOOL_NAME,
            {"instance_id": 3},
            "target_resolution",
        ),
        (
            ARCHERY_MCP_COLUMNS_TOOL_NAME,
            {"instance_id": 3, "db_name": "orders_prod"},
            "table_structure",
        ),
    ],
)
def test_successful_discovery_without_deferred_binding_is_audit_only(
    tool_name: str,
    arguments: dict[str, Any],
    stage: str,
) -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 2052,
                "checksum": "deferred-discovery",
                "sample": "SELECT * FROM orders WHERE id = 1",
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    scenario._initialize_supplemental_stage_states(state)
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=tool_name,
            objective="Let the remote Schema validate ordinary required fields",
            hypothesis_ids=(),
            arguments=arguments,
        ),
        state=state,
    )

    assert "local_rejection" not in prepared.metadata
    assert prepared.metadata["deferred_target_binding"]["stage"] == stage
    before_endpoints = dict(state.analysis_instance_endpoints)
    before_databases = dict(state.analysis_database_names)
    before_columns = dict(state.table_columns)
    before_work_items = {
        key: dict(item) for key, item in state.supplemental_work_items.items()
    }
    transition = scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "rows": [{"name": "RAW_BINDING_SENTINEL"}],
            }
        },
    )

    assert state.analysis_instance_endpoints == before_endpoints
    assert state.analysis_database_names == before_databases
    assert state.table_columns == before_columns
    assert state.supplemental_work_items == before_work_items
    assert state.pending_result_assessment is None
    rendered = json.dumps(transition.message, ensure_ascii=False)
    assert "target_binding_unavailable" in rendered
    assert "RAW_BINDING_SENTINEL" not in rendered


def test_explicit_actual_target_mismatch_is_not_collected() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1043,
                    "checksum": "actual-target-orders",
                    "sample": sample,
                    "Query_time_max": 7.0,
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Collect bound columns",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": columns_sql,
            },
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": columns_sql,
                "instance_id": 99,
                "db_name": "orders_prod",
                "rows": [{"COLUMN_NAME": "id"}],
            }
        },
    )
    assert state.slow_query_table_structure_results == []
    assert state.slow_query_analysis_failures[0]["reason_code"] == (
        "actual_target_mismatch"
    )


@pytest.mark.parametrize(
    ("metadata_table", "result_row", "result_attribute", "mismatched_field"),
    [
        (
            "COLUMNS",
            {
                "TABLE_SCHEMA": "other_prod",
                "TABLE_NAME": "orders",
                "COLUMN_NAME": "id",
            },
            "slow_query_table_structure_results",
            "db_name",
        ),
        (
            "STATISTICS",
            {
                "TABLE_SCHEMA": "orders_prod",
                "TABLE_NAME": "Orders",
                "INDEX_NAME": "PRIMARY",
            },
            "slow_query_index_results",
            "table_name",
        ),
    ],
)
def test_information_schema_row_target_mismatch_is_not_collected(
    metadata_table: str,
    result_row: dict[str, Any],
    result_attribute: str,
    mismatched_field: str,
) -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    selected_columns = (
        "TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME"
        if metadata_table == "COLUMNS"
        else "TABLE_SCHEMA, TABLE_NAME, INDEX_NAME"
    )
    metadata_sql = (
        f"SELECT {selected_columns} FROM information_schema.{metadata_table} "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1044,
                    "checksum": "row-target-orders",
                    "sample": sample,
                    "Query_time_max": 7.0,
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Collect bound metadata",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": metadata_sql,
            },
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": metadata_sql,
                "rows": [result_row],
            }
        },
    )

    assert getattr(state, result_attribute) == []
    failure = state.slow_query_analysis_failures[0]
    assert failure["reason_code"] == "actual_target_mismatch"
    assert mismatched_field in failure["detail"]


def test_incomplete_supplemental_results_are_recorded_only_as_evidence_gaps() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    columns_sql = (
        "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME "
        "FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    explain_sql = f"EXPLAIN {sample}"
    indexes_sql = (
        "SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME "
        "FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1045,
                "checksum": "incomplete-supplemental-orders",
                "sample": sample,
                "Query_time_max": 7.0,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    calls = (
        (
            columns_sql,
            {
                "TABLE_SCHEMA": "orders_prod",
                "TABLE_NAME": "orders",
                "COLUMN_NAME": "id",
            },
        ),
        (explain_sql, {"id": 1, "table": "orders", "type": "const"}),
        (
            indexes_sql,
            {
                "TABLE_SCHEMA": "orders_prod",
                "TABLE_NAME": "orders",
                "INDEX_NAME": "PRIMARY",
            },
        ),
    )

    for sql, row in calls:
        prepared = scenario.prepare_call(
            SimpleNamespace(
                tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                objective="Collect bound supplemental evidence",
                hypothesis_ids=(),
                arguments={
                    "instance_id": 3,
                    "db_name": "orders_prod",
                    "sql_content": sql,
                },
            ),
            state=state,
        )
        assert "local_rejection" not in prepared.metadata
        scenario.on_result(
            state,
            prepared,
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": sql,
                    "mcp_reported_row_count": 2,
                    "rows": [row],
                }
            },
        )
        _assess_pending_result(
            scenario,
            state,
            content_state="content_too_long",
        )

    assert state.slow_query_table_structure_results == []
    assert state.slow_query_explain_results == []
    assert state.slow_query_index_results == []
    incomplete_failures = [
        failure
        for failure in state.slow_query_analysis_failures
        if failure["reason_code"] == "supplemental_result_incomplete"
    ]
    assert [failure["stage"] for failure in incomplete_failures] == [
        "table_structure",
        "explain",
        "indexes",
    ]
    assert all(failure["error_type"] == "incomplete_result" for failure in incomplete_failures)


def test_model_complete_assessment_overrides_program_hint_after_state_restore() -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 2053,
                "checksum": "assessment-override",
                "sample": "SELECT * FROM orders WHERE id = 1",
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    scenario._initialize_supplemental_stage_states(state)
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Collect bound table structure",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": columns_sql,
            },
        ),
        state=state,
    )
    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": columns_sql,
                "mcp_reported_row_count": 2,
                "rows": [{"COLUMN_NAME": "id"}],
            }
        },
    )

    assert state.pending_result_assessment is not None
    assert state.pending_result_assessment["program_checks"]["result_incomplete"] is True
    assert state.slow_query_table_structure_results == []
    restored_state = deepcopy(state)
    restored_scenario = _scenario()
    restored_scenario.restore_state(restored_state)
    _assess_pending_result(restored_scenario, restored_state, content_state="complete")

    assert restored_state.pending_result_assessment is None
    assert restored_state.pending_supplemental_candidate is None
    assert len(restored_state.slow_query_table_structure_results) == 1
    assert not any(
        failure["reason_code"] == "supplemental_result_incomplete"
        for failure in restored_state.slow_query_analysis_failures
    )


def test_model_incomplete_assessment_overrides_program_complete_hint() -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 2054,
                "checksum": "assessment-incomplete",
                "sample": "SELECT * FROM orders WHERE id = 1",
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    scenario._initialize_supplemental_stage_states(state)
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Collect bound table structure",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": columns_sql,
            },
        ),
        state=state,
    )
    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": columns_sql,
                "rows": [{"COLUMN_NAME": "id"}],
            }
        },
    )

    assert state.pending_result_assessment is not None
    assert state.pending_result_assessment["program_checks"]["result_incomplete"] is False
    _assess_pending_result(scenario, state, content_state="content_too_long")

    assert state.slow_query_table_structure_results == []
    assert any(
        failure["reason_code"] == "supplemental_result_incomplete"
        for failure in state.slow_query_analysis_failures
    )


def test_database_discovery_actual_instance_mismatch_does_not_authorize_database() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1046,
                    "checksum": "database-target",
                    "sample": "SELECT * FROM orders",
                    "Query_time_max": 7.0,
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            objective="Discover bound databases",
            hypothesis_ids=(),
            arguments={"instance_id": 3},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "instance_id": 99,
                "rows": [{"name": "orders_prod"}],
            }
        },
    )

    assert state.analysis_database_names == {}
    assert state.slow_query_analysis_failures[0]["reason_code"] == (
        "actual_target_mismatch"
    )


@pytest.mark.parametrize(
    ("sql", "authorized_ids", "reason_code"),
    [
        (
            "SELECT SLEEP(10), * FROM mysql_slow_query_review_history "
            "WHERE id = 24413454",
            {24413454},
            "history_recovery_projection_forbidden",
        ),
        (
            "SELECT h.* FROM mysql_slow_query_review_history AS h "
            "WHERE h.id = 999 ORDER BY h.id DESC LIMIT 1",
            {24413454},
            "history_id_not_authorized",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454",
            set(),
            "history_id_not_authorized",
        ),
    ],
)
def test_id_listing_context_rejects_unsafe_or_unauthorized_per_id_queries(
    sql: str,
    authorized_ids: set[int],
    reason_code: str,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_ids = authorized_ids

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one listed history row",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == reason_code


def test_id_listing_context_allows_authorized_ast_equivalent_per_id_query() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_ids = {24413454}

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one listed history row",
            hypothesis_ids=(),
            arguments={
                **TARGET_ARGUMENTS,
                "sql_content": (
                    "SELECT h.* FROM mysql_slow_query_review_history AS h "
                    "WHERE h.id = 24413454 ORDER BY h.id ASC LIMIT 1"
                ),
            },
        ),
        state=state,
    )

    assert "local_rejection" not in prepared.metadata
    assert prepared.local_result is None


def test_malformed_nonempty_id_listing_does_not_complete_recovery() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.window_start, state.window_end = archery_harness_module.client_window(
        scenario.client,
        OCCURRED_AT,
    )
    state.resolved_endpoints = {(17, "archery"): {"db-1.example:3306"}}
    listing = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="List history ids",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": _MERGE_IDS_SQL},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        listing,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": _MERGE_IDS_SQL,
                "rows": [{"id": "not-an-integer"}],
            }
        },
    )
    followup = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Discover supplemental target",
            hypothesis_ids=(),
            arguments={},
        ),
        state=state,
    )

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert state.history_recovery_ids == set()
    assert followup.metadata["local_rejection"]["reason_code"] == (
        "history_recovery_pending"
    )


def test_pending_recovery_diagnostic_distinguishes_unlisted_rows() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {24413458}
    state.history_id_rows = {
        24413458: dict(_MERGE_RECOVERED_ROW),
        24413454: {**_MERGE_RECOVERED_ROW, "id": 24413454},
    }
    state.history_full_row_ids = {24413458, 24413454}

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Discover supplemental target",
            hypothesis_ids=(),
            arguments={},
        ),
        state=state,
    )

    rejection = prepared.metadata["local_rejection"]
    assert rejection["reason_code"] == "history_recovery_pending"
    assert "未出现在完整 id 清单" in rejection["detail"]
    assert "24413454" in rejection["detail"]


def test_unverified_full_per_id_result_cannot_decode_positional_rows() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {24413454, 24413458}
    state.history_positional_rows = [
        [24413458, "db-1.example:3306", "dpm"]
    ]
    sql = f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413454"
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one listed history row",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                # Deliberately omit full_sql: the returned field order is not
                # trustworthy enough to decode another query's positional rows.
                "rows": [
                    {
                        "id": 24413454,
                        "hostname_max": "db-1.example:3306",
                        "db_max": "dpm",
                        "sample": "SELECT 1",
                    }
                ],
            }
        },
    )
    _assess_pending_result(scenario, state, content_state="complete")

    assert state.history_positional_reference_columns == []
    assert state.history_positional_rows == [
        [24413458, "db-1.example:3306", "dpm"]
    ]
    assert state.history_id_rows == {}
    assert state.history_id_states[24413454] == "FAILED_TERMINAL"


@pytest.mark.parametrize(
    ("include_marker", "marker"),
    [(False, None), (True, 0), (True, "invalid"), (True, "exact")],
)
def test_sample_prefix_provenance_blocks_explain_even_without_valid_length_marker(
    include_marker: bool,
    marker: Any,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413640
    sample = "SELECT * FROM orders WHERE id = 1"
    sql = scenario.client.history_sample_projection_sql(row_id)
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    row: dict[str, Any] = {
        "id": row_id,
        "hostname_max": "orders-db.example:3306",
        "db_max": "orders_prod",
        "checksum": "prefix-provenance",
        "sample": sample,
        "Query_time_max": 9,
    }
    if include_marker:
        row["sample_full_length"] = (
            len(sample.encode("utf-8")) if marker == "exact" else marker
        )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover sample prefix",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [row],
            }
        },
    )
    _assess_pending_result(scenario, state, content_state="complete")
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    explain = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain recovered sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert state.history_id_rows[row_id]["sample"] == sample
    assert row_id in state.history_sample_prefix_ids
    assert explain.metadata["local_rejection"]["reason_code"] == (
        "explain_sample_not_in_history"
    )


def test_only_verified_complete_full_per_id_sample_clears_prefix_provenance() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413454
    prefix = "SELECT * FROM orders WHERE note = 'prefix"
    complete = "SELECT * FROM orders WHERE note = 'complete'"
    sql = f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    state.history_sample_prefix_ids = {row_id}
    state.history_id_rows = {
        row_id: {
            "id": row_id,
            "sample": prefix,
            "sample_full_length": len(complete.encode("utf-8")),
        }
    }
    state.history_merge_sources = [
        {"full_sql": scenario.client.history_sample_projection_sql(row_id), "row_count": 1}
    ]

    missing_sample = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover full row without sample",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        missing_sample,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [{"id": row_id, "hostname_max": "db-1.example:3306"}],
            }
        },
    )
    _assess_pending_result(scenario, state, content_state="content_too_long")

    assert state.history_id_rows[row_id]["sample"] == prefix
    assert state.history_id_rows[row_id]["sample_full_length"] == len(
        complete.encode("utf-8")
    )
    assert state.history_sample_prefix_ids == {row_id}
    assert state.history_full_row_ids == set()

    shortfall = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Reject incomplete full sample provenance",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        shortfall,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rowCount": 2,
                "rows": [{"id": row_id, "sample": complete}],
            }
        },
    )
    _assess_pending_result(scenario, state, content_state="content_too_long")

    assert state.history_id_rows[row_id]["sample"] == prefix
    assert state.history_sample_prefix_ids == {row_id}
    assert state.history_full_row_ids == set()

    complete_sample = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover verified full sample",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        complete_sample,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [
                    {
                        "id": row_id,
                        "hostname_max": "db-1.example:3306",
                        "sample": complete,
                    }
                ],
            }
        },
    )
    _assess_pending_result(scenario, state)

    assert state.history_id_rows[row_id]["sample"] == complete
    assert "sample_full_length" not in state.history_id_rows[row_id]
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == {row_id}


@pytest.mark.parametrize("projection", ["full", "sample_prefix"])
def test_per_id_row_without_sample_does_not_complete_history_recovery(
    projection: str,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413454
    sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"
        if projection == "full"
        else scenario.client.history_sample_projection_sql(row_id)
    )
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one history row",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [{"id": row_id}],
            }
        },
    )
    _assess_pending_result(scenario, state, content_state="complete")

    assert state.history_id_rows == {}
    assert state.history_id_states[row_id] == "FAILED_TERMINAL"
    assert state.history_full_row_ids == set()
    assert state.history_sample_prefix_ids == set()
    assert archery_harness_module._history_recovery_missing_ids(state) == {row_id}
    assert archery_harness_module._history_recovery_complete(state) is False


def test_complete_json_row_shortfall_starts_history_recovery() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.window_start, state.window_end = archery_harness_module.client_window(
        scenario.client,
        OCCURRED_AT,
    )
    state.resolved_endpoints = {(17, "archery"): {"db-1.example:3306"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Read alert-window history",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": FINAL_SQL,
                "rows": [{**_MERGE_RECOVERED_ROW, "id": 24413458}],
                "mcp_reported_row_count": 2,
            }
        },
    )
    _assess_pending_result(scenario, state, content_state="content_too_long")

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert state.final_result is not None
    assert state.final_result.payload["result_incomplete"] is True
    assert "row_count_shortfall" in state.final_result.payload[
        "result_incomplete_reasons"
    ]


def test_decoded_full_positional_sample_survives_later_prefix_projection() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413640
    full_sample = "SELECT * FROM orders WHERE id = 4001"
    prefix_sample = "SELECT * FROM orders WHERE id = 4"
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    state.history_sample_prefix_ids = {row_id}
    state.history_id_rows = {
        row_id: {
            "id": row_id,
            "sample": prefix_sample,
            "sample_full_length": len(full_sample.encode("utf-8")),
        }
    }
    state.history_positional_reference_columns = ["id", "sample", "ts_cnt"]
    state.history_positional_rows = [[row_id, full_sample, 7]]

    scenario._resolve_deferred_positional_rows(state)

    assert state.history_positional_rows == []
    assert state.history_id_rows[row_id]["sample"] == full_sample
    assert "sample_full_length" not in state.history_id_rows[row_id]
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == {row_id}

    sql = scenario.client.history_sample_projection_sql(row_id)
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover redundant sample prefix",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [
                    {
                        "id": row_id,
                        "sample": prefix_sample,
                        "sample_full_length": len(full_sample.encode("utf-8")),
                    }
                ],
            }
        },
    )

    assert state.history_id_rows[row_id]["sample"] == full_sample
    assert "sample_full_length" not in state.history_id_rows[row_id]
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == {row_id}


def test_unresolved_positional_rows_keep_recovery_incomplete_until_same_id_full() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {1, 2}
    state.history_positional_reference_columns = ["id", "sample"]
    state.history_positional_rows = [
        [1],
        [2, "SELECT 2"],
        [3, "SELECT 3"],
        ["invalid", "SELECT invalid"],
    ]

    scenario._resolve_deferred_positional_rows(state)

    assert state.history_id_rows == {2: {"id": 2, "sample": "SELECT 2"}}
    assert state.history_positional_rows == [
        [1],
        [3, "SELECT 3"],
        ["invalid", "SELECT invalid"],
    ]
    assert archery_harness_module._history_recovery_complete(state) is False

    state.history_full_row_ids.add(1)
    state.history_id_rows[1] = {"id": 1, "sample": "SELECT 1"}
    scenario._resolve_deferred_positional_rows(state)

    assert state.history_positional_rows == [
        [3, "SELECT 3"],
        ["invalid", "SELECT invalid"],
    ]
    assert archery_harness_module._history_recovery_complete(state) is False


def test_unscoped_id_listing_is_rejected_before_any_history_result() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.resolved_endpoints = {(17, "archery"): {"db-1.example:3306"}}
    sql = f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}"

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="List history ids",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "history_recovery_query_forbidden"
    )


def test_unknown_dynamic_sql_tool_is_rejected_even_for_valid_explain_shape() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1050,
                "checksum": "unknown-sql-tool",
                "sample": sample,
                "Query_time_max": 1,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name="custom_sql_probe_gymJPA",
            objective="Explain the selected sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == "sql_tool_forbidden"


@pytest.mark.parametrize(
    "sample",
    [
        "SELECT * FROM other_prod.orders",
        "UPDATE LOW_PRIORITY other_prod.orders SET status = 1",
        "UPDATE /*+ NO_MERGE(orders) */ other_prod.orders SET status = 1",
        "INSERT /*+ SET_VAR(foreign_key_checks=OFF) */ "
        "INTO other_prod.archive VALUES (1)",
        "DELETE FROM orders USING other_prod.orders WHERE orders.id = 1",
        "INSERT INTO archive TABLE other_prod.source_rows",
        "REPLACE INTO archive TABLE other_prod.source_rows",
        "WITH recent AS (SELECT * FROM other_prod.orders) SELECT * FROM recent",
        "WITH recent AS (TABLE other_prod.orders) SELECT * FROM recent",
        "SELECT * FROM (TABLE other_prod.orders) recent",
        "SELECT * FROM orders UNION ALL TABLE other_prod.archive",
        'SELECT * FROM "other_prod"."orders"',
        "SELECT * FROM (other_prod.secret)",
        "SELECT * FROM (other_prod.a JOIN orders b ON a.id = b.id)",
        "SELECT * FROM (orders a, other_prod.secret s)",
        "DELETE other_prod.orders FROM orders JOIN audit a ON orders.id = a.id",
        "DELETE /*+ NO_MERGE(orders) */ other_prod.orders.* "
        "FROM orders JOIN audit a ON orders.id = a.id",
    ],
)
def test_explicit_sample_schema_mismatch_is_rejected_for_supported_statements(
    sample: str,
) -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1051,
                "checksum": "schema-mismatch",
                "sample": sample,
                "Query_time_max": 2,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain the selected sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "sample_schema_mismatch"
    )


@pytest.mark.parametrize(
    "sample",
    [
        "SELECT 'FROM other_prod.decoy' FROM orders",
        "SELECT * FROM orders_prod.Orders",
    ],
)
def test_table_parser_does_not_invent_schema_mismatch(sample: str) -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1052,
                "checksum": "schema-match",
                "sample": sample,
                "Query_time_max": 2,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain the selected sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "table_structure_required"
    )


def test_list_tables_actual_target_mismatch_does_not_mutate_discovery_state() -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1053,
                "checksum": "table-discovery-target",
                "sample": "SELECT * FROM orders",
                "Query_time_max": 2,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_TABLES_TOOL_NAME,
            objective="List bound tables",
            hypothesis_ids=(),
            arguments={"instance_id": 3, "db_name": "orders_prod"},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "instance_id": 99,
                "db_name": "orders_prod",
                "rows": [{"name": "mysql_slow_query_log"}],
            }
        },
    )

    assert state.slow_log_tables == {}
    assert state.slow_query_analysis_failures[0]["reason_code"] == (
        "actual_target_mismatch"
    )


def test_structure_and_indexes_are_reused_for_same_physical_table() -> None:
    rows = [
        {
            "id": 1061,
            "checksum": "orders-a",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 3,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 1062,
            "checksum": "orders-b",
            "sample": "SELECT * FROM orders WHERE id = 2",
            "Query_time_max": 2,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    scenario, state = _bound_history_scenario(rows)
    source_a = scenario.client.slow_query_source_row(rows[0])
    source_b = scenario.client.slow_query_source_row(rows[1])
    target = {"instance_id": 3, "db_name": "orders_prod", "table_name": "orders"}
    shared_structure = {
        "stage": "table_structure",
        "source_history_row": source_a,
        "target": target,
        "result": {"rows": [{"COLUMN_NAME": "id"}], "row_count": 1},
    }
    state.slow_query_table_structure_results = [shared_structure]
    state.slow_query_index_results = [
        {
            "stage": "indexes",
            "source_history_row": source_a,
            "target": target,
            "result": {"rows": [{"INDEX_NAME": "PRIMARY"}], "row_count": 1},
        }
    ]
    explain_results = [
        {
            "stage": "explain",
            "source_history_row": source,
            "target": {"instance_id": 3, "db_name": "orders_prod"},
            "result": {"rows": [{"table": "orders"}], "row_count": 1},
        }
        for source in (source_a, source_b)
    ]
    state.slow_query_explain_results = explain_results[:1]

    incomplete = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        state.final_result.payload,
    )
    state.slow_query_explain_results.append(explain_results[1])

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain the second checksum",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {rows[1]['sample']}",
            },
        ),
        state=state,
    )
    assert "local_rejection" not in prepared.metadata
    state.slow_query_analysis_failures = [
        {
            "stage": "history_recovery",
            "reason_code": "history_recovery_result_size_forbidden",
            "terminal": False,
        }
    ]
    analysis = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        state.final_result.payload,
    )

    assert incomplete["status"] == "partial"
    assert incomplete["missing_stages"] == ["explain"]
    assert analysis["status"] == "succeeded"
    assert analysis["missing_stages"] == []
    assert analysis["failures"] == state.slow_query_analysis_failures


def test_finish_waits_for_each_candidate_explain_work_item() -> None:
    rows = [
        {
            "id": 1061,
            "checksum": "orders-a",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 3,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 1062,
            "checksum": "orders-b",
            "sample": "SELECT * FROM orders WHERE id = 2",
            "Query_time_max": 2,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    scenario, state = _bound_history_scenario(rows)
    state.available_tool_names = {
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_DATABASES_TOOL_NAME,
    }
    scenario._initialize_supplemental_stage_states(state)
    source_a = scenario.client.slow_query_source_row(rows[0])
    target = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "endpoint": "orders-db.example:3306",
        "table_name": "orders",
    }
    scenario._mark_supplemental_stage_terminal(
        state,
        "table_structure",
        archery_harness_module._SUPPLEMENTAL_SUCCEEDED,
        source_history_row=source_a,
        target=target,
    )
    scenario._mark_supplemental_stage_terminal(
        state,
        "indexes",
        archery_harness_module._SUPPLEMENTAL_SUCCEEDED,
        source_history_row=source_a,
        target=target,
    )
    scenario._mark_supplemental_stage_terminal(
        state,
        "explain",
        archery_harness_module._SUPPLEMENTAL_SUCCEEDED,
        source_history_row=source_a,
        target=target,
    )

    pending = scenario._supplemental_pending_work_items(state)
    assert pending == [
        {
            "work_item_id": next(
                item["work_item_id"]
                for item in pending
                if item["history_id"] == "1062"
            ),
            "stage": "explain",
            "status": "PENDING",
            "history_id": "1062",
            "checksum": "orders-b",
            "endpoint": "orders-db.example:3306",
            "db_name": "orders_prod",
            "table_name": None,
        }
    ]
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=archery_harness_module._FINISH_TOOL_NAME,
            objective="Finish too early",
            hypothesis_ids=(),
            arguments={"summary": "first checksum completed"},
        ),
        state=state,
    )
    transition = scenario.on_result(state, prepared, prepared.local_result)
    envelope = json.loads(
        next(message["content"] for message in transition.message if "content" in message)
    )

    assert transition.status.value == "SKIPPED"
    assert state.finish_accepted is False
    assert envelope["reason_code"] == "supplemental_analysis_pending"
    assert envelope["pending_work_items"] == pending
    assert envelope["next_action"] == "archery.supplemental.explain"


def test_discovery_tracks_matched_and_unmatched_candidates_independently() -> None:
    rows = [
        {
            "id": 1081,
            "checksum": "matched-orders",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 1082,
            "checksum": "missing-billing",
            "sample": "SELECT * FROM invoices WHERE id = 2",
            "hostname_max": "billing-db.example:3306",
            "db_max": "billing_prod",
        },
        {
            "id": 1083,
            "checksum": "missing-database",
            "sample": "SELECT * FROM payments WHERE id = 3",
            "hostname_max": "orders-db.example:3306",
            "db_max": "billing_prod",
        },
    ]
    scenario, state = _bound_history_scenario(rows)
    state.analysis_instance_endpoints.clear()
    state.analysis_database_names.clear()
    state.available_tool_names = {
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_DATABASES_TOOL_NAME,
    }
    scenario._initialize_supplemental_stage_states(state)
    instances = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Discover allowlisted instances",
            hypothesis_ids=(),
            arguments={},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        instances,
        {
            "structuredContent": {
                "status": "success",
                "rows": [
                    {"id": 3, "host": "orders-db.example", "port": 3306}
                ],
            }
        },
    )
    _assess_pending_result(scenario, state)
    databases = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            objective="Discover databases for matched instance",
            hypothesis_ids=(),
            arguments={"instance_id": 3},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        databases,
        {
            "structuredContent": {
                "status": "success",
                "rows": [{"name": "orders_prod"}],
            }
        },
    )
    _assess_pending_result(scenario, state)

    items_by_source: dict[str, dict[str, str]] = {}
    for item in state.supplemental_work_items.values():
        items_by_source.setdefault(str(item["source_key"][0]), {})[
            str(item["stage"])
        ] = str(item["status"])
    assert items_by_source["1081"]["target_resolution"] == "SUCCEEDED"
    assert items_by_source["1082"] == {
        "target_resolution": "FAILED_TERMINAL",
        "explain": "UNAVAILABLE",
        "table_structure": "UNAVAILABLE",
        "indexes": "UNAVAILABLE",
    }
    assert items_by_source["1083"] == {
        "target_resolution": "FAILED_TERMINAL",
        "explain": "UNAVAILABLE",
        "table_structure": "UNAVAILABLE",
        "indexes": "UNAVAILABLE",
    }
    failures = [
        failure
        for failure in state.slow_query_analysis_failures
        if failure.get("reason_code") == "instance_not_allowlisted"
    ]
    assert [failure["source_history_row"]["id"] for failure in failures] == [1082]
    assert any(
        failure.get("reason_code") == "database_not_allowlisted"
        and failure.get("source_history_row", {}).get("id") == 1083
        for failure in state.slow_query_analysis_failures
    )


def test_all_truncated_samples_record_no_safe_explainable_sample() -> None:
    sample = "SELECT * FROM orders"
    rows = [
        {
            "id": 1070,
            "checksum": "truncated-only",
            "sample": sample,
            "sample_full_length": len(sample.encode("utf-8")) + 1,
            "Query_time_max": 5,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    scenario, state = _bound_history_scenario(rows)

    analysis = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        state.final_result.payload,
    )

    assert analysis["status"] == "not_applicable"
    assert analysis["failures"][0]["reason_code"] == "no_safe_explainable_sample"


def test_archery_restore_state_backfills_slow_query_fields_from_old_checkpoint() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    new_fields = (
        "slow_query_explain_results",
        "slow_query_table_structure_results",
        "slow_query_index_results",
        "slow_query_analysis_failures",
    )
    for field_name in new_fields:
        delattr(state, field_name)
    for field_name in ("analysis_instance_endpoints", "analysis_database_names"):
        delattr(state, field_name)
    delattr(state, "history_result_target")
    delattr(state, "history_recovery_ids")
    delattr(state, "supplemental_analysis_started")

    scenario.restore_state(state)

    assert all(getattr(state, field_name) == [] for field_name in new_fields)
    assert state.analysis_instance_endpoints == {}
    assert state.analysis_database_names == {}
    assert state.history_result_target is None
    assert state.history_recovery_ids == set()
    assert state.history_recovery_required is False
    assert state.history_recovery_listing_completed is False
    assert state.supplemental_analysis_started is False


def test_legacy_checkpoint_accumulator_restores_conservative_recovery_provenance() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_id_rows = {
        41: {"id": 41, "sample": "SELECT * FROM legacy_orders"}
    }
    state.history_merge_sources = [
        {
            "full_sql": (
                "SELECT * FROM mysql_slow_query_review_history WHERE id = 41"
            ),
            "row_count": 1,
        }
    ]
    for field_name in (
        "history_recovery_ids",
        "history_recovery_required",
        "history_recovery_listing_completed",
        "history_sample_prefix_ids",
        "history_full_row_ids",
    ):
        delattr(state, field_name)

    scenario.restore_state(state)

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert state.history_sample_prefix_ids == {41}
    assert state.history_full_row_ids == set()
    assert archery_harness_module._history_recovery_complete(state) is False


def test_restore_state_fails_closed_for_inconsistent_current_accumulator() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_id_rows = {42: {"id": 42, "sample": "SELECT 42"}}
    state.history_merge_sources = [
        {
            "full_sql": (
                "SELECT * FROM mysql_slow_query_review_history WHERE id = 42"
            ),
            "row_count": 1,
        }
    ]
    state.history_recovery_required = False
    state.history_recovery_ids = {42}
    state.history_recovery_listing_completed = True

    scenario.restore_state(state)

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert archery_harness_module._history_recovery_complete(state) is False


def test_analysis_success_requires_same_source_target_and_table() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    history_payload = {
        "rows": [
            {
                "id": 1044,
                "checksum": "coherent-orders",
                "sample": "SELECT * FROM orders WHERE id = 1",
                "Query_time_max": 7.0,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    }
    source = scenario.client.slow_query_source_row(history_payload["rows"][0])
    correct_target = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "endpoint": "orders-db.example:3306",
        "table_name": "orders",
    }
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    state.supplemental_stage_states = {
        "target_resolution": "SUCCEEDED",
        "explain": "SUCCEEDED",
        "table_structure": "FAILED_TERMINAL",
        "indexes": "SUCCEEDED",
    }
    state.slow_query_explain_results = [
        {
            "source_history_row": source,
            "target": correct_target,
            "result": {"row_count": 1, "rows": [{"table": "orders"}]},
        }
    ]
    state.slow_query_table_structure_results = [
        {
            "source_history_row": source,
            "target": {**correct_target, "instance_id": 99},
            "result": {"row_count": 1, "rows": [{"COLUMN_NAME": "id"}]},
        }
    ]
    state.slow_query_index_results = [
        {
            "source_history_row": source,
            "target": correct_target,
            "result": {"row_count": 1, "rows": [{"INDEX_NAME": "PRIMARY"}]},
        }
    ]

    analysis = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        history_payload,
    )

    assert analysis["status"] == "partial"
    assert analysis["missing_stages"] == ["table_structure"]
    assert analysis["stage_states"] == state.supplemental_stage_states
