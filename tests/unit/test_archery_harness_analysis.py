from __future__ import annotations

import pytest

from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    _MERGE_ID_SQL_44,
    _MERGE_ID_SQL_54,
    _MERGE_ID_SQL_60,
    _MERGE_IDS_SQL,
    _MERGE_RECOVERED_ROW,
    _MERGE_WINDOW_SQL,
    _PROJECTION_ID_SQL_40,
    _PROJECTION_SAMPLE_PREFIX,
    _TRUNCATED_ID_SQL_40,
    ALERT_CONTEXT,
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    FINAL_SQL,
    INSTANCE_SQL,
    MEMBER_SQL,
    OCCURRED_AT,
    TARGET_ARGUMENTS,
    _analysis_discovery_actions,
    _analysis_discovery_calls,
    _analysis_tools,
    _call,
    _client,
    _finish,
    _lineage_actions,
    _lineage_replay_calls,
    _merge_truncated_window_fixture,
    _named_call,
    _ScriptedModel,
    _success,
    _target_call,
    _tools,
    _truncated_id_retrieval_fixture,
    _truncated_window_positional_fixture,
)


@pytest.mark.asyncio
async def test_history_without_explainable_sample_marks_analysis_not_applicable() -> None:
    history_rows = [
        {
            "id": 105,
            "checksum": "ddl-only",
            "sample": "ALTER TABLE orders ADD COLUMN unsafe int",
            "Query_time_max": 20.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-no-explainable-sample",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "not_applicable"
    assert result.slow_query_analysis["source_history_row"] is None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "no_safe_explainable_sample"
    )


@pytest.mark.asyncio
async def test_history_direct_finish_is_rejected_until_supplemental_is_terminal() -> None:
    history_rows = [
        {
            "id": 1051,
            "checksum": "finish-orders",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 20.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    columns_sql = (
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    explain_sql = "EXPLAIN SELECT * FROM orders WHERE id = 1"
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    supplemental_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    model = _ScriptedModel(
        [
            *_lineage_actions(FINAL_SQL)[:-1],
            _finish("premature-finish"),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-analysis-not-attempted",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            **supplemental_arguments,
                            "sql_content": columns_sql,
                        },
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [{"COLUMN_NAME": "id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            **supplemental_arguments,
                            "sql_content": explain_sql,
                        },
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": explain_sql,
                                "rows": [{"type": "ALL", "rows": 100}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            **supplemental_arguments,
                            "sql_content": indexes_sql,
                        },
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": indexes_sql,
                                "rows": [],
                            }
                        },
                    ),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "succeeded"
    assert any(
        "supplemental_analysis_pending" in str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
    )


@pytest.mark.asyncio
async def test_followup_allowlist_failure_preserves_history_and_remaining_facts() -> None:
    sample = "SELECT * FROM orders WHERE customer_id = 1"
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 106,
            "checksum": "orders-customer",
            "sample": sample,
            "Query_time_max": 11.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-followup-allowlist-failure",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": columns_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [
                                    {"COLUMN_NAME": "customer_id", "COLUMN_TYPE": "bigint"}
                                ],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "实例不在白名单中，已拒绝执行（allowlist）",
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": indexes_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": indexes_sql,
                                "rows": [
                                    {"INDEX_NAME": "idx_customer", "COLUMN_NAME": "customer_id"}
                                ],
                            }
                        },
                    ),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.payload["rows"] == history_rows
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_DATABASES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "partial"
    assert analysis["explain_results"] == []
    assert analysis["table_structure_results"][0]["result"]["row_count"] == 1
    assert analysis["index_results"][0]["result"]["rows"][0]["INDEX_NAME"] == (
        "idx_customer"
    )
    assert analysis["failures"][0]["reason_code"] == "instance_not_allowlisted"


@pytest.mark.asyncio
async def test_complete_window_query_resets_per_id_accumulation() -> None:
    row_a = dict(_MERGE_RECOVERED_ROW)
    row_c = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413462,
        "checksum": "d" * 32,
        "ts_cnt": 25,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window-truncated", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("window-requery", _MERGE_WINDOW_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-window-requery-resets",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _merge_truncated_window_fixture(),
                    _success(_MERGE_IDS_SQL, rows=[{"id": 24413460}]),
                    _success(_MERGE_ID_SQL_60, rows=[dict(_MERGE_RECOVERED_ROW)]),
                    _success(_MERGE_WINDOW_SQL, rows=[row_a, row_c]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert "rows_merged_from_per_id_queries" not in result.payload
    assert result.payload["rows"] == [row_a, row_c]
    assert "rows_recovered_from_truncated_json" not in result.payload


@pytest.mark.asyncio
async def test_per_id_only_history_keeps_supplemental_success_and_failure() -> None:
    per_id_sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413454"
    )
    sample = "DELETE FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_row = {
        "id": 24413454,
        "checksum": "per-id-orders",
        "sample": sample,
        "Query_time_max": 6.0,
        "hostname_max": "orders-db.example:3306",
        "db_max": "orders_prod",
    }
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("per-id", per_id_sql),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-per-id-analysis",
                tools=_analysis_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(_MERGE_IDS_SQL, rows=[{"id": 24413454}]),
                    _success(per_id_sql, rows=[history_row]),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": columns_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [{"COLUMN_NAME": "id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "permission denied for EXPLAIN",
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": indexes_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": indexes_sql,
                                "rows": [
                                    {"INDEX_NAME": "PRIMARY", "COLUMN_NAME": "id"}
                                ],
                            }
                        },
                    ),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == [history_row]
    assert result.instance_id == TARGET_ARGUMENTS["instance_id"]
    assert result.db_name == TARGET_ARGUMENTS["db_name"]
    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "partial"
    assert analysis["table_structure_results"][0]["result"]["row_count"] == 1
    assert analysis["index_results"][0]["result"]["row_count"] == 1
    assert any(
        failure["reason_code"] == "permission_denied"
        for failure in analysis["failures"]
    )


@pytest.mark.asyncio
async def test_truncated_id_retrieval_with_high_limit_skips_to_projection_hint() -> None:
    """Replay of run 2c18cb74 (attempt=18): the model already sent
    max_result_chars=24000 on the very first per-id query, so the level-1
    "retry with 24000" hint was a dead end the model correctly skipped --
    and the projection hint never fired because it required a second
    truncation of the same SQL. A first truncation under a high
    max_result_chars now goes straight to the field-level projection hint.
    """
    row_40 = {
        "id": 24413640,
        "hostname_max": "db-1.example:3306",
        "sample": _PROJECTION_SAMPLE_PREFIX,
        "sample_full_length": 321237,
        "ts_cnt": 1,
        "Query_time_max": 0.806,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    first_call = MCPModelToolCall(
        call_id="id-40",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            first_call,
            _call("id-40-projection", _PROJECTION_ID_SQL_40),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-high-limit-projection",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413640}, {"id": 24413454}],
                    ),
                    _truncated_id_retrieval_fixture(
                        _TRUNCATED_ID_SQL_40,
                        max_result_chars=24000,
                    ),
                    _success(_PROJECTION_ID_SQL_40, rows=[row_40]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    # The very first truncation under max_result_chars=24000 goes straight to
    # the field-level projection hint; the level-1 retry hint never appears.
    tool_contents = [
        str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
        if message.get("role") in {"tool", "user"}
    ]
    assert any("字段级" in content for content in tool_contents)
    assert any(
        "LEFT(sample, '4000') AS sample" in content for content in tool_contents
    )
    assert not any(
        "请立即用相同的 SQL 重试一次" in content for content in tool_contents
    )

    assert result.query_completed is True
    payload_rows = result.payload["rows"]
    assert [row["id"] for row in payload_rows] == [24413640, 24413454]
    assert payload_rows[0]["sample"] == _PROJECTION_SAMPLE_PREFIX
    assert payload_rows[0]["sample_full_length"] == 321237
    assert result.payload["merged_query_count"] == 2


@pytest.mark.asyncio
async def test_window_positional_truncation_hint_and_deferred_decode() -> None:
    """Replay of run 2c18cb74 (attempt=18): the truncated window query
    recovered positional rows whose column_list sat behind the truncation
    point, so the rows could not be structured and the merge silently lost
    them (merged 8 of 14). The window tool message now explains the loss, the
    id-listing message lists every id still missing from the merge (including
    the row that straddled the truncation point), and the deferred positional
    rows are decoded once a structured per-id row reveals the column order.
    """
    row_44 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413644,
        "checksum": "e" * 32,
        "sample": "SELECT e FROM t5",
        "ts_cnt": 3,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-44", _MERGE_ID_SQL_44),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-window-positional-decode",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _truncated_window_positional_fixture(),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[
                            {"id": 24413648},
                            {"id": 24413647},
                            {"id": 24413646},
                            {"id": 24413645},
                            {"id": 24413644},
                            {"id": 24413454},
                        ],
                    ),
                    _success(_MERGE_ID_SQL_44, rows=[row_44]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    # The assessment context records that the truncated positional rows lack
    # the column mapping needed for deterministic decoding.
    assert any(
        "missing_tabular_columns" in str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
        if message.get("role") in {"tool", "user"}
    )

    # The id-listing directive carries every id still missing from the merge,
    # including the row that straddled the truncation point (24413644).
    missing_hint = [
        str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
        if message.get("role") == "user"
        and '"directive_id":"archery.history.truncation.fetch_single_id"'
        in str(message.get("content"))
        and '"subject_key":"ids"' in str(message.get("content"))
    ]
    assert missing_hint, "missing-id hint absent from the id-listing message"
    for row_id in (24413648, 24413647, 24413646, 24413645, 24413644, 24413454):
        assert str(row_id) in missing_hint[0]

    # The model only re-queried two ids; the deferred positional rows are
    # decoded with the first structured row's column order, so all six ids
    # reach the final evidence.
    assert result.query_completed is True
    payload = result.payload
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 2
    merged_ids = sorted(row["id"] for row in payload["rows"])
    assert merged_ids == [
        24413454,
        24413644,
        24413645,
        24413646,
        24413647,
        24413648,
    ]
    decoded = next(row for row in payload["rows"] if row["id"] == 24413648)
    assert decoded["hostname_max"] == "db-1.example:3306"
    assert decoded["db_max"] == "dpm"


@pytest.mark.asyncio
async def test_actual_response_sql_overrides_requested_history_for_classification() -> None:
    actual_sql = "SELECT index_name FROM information_schema.statistics"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("mismatched-sql", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-actual-sql-wins",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": actual_sql,
                                "rows": [{"index_name": "idx_hostname"}],
                            }
                        },
                    )
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert result.requested_sql == ""
    assert result.diagnostics["history_window_state"] == "FAILED_TERMINAL"
    assert (
        result.diagnostics["history_window_failure"]["reason_code"]
        == "actual_sql_mismatch"
    )
    assert not hasattr(result, "raw_mcp_call_results")


@pytest.mark.asyncio
async def test_pre_history_auth_terminal_failure_allows_finish_without_history() -> None:
    model = _ScriptedModel(
        [
            _named_call("login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-auth-terminal-failure",
                tools=_tools(),
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                        expected_arguments={},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "authentication rejected",
                            }
                        },
                    )
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert result.diagnostics["history_window_state"] == "FAILED_TERMINAL"
    assert (
        result.diagnostics["history_window_failure"]["reason_code"]
        == "history_window_tool_failure"
    )
    assert result.payload["status"] == "evidence_insufficient"
