from __future__ import annotations

import pytest

from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
)
from app.mcp_runtime import (
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    ALERT_CONTEXT,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    FINAL_SQL,
    INSTANCE_SQL,
    MEMBER_SQL,
    OCCURRED_AT,
    _analysis_discovery_actions,
    _analysis_discovery_calls,
    _analysis_tools,
    _call,
    _client,
    _finish,
    _lineage_replay_calls,
    _named_call,
    _ScriptedModel,
    _target_call,
)


@pytest.mark.asyncio
async def test_history_followup_collects_dml_explain_structure_and_indexes() -> None:
    sample = "UPDATE orders SET status = 'done' WHERE id = 1"
    history_rows = [
        {
            "id": 101,
            "checksum": "update-orders",
            "sample": sample,
            "Query_time_max": 12.5,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
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
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-history-analysis",
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
                                    {"COLUMN_NAME": "id", "COLUMN_TYPE": "bigint"},
                                    {"COLUMN_NAME": "status", "COLUMN_TYPE": "varchar(20)"},
                                ],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": explain_sql,
                                "rows": [{"table": "orders", "type": "range", "key": "PRIMARY"}],
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
                                "rows": [{"INDEX_NAME": "PRIMARY", "COLUMN_NAME": "id"}],
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
    analysis = result.slow_query_analysis
    assert analysis["status"] == "succeeded"
    assert analysis["source_history_row"]["id"] == 101
    assert analysis["source_history_row"]["sample"] == sample
    assert analysis["target"]["instance_id"] == 3
    assert analysis["target"]["db_name"] == "orders_prod"
    assert analysis["explain_results"][0]["statement_type"] == "update"
    assert analysis["explain_results"][0]["result"]["rows"][0]["key"] == "PRIMARY"
    assert analysis["table_structure_results"][0]["result"]["row_count"] == 2
    assert analysis["index_results"][0]["result"]["row_count"] == 1
    assert analysis["missing_stages"] == []
    assert analysis["failures"] == []


@pytest.mark.asyncio
async def test_list_table_columns_can_supply_bound_structure_before_explain() -> None:
    sample = "SELECT * FROM orders WHERE customer_id = 1"
    explain_sql = f"EXPLAIN {sample}"
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 1011,
            "checksum": "list-columns-orders",
            "sample": sample,
            "Query_time_max": 12.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    column_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "tb_name": "orders",
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
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _named_call("columns", ARCHERY_MCP_COLUMNS_TOOL_NAME, column_arguments),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-list-columns-analysis",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_COLUMNS_TOOL_NAME,
                        expected_arguments=column_arguments,
                        result={
                            "structuredContent": {
                                "status": "success",
                                "rows": [{"name": "id"}, {"name": "customer_id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": explain_sql,
                                "rows": [{"table": "orders", "key": "idx_customer"}],
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
                                    {
                                        "INDEX_NAME": "idx_customer",
                                        "COLUMN_NAME": "customer_id",
                                    }
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

    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "succeeded"
    assert analysis["table_structure_results"][0]["source"] == "list_table_columns"
    assert analysis["table_structure_results"][0]["result"]["columns"] == [
        "customer_id",
        "id",
    ]
