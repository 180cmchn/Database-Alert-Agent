from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
)
from app.adapters.archery_mcp import (
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    DiscoveredMCPTool,
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    _MERGE_IDS_SQL,
    ALERT_CONTEXT,
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
    _named_call,
    _scenario,
    _ScriptedModel,
    _success,
    _target_call,
    _tools,
)


def _terminal_query_failure(sql: str) -> ReplayCallFixture:
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={
            "instance_id": 3,
            "db_name": "orders_prod",
            "limit_num": 20,
            "sql_content": sql,
        },
        result={
            "structuredContent": {
                "status": "failed",
                "message": "terminal supplemental fixture failure",
            }
        },
    )


@pytest.mark.parametrize(
    ("unsafe_sql", "arguments", "reason_code"),
    [
        (
            "SELECT 1; DELETE FROM orders",
            TARGET_ARGUMENTS,
            "multi_statement_forbidden",
        ),
        ("DELETE FROM orders", TARGET_ARGUMENTS, "direct_statement_forbidden"),
        (
            "WITH selected AS (SELECT id FROM orders) DELETE FROM orders",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        ("EXPLAIN DELETE FROM orders", TARGET_ARGUMENTS, "unbound_explain_forbidden"),
        (
            "EXPLAIN ANALYZE DELETE FROM orders",
            TARGET_ARGUMENTS,
            "explain_analyze_forbidden",
        ),
        ("SELECT SLEEP(1) FROM sql_instance", TARGET_ARGUMENTS, "direct_statement_forbidden"),
        (
            "SELECT * FROM sql_instance FOR UPDATE",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        ("SELECT @row_id := id FROM sql_instance", TARGET_ARGUMENTS, "direct_statement_forbidden"),
        (
            "SELECT f_instance_id FROM t_instance_member LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT f_instance_id FROM t_instance_member "
            "WHERE f_ip = 'db-1.example' OR f_port = 3306 LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT f_instance_id FROM t_instance_member "
            "WHERE f_ip = 'attacker.example' AND f_port = 9999 "
            "AND 'db-1.example' = 'db-1.example' AND 3306 = 3306 LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT f_id AS f_instance_id FROM t_instance_member "
            "WHERE f_ip = 'db-1.example' AND f_port = 3306 LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT host, port FROM sql_instance LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = 'archery'",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT id FROM sql_instance WHERE id = custom_lookup(53)",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT s.id FROM sql_instance s "
            "JOIN t_instance_member m ON m.f_instance_id = s.id",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT id FROM sql_instance UNION "
            "SELECT f_instance_id FROM t_instance_member",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT id FROM sql_instance WHERE id IN "
            "(SELECT f_instance_id FROM t_instance_member)",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT * FROM {OJ sql_instance LEFT JOIN t_instance_member ON 1 = 1}",
            TARGET_ARGUMENTS,
            "multi_statement_forbidden",
        ),
        (
            r"SELECT id FROM sql_instance WHERE note = 'prefix\' OR id = 53'",
            TARGET_ARGUMENTS,
            "multi_statement_forbidden",
        ),
        (
            "SELECT h.* FROM mysql_slow_query_review_history h "
            "JOIN sql_instance s ON s.id = h.id",
            TARGET_ARGUMENTS,
            "history_recovery_query_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history "
            "UNION SELECT * FROM sql_instance",
            TARGET_ARGUMENTS,
            "history_recovery_query_forbidden",
        ),
        (
            "WITH history_rows AS ("
            "SELECT * FROM mysql_slow_query_review_history"
            ") SELECT * FROM history_rows JOIN sql_instance ON 1 = 1",
            TARGET_ARGUMENTS,
            "history_recovery_query_forbidden",
        ),
        (
            "SELECT * FROM orders",
            {"instance_id": 3, "db_name": "orders_prod", "limit_num": 20},
            "direct_statement_forbidden",
        ),
    ],
)
@pytest.mark.asyncio
async def test_unsafe_pre_history_sql_is_rejected_before_mcp(
    unsafe_sql: str,
    arguments: dict[str, Any],
    reason_code: str,
) -> None:
    unsafe_call = MCPModelToolCall(
        call_id="unsafe-pre-history",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**arguments, "sql_content": unsafe_sql},
        request_id="request-unsafe-pre-history",
    )
    model = _ScriptedModel([unsafe_call, *_lineage_actions()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-unsafe-pre-history",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.diagnostics is not None
    assert result.diagnostics["model_attempted_tool_calls"] == [
        ARCHERY_MCP_QUERY_TOOL_NAME
    ] * 4
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert any(
        entry.get("reason_code") == reason_code
        and entry.get("sent_to_mcp") is False
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.parametrize(
    "unsafe_lookup",
    [
        "SELECT host, port FROM sql_instance WHERE id = 53 + 946 LIMIT 1",
        "SELECT id AS host, id AS port FROM sql_instance WHERE id = 53 LIMIT 1",
    ],
)
@pytest.mark.asyncio
async def test_sql_instance_lookup_requires_exact_returned_member_id_predicate(
    unsafe_lookup: str,
) -> None:
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("unsafe-instance", unsafe_lookup),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-arithmetic-instance-id",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert any(
        entry.get("reason_code") == "direct_statement_forbidden"
        and entry.get("sent_to_mcp") is False
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.parametrize(
    ("unsafe_lookup", "columns", "member_ids"),
    [
        (
            "SELECT f_instance_id FROM t_instance_member "
            "WHERE attacker_host = 'db-1.example' AND attacker_port = 3306 LIMIT 1",
            {
                "attacker_host",
                "attacker_port",
                "f_instance_id",
                "f_ip",
                "f_port",
            },
            set(),
        ),
        (
            "SELECT backup_host, backup_port FROM sql_instance "
            "WHERE id = 53 LIMIT 1",
            {"backup_host", "backup_port", "host", "id", "port"},
            {53},
        ),
    ],
)
def test_discovered_lookalike_endpoint_columns_are_rejected_before_transport(
    unsafe_lookup: str,
    columns: set[str],
    member_ids: set[int],
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    target = (17, "archery")
    table_name = (
        "t_instance_member" if "t_instance_member" in unsafe_lookup else "sql_instance"
    )
    state.table_columns = {target: {table_name: columns}}
    if member_ids:
        state.member_instance_ids = {target: member_ids}

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Reject lookalike endpoint columns",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": unsafe_lookup},
        ),
        state=state,
    )

    assert prepared.local_result is not None
    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "direct_statement_forbidden"
    )


@pytest.mark.asyncio
async def test_explain_analyze_is_rejected_before_mcp_and_history_is_preserved() -> None:
    sample = "DELETE FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 102,
            "checksum": "delete-orders",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    unsafe_sql = f"EXPLAIN ANALYZE {sample}"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("unsafe", unsafe_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-explain-analyze",
                tools=_tools(),
                # There is deliberately no fixture for the rejected call.
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
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
    assert analysis["status"] == "failed"
    assert analysis["failures"][0]["reason_code"] == "explain_analyze_forbidden"
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )


@pytest.mark.parametrize(
    "sample",
    [
        "SELECT * FROM {OJ orders LEFT JOIN customers ON orders.customer_id = customers.id}",
        r"SELECT * FROM orders WHERE note = 'prefix\' OR admin = 1'",
    ],
)
@pytest.mark.asyncio
async def test_lexically_ambiguous_explain_is_rejected_before_transport(
    sample: str,
) -> None:
    history_rows = [
        {
            "id": 110,
            "checksum": "ambiguous-explain",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 109,
            "checksum": "valid-control-for-ambiguous",
            "sample": "SELECT * FROM safe_orders",
            "Query_time_max": 1.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    explain_sql = f"EXPLAIN {sample}"
    model = _ScriptedModel(
        [
            *_lineage_actions()[:-1],
            _target_call(
                "ambiguous-explain",
                explain_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-ambiguous-explain",
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
    assert len(model.requests) == 6
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure.get("reason_code") == "multi_statement_forbidden"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.parametrize(
    "length_marker",
    [None, 0, -1, "invalid", 44, 46],
)
@pytest.mark.asyncio
async def test_invalid_sample_full_length_cannot_authorize_explain_transport(
    length_marker: Any,
) -> None:
    sample = "SELECT * FROM orders WHERE note = '慢查询'"
    assert len(sample.encode("utf-8")) == 45
    history_rows = [
        {
            "id": 111,
            "checksum": "invalid-sample-length",
            "sample": sample,
            "sample_full_length": length_marker,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 109,
            "checksum": "valid-control-for-length",
            "sample": "SELECT * FROM safe_orders",
            "Query_time_max": 1.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    explain_sql = f"EXPLAIN {sample}"
    model = _ScriptedModel(
        [
            *_lineage_actions()[:-1],
            _target_call(
                "invalid-length-explain",
                explain_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-invalid-sample-length",
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
    assert len(model.requests) == 6
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure.get("reason_code") == "explain_sample_not_in_history"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.asyncio
async def test_post_history_information_schema_union_udf_is_rejected_before_transport() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 112,
            "checksum": "orders-metadata-guard",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    unsafe_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "UNION SELECT mutate_state() FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    model = _ScriptedModel(
        [
            *_lineage_actions()[:-1],
            _target_call(
                "unsafe-information-schema",
                unsafe_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-information-schema-union-udf",
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
    assert len(model.requests) == 6
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure.get("reason_code") == "direct_statement_forbidden"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.asyncio
async def test_direct_dml_sample_is_rejected_before_mcp_and_history_is_preserved() -> None:
    sample = "INSERT INTO order_archive SELECT * FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 103,
            "checksum": "insert-archive",
            "sample": sample,
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("unsafe-dml", sample, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-direct-dml",
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
    assert result.slow_query_analysis["status"] == "failed"
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "sample_execution_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_direct_select_sample_formatting_variant_is_rejected_before_mcp() -> None:
    sample = "SELECT * FROM orders WHERE id=1 AND note = 'A  B'"
    direct_sql = " select * from orders where id = 1 and note='A  B'; "
    history_rows = [
        {
            "id": 1031,
            "checksum": "select-orders",
            "sample": sample,
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("direct-select", direct_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-direct-select",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["explain_results"] == []
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "sample_execution_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_arbitrary_post_history_business_select_is_rejected_before_mcp() -> None:
    history_rows = [
        {
            "id": 1032,
            "checksum": "select-orders",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    arbitrary_sql = "SELECT * FROM customers WHERE id = 1"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("arbitrary", arbitrary_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-arbitrary-select",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "direct_statement_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_multi_id_history_recovery_is_rejected_before_mcp() -> None:
    history_rows = [
        {
            "id": 1033,
            "checksum": "history-in",
            "sample": "SELECT 1",
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    in_sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
        "WHERE id IN (1033, 1034)"
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _call("multi-id", in_sql),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-multi-id",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "history_recovery_id_predicate_required"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_unscoped_history_id_listing_is_rejected_before_mcp() -> None:
    history_rows = [
        {
            "id": 10331,
            "checksum": "history-unscoped-ids",
            "sample": "SELECT 1",
            "Query_time_max": 8.0,
            "hostname_max": "db-1.example:3306",
            "db_max": "orders_prod",
        }
    ]
    unscoped_sql = f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _call("unscoped-ids", unscoped_sql),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-unscoped-ids",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "history_recovery_projection_forbidden"
    )


@pytest.mark.parametrize(
    "unsafe_sql",
    [
        (
            f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} h "
            f"JOIN {ARCHERY_SLOW_QUERY_REVIEW_TABLE} h2 ON h2.id = h.id "
            "WHERE h.hostname_max = 'db-1.example:3306' "
            "AND h.ts_min >= FROM_UNIXTIME(1784793300) "
            "AND h.ts_min < FROM_UNIXTIME(1784793600)"
        ),
        (
            f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} h, "
            f"{ARCHERY_SLOW_QUERY_REVIEW_TABLE} h2 "
            "WHERE h.hostname_max = 'db-1.example:3306' "
            "AND h.ts_min >= FROM_UNIXTIME(1784793300) "
            "AND h.ts_min < FROM_UNIXTIME(1784793600)"
        ),
        (
            f"WITH history_rows AS (SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}) "
            "SELECT * FROM history_rows "
            "WHERE hostname_max = 'db-1.example:3306' "
            "AND ts_min >= FROM_UNIXTIME(1784793300) "
            "AND ts_min < FROM_UNIXTIME(1784793600)"
        ),
        (
            f"SELECT * FROM (SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}) h "
            "WHERE hostname_max = 'db-1.example:3306' "
            "AND ts_min >= FROM_UNIXTIME(1784793300) "
            "AND ts_min < FROM_UNIXTIME(1784793600)"
        ),
        FINAL_SQL.replace("SELECT *", "SELECT id, sample"),
    ],
)
@pytest.mark.asyncio
async def test_complex_or_partial_history_window_is_rejected_before_mcp(
    unsafe_sql: str,
) -> None:
    model = _ScriptedModel([_call("unsafe-history-shape", unsafe_sql), *_lineage_actions()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-history-source-shape",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.diagnostics is not None
    assert any(
        entry.get("reason_code") == "history_recovery_query_forbidden"
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.parametrize(
    "wrong_target",
    [
        {"instance_id": 3, "db_name": "archery", "limit_num": 20},
        {"instance_id": 17, "db_name": "orders_prod", "limit_num": 20},
    ],
)
@pytest.mark.asyncio
async def test_history_recovery_wrong_target_is_rejected_before_mcp(
    wrong_target: dict[str, Any],
) -> None:
    history_rows = [
        {
            "id": 24413454,
            "hostname_max": "db-1.example:3306",
            "sample": "SELECT * FROM orders",
        }
    ]
    wrong_target_call = MCPModelToolCall(
        call_id="wrong-history-target",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**wrong_target, "sql_content": _MERGE_IDS_SQL},
        request_id="request-wrong-history-target",
    )
    model = _ScriptedModel(
        [*_lineage_actions()[:-1], wrong_target_call, _finish()]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-wrong-history-target",
                tools=_tools(),
                calls=_lineage_replay_calls(rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure["reason_code"] == "history_recovery_projection_forbidden"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.parametrize(
    "wrong_target",
    [
        {"instance_id": 3, "db_name": "archery", "limit_num": 20},
        {"instance_id": 17, "db_name": "orders_prod", "limit_num": 20},
    ],
)
@pytest.mark.asyncio
async def test_initial_history_wrong_target_is_rejected_before_mcp(
    wrong_target: dict[str, Any],
) -> None:
    history_call = MCPModelToolCall(
        call_id="wrong-initial-history-target",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**wrong_target, "sql_content": FINAL_SQL},
        request_id="request-wrong-initial-history-target",
    )
    model = _ScriptedModel(
        [_call("member", MEMBER_SQL), _call("instance", INSTANCE_SQL), history_call, _finish()]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-wrong-initial-history-target",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 2
    assert result.slow_query_analysis is None
    assert result.diagnostics is not None
    assert any(
        entry.get("reason_code") == "history_target_mismatch"
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.asyncio
async def test_unknown_non_sql_tool_is_rejected_after_history() -> None:
    history_rows = [
        {
            "id": 1034,
            "checksum": "unknown-tool",
            "sample": "SELECT 1",
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    tool_name = "run_custom_probe_gymJPA"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _named_call("custom-probe", tool_name, {"target": "orders"}),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-custom-tool",
                tools=[
                    *_tools(),
                    DiscoveredMCPTool(
                        name=tool_name,
                        input_schema={"type": "object", "additionalProperties": True},
                    ),
                ],
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "followup_tool_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_dml_plain_explain_target_syntax_failure_does_not_replace_history() -> None:
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
    history_rows = [
        {
            "id": 104,
            "checksum": "delete-orders-unsupported",
            "sample": sample,
            "Query_time_max": 7.0,
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
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-explain-not-supported",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            "instance_id": 3,
                            "db_name": "orders_prod",
                            "limit_num": 20,
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
                            "instance_id": 3,
                            "db_name": "orders_prod",
                            "limit_num": 20,
                            "sql_content": indexes_sql,
                        },
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
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            "instance_id": 3,
                            "db_name": "orders_prod",
                            "limit_num": 20,
                            "sql_content": explain_sql,
                        },
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": (
                                    "You have an error in your SQL syntax; target does not support "
                                    "EXPLAIN DELETE"
                                ),
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
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "partial"
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "explain_not_supported_by_target"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("instance_id", "db_name", "reason_code"),
    [
        (4, "orders_prod", "instance_target_mismatch"),
        (3, "other_prod", "database_target_mismatch"),
        (3, "ORDERS_PROD", "database_target_mismatch"),
    ],
)
async def test_supplemental_metadata_requires_bound_instance_and_database(
    instance_id: int,
    db_name: str,
    reason_code: str,
) -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 1041,
            "checksum": "target-orders",
            "sample": sample,
            "Query_time_max": 7.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    explain_sql = f"EXPLAIN {sample}"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("wrong-target", columns_sql, instance_id=instance_id, db_name=db_name),
            _target_call("columns-terminal", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes-terminal", indexes_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain-terminal", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id=f"archery-target-mismatch-{reason_code}",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    _terminal_query_failure(columns_sql),
                    _terminal_query_failure(indexes_sql),
                    _terminal_query_failure(explain_sql),
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
    assert result.slow_query_analysis["table_structure_results"] == []
    assert result.slow_query_analysis["failures"][0]["reason_code"] == reason_code


@pytest.mark.asyncio
async def test_plain_explain_requires_prior_structure_result_or_failure() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 1045,
            "checksum": "structure-first",
            "sample": sample,
            "Query_time_max": 7.0,
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
            _target_call("early-explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("columns-terminal", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes-terminal", indexes_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain-terminal", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-structure-first",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    _terminal_query_failure(columns_sql),
                    _terminal_query_failure(indexes_sql),
                    _terminal_query_failure(explain_sql),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "table_structure_required"
    )


@pytest.mark.asyncio
async def test_supplemental_actual_sql_mismatch_is_not_projected_as_explain() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    actual_sql = "EXPLAIN SELECT * FROM unrelated WHERE id = 1"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 1042,
            "checksum": "actual-sql-orders",
            "sample": sample,
            "Query_time_max": 7.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
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
            _target_call("explain-terminal", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes-terminal", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-actual-explain-mismatch",
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
                                "rows": [{"COLUMN_NAME": "id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": actual_sql,
                                "rows": [{"table": "unrelated", "type": "ALL"}],
                            }
                        },
                    ),
                    _terminal_query_failure(explain_sql),
                    _terminal_query_failure(indexes_sql),
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
    assert result.slow_query_analysis["explain_results"] == []
    assert any(
        failure["reason_code"] == "actual_sql_mismatch"
        for failure in result.slow_query_analysis["failures"]
    )
