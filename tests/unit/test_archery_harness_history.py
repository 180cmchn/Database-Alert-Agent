from __future__ import annotations

import json

import pytest

from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    _MERGE_ID_SQL_54,
    _MERGE_ID_SQL_58,
    _MERGE_ID_SQL_60,
    _MERGE_IDS_SQL,
    _MERGE_RECOVERED_ROW,
    _MERGE_WINDOW_SQL,
    _PROJECTION_ID_SQL_40,
    _PROJECTION_SAMPLE_PREFIX,
    _TRUNCATED_ID_SQL_40,
    ALERT_CONTEXT,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_PROMPTS,
    INSTANCE_SQL,
    MEMBER_SQL,
    OCCURRED_AT,
    TARGET_ARGUMENTS,
    _analysis_tools,
    _call,
    _client,
    _finish,
    _merge_truncated_window_fixture,
    _named_call,
    _result_assessment,
    _ScriptedModel,
    _success,
    _target_call,
    _tools,
    _truncated_id_retrieval_fixture,
)

_HISTORY_ONLY_RECOVERED_ROW = {
    **_MERGE_RECOVERED_ROW,
    "sample": "ALTER TABLE t_dpm_task_warning ADD COLUMN ignored_for_history_test int",
}


def _directive_payloads(model: _ScriptedModel) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    seen: set[str] = set()
    for request in model.requests:
        for message in request["messages"]:
            content = message.get("content")
            if not isinstance(content, str):
                continue
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(payload, dict)
                and payload.get("type") == "archery_workflow_directive"
                and isinstance(payload.get("emission_key"), str)
                and payload["emission_key"] not in seen
            ):
                seen.add(payload["emission_key"])
                payloads.append(payload)
    return payloads


@pytest.mark.asyncio
async def test_truncated_window_merges_per_id_retrieval_rows_into_final_result() -> None:
    """Replay of run 2970f801: truncation -> id listing -> per-id retrieval.

    Before this fix every history SELECT overwrote state.final_result, so the
    evidence reaching the main Agent held only the last single-id row (1 of 6).
    """
    row_60 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413460,
        "checksum": "b" * 32,
        "ts_cnt": 40,
        "Query_time_sum": 12.5,
    }
    row_54 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "ALTER TABLE orders ADD COLUMN ignored_for_history_test int",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-58", _MERGE_ID_SQL_58),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-merge",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _merge_truncated_window_fixture(_HISTORY_ONLY_RECOVERED_ROW),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413458}, {"id": 24413454}],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_58, rows=[_HISTORY_ONLY_RECOVERED_ROW]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == _MERGE_WINDOW_SQL
    assert result.executed_sql == _MERGE_WINDOW_SQL
    payload = result.payload
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 3
    assert payload["merged_full_sqls"] == [
        _MERGE_ID_SQL_60,
        _MERGE_ID_SQL_58,
        _MERGE_ID_SQL_54,
    ]
    assert "rows_recovered_from_truncated_json" not in payload
    assert [row["id"] for row in payload["rows"]] == [
        24413458,
        24413460,
        24413454,
    ]
    assert payload["rows"][0] == _HISTORY_ONLY_RECOVERED_ROW
    assert payload["rows"][1] == row_60
    assert payload["rows"][2] == row_54


@pytest.mark.asyncio
async def test_truncated_history_blocks_supplemental_calls_before_transport() -> None:
    explain_sql = f"EXPLAIN {_MERGE_RECOVERED_ROW['sample']}"
    row_60 = {**_HISTORY_ONLY_RECOVERED_ROW, "id": 24413460}
    row_54 = {**_HISTORY_ONLY_RECOVERED_ROW, "id": 24413454}
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _named_call("early-allowlist", ARCHERY_MCP_INSTANCES_TOOL_NAME, {}),
            _target_call(
                "early-explain",
                explain_sql,
                instance_id=3,
                db_name="dpm",
            ),
            _finish("premature-finish"),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-58", _MERGE_ID_SQL_58),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-blocks-supplemental",
                tools=_analysis_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _merge_truncated_window_fixture(_HISTORY_ONLY_RECOVERED_ROW),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413458}, {"id": 24413454}],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_58, rows=[_HISTORY_ONLY_RECOVERED_ROW]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 7
    assert "rows_recovered_from_truncated_json" not in result.payload
    assert result.diagnostics["history_recovery_complete"] is True
    assert result.slow_query_analysis is not None
    reason_codes = [
        failure["reason_code"]
        for failure in result.slow_query_analysis["failures"]
    ]
    assert reason_codes.count("history_recovery_pending") == 2
    assert "history_recovery_incomplete" not in reason_codes
    assert any(
        "history_recovery_pending" in str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
    )


@pytest.mark.asyncio
async def test_incomplete_per_id_recovery_keeps_merged_history_partial() -> None:
    row_60 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413460,
        "checksum": "b" * 32,
    }
    row_40 = {
        "id": 24413640,
        "hostname_max": "db-1.example:3306",
        "sample": _PROJECTION_SAMPLE_PREFIX,
        "sample_full_length": 321237,
    }
    retry_call = MCPModelToolCall(
        call_id="id-40-retry",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40-retry",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-58", _MERGE_ID_SQL_58),
            _finish("premature-finish"),
            _call("id-40", _TRUNCATED_ID_SQL_40),
            retry_call,
            _call("id-40-projection", _PROJECTION_ID_SQL_40),
            _result_assessment(
                "id-40-projection",
                scope="history_single_id",
                content_state="content_too_long",
                history_id=24413640,
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-incomplete-per-id-recovery",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _merge_truncated_window_fixture(_HISTORY_ONLY_RECOVERED_ROW),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[
                            {"id": 24413460},
                            {"id": 24413458},
                            {"id": 24413640},
                        ],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_58, rows=[_HISTORY_ONLY_RECOVERED_ROW]),
                    _truncated_id_retrieval_fixture(_TRUNCATED_ID_SQL_40),
                    _truncated_id_retrieval_fixture(
                        _TRUNCATED_ID_SQL_40,
                        max_result_chars=24000,
                    ),
                    _success(_PROJECTION_ID_SQL_40, rows=[row_40]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows_merged_from_per_id_queries"] is True
    assert result.payload["rows_recovered_from_truncated_json"] is True
    assert result.payload["history_recovery_complete"] is False
    assert result.payload["history_recovery_missing_ids"] == [24413640]
    assert [row["id"] for row in result.payload["rows"]] == [24413458, 24413460]
    assert result.diagnostics is not None
    assert result.diagnostics["history_recovery_complete"] is False
    assert result.diagnostics["history_recovery_missing_ids"] == [24413640]
    assert result.slow_query_analysis is not None
    assert any(
        failure["reason_code"] == "history_row_recovery_terminal_failure"
        for failure in result.slow_query_analysis["failures"]
    )
    assert any(
        "history_recovery_pending" in str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
    )


@pytest.mark.asyncio
async def test_id_listing_after_truncation_never_becomes_final_result() -> None:
    row_60 = {**_HISTORY_ONLY_RECOVERED_ROW, "id": 24413460}
    row_54 = {**_HISTORY_ONLY_RECOVERED_ROW, "id": 24413454}
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _finish("premature-finish"),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-58", _MERGE_ID_SQL_58),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-id-listing-only",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _merge_truncated_window_fixture(_HISTORY_ONLY_RECOVERED_ROW),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413458}, {"id": 24413454}],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_58, rows=[_HISTORY_ONLY_RECOVERED_ROW]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == _MERGE_WINDOW_SQL
    assert "rows_recovered_from_truncated_json" not in result.payload
    assert result.payload["rows"] == [
        _HISTORY_ONLY_RECOVERED_ROW,
        row_60,
        row_54,
    ]
    assert result.payload["rows_merged_from_per_id_queries"] is True


@pytest.mark.asyncio
async def test_per_id_retrieval_without_window_query_still_merges() -> None:
    """Replay of the 2026-08-17 alert run: the model jumped straight from the
    id listing to per-id retrievals without any full-column window query, so
    state.final_result stayed empty and the main Agent saw "no passthrough
    result" although every per-id row had been recovered.
    """
    row_60 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413460,
        "checksum": "b" * 32,
        "ts_cnt": 40,
        "Query_time_sum": 12.5,
    }
    row_54 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "ALTER TABLE orders ADD COLUMN ignored_for_history_test int",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-per-id-without-window",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413454}],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == _MERGE_ID_SQL_60
    payload = result.payload
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 2
    assert payload["merged_full_sqls"] == [_MERGE_ID_SQL_60, _MERGE_ID_SQL_54]
    assert "rows_recovered_from_truncated_json" not in payload
    assert [row["id"] for row in payload["rows"]] == [24413460, 24413454]
    assert payload["rows"][0] == row_60
    assert payload["rows"][1] == row_54
    assert result.diagnostics["final_result_source"] == (
        "merged_per_id_queries_without_window_query"
    )


@pytest.mark.asyncio
async def test_truncated_id_retrieval_gets_one_time_retry_hint() -> None:
    """Model assessments activate stable workflow directives in order."""
    row_54 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "ALTER TABLE orders ADD COLUMN ignored_for_history_test int",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    retry_call = MCPModelToolCall(
        call_id="id-40-retry",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40-retry",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-40", _TRUNCATED_ID_SQL_40),
            retry_call,
            _call("id-40-projection", _PROJECTION_ID_SQL_40),
            _result_assessment(
                "id-40-projection",
                scope="history_single_id",
                content_state="content_too_long",
                history_id=24413640,
            ),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-id-hint",
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
                    _truncated_id_retrieval_fixture(_TRUNCATED_ID_SQL_40),
                    _truncated_id_retrieval_fixture(
                        _TRUNCATED_ID_SQL_40,
                        max_result_chars=24000,
                    ),
                    _success(
                        _PROJECTION_ID_SQL_40,
                        rows=[
                            {
                                "id": 24413640,
                                "hostname_max": "db-1.example:3306",
                                "sample": _PROJECTION_SAMPLE_PREFIX,
                                "sample_full_length": 321237,
                            }
                        ],
                    ),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    directives = _directive_payloads(model)
    by_id = {payload["directive_id"]: payload for payload in directives}
    retry = by_id["archery.history.truncation.retry_high_limit"]
    projection = by_id["archery.history.truncation.project_sample_prefix"]
    assert retry["instruction"] == ARCHERY_PROMPTS.workflow_directives[
        "archery.history.truncation.retry_high_limit"
    ]
    assert retry["facts"]["max_result_chars"] == 24000
    assert retry["facts"]["retry_sql"] == _TRUNCATED_ID_SQL_40
    assert projection["instruction"] == ARCHERY_PROMPTS.workflow_directives[
        "archery.history.truncation.project_sample_prefix"
    ]
    assert projection["facts"]["projection_sql"] == _PROJECTION_ID_SQL_40
    assert sum(
        payload["directive_id"] == "archery.history.truncation.retry_high_limit"
        for payload in directives
    ) == 1
    assert sum(
        payload["directive_id"]
        == "archery.history.truncation.project_sample_prefix"
        for payload in directives
    ) == 1

    assert result.query_completed is True
    assert [row["id"] for row in result.payload["rows"]] == [24413454]
    assert result.payload["merged_query_count"] == 1
    assert result.diagnostics["history_id_states"]["24413640"] == "FAILED_TERMINAL"


@pytest.mark.asyncio
async def test_truncated_id_retrieval_retry_then_projection_hint_recovers_row() -> None:
    """Replay of run be8080ac (attempt=16): the retry hint worked (the model
    retried with max_result_chars=24000) but the row was still truncated
    because its sample column alone is 321,237 bytes. The second-level hint
    now directs the model to a column-projection query that clips sample via
    LEFT(sample, 4000) and records the full length via
    LENGTH(sample) AS sample_full_length, so the recovered row (prefix +
    full length) reaches the main Agent as evidence.
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
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "ALTER TABLE orders ADD COLUMN ignored_for_history_test int",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    retry_call = MCPModelToolCall(
        call_id="id-40-retry",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40-retry",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-40", _TRUNCATED_ID_SQL_40),
            retry_call,
            _call("id-40-projection", _PROJECTION_ID_SQL_40),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-id-projection",
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
                    _truncated_id_retrieval_fixture(_TRUNCATED_ID_SQL_40),
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

    directives = _directive_payloads(model)
    by_id = {payload["directive_id"]: payload for payload in directives}
    assert by_id["archery.history.truncation.retry_high_limit"][
        "instruction"
    ] == ARCHERY_PROMPTS.workflow_directives[
        "archery.history.truncation.retry_high_limit"
    ]
    projection = by_id["archery.history.truncation.project_sample_prefix"]
    assert projection["instruction"] == ARCHERY_PROMPTS.workflow_directives[
        "archery.history.truncation.project_sample_prefix"
    ]
    assert projection["facts"]["projection_sql"] == _PROJECTION_ID_SQL_40

    # The recovered row carries both the clipped prefix and the full length.
    assert result.query_completed is True
    payload_rows = result.payload["rows"]
    assert [row["id"] for row in payload_rows] == [24413640, 24413454]
    assert payload_rows[0]["sample"] == _PROJECTION_SAMPLE_PREFIX
    assert payload_rows[0]["sample_full_length"] == 321237
    assert result.payload["merged_query_count"] == 2
    assert result.diagnostics["history_id_states"]["24413640"] == (
        "RECOVERED_SAMPLE_PREFIX"
    )


@pytest.mark.asyncio
async def test_model_complete_overrides_program_incomplete_hint_for_full_row() -> None:
    row = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "model-complete",
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-54", _MERGE_ID_SQL_54),
            _result_assessment(
                "id-54",
                scope="history_single_id",
                content_state="complete",
                history_id=24413454,
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-model-complete-overrides-program-hint",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(_MERGE_IDS_SQL, rows=[{"id": 24413454}]),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            **TARGET_ARGUMENTS,
                            "sql_content": _MERGE_ID_SQL_54,
                        },
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": _MERGE_ID_SQL_54,
                                "rows": [row],
                                "rows_recovered_from_truncated_json": True,
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

    assessment = next(
        item
        for item in result.diagnostics["result_assessments"]
        if item["scope"] == "history_single_id"
    )
    assert assessment["program_checks"]["result_incomplete"] is True
    assert assessment["content_state"] == "complete"
    assert result.diagnostics["history_id_states"]["24413454"] == "RECOVERED_FULL"
    assert result.payload["result_completeness_assessment"] == "complete"
    assert "result_incomplete" not in result.payload


@pytest.mark.asyncio
async def test_per_id_tool_error_marks_only_that_id_terminal() -> None:
    row_54 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "remaining-row",
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-per-id-tool-error-terminal",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413454}],
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            **TARGET_ARGUMENTS,
                            "sql_content": _MERGE_ID_SQL_60,
                        },
                        result={
                            "isError": True,
                            "content": [
                                {"type": "text", "text": "single id query failed"}
                            ],
                        },
                    ),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.diagnostics["history_id_states"] == {
        "24413454": "RECOVERED_FULL",
        "24413460": "FAILED_TERMINAL",
    }
    assert [row["id"] for row in result.payload["rows"]] == [24413454]
    assert any(
        failure["reason_code"] == "history_row_recovery_tool_failure"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.asyncio
async def test_unknown_history_id_is_rejected_before_mcp_transport() -> None:
    row_54 = {
        **_HISTORY_ONLY_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "authorized-row",
    }
    unknown_sql = (
        "SELECT h.* FROM mysql_slow_query_review_history AS h "
        "WHERE h.id = 999 ORDER BY h.id DESC LIMIT 1"
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("unknown-id", unknown_sql),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-unknown-id-local-rejection",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(_MERGE_IDS_SQL, rows=[{"id": 24413454}]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 4
    rejected_trace = next(
        item
        for item in result.diagnostics["query_trace"]
        if item.get("outcome") == "rejected_locally"
    )
    assert rejected_trace["sent_to_mcp"] is False
    assert rejected_trace["reason_code"] == "history_id_not_authorized"
    assert any(
        '"transport_sent":false' in str(message.get("content")).lower()
        and "history_id_not_authorized" in str(message.get("content"))
        for request in model.requests
        for message in request["messages"]
    )
