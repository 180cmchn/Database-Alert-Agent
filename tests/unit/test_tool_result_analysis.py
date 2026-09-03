from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.adapters.tool_result_analysis import (
    DeterministicToolResultProcessor,
    is_context_only_tool_result,
)
from app.agent_runtime.contracts import ArtifactRef
from app.domain.errors import AdvisorError


def _artifact() -> ArtifactRef:
    artifact_id = uuid4()
    return ArtifactRef(
        artifact_id=artifact_id,
        kind="raw_tool_result",
        uri=f"agent-artifact://{artifact_id}",
        sha256="a" * 64,
        size_bytes=100,
    )


ARCHERY_COLUMN_LIST: tuple[str, ...] = (
    "id",
    "ts_min",
    "ts_max",
    "hostname_max",
    "client_max",
    "user_max",
    "db_max",
    "checksum",
    "sample",
    "ts_cnt",
    "Query_time_sum",
    "Query_time_min",
    "Query_time_max",
    "Query_time_pct_95",
    "Rows_examined_sum",
    "Rows_sent_sum",
)


def _archery_keyed_row(
    *,
    row_id: int,
    checksum: str,
    sample: str,
    query_time_sum: float,
) -> dict[str, object]:
    return {
        "id": row_id,
        "ts_min": "2026-08-14T10:12:02",
        "ts_max": "2026-08-14T10:12:02",
        "hostname_max": "100.84.97.11:4000",
        "client_max": "10.126.146.67",
        "user_max": "data_etl",
        "db_max": "prod_oms_order",
        "checksum": checksum,
        "sample": sample,
        "ts_cnt": 1.0,
        "Query_time_sum": query_time_sum,
        "Query_time_min": query_time_sum,
        "Query_time_max": query_time_sum,
        "Query_time_pct_95": query_time_sum,
        "Rows_examined_sum": None,
        "Rows_sent_sum": None,
    }


def _archery_final_result_payload(rows: list[dict[str, object]]) -> dict[str, object]:
    """Mirror the JSON embedded in the Archery ``result`` text after keying."""

    return {
        "full_sql": (
            "SELECT id, ts_min, ts_max, hostname_max, client_max, user_max, db_max, "
            "checksum, sample, ts_cnt, Query_time_sum, Query_time_min, Query_time_max, "
            "Query_time_pct_95, Rows_examined_sum, Rows_sent_sum "
            "FROM mysql_slow_query_review_history ORDER BY id DESC LIMIT 5;"
        ),
        "is_execute": False,
        "checked": None,
        "is_masked": False,
        "query_time": 0.000844,
        "mask_rule_hit": False,
        "mask_time": "",
        "warning": None,
        "error": None,
        "is_critical": False,
        "rows": rows,
        "column_list": list(ARCHERY_COLUMN_LIST),
        "column_type": [
            "LONG",
            "DATETIME",
            "DATETIME",
            "VAR_STRING",
            "VAR_STRING",
            "VAR_STRING",
            "VAR_STRING",
            "STRING",
            "BLOB",
            "FLOAT",
            "FLOAT",
            "FLOAT",
            "FLOAT",
            "FLOAT",
            "FLOAT",
            "FLOAT",
        ],
        "status": None,
        "affected_rows": len(rows),
    }


@pytest.mark.asyncio
async def test_archery_passes_final_result_json_through_without_modification() -> None:
    slower_first = _archery_keyed_row(
        row_id=24311020,
        checksum="sql-a",
        sample="select * from orders where id = 1",
        query_time_sum=9.5,
    )
    faster_second = _archery_keyed_row(
        row_id=24311019,
        checksum="sql-b",
        sample="select sleep(1)",
        query_time_sum=3.0,
    )
    payload = _archery_final_result_payload([slower_first, faster_second])
    raw_result = {
        "status": "SUCCESS",
        "structured_data": {
            "query_completed": True,
            "reported_row_count": 2,
            "parsed_row_count": 2,
            "included_row_count": 2,
            "omitted_row_count": 0,
            "final_result_payload": payload,
            "raw_result": {"sql": "select * from mysql_slow_query_review_history"},
            "raw_mcp_call_results": [
                {"tool_name": "login", "result": {"token": "TOP-SECRET"}},
                {
                    "tool_name": "sql_query",
                    "arguments": {"sql_content": "select * from t_instance_member"},
                    "result": {"password": "INSTANCE-SECRET"},
                },
                {
                    "tool_name": "sql_query",
                    "arguments": {"sql_content": "select * from sql_instance"},
                    "result": {"catalog": "CATALOG-SECRET"},
                },
            ],
            "partial": False,
            "root_cause_eligible": True,
        },
    }

    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        request={"read_only": True},
        raw_result=raw_result,
        artifact=_artifact(),
    )

    assert result.provider == "deterministic_host"
    assert result.model == "none"
    assert result.passthrough_parse_failed is False
    assert result.analysis_usable is True
    assert result.passthrough_payload is not None
    # Every embedded field survives unchanged and rows keep their original order:
    # the slower row stays first because the program never filters or re-sorts.
    assert result.passthrough_payload == payload
    assert result.passthrough_payload["rows"][0]["checksum"] == "sql-a"
    assert result.passthrough_payload["rows"][0]["sample"] == ("select * from orders where id = 1")
    assert result.passthrough_payload["affected_rows"] == 2
    assert result.passthrough_payload["column_list"] == list(ARCHERY_COLUMN_LIST)
    serialized = json.dumps(result.passthrough_payload, ensure_ascii=False)
    assert "TOP-SECRET" not in serialized
    assert "INSTANCE-SECRET" not in serialized
    assert "CATALOG-SECRET" not in serialized
    assert len(result.observations) == 1
    assert result.observations[0].source_paths == ["/structured_data/final_result_payload"]
    assert "不判断因果" in result.observations[0].statement
    assert result.limitations == []


@pytest.mark.asyncio
async def test_archery_projects_slow_query_analysis_separately_without_provenance() -> None:
    payload = _archery_final_result_payload(
        [
            _archery_keyed_row(
                row_id=24311020,
                checksum="sql-a",
                sample="UPDATE orders SET status='done' WHERE id=1",
                query_time_sum=9.5,
            )
        ]
    )
    artifact_uri = "agent-artifact://supplemental-internal"
    analysis = {
        "status": "partial",
        "source_history_row": payload["rows"][0],
        "target": {"instance_id": 3, "db_name": "orders_prod"},
        "explain_results": [{"result": {"rows": [{"type": "range"}]}}],
        "table_structure_results": [],
        "index_results": [],
        "missing_stages": ["table_structure", "indexes"],
        "failures": [
            {
                "stage": "indexes",
                "reason_code": "permission_denied",
                "detail": "denied",
                "artifact_uri": artifact_uri,
                "request_id": "internal-request",
                "raw_response": "secret-response",
            }
        ],
    }

    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "final_result_payload": payload,
                "slow_query_analysis": analysis,
            },
        },
        artifact=_artifact(),
    )

    assert result.passthrough_payload == payload
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "partial"
    serialized = json.dumps(result.slow_query_analysis, ensure_ascii=False)
    assert "permission_denied" in serialized
    assert "artifact_uri" not in serialized
    assert "agent-artifact://" not in serialized
    assert "request_id" not in serialized
    assert "raw_response" not in serialized


@pytest.mark.asyncio
async def test_archery_unparseable_final_result_passes_raw_text_verbatim() -> None:
    raw_text = (
        "SQL 查询已执行。\n执行的SQL：SELECT id FROM mysql_slow_query_review_history "
        "ORDER BY id DESC LIMIT 5\n\n返回 5 行。\n结果：\n"
        '{"full_sql": "SELECT id FROM mysql_slow_query_review_history", "rows": [ bro'
    )
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        request={},
        raw_result={
            "status": "NO_DATA",
            "structured_data": {
                "final_result_parse_failed": True,
                "final_result_text": raw_text,
            },
        },
        artifact=_artifact(),
    )

    assert result.analysis_usable is False
    assert result.passthrough_parse_failed is True
    assert result.passthrough_payload == {"final_result_text": raw_text}
    assert result.observations[0].source_paths == ["/structured_data/final_result_text"]
    assert "未删改" in result.observations[0].statement
    assert "不能用于根因判断" in result.limitations[0]


@pytest.mark.asyncio
async def test_archery_without_final_result_is_unusable() -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        request={},
        raw_result={
            "status": "NO_DATA",
            "structured_data": {"query_completed": False},
        },
        artifact=_artifact(),
    )

    assert result.analysis_usable is False
    assert result.passthrough_payload is None
    assert result.passthrough_parse_failed is False
    assert result.observations == []
    assert result.limitations


@pytest.mark.asyncio
async def test_flashduty_alert_context_uses_api_projection_without_mcp_wording() -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="alert_context",
        source_system="alert_platform",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "local": {
                    "severity": "WARNING",
                    "database": {"host": "mysql-01", "port": 3306},
                },
                "flashduty": {
                    "request_ids": {"alert_info": "must-not-enter-model"},
                    "partial_errors": {"alert_feed": "FlashDutyAPIError"},
                    "alert": {"title": "MySQL slow query", "event_cnt": 3},
                    "events": [{"type": "triggered"}],
                    "feed": None,
                    "incident": {"info": {"progress": "Triggered"}},
                },
            },
        },
        artifact=_artifact(),
    )

    projected = "\n".join(
        [result.summary, *(item.statement for item in result.observations), *result.limitations]
    )
    assert result.analysis_usable is True
    assert result.prompt_version == "program-fact-projection-v8"
    assert "FlashDuty API" in projected
    assert "MCP" not in projected
    assert "must-not-enter-model" not in projected
    assert "FlashDutyAPIError" in projected
    assert [item.source_paths for item in result.observations] == [
        ["/structured_data/local"],
        ["/structured_data/flashduty/alert"],
        ["/structured_data/flashduty/events"],
        ["/structured_data/flashduty/incident"],
    ]


@pytest.mark.asyncio
async def test_flashduty_similar_is_visible_context_only_api_projection() -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_similar_incidents",
        source_system="alert_platform",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "request_id": "must-not-enter-model",
                "items": [
                    {"incident_id": "incident-1", "title": "Past connection spike"},
                    {"incident_id": "incident-2", "title": "Past disk pressure"},
                ],
            },
        },
        artifact=_artifact(),
    )

    projected = "\n".join(
        [result.summary, *(item.statement for item in result.observations), *result.limitations]
    )
    assert result.analysis_usable is True
    assert len(result.observations) == 2
    assert "FlashDuty API" in projected
    assert "MCP" not in projected
    assert "仅作为调查上下文" in projected
    assert "不能作为当前告警的根因证据" in projected
    assert "must-not-enter-model" not in projected
    assert result.observations[0].source_paths == ["/structured_data/items/0"]
    assert is_context_only_tool_result(
        tool_name="query_similar_incidents",
        source_system="alert_platform",
    )
    assert not is_context_only_tool_result(
        tool_name="alert_context",
        source_system="alert_platform",
    )


@pytest.mark.parametrize(
    ("tool_name", "source_system", "structured_data", "context_only"),
    (
        (
            "flashduty_alert",
            "flashduty",
            {"flashduty": {"alert": {"title": "MySQL slow query"}}},
            False,
        ),
        (
            "flashduty_similar",
            "flashduty",
            {"items": [{"incident_id": "incident-1", "title": "Past incident"}]},
            True,
        ),
        (
            "flashduty_alert",
            "flashduty_alert",
            {"flashduty": {"alert": {"title": "MySQL slow query"}}},
            False,
        ),
        (
            "flashduty_similar",
            "flashduty_similar",
            {"items": [{"incident_id": "incident-1", "title": "Past incident"}]},
            True,
        ),
    ),
)
@pytest.mark.asyncio
async def test_flashduty_compatibility_aliases_route_as_api_not_mcp(
    tool_name: str,
    source_system: str,
    structured_data: dict[str, object],
    context_only: bool,
) -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name=tool_name,
        source_system=source_system,
        request={},
        raw_result={"status": "SUCCESS", "structured_data": structured_data},
        artifact=_artifact(),
    )

    projected = "\n".join(
        [result.summary, *(item.statement for item in result.observations), *result.limitations]
    )
    assert result.analysis_usable is True
    assert "FlashDuty API" in projected
    assert "MCP" not in projected
    assert (
        is_context_only_tool_result(
            tool_name=tool_name,
            source_system=source_system,
        )
        is context_only
    )


@pytest.mark.parametrize(
    ("tool_name", "source_system", "structured_data"),
    (
        (
            "query_changes",
            "alert_platform",
            {
                "request_id": "req-changes",
                "query_window": {"start_time": 1, "end_time": 2},
                "items": [{"title": "deployment", "start_time": 1}],
            },
        ),
        (
            "query_metrics",
            "flashduty_monitors",
            {
                "request_id": "req-metrics",
                "operation": "metric_trends",
                "data": {"results": [{"metric": "connections", "value": 9}]},
            },
        ),
        (
            "query_logs",
            "flashduty_monitors",
            {
                "request_id": "req-logs",
                "operation": "log_patterns",
                "data": {"results": [{"pattern": "timeout", "count": 4}]},
            },
        ),
        (
            "query_trace",
            "flashduty_monitors",
            {"request_id": "req-trace", "rows": [{"trace_id": "trace-1"}]},
        ),
        (
            "query_endpoint_errors",
            "flashduty_monitors",
            {"request_id": "req-errors", "rows": [{"status": 500, "count": 3}]},
        ),
        (
            "query_database_diagnostics",
            "flashduty_monitors",
            {
                "catalog_request_id": "req-catalog",
                "target_request_ids": ["req-target"],
                "invoke_request_id": "req-invoke",
                "target": {"locator": "db-prod-01", "kind": "mysql"},
                "selected_tools": ["mysql.connection_overview"],
                "results": [{"data": {"connections": 95}}],
            },
        ),
    ),
)
@pytest.mark.asyncio
async def test_all_flashduty_native_tools_use_bounded_api_projection(
    tool_name: str,
    source_system: str,
    structured_data: dict[str, object],
) -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name=tool_name,
        source_system=source_system,
        request={},
        raw_result={"status": "SUCCESS", "structured_data": structured_data},
        artifact=_artifact(),
    )

    projected = "\n".join(
        [result.summary, *(item.statement for item in result.observations), *result.limitations]
    )
    assert result.analysis_usable is True
    assert "FlashDuty API" in projected
    assert "MCP" not in projected
    assert "req-" not in projected
    assert all(len(item.statement) <= 1000 for item in result.observations)
    assert all(
        path.startswith("/structured_data/")
        for item in result.observations
        for path in item.source_paths
    )


@pytest.mark.asyncio
async def test_unknown_non_mcp_projection_source_fails_closed() -> None:
    with pytest.raises(AdvisorError, match="unsupported tool-result projection route"):
        await DeterministicToolResultProcessor().analyze(
            tool_name="query_unknown",
            source_system="unknown_native_provider",
            request={},
            raw_result={"status": "SUCCESS", "structured_data": {}},
            artifact=_artifact(),
        )


@pytest.mark.asyncio
async def test_prometheus_aggregates_numeric_series_without_host_sentinel_gates() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    window_start = window_end - timedelta(minutes=5)
    inside = int(window_start.timestamp())
    raw_result = {
        "status": "SUCCESS",
        "structured_data": {
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "required_target": {
                "database_engine": "mysql",
                "host": "mysql-17",
                "port": 3306,
            },
            "monitoring_results": [
                {
                    "tool_name": "list_metrics",
                    "capability": "metric_catalog",
                    "has_monitoring_observation": False,
                    "window_verification": "unknown",
                    "target_verification": "not_applicable",
                    "root_cause_eligible": False,
                    "result": {"metrics": ["secret_metric"]},
                },
                {
                    "tool_name": "query_range",
                    "capability": "range_query",
                    "has_monitoring_observation": True,
                    "window_verification": "exact",
                    "target_verification": "mismatch",
                    "root_cause_eligible": False,
                    "result": {
                        "series": [
                            {
                                "metric": {"job": "oceanbase", "instance": "ob-1:2882"},
                                "values": [[inside, "999"]],
                            }
                        ]
                    },
                },
                {
                    "tool_name": "query_range",
                    "capability": "range_query",
                    "has_monitoring_observation": True,
                    "window_verification": "superset",
                    "target_verification": "match",
                    "root_cause_eligible": True,
                    "result": {
                        "series": [
                            {
                                "metric": {"job": "mysql", "instance": "mysql-17:3306"},
                                "values": [[inside - 1, "888"]],
                            }
                        ]
                    },
                },
                {
                    "tool_name": "query_range",
                    "capability": "range_query",
                    "has_monitoring_observation": True,
                    "window_verification": "exact",
                    "target_verification": "match",
                    "root_cause_eligible": True,
                    "result": {
                        "resultType": "matrix",
                        "result": [
                            {
                                "metric": {
                                    "__name__": "threads_running",
                                    "job": "mysql",
                                    "instance": "mysql-17:3306",
                                },
                                "values": [
                                    [inside + 120, "5"],
                                    [inside, "1"],
                                    [inside + 60, "3"],
                                ],
                            }
                        ],
                    },
                },
            ],
            "partial": False,
            "root_cause_eligible": True,
        },
    }

    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result=raw_result,
        artifact=_artifact(),
    )

    projected = "\n".join([*(item.statement for item in result.observations), *result.limitations])
    selection = result.observations[0].statement
    aggregates = [item.statement for item in result.observations[1:]]
    assert "选择 1 条时序" in projected
    assert '"catalog_or_metadata":1' in selection
    assert '"target_mismatch_series":1' in selection
    assert '"outside_required_window_samples":1' in selection
    assert not any('"latest":999' in item for item in aggregates)
    assert not any('"latest":888' in item for item in aggregates)
    aggregate = next(item for item in aggregates if '"sample_count":3' in item)
    assert '"min":1' in aggregate
    assert '"max":5' in aggregate
    assert '"avg":3' in aggregate
    assert '"latest":5' in aggregate
    assert '"delta":4' in aggregate
    assert aggregate.index('"first_timestamp"') < aggregate.index('"latest_timestamp"')
    assert result.analysis_usable is True
    assert any(
        item.source_paths
        == [
            "/structured_data/monitoring_results/3/result/result/0/values",
            "/structured_data/required_target",
            "/structured_data/window_start",
            "/structured_data/window_end",
        ]
        for item in result.observations
    )


@pytest.mark.asyncio
async def test_prometheus_consumes_only_valid_bounded_range_projection() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    window_start = window_end - timedelta(minutes=5)
    auxiliary_secret = "must-not-enter-main-agent"
    raw_result = {
        "status": "SUCCESS",
        "structured_data": {
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "required_target": {
                "database_engine": "mysql",
                "host": "mysql-17",
                "port": 3306,
            },
            "monitoring_results": [
                {
                    "tool_name": "get_targets",
                    "projection_kind": "auxiliary",
                    "response": {
                        "activeTargets": [auxiliary_secret],
                        "api_key": auxiliary_secret,
                    },
                },
                {
                    "tool_name": "query_range",
                    "projection_kind": "alert_window_range",
                    "projection": {
                        "projection_kind": "alert_window_range",
                        "window": {
                            "start": window_start.isoformat(),
                            "end": window_end.isoformat(),
                        },
                        "target_match": {
                            "matched": True,
                            "authoritative_fields": [
                                "database.host",
                                "database.endpoint",
                            ],
                        },
                        "timeseries": {
                            "has_numeric_samples": True,
                            "series_count": 1,
                            "sample_count": 3,
                            "series": [
                                {
                                    "metric": {"__name__": "mysql_threads_running"},
                                    "sample_count": 3,
                                    "min": 1,
                                    "max": 5,
                                    "avg": 3,
                                    "latest": 5,
                                    "delta": 4,
                                }
                            ],
                            "omitted_series_count": 0,
                        },
                    },
                },
            ],
        },
    }

    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result=raw_result,
        artifact=_artifact(),
    )

    projected = "\n".join([*(item.statement for item in result.observations), *result.limitations])
    assert result.analysis_usable is True
    assert "通过协议校验的时序 1 条" in projected
    assert '"sample_count":3' in projected
    assert '"latest":5' in projected
    assert '"delta":4' in projected
    assert auxiliary_secret not in projected
    assert any(
        item.source_paths
        == [
            "/structured_data/monitoring_results/1/projection/timeseries/series/0",
            "/structured_data/monitoring_results/1/projection/window",
            "/structured_data/monitoring_results/1/projection/target_match",
        ]
        for item in result.observations
    )


@pytest.mark.asyncio
async def test_prometheus_range_projection_requires_alarm_host_match() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    window_start = window_end - timedelta(minutes=5)
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "required_target": {"host": "mysql-17"},
                "monitoring_results": [
                    {
                        "tool_name": "query_range",
                        "projection_kind": "alert_window_range",
                        "projection": {
                            "projection_kind": "alert_window_range",
                            "window": {
                                "start": window_start.isoformat(),
                                "end": window_end.isoformat(),
                            },
                            "target_match": {
                                "matched": True,
                                "authoritative_fields": ["cluster"],
                            },
                            "timeseries": {
                                "series_count": 1,
                                "sample_count": 1,
                                "omitted_series_count": 0,
                                "series": [
                                    {
                                        "sample_count": 1,
                                        "min": 1,
                                        "max": 1,
                                        "avg": 1,
                                        "latest": 1,
                                        "delta": 0,
                                    }
                                ],
                            },
                        },
                    }
                ],
            },
        },
        artifact=_artifact(),
    )

    projected = "\n".join([*(item.statement for item in result.observations), *result.limitations])
    assert result.analysis_usable is False
    assert '"target_match_invalid":1' in projected
    assert not any("时序聚合" in item.statement for item in result.observations[1:])


@pytest.mark.asyncio
async def test_prometheus_empty_series_is_recorded_as_no_sample_without_causality() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "window_start": (window_end - timedelta(minutes=5)).isoformat(),
                "window_end": window_end.isoformat(),
                "required_target": {"database_engine": "mysql", "host": "mysql-17"},
                "monitoring_results": [
                    {
                        "tool_name": "query_range",
                        "result": {
                            "resultType": "matrix",
                            "result": [
                                {
                                    "metric": {"__name__": "threads_running"},
                                    "values": [],
                                }
                            ],
                        },
                    },
                    {
                        "tool_name": "query_instant",
                        "window_verification": "exact",
                        "target_verification": "match",
                        "root_cause_eligible": True,
                        "result": {"value": [1, "not-a-number"]},
                    },
                    {
                        "tool_name": "query_missing_result",
                    },
                ],
            },
        },
        artifact=_artifact(),
    )

    assert result.analysis_usable is False
    assert "向主 Agent 展示 0 条时序、0 个数值样本" in result.summary
    assert '"no_numeric_samples":3' in result.observations[0].statement
    assert [item.source_paths for item in result.observations[1:]] == [
        ["/structured_data/monitoring_results/0/result"],
        ["/structured_data/monitoring_results/1/result"],
        ["/structured_data/monitoring_results/2"],
    ]
    assert all("根因判断" in item.statement for item in result.observations[1:])
    assert any("已记录为无样本" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_prometheus_v4_empty_range_uses_execution_counts_not_zero_over_zero() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={
            "status": "NO_DATA",
            "structured_data": {
                "schema_version": "prometheus-evidence-v4",
                "window_start": (window_end - timedelta(minutes=5)).isoformat(),
                "window_end": window_end.isoformat(),
                "required_target": {"database_engine": "mysql", "host": "mysql-17"},
                "monitoring_results": [],
                "range_query_attempt_count": 2,
                "range_query_success_count": 1,
                "range_query_empty_count": 1,
            },
        },
        artifact=_artifact(),
    )

    assert result.prompt_version == "program-fact-projection-v8"
    assert result.analysis_usable is False
    assert "成功范围查询 1 次" in result.summary
    assert "匹配 0/0" not in result.summary
    assert any("空结果不证明目标未被监控" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_prometheus_projection_filters_target_window_and_unverifiable_samples() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    window_start = window_end - timedelta(minutes=5)
    start_epoch = int(window_start.timestamp())
    raw_secret = "raw-response-must-stay-in-artifact"
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "required_target": {
                    "database_engine": "mysql",
                    "database": "orders",
                    "host": "db-prod-1",
                    "port": 3306,
                    "host_source": "flashduty_alert_detail.alarm_host",
                    "port_source": "flashduty_alert_detail.alarm_port",
                },
                "monitoring_results": [
                    {
                        "tool_name": "query_range",
                        "result": {
                            "result": [
                                {
                                    "metric": {
                                        "__name__": "mysql_threads_running",
                                        "job": "mysql",
                                        "instance": "db-prod-1:3306",
                                        "database": "orders",
                                    },
                                    "values": [
                                        [start_epoch + 120, "7"],
                                        [start_epoch - 1, "1000"],
                                        ["not-a-timestamp", "2000"],
                                        [start_epoch, "3"],
                                    ],
                                },
                                {
                                    "metric": {
                                        "job": "mysql",
                                        "instance": "other-db:3306",
                                        "database": "orders",
                                    },
                                    "values": [[start_epoch + 60, "9000"]],
                                },
                                {
                                    "metric": {
                                        "job": "mysql",
                                        "instance": "db-prod-1:3307",
                                        "database": "orders",
                                    },
                                    "values": [[start_epoch + 60, "8000"]],
                                },
                                {
                                    "metric": {
                                        "job": "mysql",
                                        "instance": "db-prod-1:3306",
                                        "database": "billing",
                                    },
                                    "values": [[start_epoch + 60, "7000"]],
                                },
                            ],
                            "raw_note": raw_secret,
                        },
                    }
                ],
                "raw_call_results": [{"result": raw_secret}],
            },
        },
        artifact=_artifact(),
    )

    projected = "\n".join(item.statement for item in result.observations)
    selection = result.observations[0].statement
    aggregate = result.observations[1].statement
    assert result.analysis_usable is True
    assert '"target_mismatch_series":3' in selection
    assert '"outside_required_window_samples":1' in selection
    assert '"timestamp_unverifiable_samples":1' in selection
    assert '"alarm_host":1' in selection
    assert '"alarm_port":1' in selection
    assert '"database":1' in selection
    assert '"sample_count":2' in aggregate
    assert '"min":3' in aggregate
    assert '"max":7' in aggregate
    assert '"latest":7' in aggregate
    assert '"delta":4' in aggregate
    assert "1000" not in aggregate
    assert "9000" not in aggregate
    assert raw_secret not in projected
    assert any("排除 5/7 个" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_prometheus_projection_excludes_series_with_unverified_target_labels() -> None:
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    window_start = window_end - timedelta(minutes=5)
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "required_target": {
                    "database_engine": "mysql",
                    "database": "orders",
                    "host": "db-prod-1",
                    "port": 3306,
                },
                "monitoring_results": [
                    {
                        "tool_name": "query_range",
                        "result": {
                            "result": [
                                {
                                    "metric": {"__name__": "mysql_threads_running"},
                                    "values": [[window_start.timestamp(), "999"]],
                                }
                            ]
                        },
                    }
                ],
            },
        },
        artifact=_artifact(),
    )

    projected = "\n".join(item.statement for item in result.observations)
    assert result.analysis_usable is False
    assert '"target_unverified_series":1' in projected
    assert "999" not in projected
    assert not any("时序聚合" in item.statement for item in result.observations[1:])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("structured_update", "expected_limit"),
    [
        ({"required_target": {}}, "告警详情没有可用于 Prometheus 结果归属"),
        (
            {"window_start": "2026-08-13T07:56:00+00:00"},
            "窗口不是告警发生前精确五分钟",
        ),
    ],
)
async def test_prometheus_projection_requires_trusted_target_and_exact_window(
    structured_update: dict[str, object],
    expected_limit: str,
) -> None:
    data: dict[str, object] = {
        "window_start": "2026-08-13T07:55:00+00:00",
        "window_end": "2026-08-13T08:00:00+00:00",
        "required_target": {"database_engine": "mysql", "host": "db-prod-1"},
        "monitoring_results": [
            {
                "tool_name": "query_range",
                "result": {
                    "result": [
                        {
                            "metric": {"job": "mysql", "instance": "db-prod-1:3306"},
                            "values": [[1786607700, "4"]],
                        }
                    ]
                },
            }
        ],
    }
    data.update(structured_update)

    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_prometheus",
        source_system="prometheus_mcp",
        request={},
        raw_result={"status": "SUCCESS", "structured_data": data},
        artifact=_artifact(),
    )

    assert result.analysis_usable is False
    assert any(expected_limit in item for item in result.limitations)
    assert not any("时序聚合" in item.statement for item in result.observations[1:])


@pytest.mark.asyncio
async def test_generic_processor_selects_successful_data_calls_conservatively() -> None:
    long_text = "raw-log-line\n" * 2_000
    raw_result = {
        "status": "SUCCESS",
        "structured_data": {
            "server": "custom",
            "read_only": True,
            "observations": [
                {
                    "tool_name": "failed_call",
                    "projection": {
                        "projection_type": "deterministic_fact_projection",
                        "source_path": "/result",
                        "source_sha256": "a" * 64,
                        "source_json_chars": 32,
                        "scalar_groups": [],
                    },
                    "is_error": True,
                    "has_data": False,
                },
                {
                    "tool_name": "empty_call",
                    "projection": {
                        "projection_type": "deterministic_fact_projection",
                        "source_path": "/result",
                        "source_sha256": "c" * 64,
                        "source_json_chars": 2,
                        "scalar_groups": [],
                    },
                    "is_error": False,
                    "has_data": False,
                },
                {
                    "tool_name": "read_logs",
                    "projection": {
                        "projection_type": "deterministic_fact_projection",
                        "source_path": "/result",
                        "source_sha256": "b" * 64,
                        "source_json_chars": len(long_text),
                        "scalar_groups": [
                            {
                                "path_pattern": "/content",
                                "value_count": 1,
                                "samples": [
                                    {
                                        "value": {
                                            "excerpt": "raw-log-line\n" * 40,
                                            "sha256": "c" * 64,
                                            "total_chars": len(long_text),
                                        },
                                        "source_path": "/content",
                                    }
                                ],
                            }
                        ],
                    },
                    "is_error": False,
                    "has_data": True,
                },
            ],
            "successful_observation_count": 1,
            "partial": False,
            "root_cause_eligible": True,
        },
    }

    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_custom",
        source_system="custom_mcp",
        request={"read_only": True},
        raw_result=raw_result,
        artifact=_artifact(),
    )

    projected = "\n".join(item.statement for item in result.observations)
    assert "MCP provider=custom_mcp" in projected
    assert "通用 MCP" not in projected
    assert "选择 1 次" in projected
    assert "read_logs" in projected
    assert len(projected) < 5_000
    assert "total_chars" in projected
    assert long_text not in projected
    assert "source_sha256" not in projected
    assert '"sha256"' not in projected
    assert result.observations[-1].source_paths == ["/structured_data/observations/2/projection"]


@pytest.mark.asyncio
async def test_generic_processor_removes_nested_artifact_provenance() -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_custom",
        source_system="custom_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "observations": [
                    {
                        "tool_name": "read_metrics",
                        "projection": {
                            "projection_type": "deterministic_fact_projection",
                            "artifact_id": "internal-id",
                            "nested": {
                                "raw_response": "raw-secret",
                                "source_sha256": "a" * 64,
                                "uri": "agent-artifact://internal-id",
                                "fact": "threads_running increased",
                            },
                        },
                        "is_error": False,
                        "has_data": True,
                    }
                ]
            },
        },
        artifact=_artifact(),
    )

    projected = "\n".join(item.statement for item in result.observations)
    assert "threads_running increased" in projected
    for internal_value in (
        "internal-id",
        "raw-secret",
        "source_sha256",
        "agent-artifact://",
    ):
        assert internal_value not in projected


@pytest.mark.asyncio
async def test_generic_processor_rejects_claimed_data_without_projected_facts() -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_custom",
        source_system="custom_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "observations": [
                    {
                        "tool_name": "metadata_only",
                        "projection": {
                            "projection_type": "deterministic_fact_projection",
                            "source_path": "/result",
                            "has_data": True,
                            "numeric_aggregates": [],
                            "scalar_groups": [],
                            "ignored_metadata_field_count": 4,
                        },
                        "is_error": False,
                        "has_data": True,
                    }
                ]
            },
        },
        artifact=_artifact(),
    )

    assert result.analysis_usable is False
    assert all("metadata_only" not in item.statement for item in result.observations)
    assert any("没有满足保守选择规则" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_processor_binds_projection_to_raw_artifact() -> None:
    artifact = _artifact()
    result = await DeterministicToolResultProcessor().analyze(
        tool_name="query_mcp_custom",
        source_system="custom_mcp",
        request={},
        raw_result={
            "status": "SUCCESS",
            "structured_data": {
                "observations": [],
                "partial": False,
                "root_cause_eligible": False,
            },
        },
        artifact=artifact,
    )

    assert result.source_artifact_id == artifact.artifact_id
    assert result.source_sha256 == artifact.sha256
    assert result.source_coverage_complete is True
    assert result.analysis_usable is False
    assert result.observations == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source_system", "structured_data"),
    [
        (
            "archery_mcp",
            {
                "reported_row_count": 0,
                "parsed_row_count": 0,
                "included_row_count": 0,
                "omitted_row_count": 0,
                "rows": [],
            },
        ),
        (
            "prometheus_mcp",
            {
                "monitoring_results": [
                    {
                        "tool_name": "query_range",
                        "capability": "range_query",
                        "has_monitoring_observation": True,
                        "window_verification": "exact",
                        "target_verification": "mismatch",
                        "root_cause_eligible": False,
                        "result": {"series": [{"values": []}]},
                    }
                ]
            },
        ),
        (
            "custom_mcp",
            {
                "observations": [
                    {
                        "tool_name": "failed",
                        "projection": {},
                        "is_error": True,
                        "has_data": False,
                    }
                ]
            },
        ),
    ],
)
async def test_selection_metadata_alone_is_not_usable_evidence(
    source_system: str,
    structured_data: dict[str, object],
) -> None:
    result = await DeterministicToolResultProcessor().analyze(
        tool_name=f"query_{source_system}",
        source_system=source_system,
        request={},
        raw_result={"status": "SUCCESS", "structured_data": structured_data},
        artifact=_artifact(),
    )

    assert result.analysis_usable is False
    assert result.limitations
