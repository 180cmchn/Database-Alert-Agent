from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.adapters import archery_harness as archery_harness_module
from app.adapters.archery_harness import ARCHERY_HARNESS_PROVIDER
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
)
from app.mcp_runtime import (
    DiscoveredMCPTool,
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    ALERT_CONTEXT,
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    INSTANCE_SQL,
    MEMBER_SQL,
    OCCURRED_AT,
    _call,
    _client,
    _named_call,
    _ScriptedModel,
)

INSTANCE_DIRECTORY_TEXT = (
    "实例清单（第 1 页）：\n"
    "1. [ID:3] pcm db-1.example:3306 资源组:[1]\n"
    "2. [ID:8] analytics analytics.example:3306 资源组:[2]"
)
DATABASE_DIRECTORY_TEXT = "实例 3 的数据库清单：\n1. orders_prod\n2. reporting"


def _live_archery_tools() -> list[DiscoveredMCPTool]:
    return [
        DiscoveredMCPTool(
            name=ARCHERY_MCP_LOGIN_TOOL_NAME,
            description="确认当前 Archery 身份",
            input_schema={"type": "object", "properties": {}},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            description="分页列出 allowlist 中可访问的实例",
            input_schema={
                "type": "object",
                "properties": {
                    "resource_group_id": {"type": "integer"},
                    "instance_ref": {"type": "string"},
                    "page": {"type": "integer", "minimum": 1},
                    "size": {"type": "integer", "minimum": 1, "maximum": 200},
                },
            },
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            description="列出指定实例的数据库",
            input_schema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "integer"},
                    "page": {"type": "integer", "minimum": 1},
                    "size": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["instance_id"],
            },
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_COLUMNS_TOOL_NAME,
            description="列出指定数据表的字段",
            input_schema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "integer"},
                    "db_name": {"type": "string"},
                    "tb_name": {"type": "string"},
                    "schema_name": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["instance_id", "db_name", "tb_name"],
            },
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_QUERY_TOOL_NAME,
            description="执行只读 SQL 并返回结果",
            input_schema={
                "type": "object",
                "properties": {
                    "resource_group_id": {"type": "integer"},
                    "instance_id": {"type": "integer"},
                    "instance_ref": {"type": "string"},
                    "db_name": {"type": "string"},
                    "sql_content": {"type": "string"},
                    "limit_num": {"type": "integer", "minimum": 1},
                    "max_result_chars": {"type": "integer", "minimum": 1},
                    "table_name": {"type": "string"},
                    "schema_name": {"type": "string"},
                },
                "required": ["instance_id", "db_name", "sql_content"],
            },
        ),
    ]


def _result_fixture(call, result: dict[str, Any]) -> ReplayCallFixture:
    return ReplayCallFixture(
        tool_name=call.name,
        expected_arguments=dict(call.arguments),
        result=result,
    )


def _sql_result(call, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "structuredContent": {
            "status": "success",
            "full_sql": call.arguments["sql_content"],
            "rows": rows,
        }
    }


def _text_result(text: str) -> dict[str, Any]:
    return {"structuredContent": {"response": {"result": text}}}


def _apply_result(scenario, state, call, result: dict[str, Any]) -> None:
    scenario.registry.pending.append(call)
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=call.name,
            objective="Replay one sanitized Archery call",
            hypothesis_ids=(),
            arguments=call.arguments,
        ),
        state=state,
    )
    assert "local_rejection" not in prepared.metadata
    scenario.on_result(state, prepared, result)


def _preview_replay_fixtures() -> list[ReplayCallFixture]:
    connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    model = _ScriptedModel([])
    client = _client(
        model,
        connector,
        deterministic_history_pipeline=True,
    )
    window_start, window_end = archery_harness_module.client_window(client, OCCURRED_AT)
    state = archery_harness_module.ArcheryHarnessState(
        window_start=window_start,
        window_end=window_end,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
        history_pipeline_enabled=True,
    )
    scenario = archery_harness_module.ArcheryHarnessScenario(
        client,
        state,
        archery_harness_module._PlannerCallRegistry(),
    )
    specs = scenario.build_tool_specs(_live_archery_tools())
    fixtures: list[ReplayCallFixture] = []

    directory = _named_call("instance-directory", ARCHERY_MCP_INSTANCES_TOOL_NAME, {})
    directory_result = _text_result(INSTANCE_DIRECTORY_TEXT)
    fixtures.append(_result_fixture(directory, directory_result))
    _apply_result(scenario, state, directory, directory_result)
    assert state.analysis_instance_refs_by_endpoint == {
        "db-1.example:3306": "pcm",
        "analytics.example:3306": "analytics",
    }
    assert state.analysis_instance_endpoints == {}

    member = _call("resolve-member", MEMBER_SQL)
    member_result = _sql_result(member, [{"f_instance_id": 53}])
    fixtures.append(_result_fixture(member, member_result))
    _apply_result(scenario, state, member, member_result)

    instance = _call("resolve-instance", INSTANCE_SQL)
    instance_result = _sql_result(
        instance,
        [{"host": "db-1.example", "port": 3306}],
    )
    fixtures.append(_result_fixture(instance, instance_result))
    _apply_result(scenario, state, instance, instance_result)

    ranking = scenario.next_host_call(specs)
    assert ranking is not None
    ranking_result = _sql_result(
        ranking,
        [{"id": 501, "Query_time_max": 9.5, "Query_time_sum": 63.0}],
    )
    fixtures.append(_result_fixture(ranking, ranking_result))
    _apply_result(scenario, state, ranking, ranking_result)

    sample = "SELECT * FROM orders WHERE customer_id = 42"
    compact = scenario.next_host_call(specs)
    assert compact is not None
    compact_result = _sql_result(
        compact,
        [
            {
                "id": 501,
                "hostname_max": "db-1.example:3306",
                "db_max": "orders_prod",
                "checksum": "orders-customer-lookup",
                "ts_min": "2026-07-23 15:59:00",
                "ts_max": "2026-07-23 16:00:00",
                "Query_time_max": 9.5,
                "Query_time_sum": 63.0,
                "sample_full_length": len(sample.encode("utf-8")),
            }
        ],
    )
    fixtures.append(_result_fixture(compact, compact_result))
    _apply_result(scenario, state, compact, compact_result)

    sample_call = scenario.next_host_call(specs)
    assert sample_call is not None
    sample_result = _sql_result(sample_call, [{"sample": sample}])
    fixtures.append(_result_fixture(sample_call, sample_result))
    _apply_result(scenario, state, sample_call, sample_result)

    targeted_instance = scenario.next_host_call(specs)
    assert targeted_instance is not None
    assert targeted_instance.name == ARCHERY_MCP_INSTANCES_TOOL_NAME
    assert targeted_instance.arguments == {"instance_ref": "pcm"}
    targeted_result = _text_result(INSTANCE_DIRECTORY_TEXT)
    fixtures.append(_result_fixture(targeted_instance, targeted_result))
    _apply_result(scenario, state, targeted_instance, targeted_result)
    assert state.analysis_instance_endpoints == {3: {"db-1.example:3306"}}

    databases = scenario.next_host_call(specs)
    assert databases is not None
    assert databases.arguments == {"instance_id": 3}
    databases_result = _text_result(DATABASE_DIRECTORY_TEXT)
    fixtures.append(_result_fixture(databases, databases_result))
    _apply_result(scenario, state, databases, databases_result)

    columns = scenario.next_host_call(specs)
    assert columns is not None
    columns_result = {
        "structuredContent": {
            "status": "success",
            "rows": [{"name": "id"}, {"name": "customer_id"}],
        }
    }
    fixtures.append(_result_fixture(columns, columns_result))
    _apply_result(scenario, state, columns, columns_result)

    indexes = scenario.next_host_call(specs)
    assert indexes is not None
    assert "information_schema.STATISTICS" in indexes.arguments["sql_content"]
    indexes_result = _sql_result(
        indexes,
        [{"INDEX_NAME": "idx_customer", "COLUMN_NAME": "customer_id"}],
    )
    fixtures.append(_result_fixture(indexes, indexes_result))
    _apply_result(scenario, state, indexes, indexes_result)

    explain = scenario.next_host_call(specs)
    assert explain is not None
    assert explain.arguments["sql_content"] == f"EXPLAIN {sample}"
    explain_result = _sql_result(
        explain,
        [{"id": 1, "table": "orders", "type": "ref", "key": "idx_customer"}],
    )
    fixtures.append(_result_fixture(explain, explain_result))
    _apply_result(scenario, state, explain, explain_result)

    finish = scenario.next_host_call(specs)
    assert finish is not None
    assert finish.name == "finish_archery_investigation"
    return fixtures


@pytest.mark.asyncio
async def test_live_schema_replay_requires_targeted_instance_before_allowlisting() -> None:
    fixtures = _preview_replay_fixtures()
    model = _ScriptedModel(
        [
            _named_call("instance-directory", ARCHERY_MCP_INSTANCES_TOOL_NAME, {}),
            _call("resolve-member", MEMBER_SQL),
            _call("resolve-instance", INSTANCE_SQL),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-live-schema-offline-replay",
                tools=_live_archery_tools(),
                calls=fixtures,
            )
        ],
    )
    client = _client(
        model,
        connector,
        deterministic_history_pipeline=True,
    )

    result = await client.execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["row_count"] == 1
    assert result.payload["rows"][0]["id"] == 501
    assert result.payload["rows"][0]["sample_recovery_status"] == "ANALYZED"
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["target"] == {
        "instance_id": 3,
        "db_name": "orders_prod",
        "hostname": "db-1.example:3306",
    }
    assert (
        result.slow_query_analysis["explain_results"][0]["result"]["rows"][0]["key"]
        == "idx_customer"
    )
    assert len(model.requests) == 3
    assert result.model_tool_calls == (
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert result.diagnostics["model_decision_count"] == 3
    assert result.diagnostics["host_executed_tool_calls"]
    assert connector.opened_session_ids == ["archery-live-schema-offline-replay"]
