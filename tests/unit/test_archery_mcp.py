from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_MAX_AGENT_STEPS,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_LOG_EVIDENCE_SCHEMA_VERSION,
    ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
    ARCHERY_SLOW_LOG_TABLE,
    ARCHERY_SLOW_LOG_TABLE_SEARCH_KEYWORD,
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPClient,
    ArcheryMCPProtocolError,
    ArcheryMCPReadOnlyViolation,
    ArcheryMCPToolError,
    ArcherySlowLogEvidenceTool,
    ArcherySlowLogQueryResult,
    MCPServerSettings,
    load_mcp_server_settings,
)
from app.adapters.investigation import (
    AlertContextTool,
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
    ToolExecutor,
)
from app.application.factory import apply_runtime_settings, build_runtime
from app.config import Settings
from app.domain.models import (
    InvestigationContext,
    InvestigationStrategy,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall

TEST_INSTANCE_REF = "archery-metadata"
TEST_INSTANCE_ID = 226
TEST_RESOURCE_GROUP_ID = 10
TEST_DB_NAME = "archery_data"
TEST_TIME_COLUMN = "f_insert_time"
TEST_ALERT_OCCURRED_AT = datetime.fromisoformat("2026-07-23T16:00:00+08:00")
TEST_WINDOW_START = datetime(2026, 7, 23, 7, 55, tzinfo=UTC)
TEST_WINDOW_END = datetime(2026, 7, 23, 8, 0, tzinfo=UTC)
TEST_SLOW_LOG_QUERY = (
    "select * from t_slowlog_info "
    "where `f_insert_time` >= from_unixtime(1784793300) "
    "and `f_insert_time` <= from_unixtime(1784793600) "
    "order by `f_insert_time` desc limit 20"
)
TEST_ALTERNATE_SLOW_LOG_QUERY = (
    "SELECT f_id, f_start_time, f_db, f_user, f_insert_time "
    "FROM t_slowlog_info "
    "WHERE f_start_time >= FROM_UNIXTIME(1784793300) "
    "AND f_start_time <= FROM_UNIXTIME(1784793600) "
    "ORDER BY f_start_time DESC LIMIT 5"
)
TEST_HISTORY_TIME_CLAUSE = (
    "AND ts_min >= FROM_UNIXTIME(1784793300) AND ts_min <= FROM_UNIXTIME(1784793600) "
)


def _tool_schema(name: str, *properties: str) -> dict[str, Any]:
    integer_properties = {
        "resource_group_id",
        "instance_id",
        "page",
        "size",
        "limit_num",
        "max_result_chars",
    }
    return {
        "name": name,
        "description": f"Read-only test tool {name}",
        "inputSchema": {
            "type": "object",
            "properties": {
                item: {"type": "integer" if item in integer_properties else "string"}
                for item in properties
            },
        },
    }


def _read_only_tool_schemas(
    *,
    query_properties: tuple[str, ...] = (
        "resource_group_id",
        "instance_id",
        "instance_ref",
        "db_name",
        "sql_content",
        "limit_num",
        "table_name",
        "schema_name",
        "max_result_chars",
    ),
) -> list[dict[str, Any]]:
    return [
        _tool_schema(ARCHERY_MCP_LOGIN_TOOL_NAME),
        _tool_schema(ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME, "page", "size"),
        _tool_schema(
            ARCHERY_MCP_INSTANCES_TOOL_NAME,
            "resource_group_id",
            "instance_ref",
            "page",
            "size",
        ),
        _tool_schema(
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            "instance_id",
            "page",
            "size",
        ),
        _tool_schema(
            ARCHERY_MCP_TABLES_TOOL_NAME,
            "instance_id",
            "db_name",
            "schema_name",
            "keyword",
            "size",
        ),
        _tool_schema(
            ARCHERY_MCP_COLUMNS_TOOL_NAME,
            "instance_id",
            "db_name",
            "tb_name",
            "schema_name",
            "size",
        ),
        _tool_schema(ARCHERY_MCP_QUERY_TOOL_NAME, *query_properties),
    ]


DEFAULT_MODEL_TOOL_SEQUENCE = (
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
)


def _json_response(
    request: httpx.Request,
    request_id: int,
    result: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json", **(headers or {})},
        json={"jsonrpc": "2.0", "id": request_id, "result": result},
        request=request,
    )


class PromptFollowingMCPModel:
    def __init__(
        self,
        sequence: tuple[str, ...] = DEFAULT_MODEL_TOOL_SEQUENCE,
        *,
        query_sqls: tuple[str, ...] = (TEST_SLOW_LOG_QUERY,),
        slow_log_table: str = ARCHERY_SLOW_LOG_TABLE,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.sequence = sequence
        self.query_sqls = query_sqls
        self.slow_log_table = slow_log_table

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        name = self.sequence[len(self.calls)]
        available_names = {item["function"]["name"] for item in tools}
        assert name in available_names
        query_index = sum(item["name"] == ARCHERY_MCP_QUERY_TOOL_NAME for item in self.calls)
        query_sql = self.query_sqls[min(query_index, len(self.query_sqls) - 1)]
        arguments_by_tool = {
            ARCHERY_MCP_LOGIN_TOOL_NAME: {},
            ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME: {"page": 1, "size": 200},
            ARCHERY_MCP_INSTANCES_TOOL_NAME: {
                "resource_group_id": TEST_RESOURCE_GROUP_ID,
                "instance_ref": TEST_INSTANCE_REF,
                "page": 1,
                "size": 200,
            },
            ARCHERY_MCP_DATABASES_TOOL_NAME: {
                "instance_id": TEST_INSTANCE_ID,
                "page": 1,
                "size": 200,
            },
            ARCHERY_MCP_TABLES_TOOL_NAME: {
                "instance_id": TEST_INSTANCE_ID,
                "db_name": TEST_DB_NAME,
                "keyword": ARCHERY_SLOW_LOG_TABLE_SEARCH_KEYWORD,
                "size": 200,
            },
            ARCHERY_MCP_COLUMNS_TOOL_NAME: {
                "instance_id": TEST_INSTANCE_ID,
                "db_name": TEST_DB_NAME,
                "tb_name": self.slow_log_table,
                "size": 200,
            },
            ARCHERY_MCP_QUERY_TOOL_NAME: {
                "instance_id": TEST_INSTANCE_ID,
                "db_name": TEST_DB_NAME,
                "sql_content": query_sql,
                "limit_num": 20,
                "max_result_chars": ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
            },
        }
        arguments = arguments_by_tool[name]
        self.calls.append(
            {
                "name": name,
                "messages": list(messages),
                "tools": tools,
                "arguments": arguments,
            }
        )
        return MCPModelToolCall(
            call_id=f"model-call-{len(self.calls)}",
            name=name,
            arguments=arguments,
            request_id=f"model-request-{len(self.calls)}",
        )


def _client(
    transport: httpx.AsyncBaseTransport,
    *,
    model: PromptFollowingMCPModel | None = None,
    max_agent_steps: int = ARCHERY_MCP_MAX_AGENT_STEPS,
) -> ArcheryMCPClient:
    return ArcheryMCPClient(
        MCPServerSettings(
            url="https://archery.example.test/mcp",
            headers={"X-Archery-Token": "test-archery-token"},
        ),
        model or PromptFollowingMCPModel(),
        instance_ref=TEST_INSTANCE_REF,
        db_name=TEST_DB_NAME,
        max_agent_steps=max_agent_steps,
        transport=transport,
    )


def test_project_mcp_settings_resolve_environment_without_persisting_token(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "archery": {
                        "url": "${ARCHERY_MCP_URL}",
                        "headers": {
                            "X-Archery-Token": "${ARCHERY_MCP_TOKEN}",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    server = load_mcp_server_settings(
        settings_path,
        server_name="archery",
        environment={
            "ARCHERY_MCP_URL": "https://archery.example.test/mcp",
            "ARCHERY_MCP_TOKEN": "runtime-only-token",
        },
    )

    assert server.url == "https://archery.example.test/mcp"
    assert server.headers == {"X-Archery-Token": "runtime-only-token"}
    assert "runtime-only-token" not in settings_path.read_text(encoding="utf-8")






def _archery_call_handler(
    *,
    login_result: dict[str, Any],
    query_result: dict[str, Any] | list[dict[str, Any]],
    tool_calls: list[str],
    tables_payload: dict[str, Any] | None = None,
    query_sql_calls: list[str] | None = None,
    query_argument_calls: list[dict[str, Any]] | None = None,
) -> httpx.MockTransport:
    query_results = query_result if isinstance(query_result, list) else [query_result]
    query_index = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal query_index
        if request.method == "DELETE":
            return httpx.Response(200, request=request)
        body = json.loads(request.content)
        method = body["method"]
        if method == "initialize":
            return _json_response(
                request,
                body["id"],
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "archery", "version": "1"},
                },
                headers={"Mcp-Session-Id": "session-test"},
            )
        if method == "notifications/initialized":
            return httpx.Response(202, request=request)
        if method == "tools/list":
            return _json_response(
                request,
                body["id"],
                {"tools": _read_only_tool_schemas()},
            )
        if method == "tools/call":
            tool_name = body["params"]["name"]
            tool_calls.append(tool_name)
            discovery_payloads = {
                ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME: {
                    "status": "ok",
                    "results": [{"id": TEST_RESOURCE_GROUP_ID}],
                },
                ARCHERY_MCP_INSTANCES_TOOL_NAME: {
                    "status": "ok",
                    "results": [{"id": TEST_INSTANCE_ID, "name": TEST_INSTANCE_REF}],
                },
                ARCHERY_MCP_DATABASES_TOOL_NAME: {
                    "status": "ok",
                    "results": [{"name": TEST_DB_NAME}],
                },
                ARCHERY_MCP_TABLES_TOOL_NAME: (
                    tables_payload
                    if tables_payload is not None
                    else {
                        "status": "ok",
                        "results": [{"name": ARCHERY_SLOW_LOG_TABLE}],
                    }
                ),
                ARCHERY_MCP_COLUMNS_TOOL_NAME: {
                    "status": "ok",
                    "results": [
                        {"name": "f_id"},
                        {"name": TEST_TIME_COLUMN},
                    ],
                },
            }
            if tool_name == ARCHERY_MCP_LOGIN_TOOL_NAME:
                result = login_result
            elif tool_name == ARCHERY_MCP_QUERY_TOOL_NAME:
                query_arguments = body["params"]["arguments"]
                if query_sql_calls is not None:
                    query_sql_calls.append(query_arguments["sql_content"])
                if query_argument_calls is not None:
                    query_argument_calls.append(query_arguments)
                result = query_results[min(query_index, len(query_results) - 1)]
                query_index += 1
            else:
                result = {
                    "structuredContent": discovery_payloads[tool_name],
                    "isError": False,
                }
            return _json_response(
                request,
                body["id"],
                {"content": [], **result},
            )
        raise AssertionError(method)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_archery_mcp_stops_before_select_when_login_confirmation_fails() -> None:
    tool_calls: list[str] = []
    client = _client(
        _archery_call_handler(
            login_result={
                "content": [
                    {
                        "type": "text",
                        "text": "登录已过期，请重新登录后再试",
                    }
                ],
                "isError": True,
            },
            query_result={
                "structuredContent": {
                    "status": "ok",
                    "rows": [],
                },
                "isError": False,
            },
            tool_calls=tool_calls,
        )
    )

    with pytest.raises(ArcheryMCPToolError, match="登录已过期"):
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME]




@pytest.mark.asyncio
async def test_archery_mcp_queries_discovered_dynamic_slow_log_table() -> None:
    tool_calls: list[str] = []
    table_name = "mysql_slow_log"
    query_sql = (
        f"SELECT * FROM {table_name} "
        "WHERE start_time >= FROM_UNIXTIME(1784793300) "
        "AND start_time <= FROM_UNIXTIME(1784793600) "
        "ORDER BY start_time DESC LIMIT 20"
    )
    model = PromptFollowingMCPModel(
        query_sqls=(query_sql,),
        slow_log_table=table_name,
    )
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result={
                "structuredContent": {"status": "ok", "rows": [[1]]},
                "isError": False,
            },
            tables_payload={
                "status": "ok",
                "results": [{"table_name": table_name}],
            },
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.requested_sql == query_sql
    assert result.table_name == table_name
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *DEFAULT_MODEL_TOOL_SEQUENCE]






@pytest.mark.asyncio
async def test_archery_mcp_limits_all_model_tool_calls_to_configured_budget() -> None:
    tool_calls: list[str] = []
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result={
                "structuredContent": {"status": "ok", "rows": []},
                "isError": False,
            },
            tool_calls=tool_calls,
        ),
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ]
    assert result.query_completed is False
    assert result.diagnostics is not None
    assert result.diagnostics["outcome"] == "evidence_insufficient"










@pytest.mark.asyncio
async def test_archery_mcp_recovers_from_history_timeout_with_index_aligned_window() -> None:
    tool_calls: list[str] = []
    query_sql_calls: list[str] = []
    timed_out_sql = (
        "SELECT hostname_max, sample, ts_min, ts_max "
        f"FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
        "WHERE hostname_max = 'db-1:3306' "
        "AND ts_min < FROM_UNIXTIME(1784793600) "
        "AND ts_max >= FROM_UNIXTIME(1784793300) LIMIT 20"
    )
    recovered_sql = (
        "SELECT hostname_max, sample, ts_min, ts_max "
        f"FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
        "WHERE hostname_max = 'db-1:3306' "
        "AND ts_min >= FROM_UNIXTIME(1784793300) "
        "AND ts_min < FROM_UNIXTIME(1784793600) "
        "ORDER BY ts_min DESC LIMIT 20"
    )
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME),
        query_sqls=(timed_out_sql, recovered_sql),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "status": "failed",
                        "message": "查询超时被KILL，请优化SQL后执行",
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "status": "ok",
                        "columns": ["hostname_max", "sample", "ts_min", "ts_max"],
                        "rows": [["db-1:3306", "select 1", "2026-07-23 15:59:00", None]],
                    },
                    "isError": False,
                },
            ],
            tool_calls=tool_calls,
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert result.requested_sql == recovered_sql
    assert query_sql_calls == [timed_out_sql, recovered_sql]
    timeout_feedback = model.calls[-1]["messages"][-1]["content"]
    assert "当前告警窗口的日志事实仍不完整" in timeout_feedback
    assert "information_schema.statistics" in timeout_feedback
    assert "SHOW INDEX" in timeout_feedback
    assert "ts_min >= FROM_UNIXTIME(1784793300)" in timeout_feedback
    assert "ts_min < FROM_UNIXTIME(1784793600)" in timeout_feedback
    assert "不要原样重试" in timeout_feedback
    assert "剩余1次" in timeout_feedback


def test_archery_mcp_reports_history_query_stage_after_columns_are_known() -> None:
    target = (17, "archery")
    common = {
        "target": target,
        "alert_endpoint": "100.84.97.135:3306",
        "member_instance_ids": {target: {53}},
        "resolved_endpoints": {target: {"db-1:3306"}},
        "table_columns": {
            target: {
                ARCHERY_SLOW_QUERY_REVIEW_TABLE: {
                    "hostname_max",
                    "ts_min",
                    "ts_max",
                }
            }
        },
    }

    assert ArcheryMCPClient.metadata_resolution_stage(
        **common,
        query_trace=[],
    ) == "等待 history 查询成功"
    assert ArcheryMCPClient.metadata_resolution_stage(
        **common,
        query_trace=[
            {
                "chain_stage": "history",
                "outcome": "tool_error",
                "error_detail": "查询超时被KILL，请优化SQL后执行",
            }
        ],
    ) == "等待优化后的 history 查询"

    maximum_execution_time_error = (
        "(1028, 'Sort aborted: Query execution was interrupted, "
        "maximum statement execution time exceeded')"
    )
    assert ArcheryMCPClient._is_query_timeout_detail(maximum_execution_time_error)
    assert ArcheryMCPClient.metadata_resolution_stage(
        **{**common, "table_columns": {}},
        query_trace=[
            {
                "chain_stage": "history",
                "outcome": "tool_error",
                "error_detail": maximum_execution_time_error,
            }
        ],
    ) == "等待优化后的 history 查询"


def test_archery_mcp_bounds_final_history_sort_and_identifies_index_probe() -> None:
    expensive = (
        "SELECT hostname_max, sample, ts_min, Query_time_sum "
        "FROM mysql_slow_query_review_history "
        "WHERE hostname_max = 'db-1:3306' "
        "AND ts_min >= FROM_UNIXTIME(1784793300) "
        "AND ts_min < FROM_UNIXTIME(1784793600) "
        "ORDER BY Query_time_sum DESC LIMIT 20"
    )
    bounded = expensive.replace("Query_time_sum DESC", "ts_min DESC")
    index_probe = (
        "SELECT index_name, seq_in_index, column_name "
        "FROM information_schema.statistics "
        "WHERE table_schema = 'archery' "
        "AND table_name = 'mysql_slow_query_review_history' LIMIT 20"
    )

    assert "只能按真实ts_min字段排序" in (
        ArcheryMCPClient.history_query_efficiency_issue(expensive) or ""
    )
    assert ArcheryMCPClient.history_query_efficiency_issue(bounded) is None
    assert ArcheryMCPClient.is_history_index_probe(index_probe) is True
    assert (
        ArcheryMCPClient.is_history_index_probe(
            "SELECT * FROM information_schema.tables"
        )
        is False
    )




@pytest.mark.asyncio
async def test_archery_mcp_returns_allowlist_error_to_model_for_retry() -> None:
    """A metadata ID must not terminate the agent when used as an MCP instance ID."""

    tool_calls: list[str] = []
    wrong_mcp_instance_id = 9_999
    metadata_instance_id = 53
    member_sql = (
        "SELECT f_instance_id FROM t_instance_member WHERE host = 'db-1' AND port = 3306 LIMIT 1"
    )
    instance_sql = f"SELECT host, port FROM sql_instance WHERE id = {metadata_instance_id} LIMIT 1"
    history_sql = (
        "SELECT hostname_max FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = 'db-1:3306' {TEST_HISTORY_TIME_CLAUSE}LIMIT 1"
    )

    class AllowlistRetryModel(PromptFollowingMCPModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            call = await super().request_mcp_tool_call(messages=messages, tools=tools)
            if call.name != ARCHERY_MCP_QUERY_TOOL_NAME:
                return call
            query_number = sum(item["name"] == ARCHERY_MCP_QUERY_TOOL_NAME for item in self.calls)
            instance_id = wrong_mcp_instance_id if query_number == 1 else TEST_INSTANCE_ID
            arguments = {**call.arguments, "instance_id": instance_id}
            self.calls[-1]["arguments"] = arguments
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments=arguments,
                request_id=call.request_id,
            )

    model = AllowlistRetryModel(
        sequence=(
            ARCHERY_MCP_QUERY_TOOL_NAME,
            ARCHERY_MCP_QUERY_TOOL_NAME,
            ARCHERY_MCP_QUERY_TOOL_NAME,
            ARCHERY_MCP_QUERY_TOOL_NAME,
        ),
        query_sqls=(member_sql, member_sql, instance_sql, history_sql),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "status": "failed",
                        "message": (
                            "实例不在白名单中，已拒绝执行。可访问实例（allowlist）：17: archery"
                        ),
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {"status": "ok", "rows": [[metadata_instance_id]]},
                    "isError": False,
                },
                {
                    "structuredContent": {"status": "ok", "rows": [["db-1", 3306]]},
                    "isError": False,
                },
                {
                    "structuredContent": {"status": "ok", "rows": []},
                    "isError": False,
                },
            ],
            tool_calls=tool_calls,
        ),
        model=model,
        max_agent_steps=5,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query/db-1:3306"},
    )

    assert result.requested_sql == history_sql
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *result.model_tool_calls]
    assert model.calls[0]["arguments"]["instance_id"] == wrong_mcp_instance_id
    assert model.calls[1]["arguments"]["instance_id"] == TEST_INSTANCE_ID
    assert any(
        "allowlist" in (message.get("content") or "") for message in model.calls[1]["messages"]
    )


@pytest.mark.asyncio
async def test_archery_mcp_sends_direct_history_lookup_without_host_lineage_gate() -> None:
    """The Host delegates history endpoint selection to the model and MCP."""

    tool_calls: list[str] = []
    query_sql_calls: list[str] = []
    direct_history_sql = (
        "SELECT hostname_max FROM mysql_slow_query_review_history "
        "WHERE hostname_max = '100.84.97.113:3306' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    model = PromptFollowingMCPModel(
        sequence=(
            ARCHERY_MCP_QUERY_TOOL_NAME,
        ),
        query_sqls=(direct_history_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok", "rows": []}, "isError": False},
            tool_calls=tool_calls,
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=5,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query/100.84.97.113:3306"},
    )
    assert result.requested_sql == direct_history_sql
    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    assert query_sql_calls == [direct_history_sql]
    assert result.metadata_resolution_tables == ()


def test_archery_mcp_recognizes_member_id_in_real_multicolumn_projection() -> None:
    """The live Archery projection must retain a traceable member-instance ID."""

    assert ArcheryMCPClient._member_query_selects_instance_id(
        (
            "SELECT f_id, f_instance_id, f_ip, f_port FROM t_instance_member "
            "WHERE f_ip = '100.84.97.113' AND f_port = 3306 LIMIT 1"
        ),
        set(),
    )
    assert not ArcheryMCPClient._member_query_selects_instance_id(
        "SELECT f_id, f_ip, f_port FROM t_instance_member WHERE f_id = 22 LIMIT 1",
        set(),
    )
    assert ArcheryMCPClient._member_instance_ids_for_endpoint(
        {
            "column_list": ["f_instance_id", "f_ip", "f_port"],
            "rows": [
                [22, "100.84.97.113", 3307],
                [23, "100.84.97.113", 3306],
            ],
        },
        "100.84.97.113:3306",
    ) == {23}


@pytest.mark.asyncio
async def test_archery_mcp_sends_title_endpoint_history_without_host_lineage_gate() -> None:
    """The Host does not reject a model-selected title-derived history query."""

    query_sql_calls: list[str] = []
    title_endpoint = "100.84.97.113:3306"
    direct_history_sql = (
        "SELECT hostname_max FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{title_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    model = PromptFollowingMCPModel(
        sequence=(
            ARCHERY_MCP_QUERY_TOOL_NAME,
        ),
        query_sqls=(direct_history_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok", "rows": []}, "isError": False},
            tool_calls=[],
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=5,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": f"MySQL/mysql_slow_query/{title_endpoint}"},
    )

    assert result.requested_sql == direct_history_sql
    assert query_sql_calls == [direct_history_sql]


@pytest.mark.asyncio
async def test_archery_mcp_sends_history_query_without_host_guard() -> None:
    """The Host sends the model's first history query directly to MCP."""

    query_sql_calls: list[str] = []
    direct_history_sql = (
        "SELECT hostname_max FROM mysql_slow_query_review_history "
        "WHERE hostname_max = '100.84.97.113:3306' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,),
        query_sqls=(direct_history_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok", "rows": []}, "isError": False},
            tool_calls=[],
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query/100.84.97.113:3306"},
    )

    assert query_sql_calls == [direct_history_sql]
    assert result.query_completed is True
    assert result.requested_sql == direct_history_sql


def test_archery_mcp_history_completion_requires_endpoint_and_time_scope() -> None:
    table = "mysql_slow_query_review_history"
    unscoped = f"SELECT hostname_max, ts_min, ts_max FROM {table} LIMIT 1"
    time_only = (
        f"SELECT hostname_max, ts_min FROM {table} "
        "WHERE ts_min >= FROM_UNIXTIME(1784793300) "
        "AND ts_min <= FROM_UNIXTIME(1784793600) LIMIT 20"
    )
    host_only = f"SELECT hostname_max FROM {table} WHERE hostname_max = '10.23.45.67:3306' LIMIT 20"
    scoped = (
        f"SELECT hostname_max, ts_min FROM {table} "
        "WHERE hostname_max = '10.23.45.67:3306' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )

    assert ArcheryMCPClient.slow_log_query_completion_issue(unscoped) == (
        "缺少hostname_max等值查询条件；缺少告警时间范围条件"
    )
    assert ArcheryMCPClient.slow_log_query_completion_issue(time_only) == (
        "缺少hostname_max等值查询条件"
    )
    assert ArcheryMCPClient.slow_log_query_completion_issue(host_only) == ("缺少告警时间范围条件")
    assert ArcheryMCPClient.slow_log_query_completion_issue(scoped) is None


def test_archery_mcp_runtime_completion_requires_exact_window_and_bounded_limit() -> None:
    assert (
        ArcheryMCPClient.slow_log_query_completion_issue(
            TEST_SLOW_LOG_QUERY,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        is None
    )

    history_overlap_window = (
        "SELECT hostname_max, sample, ts_min, ts_max "
        "FROM mysql_slow_query_review_history "
        "WHERE hostname_max = 'db-1:3306' "
        "AND ts_min < FROM_UNIXTIME(1784793600) "
        "AND ts_max >= FROM_UNIXTIME(1784793300) "
        "ORDER BY ts_max DESC LIMIT 20"
    )
    assert (
        ArcheryMCPClient.slow_log_query_completion_issue(
            history_overlap_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        is None
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            history_overlap_window.replace("1784793300", "1784793299"),
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    wrong_window = TEST_SLOW_LOG_QUERY.replace("1784793300", "1784793299")
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            wrong_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    no_limit = TEST_SLOW_LOG_QUERY.rsplit(" limit 20", 1)[0]
    assert "显式LIMIT" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            no_limit,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )
    assert "LIMIT必须" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            TEST_SLOW_LOG_QUERY.replace("limit 20", "limit 21"),
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )
    assert ArcheryMCPClient.slow_log_query_completion_issue(no_limit) is None

    iso_window = (
        "SELECT * FROM t_slowlog_info "
        "WHERE f_insert_time >= '2026-07-23T07:55:00+00:00' "
        "AND f_insert_time <= '2026-07-23T08:00:00+00:00' "
        "LIMIT 20 OFFSET 0"
    )
    assert (
        ArcheryMCPClient.slow_log_query_completion_issue(
            iso_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        is None
    )
    assert ArcheryMCPClient._terminal_select_limit("SELECT 1 LIMIT 0, 20") == 20

    commented_window = (
        "SELECT * FROM t_slowlog_info WHERE 1 = 1 "
        "/* f_insert_time >= FROM_UNIXTIME(1784793300) "
        "AND f_insert_time <= FROM_UNIXTIME(1784793600) */ LIMIT 20"
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            commented_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    bypassed_window = TEST_SLOW_LOG_QUERY.replace(
        "order by",
        "or 1 = 1 order by",
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            bypassed_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    union_window = (
        f"{TEST_SLOW_LOG_QUERY.rsplit(' limit 20', 1)[0]} "
        "UNION ALL SELECT * FROM t_slowlog_info WHERE 1 = 1 LIMIT 20"
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            union_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    subquery_window = (
        "SELECT * FROM mysql_slow_query_review_history "
        "WHERE hostname_max = 'db-1:3306' AND EXISTS ("
        "SELECT 1 FROM mysql_slow_query_review_history AS scoped "
        "WHERE scoped.ts_min >= FROM_UNIXTIME(1784793300) "
        "AND scoped.ts_min <= FROM_UNIXTIME(1784793600)) LIMIT 20"
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            subquery_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    negated_window = TEST_SLOW_LOG_QUERY.replace(
        "where `f_insert_time` >=",
        "where NOT (`f_insert_time` >=",
    ).replace(
        "order by",
        ") order by",
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            negated_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    expanded_window = TEST_SLOW_LOG_QUERY.replace(
        "from_unixtime(1784793300)",
        "from_unixtime(1784793300) - INTERVAL 1 DAY",
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient.slow_log_query_completion_issue(
            expanded_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )


@pytest.mark.parametrize(
    ("sql", "accepted"),
    [
        ("SELECT 'delete; update' AS sample", True),
        ("WITH sample AS (SELECT 1) SELECT * FROM sample", True),
        ("DELETE FROM t_slowlog_info", False),
        ("WITH sample AS (SELECT 1) DELETE FROM t_slowlog_info", False),
        ("SELECT 1; UPDATE t_slowlog_info SET value = 1", False),
        ("SELECT * FROM t_slowlog_info FOR UPDATE", False),
        ("SELECT * FROM t_slowlog_info FOR SHARE", False),
        ("SELECT GET_LOCK('maintenance', 1)", False),
        ("SELECT RELEASE_LOCK('maintenance')", False),
        ("SELECT SLEEP(30)", False),
        ("SELECT @captured := 1", False),
        ("SELECT 1 /*!50000 INTO OUTFILE '/tmp/result' */", False),
        ("SELECT 1 /*M!50000 INTO OUTFILE '/tmp/result' */", False),
        ("SELECT 1--1; DELETE FROM t_slowlog_info", False),
        ("SELECT 1 -- read-only comment\n", True),
    ],
)
def test_archery_mcp_only_accepts_one_read_only_select(sql: str, accepted: bool) -> None:
    assert ArcheryMCPClient._is_single_read_only_select(sql) is accepted


def test_archery_mcp_bounds_query_transport_arguments_before_network_call() -> None:
    assert ArcheryMCPClient.query_call_rejection(
        {
            "sql_content": "SELECT 1",
            "limit_num": 20,
            "max_result_chars": ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
        }
    ) is None
    assert "limit_num" in (
        ArcheryMCPClient.query_call_rejection(
            {"sql_content": "SELECT 1", "limit_num": 21}
        )
        or ""
    )
    assert "max_result_chars" in (
        ArcheryMCPClient.query_call_rejection(
            {
                "sql_content": "SELECT 1",
                "max_result_chars": ARCHERY_SLOW_LOG_MAX_RESULT_CHARS + 1,
            }
        )
        or ""
    )


@pytest.mark.asyncio
async def test_archery_mcp_continues_after_successful_unscoped_history_probe() -> None:
    """A successful LIMIT 1 sample must not replace alert-window evidence."""

    arbitrary_endpoint = "10.126.106.205:3306"
    resolved_endpoint = "100.84.97.139:3306"
    probe_sql = "SELECT hostname_max, ts_min, ts_max FROM mysql_slow_query_review_history LIMIT 1"
    final_sql = (
        "SELECT hostname_max, ts_min, ts_max "
        "FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{resolved_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}ORDER BY ts_min LIMIT 20"
    )
    query_sql_calls: list[str] = []
    model = PromptFollowingMCPModel(
        sequence=(
            ARCHERY_MCP_QUERY_TOOL_NAME,
            ARCHERY_MCP_QUERY_TOOL_NAME,
        ),
        query_sqls=(probe_sql, final_sql),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "columns": ["hostname_max", "ts_min", "ts_max"],
                        "rows": [
                            [
                                arbitrary_endpoint,
                                "2024-05-16T06:39:34",
                                "2024-05-16T06:41:18",
                            ]
                        ],
                        "rowCount": 1,
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "columns": ["hostname_max", "ts_min", "ts_max"],
                        "rows": [],
                        "rowCount": 0,
                    },
                    "isError": False,
                },
            ],
            tool_calls=[],
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=3,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query/100.84.97.135:3306"},
    )

    assert query_sql_calls == [probe_sql, final_sql]
    assert result.requested_sql == final_sql
    assert result.query_completed is True
    assert result.payload["rows"] == []
    assert result.query_time_column == "ts_min"
    probe_feedback = model.calls[-1]["messages"][-1]["content"]
    assert "仍是辅助探针" in probe_feedback
    assert "缺少hostname_max等值查询条件" in probe_feedback
    assert "未使用Host提供的精确告警时间窗口" in probe_feedback
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert "instance_identity_verification" not in result.diagnostics
    assert result.diagnostics["query_trace"][0]["outcome"] == "probe_ok"
    assert result.diagnostics["query_trace"][0]["completion"] == "probe"


@pytest.mark.asyncio
async def test_archery_mcp_does_not_verify_endpoint_identity_after_history_success() -> None:
    alert_endpoint = "100.84.97.113:3306"
    slow_log_endpoint = "10.23.45.67:3306"
    history_sql = (
        "SELECT hostname_max, sample FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{slow_log_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    query_sql_calls: list[str] = []
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,),
        query_sqls=(history_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={
                "structuredContent": {
                    "status": "ok",
                    "columns": ["hostname_max", "sample"],
                    "rows": [[slow_log_endpoint, "select 1"]],
                    "rowCount": 1,
                },
                "isError": False,
            },
            tool_calls=[],
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": f"MySQL/mysql_slow_query/{alert_endpoint}"},
    )

    assert query_sql_calls == [history_sql]
    assert result.payload["rows"] == [[slow_log_endpoint, "select 1"]]
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 2
    assert "instance_identity_verification" not in result.diagnostics


@pytest.mark.asyncio
@pytest.mark.parametrize("embedded_result_complete", [False, True])
async def test_archery_mcp_parses_wrapped_positional_rows_without_post_query_checks(
    embedded_result_complete: bool,
) -> None:
    slow_log_endpoint = "100.84.97.139:3306"
    history_sql = (
        "SELECT hostname_max, db_max, sample, ts_min, ts_max "
        "FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{slow_log_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}"
        "ORDER BY ts_min LIMIT 20"
    )
    embedded_result = (
        json.dumps(
            {
                "full_sql": history_sql + ";",
                "rows": [
                    [
                        slow_log_endpoint,
                        "store_asset",
                        f"select {index}",
                        "2026-08-03T13:42:26",
                        "2026-08-03T13:42:26",
                    ]
                    for index in range(20)
                ],
            },
            ensure_ascii=False,
        )
        if embedded_result_complete
        else '{"full_sql":"truncated","rows":[["100.84.97.139:3306"'
    )
    wrapped_result = (
        f"SQL 查询已执行。\n执行的SQL：{history_sql}\n\n返回 20 行。\n结果：\n{embedded_result}"
    )
    query_sql_calls: list[str] = []
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,),
        query_sqls=(history_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={
                "structuredContent": {"result": wrapped_result},
                "isError": False,
            },
            tool_calls=[],
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query_400/100.84.97.135:3306"},
    )

    if embedded_result_complete:
        assert len(result.payload["rows"]) == 20
        assert "row_count_source" not in result.payload
        assert result.payload["columns"][0] == "hostname_max"
        assert result.payload["columns_source"] == "verified_sql_projection"
    else:
        assert result.payload["rowCount"] == 20
        assert result.payload["row_count_source"] == "archery_text"
    assert result.query_time_column == "ts_min"
    assert query_sql_calls == [history_sql]
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 2


@pytest.mark.asyncio
async def test_archery_mcp_parses_wrapped_json_array_as_slow_log_rows() -> None:
    history_sql = (
        "SELECT hostname_max, sample, ts_min FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '100.84.97.139:3306' {TEST_HISTORY_TIME_CLAUSE}"
        "ORDER BY ts_min LIMIT 20"
    )
    rows = [
        {
            "hostname_max": "100.84.97.139:3306",
            "sample": f"select {index}",
            "ts_min": "2026-08-03T13:42:26",
        }
        for index in range(18)
    ]
    wrapped_result = (
        f"SQL 查询已执行。\n执行的SQL：{history_sql}\n\n返回 18 行。\n结果：\n"
        + json.dumps(rows, ensure_ascii=False)
    )

    payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"result": wrapped_result},
        requested_sql=history_sql,
    )

    assert payload["rows"] == rows
    assert ArcheryMCPClient.payload_row_count(payload) == 18
    assert ArcherySlowLogEvidenceTool._has_parsed_log_rows(payload) is True
    assert executed_sql == history_sql
    assert actual_sql_verified is True

    outcome = await ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload=payload)
    ).execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
        ),
    )

    assert isinstance(outcome, tuple)
    summary, structured_data = outcome
    assert "返回 18 行" in summary
    assert structured_data["root_cause_eligible"] is True
    assert structured_data["reported_row_count"] == 18
    assert structured_data["included_row_count"] == 18
    assert structured_data["rows"][0]["sample"] == "select 0"


@pytest.mark.asyncio
async def test_archery_mcp_recovers_complete_rows_from_truncated_wrapped_json() -> None:
    history_sql = (
        "SELECT hostname_max, user_max, db_max, checksum, sample, ts_min "
        "FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '100.84.97.139:3306' {TEST_HISTORY_TIME_CLAUSE}"
        "ORDER BY ts_min LIMIT 20"
    )
    complete_rows = [
        {
            "hostname_max": "100.84.97.139:3306",
            "user_max": "app_user",
            "db_max": "orders",
            "checksum": f"{index:032x}",
            "sample": f"select * from orders where id = {index}",
            "ts_min": "2026-08-03T13:42:26",
        }
        for index in range(2)
    ]
    incomplete_row = {
        **complete_rows[0],
        "checksum": f"{2:032x}",
        "sample": "select * from a very large table " + ("x" * 10_000),
    }
    truncated_result = (
        '{"rows":['
        + ",".join(json.dumps(row, ensure_ascii=False) for row in complete_rows)
        + ","
        + json.dumps(incomplete_row, ensure_ascii=False)[:200]
    )
    wrapped_result = (
        f"SQL 查询已执行。\n执行的SQL：{history_sql}\n\n返回 18 行。\n结果：\n"
        + truncated_result
    )

    payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"result": wrapped_result},
        requested_sql=history_sql,
    )

    assert payload["rows"] == complete_rows
    assert payload["rows_recovered_from_truncated_json"] is True
    assert payload["mcp_reported_row_count"] == 18
    assert payload["parsed_row_count"] == 2
    assert executed_sql == history_sql
    assert actual_sql_verified is True

    outcome = await ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload=payload)
    ).execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
        ),
    )

    assert isinstance(outcome, tuple)
    summary, structured_data = outcome
    assert "返回 18 行" in summary
    assert structured_data["root_cause_eligible"] is True
    assert structured_data["reported_row_count"] == 18
    assert structured_data["parsed_row_count"] == 2
    assert structured_data["included_row_count"] == 2
    assert structured_data["omitted_row_count"] == 16
    assert structured_data["rows"][0]["checksum"] == complete_rows[0]["checksum"]
    assert structured_data["rows"][1]["sample"] == complete_rows[1]["sample"]


@pytest.mark.asyncio
async def test_archery_mcp_limits_parsed_slow_log_rows_to_twenty() -> None:
    slow_log_endpoint = "db-history:3306"
    history_sql = (
        "SELECT hostname_max, sample FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{slow_log_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    rows = [[slow_log_endpoint, f"select {index}"] for index in range(25)]
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,),
        query_sqls=(history_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={
                "structuredContent": {
                    "columns": ["hostname_max", "sample"],
                    "rows": rows,
                    "rowCount": len(rows),
                },
                "isError": False,
            },
            tool_calls=[],
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert len(result.payload["rows"]) == 20
    assert result.payload["rowCount"] == 20
    assert result.payload["mcp_reported_row_count"] == 25
    assert result.payload["rows_limited_to"] == 20




















class RecordingArcheryClient:
    login_tool_name = ARCHERY_MCP_LOGIN_TOOL_NAME
    query_tool_name = ARCHERY_MCP_QUERY_TOOL_NAME
    slow_log_time_column = TEST_TIME_COLUMN
    window_seconds = 300

    def __init__(
        self,
        *,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.calls = 0
        self.occurred_at: datetime | None = None
        self.alert_context: dict[str, Any] | None = None
        self.payload = payload or {
            "status": "ok",
            "rows": [],
            "affected_rows": 0,
        }

    async def execute_slow_log_query(
        self,
        occurred_at: datetime,
        *,
        alert_context: dict[str, Any] | None = None,
    ) -> ArcherySlowLogQueryResult:
        self.calls += 1
        self.occurred_at = occurred_at
        self.alert_context = alert_context
        return ArcherySlowLogQueryResult(
            payload=self.payload,
            requested_sql=TEST_SLOW_LOG_QUERY,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
            executed_sql=TEST_SLOW_LOG_QUERY,
            actual_sql_verified=True,
            instance_id=TEST_INSTANCE_ID,
            db_name=TEST_DB_NAME,
            table_name=ARCHERY_SLOW_LOG_TABLE,
            query_time_column=TEST_TIME_COLUMN,
        )


def _large_slow_query_row(index: int, *, sample_chars: int = 900) -> dict[str, Any]:
    return {
        "id": 1000 + index,
        "hostname_max": "db-history:3306",
        "client_max": f"10.0.0.{index + 1}",
        "user_max": "app_user",
        "db_max": "orders",
        "checksum": f"{index:032x}",
        "sample": (
            f"SELECT * FROM orders WHERE shard_id = {index} /*"
            + ("x" * sample_chars)
            + "*/"
        ),
        "ts_min": "2026-07-23T15:55:00.000000",
        "ts_max": "2026-07-23T16:00:00.000000",
        "ts_cnt": float(index + 1),
        "Query_time_sum": 120.5 + index,
        "Query_time_max": 18.25 + index,
        "Lock_time_max": 0.25 + index,
        "Rows_sent_sum": 10 + index,
        "Rows_examined_sum": 1_000_000 + index,
        "Merge_passes_sum": index,
        "InnoDB_IO_r_wait_max": 0.75 + index,
        "QC_Hit_sum": 0,
        "Full_scan_sum": 1,
        "Full_join_sum": 0,
        "Tmp_table_on_disk_sum": 1,
        "Filesort_on_disk_sum": 1,
        "Bytes_sum": 4096 + index,
        "unrelated_text": "must not enter semantic evidence",
    }


def test_archery_outer_tool_declares_strict_empty_input_schema() -> None:
    assert ArcherySlowLogEvidenceTool.input_schema == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }


class FlakyRecordingArcheryClient(RecordingArcheryClient):
    async def execute_slow_log_query(
        self,
        occurred_at: datetime,
        *,
        alert_context: dict[str, Any] | None = None,
    ) -> ArcherySlowLogQueryResult:
        if self.calls == 0:
            self.calls += 1
            raise ArcheryMCPProtocolError("stream closed")
        return await super().execute_slow_log_query(
            occurred_at,
            alert_context=alert_context,
        )


class FailedHistoryRecordingArcheryClient(RecordingArcheryClient):
    async def execute_slow_log_query(
        self,
        occurred_at: datetime,
        *,
        alert_context: dict[str, Any] | None = None,
    ) -> ArcherySlowLogQueryResult:
        self.calls += 1
        self.occurred_at = occurred_at
        self.alert_context = alert_context
        error_detail = (
            "Query execution was interrupted, maximum statement execution time exceeded"
        )
        return ArcherySlowLogQueryResult(
            payload={"status": "evidence_insufficient"},
            requested_sql=None,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
            instance_id=TEST_INSTANCE_ID,
            db_name=TEST_DB_NAME,
            query_completed=False,
            diagnostics={
                "reason": f"remote budget exhausted; last query error: {error_detail}",
                "next_stage": "等待优化后的 history 查询",
                "query_trace": [
                    {
                        "chain_stage": "history",
                        "sent_to_mcp": True,
                        "outcome": "tool_error",
                        "error_detail": error_detail,
                    }
                ],
            },
        )


def _context(
    alert_type: str,
    *,
    title: str = "Database alert",
    database: dict[str, str] | None = None,
    labels: dict[str, str] | None = None,
) -> InvestigationContext:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": f"archery-{alert_type}",
            "severity": "WARNING",
            "title": title,
            "reason": alert_type,
            "alert_type": alert_type,
            "occurred_at": TEST_ALERT_OCCURRED_AT.isoformat(),
            "database": database,
            "labels": labels or {},
        }
    )
    return InvestigationContext(
        run_id=uuid4(),
        alert=alert,
        strategy=InvestigationStrategy(
            strategy_id="test",
            title="test",
            description="test",
        ),
    )


@pytest.mark.asyncio
async def test_archery_evidence_tool_derives_time_window_and_rejects_parameters() -> None:
    client = RecordingArcheryClient()
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]

    outcome = await tool.execute(
        ToolExecutionRequest(
            tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
        ),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
            database={
                "engine": "mysql",
                "instance": "db-1:3306",
                "database": TEST_DB_NAME,
                "host": "db-1",
            },
            labels={
                "instance": "db-1:3306",
                "db_name": TEST_DB_NAME,
                "alert_host": "db-1",
                "alert_port": "3306",
            },
        ),
    )

    assert isinstance(outcome, ToolExecutionResult)
    assert outcome.status == ToolStatus.NO_DATA
    summary, data = outcome.summary, outcome.structured_data
    assert client.calls == 1
    assert client.occurred_at == TEST_ALERT_OCCURRED_AT
    assert client.alert_context is not None
    assert client.alert_context["instance_candidates"] == ["db-1:3306", "db-1"]
    assert client.alert_context["database_candidates"] == [TEST_DB_NAME]
    assert client.alert_context["alert_host"] == "db-1"
    assert client.alert_context["alert_port"] == "3306"
    assert client.alert_context["alert_endpoint"] == "db-1:3306"
    assert "返回 0 行" in summary
    assert f"实例 ID {TEST_INSTANCE_ID}" in summary
    assert f"慢日志表 {ARCHERY_SLOW_LOG_TABLE}" in summary
    assert "实际执行 SQL 已由 Archery 回显并与模型提交一致" in summary
    assert "可能被截断" not in summary
    assert data["schema_version"] == ARCHERY_SLOW_LOG_EVIDENCE_SCHEMA_VERSION
    assert data["query_completed"] is True
    assert data["allow_followup_dispatch"] is False
    assert data["actual_sql_verified"] is True
    assert data["target"] == {
        "instance_id": TEST_INSTANCE_ID,
        "db_name": TEST_DB_NAME,
        "table_name": ARCHERY_SLOW_LOG_TABLE,
    }
    assert data["query_window"] == {
        "start": TEST_WINDOW_START.isoformat(),
        "end": TEST_WINDOW_END.isoformat(),
        "duration_seconds": 300,
        "time_column": TEST_TIME_COLUMN,
    }
    assert data["reported_row_count"] == 0
    assert data["included_row_count"] == 0
    assert data["omitted_row_count"] == 0
    assert data["rows"] == []
    assert "result" not in data
    assert "diagnostics" not in data
    assert data["root_cause_eligible"] is False
    assert "实际执行 SQL 未核对" not in data["root_cause_ineligible_reason"]
    assert "可能截断" not in data["root_cause_ineligible_reason"]

    with pytest.raises(ArcheryMCPReadOnlyViolation):
        await tool.execute(
            ToolExecutionRequest(
                tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
                parameters={"window_seconds": 86_400},
            ),
            _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306"),
        )
    with pytest.raises(ArcheryMCPReadOnlyViolation):
        await tool.execute(
            ToolExecutionRequest(
                tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
            ),
            _context("慢查询过多", title="MySQL/mysql_slow_queryable_400/db-1:3306"),
        )
    assert client.calls == 1


@pytest.mark.asyncio
async def test_archery_evidence_distinguishes_failed_history_from_never_executed() -> None:
    client = FailedHistoryRecordingArcheryClient()
    outcome = await ArcherySlowLogEvidenceTool(client).execute(  # type: ignore[arg-type]
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
        ),
    )

    assert isinstance(outcome, ToolExecutionResult)
    assert outcome.status == ToolStatus.NO_DATA
    assert "最终 history 查询未成功" in outcome.summary
    assert "未执行最终 history 查询" not in outcome.summary
    assert "下一阶段：等待优化后的 history 查询" in outcome.summary
    assert outcome.structured_data["query_completed"] is False
    assert outcome.structured_data["root_cause_ineligible_reason"] == (
        "最终慢查询 SQL 未成功；当前证据不足"
    )




@pytest.mark.asyncio
async def test_archery_evidence_with_logs_is_usable_without_endpoint_comparison() -> None:
    client = RecordingArcheryClient(
        payload={
            "status": "ok",
            "columns": ["hostname_max", "sample"],
            "rows": [["100.84.97.20:3311", "select 1"]],
            "rowCount": 1,
        },
    )
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]

    summary, data = await tool.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/100.84.97.124:3311",
        ),
    )

    assert "慢查询日志已作为本次告警窗口的实时证据进入分析" in summary
    assert "100.84.97.20:3311" not in summary
    assert "100.84.97.124:3311" not in summary
    assert "实例归属" not in summary
    assert "f_instance_id" not in summary
    assert "instance_identity_verification" not in data
    assert "analysis_usable" not in data
    assert data["root_cause_eligible"] is True
    assert data["root_cause_ineligible_reason"] == ""
    assert data["rows"] == [
        {
            "hostname_max": "100.84.97.20:3311",
            "sample": "select 1",
        }
    ]


@pytest.mark.asyncio
async def test_archery_semantic_summary_avoids_outer_executor_blind_truncation() -> None:
    max_result_chars = 12_000
    rows = [_large_slow_query_row(index) for index in range(18)]
    tool = ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(
            payload={
                "status": "ok",
                "rows": rows,
                "rowCount": len(rows),
                "opaque_diagnostics": "z" * 50_000,
            }
        ),
        max_evidence_chars=max_result_chars,
    )
    executor = ToolExecutor(
        InvestigationToolRegistry([tool]),
        max_result_chars=max_result_chars,
    )

    record = await executor.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-history:3306",
        ),
    )

    serialized = json.dumps(record.structured_data, ensure_ascii=False, default=str)
    parsed = json.loads(serialized)
    assert record.status == ToolStatus.SUCCESS
    assert record.truncated is False
    assert len(serialized) < max_result_chars
    assert parsed["root_cause_eligible"] is True
    assert parsed["reported_row_count"] == 18
    assert 0 < parsed["included_row_count"] < 18
    assert parsed["omitted_row_count"] == 18 - parsed["included_row_count"]
    assert parsed["semantic_compression"]["sample_truncated_count"] == 0
    first = parsed["rows"][0]
    assert first["hostname_max"] == "db-history:3306"
    assert first["client_max"] == "10.0.0.1"
    assert first["user_max"] == "app_user"
    assert first["db_max"] == "orders"
    assert first["checksum"] == "00000000000000000000000000000000"
    assert first["sample"] == rows[0]["sample"]
    assert first["Query_time_max"] == 18.25
    assert first["Rows_examined_sum"] == 1_000_000
    assert first["InnoDB_IO_r_wait_max"] == 0.75
    assert "id" not in first
    assert "unrelated_text" not in first
    assert "opaque_diagnostics" not in serialized


@pytest.mark.asyncio
async def test_archery_semantic_summary_removes_only_complete_tail_rows() -> None:
    max_result_chars = 2_200
    rows = [_large_slow_query_row(index, sample_chars=700) for index in range(3)]
    tool = ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload={"rows": rows, "rowCount": len(rows)}),
        max_evidence_chars=max_result_chars,
    )
    executor = ToolExecutor(
        InvestigationToolRegistry([tool]),
        max_result_chars=max_result_chars,
    )

    record = await executor.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-history:3306",
        ),
    )

    serialized = json.dumps(record.structured_data, ensure_ascii=False, default=str)
    assert record.truncated is False
    assert len(serialized) < max_result_chars
    assert record.structured_data["included_row_count"] == 1
    assert record.structured_data["omitted_row_count"] == 2
    assert record.structured_data["rows"][0]["sample"] == rows[0]["sample"]
    assert "sample_truncated" not in record.structured_data["rows"][0]
    assert json.loads(serialized)["rows"] == record.structured_data["rows"]


@pytest.mark.asyncio
async def test_archery_semantic_summary_bounds_one_oversized_sql_statement() -> None:
    max_result_chars = 1_000
    row = _large_slow_query_row(0, sample_chars=20_000)
    tool = ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload={"rows": [row], "rowCount": 1}),
        max_evidence_chars=max_result_chars,
    )
    executor = ToolExecutor(
        InvestigationToolRegistry([tool]),
        max_result_chars=max_result_chars,
    )

    record = await executor.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-history:3306",
        ),
    )

    serialized = json.dumps(record.structured_data, ensure_ascii=False, default=str)
    summarized_row = record.structured_data["rows"][0]
    assert record.status == ToolStatus.SUCCESS
    assert record.truncated is False
    assert len(serialized) < max_result_chars
    assert record.structured_data["included_row_count"] == 1
    assert record.structured_data["omitted_row_count"] == 0
    assert record.structured_data["root_cause_eligible"] is True
    assert summarized_row["sample_truncated"] is True
    assert summarized_row["sample_original_char_count"] == len(row["sample"])
    assert summarized_row["sample"]
    assert row["sample"].startswith(summarized_row["sample"])
    assert len(summarized_row["sample"]) < len(row["sample"])
    assert record.structured_data["semantic_compression"]["sample_truncated_count"] == 1
    assert json.loads(serialized)["rows"][0]["checksum"] == row["checksum"]


@pytest.mark.asyncio
async def test_archery_reported_count_without_parsed_rows_is_no_data() -> None:
    client = RecordingArcheryClient(
        payload={
            "status": "ok",
            "rowCount": 20,
            "content": ["result truncated before rows were decoded"],
        },
    )
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]

    outcome = await tool.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
        ),
    )

    assert isinstance(outcome, ToolExecutionResult)
    assert outcome.status == ToolStatus.NO_DATA
    assert "MCP 报告 20 行，但日志行未能解析" in outcome.summary
    assert "返回 20 行" not in outcome.summary
    assert outcome.structured_data["root_cause_eligible"] is False
    assert "未返回可解析的日志行" in outcome.structured_data[
        "root_cause_ineligible_reason"
    ]


@pytest.mark.asyncio
async def test_strategy_requires_archery_evidence_only_for_slow_query_title_identifier() -> None:
    provider = DefaultInvestigationStrategyProvider(available_tools=["alert_context"])

    strategy = await provider.select(
        _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306").alert
    )
    other = await provider.select(
        _context("慢查询过多", title="MySQL/mysql_slow_queryable_400/db-1:3306").alert
    )

    request = next(
        item for item in strategy.tool_plan if item.tool_name == ARCHERY_SLOW_LOG_TOOL_NAME
    )
    assert request.required is True
    assert request.parameters == {}
    assert strategy.strategy_id == "database-excessive-slow-query-v1"
    assert all(item.tool_name != ARCHERY_SLOW_LOG_TOOL_NAME for item in other.tool_plan)


def _settings(tmp_path: Path, *, real_model: bool = False) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    mcp_settings_path = tmp_path / "mcp" / "settings.json"
    mcp_settings_path.parent.mkdir()
    mcp_settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "archery": {
                        "url": "${ARCHERY_MCP_URL}",
                        "headers": {
                            "X-Archery-Token": "${ARCHERY_MCP_TOKEN}",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return Settings(
        _env_file=None,
        ai_provider="openai_compatible" if real_model else "fake",
        ai_api_key="test-model-key" if real_model else "",
        ai_model="test-tool-model" if real_model else "",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=runbooks,
        mcp_settings_path=mcp_settings_path,
        archery_mcp_url="https://archery.example.test/mcp",
        archery_mcp_token="test-archery-token",
    )


@pytest.mark.asyncio
async def test_factory_registers_only_model_capable_archery_tool(tmp_path: Path) -> None:
    settings = _settings(tmp_path, real_model=True).model_copy(
        update={
            "archery_mcp_max_agent_steps": 18,
            "tool_max_result_chars": 4321,
        }
    )
    runtime = build_runtime(settings)

    tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)

    assert isinstance(tool, ArcherySlowLogEvidenceTool)
    assert tool.client.instance_ref == ""
    assert tool.client.db_name == ""
    assert tool.client.window_seconds == 300
    assert tool.client.max_agent_steps == 18
    assert tool.max_evidence_chars == 4321

    apply_runtime_settings(
        runtime,
        settings.model_copy(
            update={
                "archery_mcp_max_agent_steps": 24,
                "tool_max_result_chars": 5432,
            }
        ),
    )
    updated_tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)
    assert isinstance(updated_tool, ArcherySlowLogEvidenceTool)
    assert updated_tool.client.max_agent_steps == 24
    assert updated_tool.max_evidence_chars == 5432

    apply_runtime_settings(
        runtime,
        settings.model_copy(
            update={
                "ai_provider": "fake",
                "ai_api_key": "",
                "ai_model": "",
            }
        ),
    )

    assert runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME) is None
    await runtime.service.close()


@pytest.mark.asyncio
async def test_slow_query_result_is_persisted_as_live_agent_evidence(
    tmp_path: Path,
) -> None:
    client = RecordingArcheryClient()
    runtime = build_runtime(
        _settings(tmp_path),
        tool_registry=InvestigationToolRegistry(
            [
                AlertContextTool(),
                ArcherySlowLogEvidenceTool(client),  # type: ignore[arg-type]
            ]
        ),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "slow-query-live-evidence-1",
            "severity": "WARNING",
            "title": "MySQL/mysql_slow_query_400/db-1:3306",
            "reason": "mysql_slow_query_400",
            "alert_type": "mysql_slow_query_400",
            "occurred_at": TEST_ALERT_OCCURRED_AT.isoformat(),
            "database": {
                "engine": "mysql",
                "instance": "db-1:3306",
                "database": TEST_DB_NAME,
                "host": "db-1",
            },
        },
    )

    evidence = next(
        item for item in result.evidence_records if item.tool_name == ARCHERY_SLOW_LOG_TOOL_NAME
    )
    assert client.calls == 1
    assert evidence.status == ToolStatus.NO_DATA
    assert evidence.source_system == "archery_mcp"
    assert evidence.request == {}
    assert evidence.structured_data["reported_row_count"] == 0
    assert evidence.structured_data["included_row_count"] == 0
    assert evidence.structured_data["rows"] == []
    assert evidence.structured_data["actual_sql_verified"] is True
    assert evidence.structured_data["target"]["instance_id"] == TEST_INSTANCE_ID
    assert evidence.structured_data["query_window"]["start"] == (
        TEST_WINDOW_START.isoformat()
    )
    assert evidence.structured_data["root_cause_eligible"] is False
    assert result.recommendation is not None
    assert result.recommendation.summary == "现有结果无法得出根因"
    assert result.recommendation.root_causes == []
    assert result.recommendation.likely_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]
