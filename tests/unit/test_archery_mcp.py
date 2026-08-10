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
    ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
    ARCHERY_SLOW_LOG_PROMPT_VERSION,
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


@pytest.mark.asyncio
async def test_archery_mcp_executes_alert_window_query_and_parses_sse_result() -> None:
    calls: list[tuple[str, dict[str, Any], dict[str, str]]] = []
    model = PromptFollowingMCPModel()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Archery-Token"] == "test-archery-token"
        assert "Authorization" not in request.headers
        if request.method == "DELETE":
            assert request.headers["Mcp-Session-Id"] == "session-1"
            calls.append(("DELETE", {}, dict(request.headers)))
            return httpx.Response(200, request=request)

        body = json.loads(request.content)
        method = body["method"]
        calls.append((method, body, dict(request.headers)))
        if method == "initialize":
            assert "Mcp-Session-Id" not in request.headers
            return _json_response(
                request,
                body["id"],
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "archery", "version": "1"},
                },
                headers={"Mcp-Session-Id": "session-1"},
            )
        assert request.headers["Mcp-Session-Id"] == "session-1"
        assert request.headers["MCP-Protocol-Version"] == "2025-06-18"
        if method == "notifications/initialized":
            return httpx.Response(202, request=request)
        if method == "tools/list":
            return _json_response(
                request,
                body["id"],
                {
                    "tools": [
                        *_read_only_tool_schemas(),
                        _tool_schema(
                            "apply_query_permission_gymJPA",
                            "instance_id",
                            "db_name",
                        ),
                    ]
                },
            )
        if method == "tools/call":
            tool_name = body["params"]["name"]
            expected_arguments = model.calls[-1]["arguments"] if model.calls else {}
            assert body["params"]["arguments"] == expected_arguments
            if tool_name != ARCHERY_MCP_QUERY_TOOL_NAME:
                payloads = {
                    ARCHERY_MCP_LOGIN_TOOL_NAME: {
                        "status": "ok",
                        "username": "test-user",
                    },
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
                    ARCHERY_MCP_TABLES_TOOL_NAME: {
                        "status": "ok",
                        "results": [{"name": ARCHERY_SLOW_LOG_TABLE}],
                    },
                    ARCHERY_MCP_COLUMNS_TOOL_NAME: {
                        "status": "ok",
                        "results": [
                            {"name": "f_id"},
                            {"name": TEST_TIME_COLUMN},
                        ],
                    },
                }
                return _json_response(
                    request,
                    body["id"],
                    {
                        "structuredContent": payloads[tool_name],
                        "content": [],
                        "isError": False,
                    },
                )
            message = {
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "ok",
                                    "columns": ["id", "sql_text"],
                                    "rows": [[1, "select 1"]],
                                    "rowCount": 1,
                                }
                            ),
                        }
                    ],
                    "isError": False,
                },
            }
            return httpx.Response(
                200,
                headers={"Content-Type": "text/event-stream"},
                text=f"event: message\ndata: {json.dumps(message)}\n\n",
                request=request,
            )
        raise AssertionError(method)

    client = _client(httpx.MockTransport(handler), model=model)

    alert_context = {
        "title": "MySQL/mysql_slow_query_400/db-prod-01:3306",
        "instance_candidates": ["db-prod-01:3306"],
        "database_candidates": [TEST_DB_NAME],
    }
    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context=alert_context,
    )

    assert result.payload["rows"] == [[1, "select 1"]]
    assert result.payload["rowCount"] == 1
    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert result.window_start == TEST_WINDOW_START
    assert result.window_end == TEST_WINDOW_END
    assert result.model_tool_calls == DEFAULT_MODEL_TOOL_SEQUENCE
    assert result.model_request_ids == tuple(
        f"model-request-{index}" for index in range(1, len(DEFAULT_MODEL_TOOL_SEQUENCE) + 1)
    )
    assert [item["name"] for item in model.calls] == list(DEFAULT_MODEL_TOOL_SEQUENCE)
    assert model.calls[0]["messages"][-1]["role"] == "user"
    assert "archery_login_confirmed" in model.calls[0]["messages"][-1]["content"]
    exposed_tool_names = {
        item["function"]["name"] for item in model.calls[0]["tools"]
    }
    assert "apply_query_permission_gymJPA" not in exposed_tool_names
    task_prompt = model.calls[0]["messages"][1]["content"]
    assert "Host 登录不计入以下预算" in task_prompt
    assert "https://archery.example.test/mcp" in task_prompt
    assert "db-prod-01:3306" in task_prompt
    assert TEST_DB_NAME in task_prompt
    assert "最终查询必须使用MCP返回的真实整数instance_id和数据库名" in task_prompt
    assert "结合MCP实时返回补齐必要的目标标识" in task_prompt
    assert "必须按以下链路定位 hostname_max" in task_prompt
    assert "f_ip = alert_host and f_port = alert_port" in task_prompt
    assert "t_instance_member" in task_prompt
    assert "f_instance_id" in task_prompt
    assert "sql_instance.id" in task_prompt
    assert "mysql_slow_query_review_history" in task_prompt
    assert "hostname_max" in task_prompt
    assert "严格组合为host:port" in task_prompt
    assert "避免为了验证host反复枚举或校验无关实例" in task_prompt
    assert "三张表都在该实例和数据库中" in task_prompt
    assert "若 history 表的必经解析链路走不通" in task_prompt
    assert "MCP返回的错误在其它慢日志表或只读探针中选择合理替代路径" in task_prompt
    assert "12次远端调用预算" in task_prompt
    assert "被Host拒绝的调用不消耗远端预算" in task_prompt
    assert (
        "表名可来自list_db_tables、元数据查询或推荐线索"
        in (model.calls[0]["messages"][0]["content"])
    )
    assert "list_table_columns读取真实字段" in task_prompt
    assert ARCHERY_SLOW_LOG_TABLE not in task_prompt
    assert "之前5分钟" in task_prompt
    assert "LIMIT数值不得超过20" in task_prompt
    assert "limit_num也不得超过20" in task_prompt
    assert "hostname_max等值条件和告警时间范围条件" in task_prompt
    assert "缺少其中任一条件的成功查询只算辅助探针" in task_prompt
    assert "无WHERE的LIMIT 1样例" in task_prompt
    assert TEST_WINDOW_START.isoformat() in task_prompt
    assert TEST_WINDOW_END.isoformat() in task_prompt
    assert "依据list_table_columns返回的真实字段名和类型" in task_prompt
    assert "ts_min < 窗口结束且ts_max >= 窗口开始" in task_prompt
    assert "对于DATETIME或TIMESTAMP字段" in task_prompt
    assert "分钟级窗口优先使用f_insert_time" in task_prompt
    assert "窗口起始Unix秒为1784793300、结束Unix秒为1784793600" in task_prompt
    assert "不要自行换算或修改这两个Unix秒" in task_prompt
    assert "不要直接去掉ISO时间的时区偏移" in task_prompt
    assert model.calls[1]["messages"][-1]["role"] == "tool"
    assert "实时证据" in model.calls[1]["messages"][-1]["content"]
    assert exposed_tool_names == set(DEFAULT_MODEL_TOOL_SEQUENCE)
    assert ARCHERY_MCP_LOGIN_TOOL_NAME not in exposed_tool_names
    query_arguments = model.calls[-1]["arguments"]
    assert query_arguments["instance_id"] == TEST_INSTANCE_ID
    assert "instance_ref" not in query_arguments
    assert result.db_name == TEST_DB_NAME
    assert result.table_name == ARCHERY_SLOW_LOG_TABLE
    assert [item[0] for item in calls] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
        "tools/call",
        "tools/call",
        "tools/call",
        "tools/call",
        "tools/call",
        "tools/call",
        "DELETE",
    ]
    assert (
        sum(
            body.get("params", {}).get("name") == ARCHERY_MCP_LOGIN_TOOL_NAME
            for method, body, _headers in calls
            if method == "tools/call"
        )
        == 1
    )


@pytest.mark.asyncio
async def test_archery_mcp_sends_query_when_server_schema_omits_host_requirements() -> None:
    tool_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            return httpx.Response(200, request=request)
        body = json.loads(request.content)
        if body["method"] == "initialize":
            return _json_response(
                request,
                body["id"],
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "archery", "version": "1"},
                },
                headers={"Mcp-Session-Id": "session-2"},
            )
        if body["method"] == "notifications/initialized":
            return httpx.Response(202, request=request)
        if body["method"] == "tools/list":
            return _json_response(
                request,
                body["id"],
                {"tools": _read_only_tool_schemas(query_properties=("sql_content",))},
            )
        if body["method"] == "tools/call":
            tool_calls.append(body["params"])
            return _json_response(
                request,
                body["id"],
                {
                    "structuredContent": {"status": "ok", "rows": []},
                    "content": [],
                    "isError": False,
                },
            )
        raise AssertionError(body["method"])

    client = _client(httpx.MockTransport(handler))

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert tool_calls[-1]["name"] == ARCHERY_MCP_QUERY_TOOL_NAME


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
async def test_archery_mcp_does_not_require_table_discovery_before_slow_log_query() -> None:
    tool_calls: list[str] = []
    sequence = (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    model = PromptFollowingMCPModel(sequence=sequence)
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
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == {"status": "ok", "rows": []}
    assert [item["name"] for item in model.calls] == [
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]


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
async def test_archery_mcp_allows_recovery_after_empty_table_search() -> None:
    tool_calls: list[str] = []
    sequence = (
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_DATABASES_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    model = PromptFollowingMCPModel(sequence=sequence)
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
            tables_payload={"status": "ok", "results": []},
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == {"status": "ok", "rows": []}
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *sequence]


@pytest.mark.asyncio
async def test_archery_mcp_returns_metadata_business_error_to_model_and_recovers() -> None:
    tool_calls: list[str] = []
    error_detail = "表目录服务暂时不可用，请稍后重试"
    sequence = (
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    model = PromptFollowingMCPModel(sequence=sequence)
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            tables_payload={"status": "failed", "message": error_detail},
            query_result={
                "structuredContent": {"status": "ok", "rows": [[1]]},
                "isError": False,
            },
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert result.payload["rows"] == [[1]]
    assert result.model_tool_calls == sequence
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *sequence]
    assert any(
        error_detail in (message.get("content") or "")
        for message in model.calls[-1]["messages"]
    )


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
async def test_archery_mcp_retries_model_selection_once_without_repeating_login() -> None:
    tool_calls: list[str] = []
    delegate = PromptFollowingMCPModel(sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,))

    class FlakyModel:
        def __init__(self) -> None:
            self.attempts = 0
            self.messages: list[list[dict[str, Any]]] = []

        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.attempts += 1
            self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
            if self.attempts == 1:
                raise RuntimeError("temporary model selection failure")
            return await delegate.request_mcp_tool_call(messages=messages, tools=tools)

    model = FlakyModel()
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok", "rows": []}, "isError": False},
            tool_calls=tool_calls,
        ),
        model=model,  # type: ignore[arg-type]
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert model.attempts == 2
    repair = json.loads(model.messages[1][-1]["content"])
    assert repair["host_event"] == "model_tool_selection_retry"
    assert repair["previous_error_type"] == "ArcheryMCPModelError"
    assert repair["remaining_model_tool_calls"] == 2
    assert repair["host_login_counts_toward_budget"] is False
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME]


@pytest.mark.asyncio
async def test_archery_mcp_preserves_last_budgeted_call_for_query_error_recovery() -> None:
    """Host login must not make a model stop one call before its configured limit."""

    tool_calls: list[str] = []
    failed_sql = (
        "SELECT hostname_max, missing_column FROM mysql_slow_query_review_history "
        "WHERE hostname_max = 'db-1:3306' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    final_sql = (
        "SELECT hostname_max, sample, ts_min FROM mysql_slow_query_review_history "
        "WHERE hostname_max = 'db-1:3306' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )

    class BudgetAwareModel(PromptFollowingMCPModel):
        def __init__(self) -> None:
            super().__init__(
                sequence=(ARCHERY_MCP_QUERY_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME),
                query_sqls=(failed_sql, final_sql),
            )
            self.visible_tool_call_counts: list[int] = []

        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            visible_calls = sum(
                len(message.get("tool_calls") or [])
                for message in messages
                if message.get("role") == "assistant"
            )
            self.visible_tool_call_counts.append(visible_calls)
            if visible_calls >= 2:
                raise RuntimeError("model stopped because the visible budget was exhausted")
            return await super().request_mcp_tool_call(messages=messages, tools=tools)

    model = BudgetAwareModel()
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "status": "failed",
                        "message": "Unknown column 'missing_column' in field list",
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "status": "ok",
                        "columns": ["hostname_max", "sample", "ts_min"],
                        "rows": [["db-1:3306", "select 1", "2026-07-23T08:00:00"]],
                    },
                    "isError": False,
                },
            ],
            tool_calls=tool_calls,
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert result.requested_sql == final_sql
    assert model.visible_tool_call_counts == [0, 1]
    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    retry_feedback = model.calls[-1]["messages"][-1]["content"]
    assert "剩余1次" in retry_feedback
    assert "Host登录和未通过Host校验的调用不计入该预算" in retry_feedback
    assert result.diagnostics is not None
    assert result.diagnostics["query_trace"][0]["outcome"] == "tool_error"
    assert "Unknown column" in result.diagnostics["query_trace"][0]["error_detail"]


@pytest.mark.asyncio
async def test_archery_mcp_host_rejection_does_not_consume_remote_call_budget() -> None:
    tool_calls: list[str] = []
    query_sql_calls: list[str] = []

    class RejectedThenValidModel(PromptFollowingMCPModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            call = await super().request_mcp_tool_call(messages=messages, tools=tools)
            if len(self.calls) != 1:
                return call
            arguments = {**call.arguments, "sql_content": "SHOW INDEX FROM slow_query"}
            self.calls[-1]["arguments"] = arguments
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments=arguments,
                request_id=call.request_id,
            )

    model = RejectedThenValidModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME),
        query_sqls=(TEST_SLOW_LOG_QUERY, TEST_SLOW_LOG_QUERY),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={
                "structuredContent": {"status": "ok", "rows": [[1]]},
                "isError": False,
            },
            tool_calls=tool_calls,
            query_sql_calls=query_sql_calls,
        ),
        model=model,
        max_agent_steps=1,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert query_sql_calls == [TEST_SLOW_LOG_QUERY]
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME]
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert result.diagnostics is not None
    assert result.diagnostics["model_attempted_tool_calls"] == [
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    assert result.diagnostics["model_decision_count"] == 2
    assert result.diagnostics["mcp_tool_call_count"] == 1
    rejection_feedback = model.calls[-1]["messages"][-1]["content"]
    assert "已实际发送0/1次，剩余1次" in rejection_feedback


@pytest.mark.asyncio
async def test_archery_mcp_bounds_repeated_host_rejections_by_decision_limit() -> None:
    tool_calls: list[str] = []

    class AlwaysRejectedModel(PromptFollowingMCPModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            call = await super().request_mcp_tool_call(messages=messages, tools=tools)
            arguments = {**call.arguments, "sql_content": "SHOW INDEX FROM slow_query"}
            self.calls[-1]["arguments"] = arguments
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments=arguments,
                request_id=call.request_id,
            )

    model = AlwaysRejectedModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,) * 4,
        query_sqls=(TEST_SLOW_LOG_QUERY,),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok"}, "isError": False},
            tool_calls=tool_calls,
        ),
        model=model,
        max_agent_steps=2,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is False
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME]
    assert result.diagnostics is not None
    assert result.diagnostics["model_decision_count"] == 4
    assert result.diagnostics["model_decision_limit"] == 4
    assert result.diagnostics["mcp_tool_call_count"] == 0
    assert "有限决策次数" in result.diagnostics["reason"]


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
    assert "实时证据暂缺" in timeout_feedback
    assert "不能作为任何根因假设的反证" in timeout_feedback
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

    assert ArcheryMCPClient._metadata_resolution_stage(
        **common,
        query_trace=[],
    ) == "等待 history 查询成功"
    assert ArcheryMCPClient._metadata_resolution_stage(
        **common,
        query_trace=[
            {
                "chain_stage": "history",
                "outcome": "tool_error",
                "error_detail": "查询超时被KILL，请优化SQL后执行",
            }
        ],
    ) == "等待优化后的 history 查询"


@pytest.mark.asyncio
async def test_archery_mcp_returns_partial_trace_after_model_retry_is_exhausted() -> None:
    tool_calls: list[str] = []

    class FailingModel:
        def __init__(self) -> None:
            self.attempts = 0

        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.attempts += 1
            raise RuntimeError("model unavailable")

    model = FailingModel()
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok", "rows": []}, "isError": False},
            tool_calls=tool_calls,
        ),
        model=model,  # type: ignore[arg-type]
        max_agent_steps=1,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is False
    assert model.attempts == 2
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME]
    assert result.diagnostics is not None
    assert "连续两次" in result.diagnostics["reason"]


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

    assert ArcheryMCPClient._slow_log_query_completion_issue(unscoped) == (
        "缺少hostname_max等值查询条件；缺少告警时间范围条件"
    )
    assert ArcheryMCPClient._slow_log_query_completion_issue(time_only) == (
        "缺少hostname_max等值查询条件"
    )
    assert ArcheryMCPClient._slow_log_query_completion_issue(host_only) == ("缺少告警时间范围条件")
    assert ArcheryMCPClient._slow_log_query_completion_issue(scoped) is None


def test_archery_mcp_runtime_completion_requires_exact_window_and_bounded_limit() -> None:
    assert (
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
            history_overlap_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        is None
    )
    assert "精确告警时间窗口" in (
        ArcheryMCPClient._slow_log_query_completion_issue(
            history_overlap_window.replace("1784793300", "1784793299"),
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    wrong_window = TEST_SLOW_LOG_QUERY.replace("1784793300", "1784793299")
    assert "精确告警时间窗口" in (
        ArcheryMCPClient._slow_log_query_completion_issue(
            wrong_window,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )

    no_limit = TEST_SLOW_LOG_QUERY.rsplit(" limit 20", 1)[0]
    assert "显式LIMIT" in (
        ArcheryMCPClient._slow_log_query_completion_issue(
            no_limit,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )
    assert "LIMIT必须" in (
        ArcheryMCPClient._slow_log_query_completion_issue(
            TEST_SLOW_LOG_QUERY.replace("limit 20", "limit 21"),
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
        )
        or ""
    )
    assert ArcheryMCPClient._slow_log_query_completion_issue(no_limit) is None

    iso_window = (
        "SELECT * FROM t_slowlog_info "
        "WHERE f_insert_time >= '2026-07-23T07:55:00+00:00' "
        "AND f_insert_time <= '2026-07-23T08:00:00+00:00' "
        "LIMIT 20 OFFSET 0"
    )
    assert (
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
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
        ArcheryMCPClient._slow_log_query_completion_issue(
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
    assert ArcheryMCPClient._query_call_rejection(
        {
            "sql_content": "SELECT 1",
            "limit_num": 20,
            "max_result_chars": ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
        }
    ) is None
    assert "limit_num" in (
        ArcheryMCPClient._query_call_rejection(
            {"sql_content": "SELECT 1", "limit_num": 21}
        )
        or ""
    )
    assert "max_result_chars" in (
        ArcheryMCPClient._query_call_rejection(
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


@pytest.mark.asyncio
async def test_archery_mcp_returns_auxiliary_read_only_sql_to_model() -> None:
    tool_calls: list[str] = []
    sequence = (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    model = PromptFollowingMCPModel(
        sequence=sequence,
        query_sqls=("SELECT NOW() AS server_time", TEST_SLOW_LOG_QUERY),
    )
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result=[
                {
                    "structuredContent": {
                        "rows": [["2026-08-03 14:00:00"]],
                        "column_list": ["server_time"],
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {"status": "ok", "rows": [[1]]},
                    "isError": False,
                },
            ],
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert result.payload["rows"] == [[1]]
    assert result.model_tool_calls == sequence
    assert any(
        "server_time" in (message.get("content") or "") for message in model.calls[-1]["messages"]
    )
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *sequence]


@pytest.mark.asyncio
async def test_archery_mcp_returns_sql_error_to_model_and_allows_retry() -> None:
    tool_calls: list[str] = []
    failed_sql = (
        "SELECT LEFT(f_sql_text, 500) AS f_sql_text_preview "
        "FROM t_slowlog_info ORDER BY f_start_time DESC LIMIT 20"
    )
    sequence = (
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_COLUMNS_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    model = PromptFollowingMCPModel(
        sequence=sequence,
        query_sqls=(failed_sql, TEST_ALTERNATE_SLOW_LOG_QUERY),
    )
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result=[
                {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "SQL 查询失败：{'errors': '(1064, SQL syntax error near FROM)'}"
                            ),
                        }
                    ],
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "rows": [[1]],
                        "column_list": ["f_id"],
                        "affected_rows": 1,
                    },
                    "isError": False,
                },
            ],
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.requested_sql == TEST_ALTERNATE_SLOW_LOG_QUERY
    assert result.payload["rows"] == [[1]]
    assert result.model_tool_calls == sequence
    retry_messages = model.calls[-1]["messages"]
    assert retry_messages[-1]["role"] == "tool"
    assert "1064" in retry_messages[-1]["content"]
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *sequence]


@pytest.mark.asyncio
async def test_archery_mcp_rejects_write_sql_before_mcp_and_allows_model_retry() -> None:
    tool_calls: list[str] = []
    query_sql_calls: list[str] = []

    class TamperingModel(PromptFollowingMCPModel):
        query_calls = 0

        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            call = await super().request_mcp_tool_call(
                messages=messages,
                tools=tools,
            )
            if call.name != ARCHERY_MCP_QUERY_TOOL_NAME:
                return call
            self.query_calls += 1
            if self.query_calls > 1:
                return call
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments={
                    **call.arguments,
                    "sql_content": "delete from t_slowlog_info",
                },
                request_id=call.request_id,
            )

    model = TamperingModel(
        sequence=(*DEFAULT_MODEL_TOOL_SEQUENCE, ARCHERY_MCP_QUERY_TOOL_NAME),
        query_sqls=(TEST_SLOW_LOG_QUERY, TEST_SLOW_LOG_QUERY),
    )
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
            query_sql_calls=query_sql_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.query_completed is True
    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *DEFAULT_MODEL_TOOL_SEQUENCE]
    assert query_sql_calls == [TEST_SLOW_LOG_QUERY]
    assert any(
        "未发送到 MCP" in (message.get("content") or "") for message in model.calls[-1]["messages"]
    )


@pytest.mark.asyncio
async def test_archery_mcp_rejects_business_error_without_mcp_is_error() -> None:
    tool_calls: list[str] = []
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result={
                "structuredContent": {
                    "status": "failed",
                    "message": "您没有执行该 SQL 查询的权限",
                },
                "isError": False,
            },
            tool_calls=tool_calls,
        )
    )

    with pytest.raises(ArcheryMCPToolError, match="没有执行该 SQL 查询的权限"):
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *DEFAULT_MODEL_TOOL_SEQUENCE]


@pytest.mark.asyncio
async def test_archery_mcp_rejects_query_result_that_requests_login() -> None:
    tool_calls: list[str] = []
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {
                    "status": "ok",
                    "username": "test-user",
                },
                "isError": False,
            },
            query_result={
                "structuredContent": {
                    "result": ("需要先登录 Archery（未获取到用户名）。请先调用 ensure_login()。")
                },
                "isError": False,
            },
            tool_calls=tool_calls,
        )
    )

    with pytest.raises(ArcheryMCPToolError, match="需要先登录") as captured:
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert ARCHERY_MCP_LOGIN_TOOL_NAME == "ensure_login_gymJPA"
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *DEFAULT_MODEL_TOOL_SEQUENCE]
    assert captured.value.diagnostic_data["login_tool"] == "ensure_login_gymJPA"
    assert captured.value.diagnostic_data["mcp_client"] == "official_python_sdk"
    assert captured.value.diagnostic_data["mcp_transport"] == "streamable_http"
    assert captured.value.diagnostic_data["mcp_invocation"] == "model_tool_calling"
    assert captured.value.diagnostic_data["prompt_version"] == (ARCHERY_SLOW_LOG_PROMPT_VERSION)
    assert captured.value.diagnostic_data["model_tool_calls"] == list(DEFAULT_MODEL_TOOL_SEQUENCE)
    assert captured.value.diagnostic_data["username_field_present"] is True
    assert captured.value.diagnostic_data["mcp_session_id_present"] is True


@pytest.mark.asyncio
async def test_archery_mcp_accepts_result_without_actual_executed_sql() -> None:
    tool_calls: list[str] = []
    query_payload = {
        "status": "ok",
        "columns": ["f_id"],
        "rows": [[1]],
        "rowCount": 1,
    }
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result={
                "structuredContent": query_payload,
                "content": [
                    {
                        "type": "text",
                        "text": "查询成功",
                    }
                ],
                "isError": False,
            },
            tool_calls=tool_calls,
        )
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == query_payload
    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME, *DEFAULT_MODEL_TOOL_SEQUENCE]


@pytest.mark.asyncio
async def test_archery_mcp_preserves_native_success_payload_without_status_flag() -> None:
    tool_calls: list[str] = []
    query_payload = {
        "full_sql": TEST_ALTERNATE_SLOW_LOG_QUERY,
        "is_execute": False,
        "checked": None,
        "error": None,
        "rows": [[1, "2024-05-14", "ecs"]],
        "column_list": ["f_id", "f_start_time", "f_db"],
        "status": None,
        "affected_rows": 1,
    }
    model = PromptFollowingMCPModel(
        sequence=(
            ARCHERY_MCP_TABLES_TOOL_NAME,
            ARCHERY_MCP_QUERY_TOOL_NAME,
        ),
        query_sqls=(TEST_ALTERNATE_SLOW_LOG_QUERY,),
    )
    client = _client(
        _archery_call_handler(
            login_result={
                "content": [{"type": "text", "text": "Token 认证已就绪。"}],
                "isError": False,
            },
            query_result={
                "structuredContent": query_payload,
                "isError": False,
            },
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == query_payload
    assert result.requested_sql == TEST_ALTERNATE_SLOW_LOG_QUERY
    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]


@pytest.mark.asyncio
async def test_archery_mcp_normalizes_text_wrapped_success_result() -> None:
    tool_calls: list[str] = []
    query_sql = (
        "SELECT f_id, f_instances_id, f_time_point FROM t_slowlog_info "
        "WHERE f_time_point >= FROM_UNIXTIME(1784793300) "
        "AND f_time_point <= FROM_UNIXTIME(1784793600) "
        "ORDER BY f_time_point DESC LIMIT 20"
    )
    full_sql = query_sql.replace("LIMIT 20", "limit 20") + ";"
    query_payload = {
        "full_sql": full_sql,
        "is_execute": False,
        "warning": None,
        "error": None,
        "rows": [],
        "column_list": ["f_id", "f_instances_id", "f_time_point"],
        "status": None,
        "affected_rows": 0,
    }
    wrapped_result = (
        "SQL 查询已执行。\n"
        f"执行的SQL：{query_sql}\n\n"
        "返回 0 行。\n"
        "结果：\n"
        f"{json.dumps(query_payload, ensure_ascii=False, indent=2)}"
    )
    model = PromptFollowingMCPModel(
        sequence=(
            ARCHERY_MCP_TABLES_TOOL_NAME,
            ARCHERY_MCP_QUERY_TOOL_NAME,
        ),
        query_sqls=(query_sql,),
    )
    client = _client(
        _archery_call_handler(
            login_result={
                "content": [{"type": "text", "text": "Token 认证已就绪。"}],
                "isError": False,
            },
            query_result={
                "structuredContent": {"result": wrapped_result},
                "isError": False,
            },
            tool_calls=tool_calls,
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == query_payload
    assert result.requested_sql == query_sql
    assert result.executed_sql == full_sql
    assert result.actual_sql_verified is True
    assert result.instance_id == TEST_INSTANCE_ID
    assert result.query_time_column == "f_time_point"
    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]


@pytest.mark.asyncio
async def test_archery_mcp_merges_text_result_with_structured_status() -> None:
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {"status": "ok"},
                "isError": False,
            },
            query_result={
                "structuredContent": {"status": "ok"},
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "columns": ["f_id"],
                                "rows": [[1]],
                                "rowCount": 1,
                            }
                        ),
                    }
                ],
                "isError": False,
            },
            tool_calls=[],
        )
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == {
        "status": "ok",
        "columns": ["f_id"],
        "rows": [[1]],
        "rowCount": 1,
    }


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
    assert data["sql"] == TEST_SLOW_LOG_QUERY
    assert data["executed_sql"] == TEST_SLOW_LOG_QUERY
    assert data["login_confirmed"] is True
    assert data["login_tool"] == ARCHERY_MCP_LOGIN_TOOL_NAME
    assert data["mcp_invocation"] == "model_tool_calling"
    assert data["prompt_version"] == ARCHERY_SLOW_LOG_PROMPT_VERSION
    assert data["actual_sql_verified"] is True
    assert data["target"] == {
        "selection_basis": "alert_context_and_mcp_discovery",
        "instance_id": TEST_INSTANCE_ID,
        "db_name": TEST_DB_NAME,
        "table_name": ARCHERY_SLOW_LOG_TABLE,
        "alert_context": client.alert_context,
    }
    assert data["query_window"] == {
        "basis": "alert.occurred_at",
        "alert_occurred_at": TEST_ALERT_OCCURRED_AT.isoformat(),
        "start": TEST_WINDOW_START.isoformat(),
        "end": TEST_WINDOW_END.isoformat(),
        "duration_seconds": 300,
        "time_column": TEST_TIME_COLUMN,
    }
    assert data["scope"] == "alert_target_slow_log_snapshot"
    assert data["result_bounds"]["truncation_possible"] is False
    assert data["root_cause_eligible"] is False
    assert "实际执行 SQL 未核对" not in data["root_cause_ineligible_reason"]
    assert "可能截断" not in data["root_cause_ineligible_reason"]
    assert data["result"]["rows"] == []

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
async def test_archery_evidence_reconnects_once_after_protocol_failure() -> None:
    client = FlakyRecordingArcheryClient()
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
    assert client.calls == 2
    assert outcome.structured_data["mcp_session_attempts"] == 2
    assert (
        outcome.structured_data["reconnect_error_type"]
        == ArcheryMCPProtocolError.__name__
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
        update={"archery_mcp_max_agent_steps": 18}
    )
    runtime = build_runtime(settings)

    tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)

    assert isinstance(tool, ArcherySlowLogEvidenceTool)
    assert tool.client.instance_ref == ""
    assert tool.client.db_name == ""
    assert tool.client.window_seconds == 300
    assert tool.client.max_agent_steps == 18

    apply_runtime_settings(
        runtime,
        settings.model_copy(update={"archery_mcp_max_agent_steps": 24}),
    )
    updated_tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)
    assert isinstance(updated_tool, ArcherySlowLogEvidenceTool)
    assert updated_tool.client.max_agent_steps == 24

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
    assert evidence.structured_data["result"]["affected_rows"] == 0
    assert evidence.structured_data["login_confirmed"] is True
    assert evidence.structured_data["sql"] == TEST_SLOW_LOG_QUERY
    assert evidence.structured_data["actual_sql_verified"] is True
    assert evidence.structured_data["target"]["instance_id"] == TEST_INSTANCE_ID
    assert evidence.structured_data["query_window"]["basis"] == "alert.occurred_at"
    assert evidence.structured_data["root_cause_eligible"] is False
    assert result.recommendation is not None
    assert result.recommendation.root_causes[0].status.value == "UNKNOWN"
    assert str(evidence.id) not in result.recommendation.root_causes[0].evidence_refs
    await runtime.repository.close()  # type: ignore[attr-defined]
