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
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
    ARCHERY_SLOW_LOG_PROMPT_VERSION,
    ARCHERY_SLOW_LOG_TABLE,
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ArcheryMCPClient,
    ArcheryMCPConfigurationError,
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
from app.domain.models import InvestigationContext, InvestigationStrategy, ToolExecutionRequest
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
    "order by `f_insert_time` desc"
)
TEST_ALTERNATE_SLOW_LOG_QUERY = (
    "SELECT f_id, f_start_time, f_db, f_user, f_insert_time "
    "FROM t_slowlog_info ORDER BY f_start_time DESC LIMIT 5"
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
                item: {
                    "type": "integer" if item in integer_properties else "string"
                }
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
    ARCHERY_MCP_LOGIN_TOOL_NAME,
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
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.sequence = sequence
        self.query_sqls = query_sqls

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        name = self.sequence[len(self.calls)]
        available_names = {item["function"]["name"] for item in tools}
        assert name in available_names
        query_index = sum(
            item["name"] == ARCHERY_MCP_QUERY_TOOL_NAME for item in self.calls
        )
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
                "keyword": ARCHERY_SLOW_LOG_TABLE,
                "size": 200,
            },
            ARCHERY_MCP_COLUMNS_TOOL_NAME: {
                "instance_id": TEST_INSTANCE_ID,
                "db_name": TEST_DB_NAME,
                "tb_name": ARCHERY_SLOW_LOG_TABLE,
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
) -> ArcheryMCPClient:
    return ArcheryMCPClient(
        MCPServerSettings(
            url="https://archery.example.test/mcp",
            headers={"X-Archery-Token": "test-archery-token"},
        ),
        model or PromptFollowingMCPModel(),
        instance_ref=TEST_INSTANCE_REF,
        db_name=TEST_DB_NAME,
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


def test_archery_discovery_arguments_are_delegated_to_mcp_schema() -> None:
    client = _client(
        httpx.MockTransport(lambda request: httpx.Response(500, request=request))
    )
    for arguments in (
        {},
        {"resource_group_id": TEST_RESOURCE_GROUP_ID},
        {"instance_ref": ""},
        {"instance_ref": TEST_INSTANCE_REF},
        {"instance_ref": "another-instance"},
        {"instance_ref": {"server_specific": True}},
    ):
        client._validate_model_tool_call(
            MCPModelToolCall(
                call_id="discovery-call",
                name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
                arguments=arguments,
            ),
            login_confirmed=True,
        )


def test_archery_query_accepts_instance_id_or_configured_reference() -> None:
    client = _client(
        httpx.MockTransport(lambda request: httpx.Response(500, request=request))
    )
    for identity in (
        {"instance_id": str(TEST_INSTANCE_ID)},
        {"instance_ref": TEST_INSTANCE_REF},
    ):
        call = client._normalize_model_tool_call(
            MCPModelToolCall(
                call_id="query-call",
                name=ARCHERY_MCP_QUERY_TOOL_NAME,
                arguments={
                    **identity,
                    "db_name": TEST_DB_NAME,
                    "sql_content": TEST_ALTERNATE_SLOW_LOG_QUERY,
                },
            )
        )
        assert call.arguments["limit_num"] == 20
        assert call.arguments["max_result_chars"] == 24_000
        client._validate_model_tool_call(
            call,
            login_confirmed=True,
        )


def test_archery_normalizes_numeric_instance_id_without_tracking_discovery() -> None:
    client = _client(
        httpx.MockTransport(lambda request: httpx.Response(500, request=request))
    )
    for arguments in (
        {"instance_id": str(TEST_INSTANCE_ID), "page": 1},
        {
            "instance_id": TEST_INSTANCE_ID,
            "instance_ref": TEST_INSTANCE_REF,
            "page": 1,
        },
    ):
        normalized = client._normalize_model_tool_call(
            MCPModelToolCall(
                call_id="database-discovery",
                name=ARCHERY_MCP_DATABASES_TOOL_NAME,
                arguments=arguments,
            )
        )

        assert normalized.arguments == {
            "instance_id": TEST_INSTANCE_ID,
            "page": 1,
        }
        client._validate_model_tool_call(
            normalized,
            login_confirmed=True,
        )


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
                {"tools": _read_only_tool_schemas()},
            )
        if method == "tools/call":
            tool_name = body["params"]["name"]
            assert body["params"]["arguments"] == model.calls[-1]["arguments"]
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
                        "results": [
                            {"id": TEST_INSTANCE_ID, "name": TEST_INSTANCE_REF}
                        ],
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

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload["rows"] == [[1, "select 1"]]
    assert result.payload["rowCount"] == 1
    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert result.window_start == TEST_WINDOW_START
    assert result.window_end == TEST_WINDOW_END
    assert result.model_tool_calls == DEFAULT_MODEL_TOOL_SEQUENCE
    assert result.model_request_ids == tuple(
        f"model-request-{index}"
        for index in range(1, len(DEFAULT_MODEL_TOOL_SEQUENCE) + 1)
    )
    assert [item["name"] for item in model.calls] == list(
        DEFAULT_MODEL_TOOL_SEQUENCE
    )
    task_prompt = model.calls[0]["messages"][1]["content"]
    assert "https://archery.example.test/mcp" in task_prompt
    assert f"实例：{TEST_INSTANCE_REF}" in task_prompt
    assert f"数据库id：{TEST_DB_NAME}" in task_prompt
    assert ARCHERY_SLOW_LOG_TABLE in task_prompt
    assert "之前5分钟" in task_prompt
    assert "最多20条" in task_prompt
    assert TEST_WINDOW_START.isoformat() in task_prompt
    assert TEST_WINDOW_END.isoformat() in task_prompt
    assert "f_start_time是只含YYYY-MM-DD的varchar(10)" in task_prompt
    assert "分钟级时间窗口请使用f_insert_time筛选和排序" in task_prompt
    assert "不要用f_start_time或f_time_point与完整时间戳比较" in task_prompt
    assert "FROM_UNIXTIME(Unix秒)" in task_prompt
    assert "不要直接去掉ISO时间的时区偏移" in task_prompt
    assert model.calls[1]["messages"][-1]["role"] == "tool"
    assert "实时证据" in model.calls[1]["messages"][-1]["content"]
    assert {
        item["function"]["name"] for item in model.calls[0]["tools"]
    } == set(DEFAULT_MODEL_TOOL_SEQUENCE)
    assert all(
        item["function"]["name"] != "apply_query_permission_gymJPA"
        for item in model.calls[0]["tools"]
    )
    query_arguments = model.calls[-1]["arguments"]
    assert query_arguments["instance_id"] == TEST_INSTANCE_ID
    assert "instance_ref" not in query_arguments
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


@pytest.mark.asyncio
async def test_archery_mcp_rejects_query_tool_without_required_arguments() -> None:
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
                {
                    "tools": _read_only_tool_schemas(
                        query_properties=("sql_content",)
                    )
                },
            )
        if body["method"] == "tools/call":
            tool_calls.append(body["params"])
            raise AssertionError("tools/call must not run for an incompatible schema")
        raise AssertionError(body["method"])

    client = _client(httpx.MockTransport(handler))

    with pytest.raises(
        ArcheryMCPConfigurationError,
        match="instance_id or instance_ref",
    ):
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == []


def _archery_call_handler(
    *,
    login_result: dict[str, Any],
    query_result: dict[str, Any] | list[dict[str, Any]],
    tool_calls: list[str],
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
                    "results": [
                        {"id": TEST_INSTANCE_ID, "name": TEST_INSTANCE_REF}
                    ],
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
            if tool_name == ARCHERY_MCP_LOGIN_TOOL_NAME:
                result = login_result
            elif tool_name == ARCHERY_MCP_QUERY_TOOL_NAME:
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
async def test_archery_mcp_allows_query_after_login_without_host_discovery_tracking() -> None:
    tool_calls: list[str] = []
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_LOGIN_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME)
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
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload == {"status": "ok", "rows": []}
    assert [item["name"] for item in model.calls] == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]


@pytest.mark.asyncio
async def test_archery_mcp_returns_sql_error_to_model_and_allows_retry() -> None:
    tool_calls: list[str] = []
    failed_sql = (
        "SELECT LEFT(f_sql_text, 500) AS f_sql_text_preview "
        "FROM t_slowlog_info ORDER BY f_start_time DESC LIMIT 20"
    )
    sequence = (
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
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
                                "SQL 查询失败：{'errors': "
                                "'(1064, SQL syntax error near FROM)'}"
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
    assert tool_calls == list(sequence)


@pytest.mark.asyncio
async def test_archery_mcp_rejects_non_select_sql_before_query_tool_call() -> None:
    tool_calls: list[str] = []

    class TamperingModel(PromptFollowingMCPModel):
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
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments={
                    **call.arguments,
                    "sql_content": "delete from t_slowlog_info",
                },
                request_id=call.request_id,
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
        ),
        model=TamperingModel(),
    )

    with pytest.raises(ArcheryMCPReadOnlyViolation, match="outside the approved"):
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == list(DEFAULT_MODEL_TOOL_SEQUENCE[:-1])


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

    assert tool_calls == list(DEFAULT_MODEL_TOOL_SEQUENCE)


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
                    "result": (
                        "需要先登录 Archery（未获取到用户名）。"
                        "请先调用 ensure_login()。"
                    )
                },
                "isError": False,
            },
            tool_calls=tool_calls,
        )
    )

    with pytest.raises(ArcheryMCPToolError, match="需要先登录") as captured:
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert ARCHERY_MCP_LOGIN_TOOL_NAME == "ensure_login_gymJPA"
    assert tool_calls == list(DEFAULT_MODEL_TOOL_SEQUENCE)
    assert captured.value.diagnostic_data["login_tool"] == "ensure_login_gymJPA"
    assert captured.value.diagnostic_data["mcp_client"] == "official_python_sdk"
    assert captured.value.diagnostic_data["mcp_transport"] == "streamable_http"
    assert captured.value.diagnostic_data["mcp_invocation"] == "model_tool_calling"
    assert captured.value.diagnostic_data["prompt_version"] == (
        ARCHERY_SLOW_LOG_PROMPT_VERSION
    )
    assert captured.value.diagnostic_data["model_tool_calls"] == list(
        DEFAULT_MODEL_TOOL_SEQUENCE
    )
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
    assert tool_calls == list(DEFAULT_MODEL_TOOL_SEQUENCE)


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
        sequence=(ARCHERY_MCP_LOGIN_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME),
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
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]


@pytest.mark.asyncio
async def test_archery_mcp_normalizes_text_wrapped_success_result() -> None:
    tool_calls: list[str] = []
    query_sql = (
        "SELECT f_id, f_instances_id, f_time_point FROM t_slowlog_info "
        "WHERE f_time_point >= '2026-08-03 02:06:57' "
        "AND f_time_point <= '2026-08-03 02:11:57' "
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
        sequence=(ARCHERY_MCP_LOGIN_TOOL_NAME, ARCHERY_MCP_QUERY_TOOL_NAME),
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
    instance_ref = TEST_INSTANCE_REF
    db_name = TEST_DB_NAME
    slow_log_time_column = TEST_TIME_COLUMN
    window_seconds = 300

    def __init__(self) -> None:
        self.calls = 0
        self.occurred_at: datetime | None = None

    async def execute_slow_log_query(
        self, occurred_at: datetime
    ) -> ArcherySlowLogQueryResult:
        self.calls += 1
        self.occurred_at = occurred_at
        return ArcherySlowLogQueryResult(
            payload={"status": "ok", "rows": [], "affected_rows": 0},
            requested_sql=TEST_SLOW_LOG_QUERY,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
            executed_sql=TEST_SLOW_LOG_QUERY,
            actual_sql_verified=True,
            instance_id=TEST_INSTANCE_ID,
            query_time_column=TEST_TIME_COLUMN,
        )


def _context(alert_type: str, *, title: str = "Database alert") -> InvestigationContext:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": f"archery-{alert_type}",
            "severity": "WARNING",
            "title": title,
            "reason": alert_type,
            "alert_type": alert_type,
            "occurred_at": TEST_ALERT_OCCURRED_AT.isoformat(),
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

    summary, data = await tool.execute(
        ToolExecutionRequest(
            tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
        ),
        _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306"),
    )

    assert client.calls == 1
    assert client.occurred_at == TEST_ALERT_OCCURRED_AT
    assert "返回 0 行" in summary
    assert f"实例 ID {TEST_INSTANCE_ID}" in summary
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
        "instance_ref": TEST_INSTANCE_REF,
        "instance_id": TEST_INSTANCE_ID,
        "db_name": TEST_DB_NAME,
    }
    assert data["query_window"] == {
        "basis": "alert.occurred_at",
        "alert_occurred_at": TEST_ALERT_OCCURRED_AT.isoformat(),
        "start": TEST_WINDOW_START.isoformat(),
        "end": TEST_WINDOW_END.isoformat(),
        "duration_seconds": 300,
        "time_column": TEST_TIME_COLUMN,
    }
    assert data["scope"] == "requested_alert_time_window_global_slow_log_snapshot"
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
async def test_strategy_requires_archery_evidence_only_for_slow_query_title_identifier() -> None:
    provider = DefaultInvestigationStrategyProvider(
        available_tools=["alert_context"]
    )

    strategy = await provider.select(
        _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306").alert
    )
    other = await provider.select(
        _context("慢查询过多", title="MySQL/mysql_slow_queryable_400/db-1:3306").alert
    )

    request = next(
        item
        for item in strategy.tool_plan
        if item.tool_name == ARCHERY_SLOW_LOG_TOOL_NAME
    )
    assert request.required is True
    assert request.parameters == {}
    assert strategy.strategy_id == "database-excessive-slow-query-v1"
    assert all(
        item.tool_name != ARCHERY_SLOW_LOG_TOOL_NAME for item in other.tool_plan
    )


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
        archery_mcp_instance_ref=TEST_INSTANCE_REF,
        archery_mcp_db_name=TEST_DB_NAME,
    )


@pytest.mark.asyncio
async def test_factory_registers_only_model_capable_archery_tool(tmp_path: Path) -> None:
    settings = _settings(tmp_path, real_model=True)
    runtime = build_runtime(settings)

    tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)

    assert isinstance(tool, ArcherySlowLogEvidenceTool)
    assert tool.client.instance_ref == TEST_INSTANCE_REF
    assert tool.client.db_name == TEST_DB_NAME
    assert tool.client.window_seconds == 300

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
        },
    )

    evidence = next(
        item
        for item in result.evidence_records
        if item.tool_name == ARCHERY_SLOW_LOG_TOOL_NAME
    )
    assert client.calls == 1
    assert evidence.status.value == "SUCCESS"
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
