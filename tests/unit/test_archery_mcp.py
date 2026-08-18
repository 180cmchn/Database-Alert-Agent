from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_LOG_EVIDENCE_SCHEMA_VERSION,
    ARCHERY_SLOW_LOG_TABLE,
    ARCHERY_SLOW_LOG_TABLE_SEARCH_KEYWORD,
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPClient,
    ArcheryMCPProtocolError,
    ArcherySlowLogEvidenceTool,
    ArcherySlowLogQueryResult,
    MCPServerSettings,
    load_mcp_server_settings,
)
from app.adapters.investigation import (
    AlertContextTool,
    InvestigationToolRegistry,
    ToolExecutor,
)
from app.application.factory import apply_runtime_settings, build_runtime
from app.config import Settings
from app.domain.models import (
    AdvisorMetadata,
    InvestigationContext,
    InvestigationDecision,
    InvestigationDecisionResult,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import MCPPromptBundle, load_mcp_catalog

TEST_INSTANCE_REF = "archery-metadata"
ARCHERY_MCP_LOGIN_TOOL_NAME = "ensure_login_gymJPA"
ARCHERY_MCP_QUERY_TOOL_NAME = "sql_query_gymJPA"
TEST_INSTANCE_ID = 226
TEST_RESOURCE_GROUP_ID = 10
TEST_DB_NAME = "archery_data"
TEST_TIME_COLUMN = "f_insert_time"
TEST_ALERT_OCCURRED_AT = datetime.fromisoformat("2026-07-23T16:00:00+08:00")
TEST_WINDOW_START = datetime(2026, 7, 23, 7, 55, tzinfo=UTC)
TEST_WINDOW_END = datetime(2026, 7, 23, 8, 0, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARCHERY_PROMPTS = load_mcp_catalog(
    PROJECT_ROOT / "config/mcp/settings.json"
).require("archery").prompts
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
FINISH_TOOL_NAME = "finish_archery_investigation"


def _write_prompt_files(
    directory: Path,
    server_name: str,
    prompts: MCPPromptBundle = ARCHERY_PROMPTS,
) -> dict[str, str]:
    prompt_directory = directory / "prompts" / server_name
    prompt_directory.mkdir(parents=True, exist_ok=True)
    references: dict[str, str] = {}
    for prompt_name in ("role", "purpose", "workflow", "safety"):
        path = prompt_directory / f"{prompt_name}.md"
        path.write_text(getattr(prompts, prompt_name), encoding="utf-8")
        references[prompt_name] = str(path.relative_to(directory))
    return references


def _tool_schema(name: str, *properties: str) -> dict[str, Any]:
    integer_properties = {
        "resource_group_id",
        "instance_id",
        "page",
        "size",
        "limit_num",
    }
    return {
        "name": name,
        "description": f"Read-only test tool {name}",
        "annotations": {"readOnlyHint": True},
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
        name = (
            self.sequence[len(self.calls)]
            if len(self.calls) < len(self.sequence)
            else FINISH_TOOL_NAME
        )
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
            },
            FINISH_TOOL_NAME: {
                "reason": "Archery evidence collection is complete",
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
            prompts=ARCHERY_PROMPTS,
        ),
        model or PromptFollowingMCPModel(),
        transport=transport,
    )


def test_agent_messages_projects_beijing_window_literals_for_ts_columns() -> None:
    client = _client(httpx.MockTransport(lambda request: httpx.Response(200, json={})))
    occurred_at = datetime(2026, 8, 17, 1, 46, 12, tzinfo=UTC)
    window_start = occurred_at - timedelta(seconds=300)

    messages = client.agent_messages(
        occurred_at=occurred_at,
        window_start=window_start,
        window_end=occurred_at,
        alert_context={"alarm_host": "100.84.97.135", "alarm_port": 3306},
    )

    assert messages[0]["role"] == "system"
    task = json.loads(messages[1]["content"])
    window = task["required_window"]
    # The window itself stays UTC-authoritative for the outer audit trail.
    assert window["start"] == "2026-08-17T01:41:12+00:00"
    assert window["end"] == "2026-08-17T01:46:12+00:00"
    assert window["start_unix_seconds"] == int(window_start.timestamp())
    assert window["end_unix_seconds"] == int(occurred_at.timestamp())
    # ts_min/ts_max are stored as Beijing time (UTC+8): the model must receive
    # ready-made literals instead of deriving (and mis-translating) them.
    assert window["ts_column_timezone"] == "UTC+8"
    assert window["start_beijing"] == "2026-08-17 09:41:12"
    assert window["end_beijing"] == "2026-08-17 09:46:12"
    assert window["ts_min_lower_bound_beijing"] == "2026-08-17 08:41:12"


def test_project_mcp_settings_resolve_environment_without_persisting_token(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    prompts = _write_prompt_files(tmp_path, "archery")
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "archery": {
                        "url": "${ARCHERY_MCP_URL}",
                        "headers": {
                            "X-Archery-Token": "${ARCHERY_MCP_TOKEN}",
                        },
                        "prompts": prompts,
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
    assert server.prompts == ARCHERY_PROMPTS
    assert "runtime-only-token" not in settings_path.read_text(encoding="utf-8")


def test_archery_settings_accept_catalog_selected_authentication_header(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    prompts = _write_prompt_files(tmp_path, "archery")
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "archery": {
                        "url": "${ARCHERY_MCP_URL}",
                        "headers": {
                            "Authorization": "${ARCHERY_MCP_TOKEN}",
                        },
                        "prompts": prompts,
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
            "ARCHERY_MCP_TOKEN": "Bearer runtime-token",
        },
    )
    client = ArcheryMCPClient(server, PromptFollowingMCPModel())

    assert client.headers == {"Authorization": "Bearer runtime-token"}


@pytest.mark.asyncio
async def test_archery_prompt_file_update_changes_actual_model_messages(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    first_prompts = MCPPromptBundle(
        role="archery-role-from-file",
        purpose="archery-purpose-from-file",
        workflow="archery-workflow-v1-from-file",
        safety="read_only: true\narchery-safety-from-file",
    )
    prompt_references = _write_prompt_files(
        tmp_path,
        "archery",
        first_prompts,
    )
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "archery": {
                        "url": "${ARCHERY_MCP_URL}",
                        "headers": {
                            "X-Archery-Token": "${ARCHERY_MCP_TOKEN}"
                        },
                        "prompts": prompt_references,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    environment = {
        "ARCHERY_MCP_URL": "https://archery.example.test/mcp",
        "ARCHERY_MCP_TOKEN": "test-archery-token",
    }

    async def capture_system_message() -> str:
        model = PromptFollowingMCPModel(
            sequence=(ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,)
        )
        client = ArcheryMCPClient.from_settings(
            settings_path,
            model,
            environment=environment,
            transport=_archery_call_handler(
                login_result={
                    "structuredContent": {"status": "ok"},
                    "isError": False,
                },
                query_result={
                    "structuredContent": {"status": "ok", "rows": []},
                    "isError": False,
                },
                tool_calls=[],
            ),
        )
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)
        return str(model.calls[0]["messages"][0]["content"])

    first_message = await capture_system_message()
    workflow_path = tmp_path / prompt_references["workflow"]
    workflow_path.write_text("archery-workflow-v2-from-file", encoding="utf-8")
    second_message = await capture_system_message()

    assert "[role]\narchery-role-from-file" in second_message
    assert "[purpose]\narchery-purpose-from-file" in second_message
    assert "[safety]\nread_only: true\narchery-safety-from-file" in second_message
    assert "archery-workflow-v1-from-file" in first_message
    assert "archery-workflow-v1-from-file" not in second_message
    assert "[workflow]\narchery-workflow-v2-from-file" in second_message






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
async def test_archery_mcp_returns_login_failure_as_observation_for_agent_decision() -> None:
    tool_calls: list[str] = []
    model = PromptFollowingMCPModel(sequence=(ARCHERY_MCP_LOGIN_TOOL_NAME,))
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
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME]
    assert result.query_completed is False
    assert len(model.calls) == 2
    raw_feedback = model.calls[1]["messages"][-1]["content"]
    assert isinstance(raw_feedback, str)
    decoded_feedback = json.loads(raw_feedback)
    assert decoded_feedback["isError"] is True
    assert decoded_feedback["content"][0]["text"] == "登录已过期，请重新登录后再试"




@pytest.mark.asyncio
async def test_archery_mcp_treats_other_slow_log_tables_as_auxiliary_results() -> None:
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

    assert result.query_completed is False
    assert result.requested_sql == ""
    assert not hasattr(result, "raw_mcp_call_results")
    assert tool_calls == list(DEFAULT_MODEL_TOOL_SEQUENCE)






@pytest.mark.asyncio
async def test_archery_mcp_recovers_from_history_timeout_with_index_aligned_window() -> None:
    tool_calls: list[str] = []
    query_sql_calls: list[str] = []
    member_sql = (
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE host = 'db-1' AND port = 3306 LIMIT 1"
    )
    instance_sql = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"
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
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,) * 4,
        query_sqls=(member_sql, instance_sql, timed_out_sql, recovered_sql),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "status": "ok",
                        "columns": ["f_instance_id"],
                        "rows": [[53]],
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "status": "ok",
                        "columns": ["host", "port"],
                        "rows": [["db-1", 3306]],
                    },
                    "isError": False,
                },
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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"alert_host": "db-1", "alert_port": 3306},
    )

    assert result.query_completed is True
    assert result.requested_sql == recovered_sql
    assert query_sql_calls == [member_sql, instance_sql, timed_out_sql, recovered_sql]
    timeout_feedback = model.calls[-2]["messages"][-1]["content"]
    assert "查询超时被KILL，请优化SQL后执行" in timeout_feedback


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


def test_archery_mcp_classifies_history_without_host_window_sort_or_limit_checks() -> None:
    assert ArcheryMCPClient.is_history_result_query(
        "SELECT hostname_max, sample FROM mysql_slow_query_review_history"
    )
    assert ArcheryMCPClient.is_history_result_query(
        "SELECT * FROM mysql_slow_query_review_history ORDER BY Query_time_sum DESC"
    )
    assert not ArcheryMCPClient.is_history_result_query(
        "SELECT * FROM information_schema.statistics "
        "WHERE table_name = 'mysql_slow_query_review_history'"
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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"alert_host": "db-1", "alert_port": 3306},
    )

    assert result.requested_sql == history_sql
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert tool_calls == list(result.model_tool_calls)
    assert model.calls[0]["arguments"]["instance_id"] == wrong_mcp_instance_id
    assert model.calls[1]["arguments"]["instance_id"] == TEST_INSTANCE_ID
    assert any(
        "allowlist" in (message.get("content") or "") for message in model.calls[1]["messages"]
    )


@pytest.mark.asyncio
async def test_archery_mcp_forwards_history_without_flashduty_endpoint() -> None:

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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query/100.84.97.113:3306"},
    )
    assert result.query_completed is True
    assert result.requested_sql == direct_history_sql
    assert tool_calls == [ARCHERY_MCP_QUERY_TOOL_NAME]
    assert query_sql_calls == [direct_history_sql]
    assert result.metadata_resolution_tables == ()
    assert result.diagnostics is not None
    assert result.diagnostics["alert_endpoint"] is None


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
async def test_archery_mcp_does_not_parse_endpoint_from_title() -> None:

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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": f"MySQL/mysql_slow_query/{title_endpoint}"},
    )

    assert result.query_completed is True
    assert result.requested_sql == direct_history_sql
    assert query_sql_calls == [direct_history_sql]
    assert result.diagnostics is not None
    assert result.diagnostics["alert_endpoint"] is None


@pytest.mark.asyncio
async def test_archery_mcp_does_not_host_reject_history_without_resolved_lineage() -> None:

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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": "MySQL/mysql_slow_query/100.84.97.113:3306"},
    )

    assert query_sql_calls == [direct_history_sql]
    assert result.query_completed is True
    assert result.requested_sql == direct_history_sql
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_tool_call_count"] == 1


@pytest.mark.asyncio
async def test_archery_mcp_forwards_unscoped_history_and_extra_arguments_unchanged() -> None:
    history_sql = "SELECT hostname_max, sample FROM mysql_slow_query_review_history"
    forwarded_arguments = {
        "instance_id": TEST_INSTANCE_ID,
        "db_name": TEST_DB_NAME,
        "sql_content": history_sql,
        "limit_num": 9_999,
        "provider_extension": {"mode": "deployment-specific"},
    }

    class ExtendedArgumentsModel(PromptFollowingMCPModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            call = await super().request_mcp_tool_call(messages=messages, tools=tools)
            if call.name != ARCHERY_MCP_QUERY_TOOL_NAME:
                return call
            self.calls[-1]["arguments"] = forwarded_arguments
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments=forwarded_arguments,
                request_id=call.request_id,
            )

    argument_calls: list[dict[str, Any]] = []
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={
                "structuredContent": {
                    "status": "ok",
                    "columns": ["hostname_max", "sample"],
                    "rows": [["db-1:3306", "select 1"]],
                },
                "isError": False,
            },
            tool_calls=[],
            query_argument_calls=argument_calls,
        ),
        model=ExtendedArgumentsModel(
            sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,),
            query_sqls=(history_sql,),
        ),
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert argument_calls == [forwarded_arguments]
    assert result.query_completed is True
    assert result.requested_sql == history_sql


@pytest.mark.asyncio
async def test_archery_mcp_does_not_block_nonconforming_sql() -> None:
    provider_specific_sql = "CALL provider_specific_diagnostic()"
    argument_calls: list[dict[str, Any]] = []
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result={"structuredContent": {"status": "ok"}, "isError": False},
            tool_calls=[],
            query_argument_calls=argument_calls,
        ),
        model=PromptFollowingMCPModel(
            sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,),
            query_sqls=(provider_specific_sql,),
        ),
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert argument_calls[0]["sql_content"] == provider_specific_sql
    assert result.query_completed is False


@pytest.mark.asyncio
async def test_archery_mcp_continues_after_successful_unscoped_history_probe() -> None:
    """A successful LIMIT 1 sample must not replace alert-window evidence."""

    arbitrary_endpoint = "10.126.106.205:3306"
    resolved_endpoint = "100.84.97.139:3306"
    member_sql = (
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE host = '100.84.97.135' AND port = 3306 LIMIT 1"
    )
    instance_sql = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"
    probe_sql = "SELECT hostname_max, ts_min, ts_max FROM mysql_slow_query_review_history LIMIT 1"
    final_sql = (
        "SELECT hostname_max, ts_min, ts_max "
        "FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{resolved_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}ORDER BY ts_min LIMIT 20"
    )
    query_sql_calls: list[str] = []
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,) * 4,
        query_sqls=(member_sql, instance_sql, probe_sql, final_sql),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "columns": ["f_instance_id"],
                        "rows": [[53]],
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "columns": ["host", "port"],
                        "rows": [["100.84.97.139", 3306]],
                    },
                    "isError": False,
                },
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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"alert_host": "100.84.97.135", "alert_port": 3306},
    )

    assert query_sql_calls == [member_sql, instance_sql, probe_sql, final_sql]
    assert result.requested_sql == final_sql
    assert result.query_completed is True
    assert result.payload["rows"] == []
    assert result.query_time_column == "ts_min"
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 4
    assert "instance_identity_verification" not in result.diagnostics
    assert result.diagnostics["query_trace"][2]["outcome"] == "ok"


@pytest.mark.asyncio
async def test_archery_mcp_forwards_history_with_model_selected_endpoint() -> None:
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
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"title": f"MySQL/mysql_slow_query/{alert_endpoint}"},
    )

    assert query_sql_calls == [history_sql]
    assert result.query_completed is True
    assert result.payload["status"] == "ok"
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 1
    assert result.diagnostics["alert_endpoint"] is None


@pytest.mark.parametrize("embedded_result_complete", [False, True])
def test_archery_mcp_parses_wrapped_positional_rows_without_post_query_checks(
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
    payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"result": wrapped_result},
        requested_sql=history_sql,
    )

    if embedded_result_complete:
        assert len(payload["rows"]) == 20
        assert "row_count_source" not in payload
        assert payload["columns"][0] == "hostname_max"
        assert payload["columns_source"] == "verified_sql_projection"
    else:
        assert payload["rowCount"] == 20
        assert payload["row_count_source"] == "archery_text"
    assert executed_sql is not None
    assert executed_sql.rstrip(";") == history_sql
    assert actual_sql_verified is True


@pytest.mark.asyncio
async def test_archery_mcp_parses_response_result_wrapped_tabular_payload() -> None:
    history_sql = (
        "SELECT hostname_max, sample, Query_time_sum "
        "FROM mysql_slow_query_review_history LIMIT 2"
    )
    rows = [
        ["db-a.example:3306", "select 1", 1.25],
        ["db-a.example:3306", "select 2", 0.75],
    ]
    wrapped_result = (
        f"SQL 查询已执行。\n执行的SQL：{history_sql}\n\n返回 2 行。\n结果：\n"
        + json.dumps(
            {
                "full_sql": history_sql + ";",
                "rows": rows,
                "column_list": ["hostname_max", "sample", "Query_time_sum"],
                "affected_rows": 2,
            },
            ensure_ascii=False,
        )
    )

    payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"response": {"result": wrapped_result}},
        requested_sql=history_sql,
    )

    assert payload["rows"] == rows
    assert ArcheryMCPClient.payload_row_count(payload) == 2
    assert ArcheryMCPClient._tabular_rows(payload) == [
        {
            "hostname_max": "db-a.example:3306",
            "sample": "select 1",
            "Query_time_sum": 1.25,
        },
        {
            "hostname_max": "db-a.example:3306",
            "sample": "select 2",
            "Query_time_sum": 0.75,
        },
    ]
    assert executed_sql is not None
    assert executed_sql.rstrip(";") == history_sql
    assert actual_sql_verified is True

    outcome = await ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload=payload)
    ).execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context("database_latency", title="MySQL/mysql_slow_query_400/db-a.example:3306"),
    )

    assert isinstance(outcome, tuple)
    _summary, structured_data = outcome
    assert structured_data["reported_row_count"] == 2
    assert structured_data["parsed_row_count"] == 2
    assert structured_data["included_row_count"] == 2
    assert structured_data["omitted_row_count"] == 0
    assert structured_data["root_cause_eligible"] is True


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
    assert structured_data["partial"] is False
    assert structured_data["root_cause_eligible"] is True
    assert structured_data["reported_row_count"] == 18
    assert structured_data["included_row_count"] == 18
    assert structured_data["rows"][0]["sample"] == "select 0"


@pytest.mark.parametrize(
    ("payload", "expected_rows", "expected_count"),
    [
        (
            {"rows": [], "results": [{"id": 17}]},
            [],
            0,
        ),
        (
            {"data": {"results": [{"id": 17, "name": "archery-production"}]}},
            [{"id": 17, "name": "archery-production"}],
            1,
        ),
    ],
)
def test_archery_tabular_row_shapes_use_consistent_precedence(
    payload: dict[str, Any],
    expected_rows: list[dict[str, Any]],
    expected_count: int,
) -> None:
    assert ArcheryMCPClient._tabular_rows(payload) == expected_rows
    assert ArcheryMCPClient.payload_row_count(payload) == expected_count


def test_archery_select_row_count_does_not_use_affected_rows_without_rows() -> None:
    payload = {"response": {"result": {"affected_rows": 0}}}

    assert ArcheryMCPClient.payload_row_count(payload) is None
    assert ArcherySlowLogEvidenceTool._reported_row_count(payload) is None


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

    assert isinstance(outcome, ToolExecutionResult)
    assert outcome.status == ToolStatus.NO_DATA
    summary, structured_data = outcome.summary, outcome.structured_data
    assert "字符截断" in summary
    assert structured_data["partial"] is True
    assert structured_data["root_cause_eligible"] is False
    assert structured_data["root_cause_ineligible_reason"] == (
        "remote_result_character_truncated"
    )
    assert structured_data["reported_row_count"] == 18
    assert structured_data["parsed_row_count"] == 2
    assert structured_data["included_row_count"] == 2
    assert structured_data["omitted_row_count"] == 16
    assert structured_data["rows"][0]["checksum"] == complete_rows[0]["checksum"]
    assert structured_data["rows"][1]["sample"] == complete_rows[1]["sample"]


@pytest.mark.asyncio
async def test_archery_mcp_preserves_all_rows_returned_by_remote_service() -> None:
    slow_log_endpoint = "db-history:3306"
    member_sql = (
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE host = 'db-history' AND port = 3306 LIMIT 1"
    )
    instance_sql = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"
    history_sql = (
        "SELECT hostname_max, sample FROM mysql_slow_query_review_history "
        f"WHERE hostname_max = '{slow_log_endpoint}' "
        f"{TEST_HISTORY_TIME_CLAUSE}LIMIT 20"
    )
    rows = [[slow_log_endpoint, f"select {index}"] for index in range(25)]
    model = PromptFollowingMCPModel(
        sequence=(ARCHERY_MCP_QUERY_TOOL_NAME,) * 3,
        query_sqls=(member_sql, instance_sql, history_sql),
    )
    client = _client(
        _archery_call_handler(
            login_result={"structuredContent": {"status": "ok"}, "isError": False},
            query_result=[
                {
                    "structuredContent": {
                        "columns": ["f_instance_id"],
                        "rows": [[53]],
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "columns": ["host", "port"],
                        "rows": [["db-history", 3306]],
                    },
                    "isError": False,
                },
                {
                    "structuredContent": {
                        "columns": ["hostname_max", "sample"],
                        "rows": rows,
                        "rowCount": len(rows),
                    },
                    "isError": False,
                },
            ],
            tool_calls=[],
        ),
        model=model,
    )

    result = await client.execute_slow_log_query(
        TEST_ALERT_OCCURRED_AT,
        alert_context={"alert_host": "db-history", "alert_port": 3306},
    )

    assert result.payload["rows"] == rows
    assert result.payload["rowCount"] == 25
    assert "rows_limited_to" not in result.payload




















class RecordingArcheryClient:
    slow_log_time_column = TEST_TIME_COLUMN
    window_seconds = 300
    prompts = ARCHERY_PROMPTS

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


def test_archery_outer_tool_accepts_extension_parameters_without_retry_metadata() -> None:
    assert ArcherySlowLogEvidenceTool.input_schema == {
        "type": "object",
        "properties": {},
        "additionalProperties": True,
    }
    assert not hasattr(ArcherySlowLogEvidenceTool, "max_attempts")


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
    database: dict[str, Any] | None = None,
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
    )


def test_archery_endpoint_requires_canonical_host_and_port() -> None:
    assert (
        ArcheryMCPClient.alert_endpoint_from_context(
            {
                "title": "MySQL/mysql_slow_query/title-host:3306",
                "target_labels": {
                    "alarm_host": "label-host",
                    "alarm_port": "3307",
                },
            }
        )
        is None
    )
    assert (
        ArcheryMCPClient.alert_endpoint_from_context(
            {
                "alert_host": "detail-host",
                "alert_port": 3306,
                "title": "MySQL/mysql_slow_query/wrong-host:3307",
            }
        )
        == "detail-host:3306"
    )
@pytest.mark.asyncio
async def test_archery_evidence_tool_ignores_parameters_and_uses_alert_detail_context() -> None:
    client = RecordingArcheryClient()
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]

    outcome = await tool.execute(
        ToolExecutionRequest(
            tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
            parameters={
                "window_seconds": 86_400,
                "host": "parameter-host.example",
                "port": 65_535,
                "occurred_at": "2099-01-01T00:00:00Z",
            },
        ),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
            database={
                "engine": "mysql",
                "instance": "db-1:3306",
                "database": TEST_DB_NAME,
                "host": "db-1",
                "port": 3306,
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
async def test_archery_evidence_preserves_complete_sanitized_result() -> None:
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
    )
    executor = ToolExecutor(InvestigationToolRegistry([tool]))

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
    assert parsed["root_cause_eligible"] is True
    assert parsed["reported_row_count"] == 18
    assert parsed["included_row_count"] == 18
    assert parsed["omitted_row_count"] == 0
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
    assert "raw_result" not in parsed
    assert "raw_mcp_call_results" not in parsed
    # The final result is passed through with format conversion only, so every
    # field of the embedded payload (including provider diagnostics) survives
    # verbatim inside final_result_payload instead of being filtered away.
    assert parsed["final_result_payload"]["opaque_diagnostics"] == "z" * 50_000
    assert parsed["final_result_payload"]["rowCount"] == 18
    assert parsed["final_result_payload"]["rows"][0]["sample"] == rows[0]["sample"]


@pytest.mark.asyncio
async def test_archery_evidence_preserves_all_complete_rows() -> None:
    rows = [_large_slow_query_row(index, sample_chars=700) for index in range(3)]
    tool = ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload={"rows": rows, "rowCount": len(rows)}),
    )
    executor = ToolExecutor(InvestigationToolRegistry([tool]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-history:3306",
        ),
    )

    assert record.truncated is False
    assert record.structured_data["included_row_count"] == 3
    assert record.structured_data["omitted_row_count"] == 0
    assert record.structured_data["rows"][0]["sample"] == rows[0]["sample"]
    assert "raw_result" not in record.structured_data
    assert "raw_mcp_call_results" not in record.structured_data


@pytest.mark.asyncio
async def test_archery_evidence_preserves_one_oversized_sql_statement() -> None:
    row = _large_slow_query_row(0, sample_chars=20_000)
    tool = ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload={"rows": [row], "rowCount": 1}),
    )
    executor = ToolExecutor(InvestigationToolRegistry([tool]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-history:3306",
        ),
    )

    summarized_row = record.structured_data["rows"][0]
    assert record.status == ToolStatus.SUCCESS
    assert record.truncated is False
    assert record.structured_data["included_row_count"] == 1
    assert record.structured_data["omitted_row_count"] == 0
    assert record.structured_data["root_cause_eligible"] is True
    assert summarized_row["sample"] == row["sample"]
    assert "raw_result" not in record.structured_data
    assert "raw_mcp_call_results" not in record.structured_data


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


def _settings(tmp_path: Path, *, real_model: bool = False) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    mcp_settings_path = tmp_path / "mcp" / "settings.json"
    mcp_settings_path.parent.mkdir()
    prompts = _write_prompt_files(mcp_settings_path.parent, "archery")
    mcp_settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "archery": {
                        "url": "${ARCHERY_MCP_URL}",
                        "headers": {
                            "X-Archery-Token": "${ARCHERY_MCP_TOKEN}",
                        },
                        "prompts": prompts,
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
    settings = _settings(tmp_path, real_model=True)
    runtime = build_runtime(settings)

    tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)

    assert isinstance(tool, ArcherySlowLogEvidenceTool)
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
    class ArcherySelectingAdvisor(FakeAIAdvisor):
        def __init__(self) -> None:
            self.decision_count = 0

        async def decide_investigation(self, **_kwargs: Any) -> InvestigationDecisionResult:
            self.decision_count += 1
            decision = (
                InvestigationDecision(
                    action="tool",
                    tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
                    objective="Collect the configured Archery slow-log evidence.",
                )
                if self.decision_count == 1
                else InvestigationDecision(
                    action="finish",
                    reason="The selected Archery investigation is complete.",
                )
            )
            return InvestigationDecisionResult(
                decision=decision,
                metadata=AdvisorMetadata(
                    provider=self.provider,
                    model=self.model,
                    prompt_version=self.prompt_version,
                    request_id=f"archery-react-{self.decision_count}",
                ),
            )

    client = RecordingArcheryClient()
    runtime = build_runtime(
        _settings(tmp_path),
        advisor=ArcherySelectingAdvisor(),
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
    assert evidence.structured_data["processing_status"] == "completed"
    assert "source_artifact" not in evidence.structured_data
    analysis = evidence.structured_data["tool_result_analysis"]
    assert analysis["provider"] == "deterministic_host"
    assert "source_artifact_id" not in analysis
    assert "source_sha256" not in analysis
    assert analysis["analysis_usable"] is False
    assert analysis["source_coverage_complete"] is True
    assert analysis["observations"][0]["source_paths"] == [
        "/structured_data/final_result_payload",
    ]
    assert evidence.structured_data["root_cause_eligible"] is False
    assert result.recommendation is not None
    assert result.recommendation.summary == "现有结果无法得出根因"
    assert result.recommendation.root_causes == []
    assert result.recommendation.likely_causes == []
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_slow_log_evidence_keys_positional_rows_by_column_list() -> None:
    client = RecordingArcheryClient(
        payload={
            "full_sql": (
                "SELECT id, checksum, sample FROM mysql_slow_query_review_history;"
            ),
            "is_execute": False,
            "rows": [
                [24311020, "2DBE950C61C1BBB4617E83D777A3A810", "select * from orders"],
                [24311019, "FFFCA4D67EA0A788813031B8BBC3B329", "commit"],
            ],
            "column_list": ["id", "checksum", "sample"],
            "column_type": ["LONG", "STRING", "BLOB"],
            "status": None,
            "affected_rows": 2,
        }
    )
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]
    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)
    structured = tool._build_slow_query_evidence(
        result,
        session_attempts=1,
        root_cause_ineligible_reason="",
    )

    payload = structured["final_result_payload"]
    assert payload["rows"] == [
        {
            "id": 24311020,
            "checksum": "2DBE950C61C1BBB4617E83D777A3A810",
            "sample": "select * from orders",
        },
        {
            "id": 24311019,
            "checksum": "FFFCA4D67EA0A788813031B8BBC3B329",
            "sample": "commit",
        },
    ]
    assert payload["column_list"] == ["id", "checksum", "sample"]
    assert payload["full_sql"] == (
        "SELECT id, checksum, sample FROM mysql_slow_query_review_history;"
    )
    assert "final_result_parse_failed" not in structured


@pytest.mark.asyncio
async def test_slow_log_evidence_keeps_raw_text_when_json_unparseable() -> None:
    raw_text = (
        "SQL 查询已执行。\n执行的SQL：SELECT id FROM mysql_slow_query_review_history\n\n"
        '返回 5 行。\n结果：\n{"full_sql": "SELECT id", "rows": [ bro'
    )
    client = RecordingArcheryClient(payload={"content": [raw_text]})
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]
    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)
    structured = tool._build_slow_query_evidence(
        result,
        session_attempts=1,
        root_cause_ineligible_reason="",
    )

    assert structured["final_result_parse_failed"] is True
    assert structured["final_result_text"] == raw_text
    assert "final_result_payload" not in structured
