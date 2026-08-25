from __future__ import annotations

import json
from copy import deepcopy
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
    ArcheryMCPToolError,
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
TEST_DB_NAME = "archery"
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
    "AND ts_min >= FROM_UNIXTIME(1784793300) AND ts_min < FROM_UNIXTIME(1784793600) "
)
FINISH_TOOL_NAME = "finish_archery_investigation"
RESULT_ASSESSMENT_TOOL_NAME = "report_archery_result_assessment"


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
        available_names = {item["function"]["name"] for item in tools}
        if available_names == {RESULT_ASSESSMENT_TOOL_NAME}:
            name = RESULT_ASSESSMENT_TOOL_NAME
        else:
            scripted_call_count = sum(
                item["name"] != RESULT_ASSESSMENT_TOOL_NAME for item in self.calls
            )
            name = (
                self.sequence[scripted_call_count]
                if scripted_call_count < len(self.sequence)
                else FINISH_TOOL_NAME
            )
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
        if name == RESULT_ASSESSMENT_TOOL_NAME:
            properties = tools[0]["function"]["parameters"]["properties"]
            arguments = {
                key: schema["const"]
                for key, schema in properties.items()
                if "const" in schema
            }
            arguments.update(
                {
                    "content_state": "complete",
                    "basis": "appears_complete",
                }
            )
        else:
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
        deterministic_history_pipeline=False,
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
    assert server.prompts.execution_instructions == ARCHERY_PROMPTS.execution_instructions
    assert server.prompts.workflow_revision == ""
    # The helper writes the already-rendered workflow, so the synthetic catalog
    # intentionally has no source markers from which to reconstruct directives.
    assert server.prompts.workflow_directives == {}
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


def test_archery_prompt_file_update_changes_actual_model_messages(
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

    def capture_system_message() -> str:
        client = ArcheryMCPClient.from_settings(
            settings_path,
            PromptFollowingMCPModel(),
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
        messages = client.agent_messages(
            occurred_at=TEST_ALERT_OCCURRED_AT,
            window_start=TEST_ALERT_OCCURRED_AT - timedelta(seconds=300),
            window_end=TEST_ALERT_OCCURRED_AT,
            alert_context={"alarm_host": "db.example.test", "alarm_port": 3306},
        )
        return str(messages[0]["content"])

    first_message = capture_system_message()
    workflow_path = tmp_path / prompt_references["workflow"]
    workflow_path.write_text("archery-workflow-v2-from-file", encoding="utf-8")
    second_message = capture_system_message()

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
    raw_feedback = next(
        message["content"]
        for message in model.calls[1]["messages"]
        if message.get("role") == "tool"
        and message.get("tool_call_id") == "model-call-1"
    )
    assert isinstance(raw_feedback, str)
    decoded_feedback = json.loads(raw_feedback)
    assert decoded_feedback["isError"] is True
    assert decoded_feedback["content"][0]["text"] == "登录已过期，请重新登录后再试"




@pytest.mark.asyncio
async def test_archery_mcp_rejects_other_slow_log_tables_before_transport() -> None:
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
    assert tool_calls == list(DEFAULT_MODEL_TOOL_SEQUENCE[:-1])
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == len(DEFAULT_MODEL_TOOL_SEQUENCE) - 1
    assert any(
        entry.get("reason_code") == "history_recovery_query_forbidden"
        and entry.get("sent_to_mcp") is False
        for entry in result.diagnostics["query_trace"]
    )






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
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
        "WHERE hostname_max = 'db-1:3306' "
        "AND ts_min >= FROM_UNIXTIME(1784789700) "
        "AND ts_min < FROM_UNIXTIME(1784793600) "
        "AND ts_max >= FROM_UNIXTIME(1784793300) LIMIT 20"
    )
    recovered_sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
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
    assert any(
        "查询超时被KILL，请优化SQL后执行" in message.get("content", "")
        for call in model.calls
        for message in call["messages"]
        if message.get("role") == "tool"
        and isinstance(message.get("content"), str)
    )


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


def test_archery_mcp_classifies_id_listing_and_per_id_retrieval_queries() -> None:
    history_table = ARCHERY_SLOW_QUERY_REVIEW_TABLE
    assert ArcheryMCPClient.is_history_id_only_projection(
        f"SELECT id FROM {history_table} WHERE hostname_max = 'h:3306' ORDER BY id DESC"
    )
    assert not ArcheryMCPClient.is_history_id_only_projection(
        f"SELECT id, hostname_max FROM {history_table} WHERE id = 24413454"
    )
    assert not ArcheryMCPClient.is_history_id_only_projection(
        f"SELECT * FROM {history_table} WHERE hostname_max = 'h:3306'"
    )
    assert ArcheryMCPClient.is_history_id_retrieval_query(
        f"SELECT * FROM {history_table} WHERE id = 24413454"
    )
    assert not ArcheryMCPClient.is_history_id_retrieval_query(
        f"SELECT id, hostname_max FROM {history_table} "
        "WHERE hostname_max = 'h:3306' AND id IN (24413454, 24413460)"
    )
    window_sql = (
        f"SELECT * FROM {history_table} "
        "WHERE hostname_max = 'h:3306' AND ts_min >= '2026-08-17 08:41:12' "
        "AND ts_min < '2026-08-17 09:46:12' AND ts_max >= '2026-08-17 09:41:12' "
        "ORDER BY id DESC"
    )
    assert not ArcheryMCPClient.is_history_id_retrieval_query(window_sql)
    assert not ArcheryMCPClient.is_history_id_only_projection(window_sql)
    # In-word identifiers such as f_instance_id must never look like id retrieval.
    assert not ArcheryMCPClient.is_history_id_retrieval_query(
        f"SELECT * FROM {history_table} WHERE f_instance_id = 53"
    )
    projection_sql = ArcheryMCPClient.history_sample_projection_sql(24413640)
    # The fixed projection that clips oversized sample text is still a per-id
    # retrieval and must keep merging into the final payload.
    assert ArcheryMCPClient.is_history_id_retrieval_query(
        projection_sql
    )
    assert ArcheryMCPClient.is_history_id_retrieval_query(
        projection_sql.lower()
        .replace(", ", ",\n    ")
        .replace(" from ", "\nfrom\n")
        .replace(" where ", "\nwhere\n")
    )
    assert not ArcheryMCPClient.is_history_id_retrieval_query(
        f"SELECT SLEEP(10), * FROM {history_table} WHERE id = 24413640"
    )
    assert not ArcheryMCPClient.is_history_id_retrieval_query(
        "SELECT id, sample, LEFT(sample, '4000') AS sample, "
        f"LENGTH(sample) AS sample_full_length FROM {history_table} "
        "WHERE id = 24413640"
    )
    assert not ArcheryMCPClient.is_history_id_retrieval_query(
        f"SELECT * FROM {history_table} WHERE id = 24413640 AND 1 = 1"
    )


def test_history_sample_and_chunk_retrieval_use_closed_host_shapes() -> None:
    sample_sql = ArcheryMCPClient.history_sample_sql(24413640)
    chunk_sql = ArcheryMCPClient.history_sample_chunk_sql(24413640, 1, 10_000)

    assert ArcheryMCPClient.history_id_retrieval(sample_sql) == (
        24413640,
        "sample",
    )
    assert ArcheryMCPClient.history_sample_chunk_retrieval(chunk_sql) == (
        24413640,
        1,
        10_000,
    )
    assert ArcheryMCPClient.history_sample_chunk_size(12_000) == 10_000
    invalid = (
        chunk_sql.replace("10000", "10001"),
        chunk_sql.replace("SUBSTRING(sample, 1", "SUBSTRING(sample, 0"),
        chunk_sql.replace("AS sample_chunk", "AS sample"),
        chunk_sql.replace("WHERE id = 24413640", "WHERE id IN (24413640, 24413641)"),
    )
    assert all(
        ArcheryMCPClient.history_sample_chunk_retrieval(sql) is None
        for sql in invalid
    )


def test_agent_sample_structure_retains_both_ends_of_large_literal_in() -> None:
    sample = (
        "SELECT * FROM orders WHERE id IN ("
        + ",".join(str(value) for value in range(20_000))
        + ") AND status = 'open'"
    )

    structured = ArcheryMCPClient.compress_sample_for_agent(sample)

    assert structured["representation"] == "structured"
    assert structured["structure_executable"] is True
    assert len(structured["sample"]) <= 12_000
    assert "IN (0," in structured["sample"]
    assert "19999)" in structured["sample"]
    assert structured["in_lists"][0]["omitted_value_count"] > 0


def test_non_in_oversized_sample_uses_non_executable_head_tail_display() -> None:
    sample = "SELECT * FROM notes WHERE body = '" + ("x" * 13_000) + "'"

    structured = ArcheryMCPClient.compress_sample_for_agent(sample)

    assert structured["representation"] == "structured"
    assert structured["structure_executable"] is False
    assert len(structured["sample"]) == 12_000
    assert "sample middle omitted for Agent context" in structured["sample"]


@pytest.mark.parametrize(
    "sql",
    (
        "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
        "ORDER BY id DESC",
        "select * from `mysql_slow_query_review_history` where `id`=24413454 "
        "order by `id` asc limit 1",
        "SELECT h.* FROM archery.mysql_slow_query_review_history AS h "
        "WHERE h.id = 24413454 ORDER BY h.id DESC LIMIT 1",
        "SELECT * FROM mysql_slow_query_review_history h WHERE 24413454 = h.id",
        "SELECT * FROM `archery`.`mysql_slow_query_review_history` AS `H` "
        "WHERE (`H`.`ID` = 24413454);",
        "/* formatting comment */ SELECT * "
        "FROM mysql_slow_query_review_history WHERE id = 24413454",
    ),
)
def test_history_id_retrieval_accepts_safe_mysql_ast_equivalents(sql: str) -> None:
    assert ArcheryMCPClient.history_id_retrieval(sql) == (24413454, "full")


def test_history_id_retrieval_accepts_aliased_sample_prefix_projection() -> None:
    sql = (
        "SELECT h.id, h.hostname_max, h.client_max, h.user_max, h.db_max, "
        "h.checksum, h.ts_min, h.ts_max, h.ts_cnt, h.Query_time_sum, "
        "h.Query_time_min, h.Query_time_max, h.Query_time_pct_95, "
        "h.Query_time_median, h.Lock_time_sum, h.Lock_time_max, "
        "h.Rows_sent_sum, h.Rows_examined_sum, h.Full_scan_cnt, "
        "h.Tmp_table_cnt, h.Filesort_cnt, h.Bytes_sum, "
        "LEFT(h.sample, '4000') AS sample, "
        "LENGTH(h.sample) AS sample_full_length "
        "FROM `archery`.`mysql_slow_query_review_history` AS h "
        "WHERE h.id = 24413640 ORDER BY h.id DESC LIMIT 1"
    )

    assert ArcheryMCPClient.history_id_retrieval(sql) == (
        24413640,
        "sample_prefix",
    )


@pytest.mark.parametrize(
    ("sql", "reason_code"),
    (
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "AND checksum = 'x'",
            "history_recovery_id_predicate_required",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history h "
            "JOIN other_table o ON o.id = h.id WHERE h.id = 24413454",
            "history_recovery_query_shape_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history h, other_table o "
            "WHERE h.id = 24413454",
            "history_recovery_query_shape_forbidden",
        ),
        (
            "SELECT * INTO OUTFILE '/tmp/history.txt' "
            "FROM mysql_slow_query_review_history WHERE id = 24413454",
            "history_recovery_sql_parse_failed",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history "
            "WHERE id IN (24413454, 24413455)",
            "history_recovery_id_predicate_required",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "ORDER BY checksum DESC",
            "history_recovery_order_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 LIMIT 2",
            "history_recovery_limit_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "OFFSET 1",
            "history_recovery_limit_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "LIMIT 1 OFFSET 0",
            "history_recovery_limit_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = "
            "(SELECT max(id) FROM mysql_slow_query_review_history)",
            "history_recovery_not_single_select",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "UNION SELECT * FROM mysql_slow_query_review_history WHERE id = 24413455",
            "history_recovery_not_single_select",
        ),
        (
            "SELECT * FROM (SELECT * FROM mysql_slow_query_review_history "
            "WHERE id = 24413454) AS h",
            "history_recovery_not_single_select",
        ),
        (
            "SELECT * FROM another_table WHERE id = 24413454",
            "history_recovery_target_forbidden",
        ),
        (
            "SELECT * FROM other_schema.mysql_slow_query_review_history "
            "WHERE id = 24413454",
            "history_recovery_target_forbidden",
        ),
        (
            "SELECT * FROM mysql_ſlow_query_review_history WHERE id = 24413454",
            "history_recovery_target_forbidden",
        ),
        (
            "SELECT * FROM `mysql_ſlow_query_review_history` WHERE id = 24413454",
            "history_recovery_target_forbidden",
        ),
        (
            "SELECT evil.h.* FROM mysql_slow_query_review_history AS h "
            "WHERE h.id = 24413454",
            "history_recovery_projection_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "FOR UPDATE",
            "history_recovery_query_shape_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "LOCK IN SHARE MODE",
            "history_recovery_query_shape_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "ORDER BY id NULLS FIRST",
            "history_recovery_order_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "ORDER BY id DESC NULLS LAST",
            "history_recovery_order_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history USE INDEX (PRIMARY) "
            "WHERE id = 24413454",
            "history_recovery_query_shape_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454 "
            "/*!50000 FOR UPDATE */",
            "history_recovery_sql_parse_failed",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454; "
            "SELECT 1",
            "history_recovery_not_single_statement",
        ),
    ),
)
def test_history_id_retrieval_rejects_ast_scope_expansion(
    sql: str,
    reason_code: str,
) -> None:
    retrieval, actual_reason = ArcheryMCPClient.history_id_retrieval_validation(sql)

    assert retrieval is None
    assert actual_reason == reason_code


def test_history_sample_projection_rejects_any_projection_drift() -> None:
    projection_sql = ArcheryMCPClient.history_sample_projection_sql(24413640)

    invalid = (
        projection_sql.replace("SELECT id,", "SELECT id, secret_column,"),
        projection_sql.replace(
            "LEFT(sample, '4000') AS sample",
            "sample",
        ),
        projection_sql.replace(
            "SELECT id, hostname_max",
            "SELECT hostname_max, id",
        ),
        projection_sql.replace("client_max, ", ""),
        projection_sql.replace("id, hostname_max", "id, id, hostname_max"),
    )

    assert all(
        not ArcheryMCPClient.is_history_id_retrieval_query(sql) for sql in invalid
    )


def test_accumulate_history_rows_merges_by_id_with_field_union() -> None:
    rows_by_id: dict[int, dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []

    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {"rows": [{"id": 24413458, "sample": "UPDATE t", "ts_cnt": 6}]},
        sql="SELECT * FROM mysql_slow_query_review_history WHERE id = 24413458",
        include_source=True,
    )
    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {
            "rows": [
                {"id": "24413458", "ts_cnt": 12},
                {"id": 24413460, "sample": "SELECT 1", "ts_cnt": 40},
                {"sample": "row without id cannot join the merge"},
            ]
        },
        sql=(
            "SELECT * FROM mysql_slow_query_review_history "
            "WHERE id IN (24413458, 24413460)"
        ),
        include_source=True,
    )
    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {"rows": [{"id": 24413460}]},
        sql="SELECT * FROM mysql_slow_query_review_history WHERE id = 24413460",
        include_source=False,
    )

    payload = ArcheryMCPClient.merged_history_payload(rows_by_id, sources)
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 2
    assert [row["id"] for row in payload["rows"]] == ["24413458", 24413460]
    assert payload["rows"][0] == {
        "id": "24413458",
        "sample": "UPDATE t",
        "ts_cnt": 12,
    }
    assert payload["rows"][1] == {"id": 24413460, "sample": "SELECT 1", "ts_cnt": 40}
    assert "rows_recovered_from_truncated_json" not in payload
    assert payload["merged_full_sqls"] == [
        "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413458",
        "SELECT * FROM mysql_slow_query_review_history "
        "WHERE id IN (24413458, 24413460)",
    ]


def test_sample_prefix_merge_does_not_downgrade_complete_sample() -> None:
    rows_by_id: dict[int, dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []
    complete_sample = "UPDATE orders SET note = 'complete statement' WHERE id = 7"

    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {
            "rows": [
                {
                    "id": 24413458,
                    "sample": complete_sample,
                    "ts_cnt": 6,
                }
            ]
        },
        sql="SELECT * FROM mysql_slow_query_review_history WHERE id = 24413458",
        include_source=True,
        projection="full",
    )
    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {
            "rows": [
                {
                    "id": 24413458,
                    "sample": "UPDATE orders SET note = 'complete",
                    "sample_full_length": len(complete_sample.encode("utf-8")),
                    "ts_cnt": 12,
                }
            ]
        },
        sql=ArcheryMCPClient.history_sample_projection_sql(24413458),
        include_source=True,
        projection="sample_prefix",
    )

    assert rows_by_id[24413458]["sample"] == complete_sample
    assert rows_by_id[24413458]["ts_cnt"] == 12
    assert "sample_full_length" not in rows_by_id[24413458]


def test_full_row_merge_replaces_prefix_and_removes_stale_length() -> None:
    rows_by_id: dict[int, dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []
    complete_sample = "DELETE FROM orders WHERE archived = 1"

    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {
            "rows": [
                {
                    "id": 24413458,
                    "sample": "DELETE FROM orders WHERE arch",
                    "sample_full_length": len(complete_sample.encode("utf-8")),
                    "ts_cnt": 6,
                }
            ]
        },
        sql=ArcheryMCPClient.history_sample_projection_sql(24413458),
        include_source=True,
        projection="sample_prefix",
    )
    ArcheryMCPClient.accumulate_history_rows(
        rows_by_id,
        sources,
        {
            "rows": [
                {
                    "id": 24413458,
                    "sample": complete_sample,
                    "ts_cnt": 12,
                }
            ]
        },
        sql="SELECT * FROM mysql_slow_query_review_history WHERE id = 24413458",
        include_source=True,
        projection="full",
    )

    assert rows_by_id[24413458] == {
        "id": 24413458,
        "sample": complete_sample,
        "ts_cnt": 12,
    }


def test_positional_merge_returns_each_unresolved_row_and_preserves_full_sample() -> None:
    prefix_ids = {1}
    trusted_full_ids = {4}
    rows_by_id = {
        1: {
            "id": 1,
            "sample": "SELECT * FROM orders WHERE note = 'prefix",
            "sample_full_length": 99,
            "ts_cnt": 7,
        }
    }
    deferred: list[Any] = [
        [1, "SELECT * FROM orders WHERE note = 'complete'", 3],
        [2, "short"],
        ["not-an-id", "SELECT 3", 1],
        [3, "SELECT 3", 1],
        [4],
    ]

    unresolved = ArcheryMCPClient.merge_positional_rows_with_reference(
        rows_by_id,
        deferred,
        ["id", "sample", "ts_cnt"],
        allowed_ids={1, 2, 4},
        trusted_full_row_ids=trusted_full_ids,
        sample_prefix_ids=prefix_ids,
    )

    assert rows_by_id[1] == {
        "id": 1,
        "sample": "SELECT * FROM orders WHERE note = 'complete'",
        "ts_cnt": 7,
    }
    assert unresolved == deferred[1:4]
    assert prefix_ids == set()
    assert trusted_full_ids == {1, 4}


@pytest.mark.asyncio
async def test_merged_history_payload_reaches_evidence_as_eligible_success() -> None:
    rows_by_id = {
        row["id"]: dict(row)
        for row in (
            _large_slow_query_row(0),
            _large_slow_query_row(1),
            _large_slow_query_row(2),
        )
    }
    merged = ArcheryMCPClient.merged_history_payload(
        rows_by_id,
        [
            {
                "full_sql": (
                    "SELECT * FROM mysql_slow_query_review_history WHERE id = 1000"
                ),
                "row_count": 1,
            },
            {
                "full_sql": (
                    "SELECT * FROM mysql_slow_query_review_history "
                    "WHERE id IN (1001, 1002)"
                ),
                "row_count": 2,
            },
        ],
    )

    outcome = await ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload=merged)
    ).execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context(
            "database_latency",
            title="MySQL/mysql_slow_query_400/db-1:3306",
        ),
    )

    assert not isinstance(outcome, ToolExecutionResult)
    summary, structured_data = outcome
    assert "字符截断" not in summary
    assert structured_data["query_completed"] is True
    assert structured_data["root_cause_eligible"] is True
    passthrough = structured_data["final_result_payload"]
    assert passthrough["rows_merged_from_per_id_queries"] is True
    assert len(passthrough["rows"]) == 3




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
        "SELECT * FROM mysql_slow_query_review_history "
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
                    "structuredContent": {
                        "status": "ok",
                        "columns": ["f_instance_id"],
                        "rows": [[metadata_instance_id]],
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
        "SELECT * FROM mysql_slow_query_review_history "
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
    assert result.query_completed is False
    assert result.requested_sql == ""
    assert tool_calls == []
    assert query_sql_calls == []
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
    assert not ArcheryMCPClient._member_query_selects_instance_id(
        "SELECT f_id AS f_instance_id FROM t_instance_member "
        "WHERE f_ip = '100.84.97.113' AND f_port = 3306 LIMIT 1",
        set(),
    )
    assert not ArcheryMCPClient._sql_instance_query_selects_endpoint(
        "SELECT id AS host, id AS port FROM sql_instance WHERE id = 53 LIMIT 1",
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
        "SELECT * FROM mysql_slow_query_review_history "
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

    assert result.query_completed is False
    assert result.requested_sql == ""
    assert query_sql_calls == []
    assert result.diagnostics is not None
    assert result.diagnostics["alert_endpoint"] is None


@pytest.mark.asyncio
async def test_archery_mcp_rejects_history_without_resolved_lineage() -> None:

    query_sql_calls: list[str] = []
    direct_history_sql = (
        "SELECT * FROM mysql_slow_query_review_history "
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

    assert query_sql_calls == []
    assert result.query_completed is False
    assert result.requested_sql == ""
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_tool_call_count"] == 0


@pytest.mark.asyncio
async def test_archery_mcp_rejects_unscoped_history_with_extra_arguments() -> None:
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

    assert argument_calls == []
    assert result.query_completed is False
    assert result.requested_sql == ""


@pytest.mark.asyncio
async def test_archery_mcp_blocks_nonconforming_sql_before_transport() -> None:
    provider_specific_sql = "CALL provider_specific_diagnostic()"
    argument_calls: list[dict[str, Any]] = []
    tool_calls: list[str] = []
    client = _client(
        _archery_call_handler(
            login_result={
                "structuredContent": {
                    "status": "failed",
                    "message": "authentication rejected",
                },
                "isError": True,
            },
            query_result={"structuredContent": {"status": "ok"}, "isError": False},
            tool_calls=tool_calls,
            query_argument_calls=argument_calls,
        ),
        model=PromptFollowingMCPModel(
            sequence=(ARCHERY_MCP_QUERY_TOOL_NAME, ARCHERY_MCP_LOGIN_TOOL_NAME),
            query_sqls=(provider_specific_sql,),
        ),
    )

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert argument_calls == []
    assert tool_calls == [ARCHERY_MCP_LOGIN_TOOL_NAME]
    assert result.query_completed is False


@pytest.mark.asyncio
async def test_archery_mcp_continues_after_successful_unscoped_history_probe() -> None:
    """A successful LIMIT 1 sample must not replace alert-window evidence."""

    resolved_endpoint = "100.84.97.139:3306"
    member_sql = (
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE host = '100.84.97.135' AND port = 3306 LIMIT 1"
    )
    instance_sql = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"
    probe_sql = "SELECT hostname_max, ts_min, ts_max FROM mysql_slow_query_review_history LIMIT 1"
    final_sql = (
        "SELECT * FROM mysql_slow_query_review_history "
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

    assert query_sql_calls == [member_sql, instance_sql, final_sql]
    assert result.requested_sql == final_sql
    assert result.query_completed is True
    assert result.payload["rows"] == []
    assert result.query_time_column == "ts_min"
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert "instance_identity_verification" not in result.diagnostics
    assert result.diagnostics["query_trace"][2]["outcome"] == "rejected_locally"


@pytest.mark.asyncio
async def test_archery_mcp_rejects_history_with_unresolved_model_selected_endpoint() -> None:
    alert_endpoint = "100.84.97.113:3306"
    slow_log_endpoint = "10.23.45.67:3306"
    history_sql = (
        "SELECT * FROM mysql_slow_query_review_history "
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

    assert query_sql_calls == []
    assert result.query_completed is False
    assert result.model_tool_calls == ()
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 0
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


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (
            {"columns": ["id", "sample"], "rows": [[1]]},
            "positional_row_width_mismatch",
        ),
        (
            {"columns": ["id", "sample"], "rows": [{"id": 1}, [2, "SELECT 2"]]},
            "mixed_tabular_row_shapes",
        ),
        (
            {"column_list": ["id", "ID"], "rows": [[1, 1]]},
            "duplicate_tabular_columns",
        ),
        (
            {"column_list": ["id", 7], "rows": [[1, "SELECT 1"]]},
            "invalid_tabular_columns",
        ),
        (
            {"rows": [[1, "SELECT 1"]]},
            "missing_tabular_columns",
        ),
    ],
)
def test_archery_tabular_shape_failures_never_partially_zip_rows(
    payload: dict[str, Any],
    reason: str,
) -> None:
    assert ArcheryMCPClient.tabular_shape_issue(payload) == reason
    assert ArcheryMCPClient._tabular_rows(payload) == []
    assert ArcheryMCPClient.is_result_incomplete(payload) is True


def test_mapping_rows_do_not_depend_on_positional_column_metadata() -> None:
    payload = {
        "column_list": ["duplicate", "DUPLICATE"],
        "rows": [{"id": 1, "sample": "SELECT 1"}],
    }

    assert ArcheryMCPClient.tabular_shape_issue(payload) is None
    assert ArcheryMCPClient._tabular_rows(payload) == payload["rows"]
    assert ArcheryMCPClient.is_result_incomplete(payload) is False


def test_complete_json_reported_row_shortfall_gets_unified_incomplete_marker() -> None:
    sql = "SELECT id, sample FROM mysql_slow_query_review_history WHERE id = 1"
    embedded = json.dumps(
        {
            "full_sql": sql,
            "columns": ["id", "sample"],
            "rows": [[1, "SELECT 1"]],
        }
    )
    wrapped = f"SQL 查询已执行。\n执行的SQL：{sql}\n返回 2 行。\n结果：\n{embedded}"

    payload, _executed_sql, _verified = ArcheryMCPClient.normalize_query_payload(
        {"result": wrapped},
        requested_sql=sql,
    )

    assert payload["rows"] == [[1, "SELECT 1"]]
    assert payload["result_incomplete"] is True
    assert "row_count_shortfall" in payload["result_incomplete_reasons"]


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
        "SELECT * FROM mysql_slow_query_review_history "
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
    assert "实际执行 SQL 已由 Archery 回显并通过 provider 执行契约核验" in summary
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
    assert tool.capability == "database.slow_query"

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
@pytest.mark.parametrize(
    "payload",
    [
        {
            "rows": [
                {
                    "hostname_max": "db-1:3306",
                    "sample": "SELECT * FROM orders",
                }
            ],
            "mcp_reported_row_count": 2,
        },
        {
            "columns": ["hostname_max", "sample"],
            "rows": [
                ["db-1:3306", "SELECT * FROM orders"],
                ["db-1:3306"],
            ],
        },
    ],
)
async def test_incomplete_history_payload_is_no_data_and_preserves_raw_rows(
    payload: dict[str, Any],
) -> None:
    raw_rows = deepcopy(payload["rows"])
    outcome = await ArcherySlowLogEvidenceTool(  # type: ignore[arg-type]
        RecordingArcheryClient(payload=payload)
    ).execute(
        ToolExecutionRequest(tool_name=ARCHERY_SLOW_LOG_TOOL_NAME),
        _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306"),
    )

    assert isinstance(outcome, ToolExecutionResult)
    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data["partial"] is True
    assert outcome.structured_data["root_cause_eligible"] is False
    assert outcome.structured_data["root_cause_ineligible_reason"]
    assert outcome.structured_data["final_result_payload"]["rows"] == raw_rows


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


@pytest.mark.parametrize(
    ("sample", "statement_type"),
    [
        ("SELECT * FROM orders WHERE id = 1", "select"),
        ("UPDATE orders SET status = 'done' WHERE id = 1", "update"),
        ("DELETE FROM orders WHERE id = 1", "delete"),
        ("INSERT INTO archive SELECT * FROM orders WHERE id = 1", "insert"),
        ("REPLACE INTO cache_rows(id) VALUES (1)", "replace"),
        ("WITH selected AS (SELECT 1 AS id) UPDATE orders SET status='done'", "update"),
    ],
)
def test_archery_mcp_accepts_supported_dml_as_plain_explain_inner_statement(
    sample: str,
    statement_type: str,
) -> None:
    assert ArcheryMCPClient.explainable_statement_type(sample) == statement_type
    assert ArcheryMCPClient.plain_explain_inner_sql(f"EXPLAIN {sample}") == sample


def test_with_dml_table_references_include_cte_source_and_write_target() -> None:
    assert ArcheryMCPClient.explainable_table_references(
        "WITH selected AS (SELECT id FROM source_orders) "
        "UPDATE orders SET status = 'done' WHERE id IN (SELECT id FROM selected)"
    ) == {"source_orders", "orders"}


@pytest.mark.parametrize(
    "sql",
    [
        "EXPLAIN ANALYZE SELECT * FROM orders",
        "EXPLAIN FORMAT=TREE ANALYZE SELECT * FROM orders",
        "EXPLAIN UPDATE orders SET status='done'; DELETE FROM orders",
        "EXPLAIN ALTER TABLE orders ADD COLUMN unsafe int",
        "EXPLAIN CALL refresh_orders()",
    ],
)
def test_archery_mcp_rejects_executing_or_non_explainable_explain_variants(sql: str) -> None:
    assert ArcheryMCPClient.plain_explain_inner_sql(sql) is None


def test_archery_mcp_selects_explainable_rows_by_query_time_id_and_checksum() -> None:
    payload = {
        "rows": [
            {
                "id": 7,
                "checksum": "same",
                "sample": "SELECT * FROM older",
                "Query_time_max": 10,
            },
            {
                "id": 9,
                "checksum": "same",
                "sample": "UPDATE newest SET value = 1",
                "Query_time_max": 10,
            },
            {
                "id": 10,
                "checksum": "ddl",
                "sample": "ALTER TABLE unsafe ADD COLUMN value int",
                "Query_time_max": 99,
            },
            {
                "id": 8,
                "checksum": "second",
                "sample": "DELETE FROM second WHERE id = 1",
                "Query_time_max": 8,
            },
        ]
    }

    selected = ArcheryMCPClient.select_explainable_history_rows(payload)

    assert [row["id"] for row in selected] == [9, 8]
    assert selected[0]["sample"].startswith("UPDATE")


def test_archery_mcp_excludes_explicitly_truncated_samples_from_explain() -> None:
    complete = "SELECT * FROM complete_orders"
    truncated_prefix = "SELECT * FROM truncated_orders WHERE note = 'prefix'"
    payload = {
        "rows": [
            {
                "id": 12,
                "checksum": "truncated",
                "sample": truncated_prefix,
                "sample_full_length": len(truncated_prefix.encode("utf-8")) + 100,
                "Query_time_max": 99,
            },
            {
                "id": 11,
                "checksum": "complete",
                "sample": complete,
                "sample_full_length": len(complete.encode("utf-8")),
                "Query_time_max": 1,
            },
        ]
    }

    selected = ArcheryMCPClient.select_explainable_history_rows(payload)

    assert [row["id"] for row in selected] == [11]
    assert ArcheryMCPClient.history_row_for_explain(
        f"EXPLAIN {truncated_prefix}", payload
    ) is None


def test_archery_mcp_requires_exact_positive_sample_full_length_when_present() -> None:
    sample = "SELECT * FROM multibyte_orders WHERE note = '慢查询'"
    byte_length = len(sample.encode("utf-8"))
    rows = [
        {
            "id": index,
            "checksum": f"invalid-length-{index}",
            "sample": sample,
            "sample_full_length": marker,
            "Query_time_max": 10,
        }
        for index, marker in enumerate(
            (None, 0, -1, "invalid", byte_length - 1, byte_length + 1),
            start=1,
        )
    ]
    rows.append(
        {
            "id": 99,
            "checksum": "exact-length",
            "sample": sample,
            "sample_full_length": str(byte_length),
            "Query_time_max": 1,
        }
    )

    selected = ArcheryMCPClient.select_explainable_history_rows({"rows": rows})

    assert [row["id"] for row in selected] == [99]


def test_sql_equivalence_preserves_physical_table_identity() -> None:
    assert ArcheryMCPClient.sql_equivalent(
        "SELECT LOW_PRIORITY * FROM orders",
        "select low_priority * from orders",
    )
    assert not ArcheryMCPClient.sql_equivalent(
        "SELECT * FROM Orders",
        "select * from orders",
    )
    assert not ArcheryMCPClient.sql_equivalent(
        "SELECT * FROM orders",
        "SELECT * FROM other_prod.orders",
    )
    assert not ArcheryMCPClient.sql_equivalent(
        "SELECT A.id FROM Orders A JOIN orders a ON A.id = a.id",
        "select a.id from orders A join Orders a on a.id = A.id",
    )
    assert not ArcheryMCPClient.sql_equivalent(
        "SELECT A.id FROM orders A JOIN audit a ON A.id = a.id",
        "select a.id from orders A join audit a on a.id = A.id",
    )


def test_sql_equivalence_preserves_optimizer_hint_identity() -> None:
    expected = "SELECT /*+ INDEX(orders PRIMARY) */ * FROM orders"

    assert ArcheryMCPClient.sql_equivalent(
        expected,
        "select /*+ INDEX(orders PRIMARY) */ * from orders",
    )
    assert not ArcheryMCPClient.sql_equivalent(
        expected,
        "SELECT /*+ INDEX(orders idx_customer) */ * FROM orders",
    )


def test_normalized_query_accepts_provider_appended_declared_limit() -> None:
    requested = (
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE f_ip = '100.84.97.117' AND f_port = '3306'"
    )
    actual = requested + " LIMIT 100"
    embedded = {
        "full_sql": actual.lower().replace("select", "SELECT", 1) + ";",
        "rows": [[3]],
        "column_list": ["f_instance_id"],
    }
    wrapped = (
        "SQL query executed.\n"
        f"Executed SQL: {actual}\n\n"
        "Result:\n" + json.dumps(embedded)
    )
    response = {
        "response": {
            "result": wrapped.replace("Executed SQL:", "执行的SQL：").replace(
                "Result:", "结果："
            )
        }
    }

    payload, executed_sql, actual_sql_verified = (
        ArcheryMCPClient.normalize_query_payload(
            response,
            requested_sql=requested,
            provider_limit_num=100,
        )
    )
    _payload_without_contract, _executed_without_contract, verified_without_contract = (
        ArcheryMCPClient.normalize_query_payload(
            response,
            requested_sql=requested,
        )
    )

    assert payload["rows"] == [[3]]
    assert payload["column_list"] == ["f_instance_id"]
    assert executed_sql == embedded["full_sql"]
    assert actual_sql_verified is True
    assert verified_without_contract is False


@pytest.mark.parametrize(
    ("requested", "actual", "provider_limit_num"),
    [
        (
            "SELECT host, port FROM sql_instance WHERE id = 3",
            "SELECT host, port FROM sql_instance WHERE id = 3 LIMIT 100",
            20,
        ),
        (
            "SELECT host, port FROM sql_instance WHERE id = 3",
            "SELECT host, port FROM sql_instance WHERE id = 4 LIMIT 100",
            100,
        ),
        (
            "SELECT host, port FROM sql_instance WHERE id = 3",
            "SELECT id, host, port FROM sql_instance WHERE id = 3 LIMIT 100",
            100,
        ),
        (
            "SELECT host, port FROM sql_instance WHERE id = 3 LIMIT 1",
            "SELECT host, port FROM sql_instance WHERE id = 3 LIMIT 100",
            100,
        ),
        (
            "EXPLAIN SELECT * FROM orders WHERE id = 3",
            "EXPLAIN SELECT * FROM orders WHERE id = 3 LIMIT 100",
            100,
        ),
    ],
)
def test_execution_sql_equivalence_rejects_unbound_provider_rewrites(
    requested: str,
    actual: str,
    provider_limit_num: int,
) -> None:
    assert not ArcheryMCPClient.execution_sql_equivalent(
        requested,
        actual,
        provider_limit_num=provider_limit_num,
    )


def test_normalized_query_rejects_echoed_physical_table_change() -> None:
    requested = "EXPLAIN SELECT * FROM Orders WHERE id = 1"
    actual = "explain select * from orders where id = 1"

    _payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"full_sql": actual, "rows": [{"table": "orders"}]},
        requested_sql=requested,
    )

    assert executed_sql == actual
    assert actual_sql_verified is False


def test_normalized_query_rejects_conflicting_nested_actual_sql_echoes() -> None:
    requested = "SELECT id FROM sql_instance WHERE id = 53"
    conflicting = "SELECT host FROM sql_instance WHERE id = 99"

    _payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {
            "full_sql": requested,
            "execution": {"executed_sql": conflicting},
            "rows": [{"id": 53}],
        },
        requested_sql=requested,
    )

    assert executed_sql == requested
    assert actual_sql_verified is False


def test_normalized_query_rejects_conflicting_raw_text_actual_sql_echo() -> None:
    requested = "SELECT id FROM sql_instance WHERE id = 53"
    conflicting = "SELECT host FROM sql_instance WHERE id = 99"

    _payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"full_sql": requested, "rows": [{"id": 53}]},
        requested_sql=requested,
        supplemental_text=(
            json.dumps({"response": {"full_sql": conflicting}}),
        ),
    )

    assert executed_sql == requested
    assert actual_sql_verified is False


def test_normalized_query_rejects_conflicting_sql_echoes_in_one_text_block() -> None:
    requested = "SELECT id FROM sql_instance WHERE id = 53"
    conflicting = "SELECT host FROM sql_instance WHERE id = 99"

    _payload, executed_sql, actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        {"rows": [{"id": 53}]},
        requested_sql=requested,
        supplemental_text=(
            "SQL 查询已执行。\n"
            f"执行的SQL：{requested}\n\n"
            f"执行的SQL：{conflicting}\n\n"
            "返回 1 行。",
        ),
    )

    assert executed_sql == requested
    assert actual_sql_verified is False


def test_normalized_query_keeps_first_embedded_result_when_it_equals_outer_payload() -> None:
    requested = "SELECT id FROM sql_instance WHERE id = 53"
    first = {"rows": [{"id": 53}]}
    second = {"rows": [{"id": 99}]}

    payload, _executed_sql, _actual_sql_verified = ArcheryMCPClient.normalize_query_payload(
        first,
        requested_sql=requested,
        supplemental_text=(
            "结果：" + json.dumps(first),
            "结果：" + json.dumps(second),
        ),
    )

    assert payload == first


def test_explain_sample_identity_preserves_string_literal_semantics() -> None:
    payload = {
        "rows": [
            {
                "id": 11,
                "checksum": "literal-orders",
                "sample": "SELECT * FROM orders WHERE note = 'A  B'",
                "Query_time_max": 1,
            }
        ]
    }

    assert ArcheryMCPClient.history_row_for_explain(
        " explain select * from orders where note='A  B'; ",
        payload,
    ) is not None
    assert ArcheryMCPClient.history_row_for_explain(
        "EXPLAIN SELECT * FROM orders WHERE note = 'a b'",
        payload,
    ) is None


def test_information_schema_classifier_rejects_additional_physical_tables() -> None:
    assert ArcheryMCPClient.is_information_schema_columns_query(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS"
    )
    assert not ArcheryMCPClient.is_information_schema_columns_query(
        "SELECT c.COLUMN_NAME FROM information_schema.COLUMNS c "
        "JOIN orders o ON o.name = c.COLUMN_NAME"
    )
    assert not ArcheryMCPClient.is_information_schema_columns_query(
        "SELECT SLEEP(1) FROM information_schema.COLUMNS"
    )
    assert not ArcheryMCPClient.is_information_schema_columns_query(
        "SELECT COLUMN_NAME INTO OUTFILE '/tmp/columns' "
        "FROM information_schema.COLUMNS"
    )
    assert not ArcheryMCPClient.is_information_schema_columns_query(
        "SELECT TABLE_NAME AS COLUMN_NAME FROM information_schema.COLUMNS"
    )
    exact = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    assert ArcheryMCPClient.has_exact_information_schema_target_filters(exact)
    assert not ArcheryMCPClient.has_exact_information_schema_target_filters(
        exact + " AND COLUMN_NAME = 'id'"
    )


def test_allowlist_discovery_extracts_only_explicit_row_local_targets() -> None:
    payload = {
        "rows": [
            {"id": 3, "host": "orders-db.example", "port": 3306},
            {"instance_id": 4, "endpoint": "report-db.example:3307"},
            {"id": 5, "name": "looks-like-db.example:3308"},
            {"f_instance_id": 6, "address": "ignored-db.example:3309"},
        ]
    }

    assert ArcheryMCPClient.allowlisted_instance_endpoints(payload) == {
        3: {"orders-db.example:3306"},
        4: {"report-db.example:3307"},
    }
    assert ArcheryMCPClient.allowlisted_database_names(
        {"rows": [{"name": "orders_prod"}, {"db_name": "reporting"}]}
    ) == {"orders_prod", "reporting"}


def test_allowlist_discovery_parses_strict_live_text_contracts() -> None:
    instances = (
        "实例清单（第 1 页）：\n"
        "1. [ID:3] pcm 100.84.97.100:3306 资源组:[1]\n"
        "2. [ID:17] archery 100.84.97.141:3307 资源组:[2, 9, 13]"
    )
    databases = (
        "实例 3 的数据库清单：\n"
        "1. pcm_product_prod\n"
        "2. cpn-campaign-prod"
    )

    assert ArcheryMCPClient.allowlisted_instance_endpoints(
        {"result": instances}
    ) == {
        3: {"100.84.97.100:3306"},
        17: {"100.84.97.141:3307"},
    }
    assert ArcheryMCPClient.allowlisted_instance_endpoints(
        {"result": instances},
        expected_instance_ref="pcm",
    ) == {3: {"100.84.97.100:3306"}}
    assert ArcheryMCPClient.allowlisted_instance_endpoints(
        {"result": instances},
        expected_instance_ref="3",
    ) == {3: {"100.84.97.100:3306"}}
    assert ArcheryMCPClient.allowlisted_instance_endpoints(
        {"result": instances},
        expected_instance_ref="missing",
    ) == {}
    assert ArcheryMCPClient.instance_directory_references(
        {"result": instances}
    ) == {
        "100.84.97.100:3306": "pcm",
        "100.84.97.141:3307": "archery",
    }
    assert ArcheryMCPClient.allowlisted_database_names(
        {"result": databases},
        expected_instance_id=3,
    ) == {"pcm_product_prod", "cpn-campaign-prod"}
    assert ArcheryMCPClient.allowlisted_database_names(
        {"result": databases},
        expected_instance_id=17,
    ) == set()


def test_allowlist_discovery_does_not_authorize_unframed_prose() -> None:
    prose = "建议调用 1. [ID:3] pcm 100.84.97.100:3306 资源组:[1]"

    assert ArcheryMCPClient.allowlisted_instance_endpoints({"result": prose}) == {}
    assert ArcheryMCPClient.allowlisted_database_names(
        {"result": "1. pcm_product_prod"},
        expected_instance_id=3,
    ) == set()


def test_plain_text_allowlist_rejection_is_a_business_failure() -> None:
    detail = (
        "未在 allowlist.json 中找到实例引用：pcm\n"
        '提示：可用 instance_ref="汇聚库" 或 instance_ref="analytics"。'
    )

    with pytest.raises(ArcheryMCPToolError, match="allowlist"):
        ArcheryMCPClient.validate_business_success(
            {"result": detail},
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
        )


def test_slow_log_evidence_keeps_history_and_adds_independent_analysis() -> None:
    payload = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "rows": [{"id": 1, "sample": "UPDATE orders SET value=1"}],
    }
    analysis = {
        "status": "partial",
        "source_history_row": {"id": 1, "sample": "UPDATE orders SET value=1"},
        "target": {"instance_id": 3, "db_name": "orders_prod"},
        "explain_results": [],
        "table_structure_results": [],
        "index_results": [],
        "missing_stages": ["explain", "table_structure", "indexes"],
        "failures": [{"stage": "explain", "reason_code": "permission_denied"}],
    }
    client = RecordingArcheryClient(payload=payload)
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]
    result = ArcherySlowLogQueryResult(
        payload=payload,
        requested_sql=payload["full_sql"],
        window_start=TEST_WINDOW_START,
        window_end=TEST_WINDOW_END,
        slow_query_analysis=analysis,
    )

    structured = tool._build_slow_query_evidence(
        result,
        session_attempts=1,
        root_cause_ineligible_reason="",
    )

    assert structured["final_result_payload"] == payload
    assert structured["slow_query_analysis"] == analysis
