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
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_SLOW_LOG_LIMIT,
    ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ArcheryMCPClient,
    ArcheryMCPConfigurationError,
    ArcheryMCPReadOnlyViolation,
    ArcheryMCPToolError,
    ArcherySlowLogEvidenceTool,
    ArcherySlowLogQueryResult,
)
from app.adapters.investigation import (
    AlertContextTool,
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
)
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import InvestigationContext, InvestigationStrategy, ToolExecutionRequest

TEST_INSTANCE_REF = "archery-metadata"
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


def _tool_schema(name: str, *properties: str) -> dict[str, Any]:
    return {
        "name": name,
        "inputSchema": {
            "type": "object",
            "properties": {item: {"type": "string"} for item in properties},
            "required": list(properties),
        },
    }


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


def _client(transport: httpx.AsyncBaseTransport) -> ArcheryMCPClient:
    return ArcheryMCPClient(
        "https://archery.example.test/mcp",
        "test-archery-token",
        instance_ref=TEST_INSTANCE_REF,
        db_name=TEST_DB_NAME,
        transport=transport,
    )


@pytest.mark.asyncio
async def test_archery_mcp_executes_alert_window_query_and_parses_sse_result() -> None:
    calls: list[tuple[str, dict[str, Any], dict[str, str]]] = []

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
                        _tool_schema(ARCHERY_MCP_LOGIN_TOOL_NAME),
                        _tool_schema(
                            ARCHERY_MCP_QUERY_TOOL_NAME,
                            "instance_ref",
                            "db_name",
                            "sql_content",
                            "limit_num",
                            "max_result_chars",
                        )
                    ]
                },
            )
        if method == "tools/call":
            if body["params"]["name"] == ARCHERY_MCP_LOGIN_TOOL_NAME:
                assert body["params"] == {
                    "name": ARCHERY_MCP_LOGIN_TOOL_NAME,
                    "arguments": {},
                }
                return _json_response(
                    request,
                    body["id"],
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"status": "ok", "username": "test-user"}
                                ),
                            }
                        ],
                        "isError": False,
                    },
                )
            assert body["params"] == {
                "name": ARCHERY_MCP_QUERY_TOOL_NAME,
                "arguments": {
                    "instance_ref": TEST_INSTANCE_REF,
                    "db_name": TEST_DB_NAME,
                    "sql_content": TEST_SLOW_LOG_QUERY,
                    "limit_num": ARCHERY_SLOW_LOG_LIMIT,
                    "max_result_chars": ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
                },
            }
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

    client = _client(httpx.MockTransport(handler))

    result = await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert result.payload["rows"] == [[1, "select 1"]]
    assert result.payload["rowCount"] == 1
    assert result.requested_sql == TEST_SLOW_LOG_QUERY
    assert result.window_start == TEST_WINDOW_START
    assert result.window_end == TEST_WINDOW_END
    assert [item[0] for item in calls] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
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
                    "tools": [
                        _tool_schema(ARCHERY_MCP_LOGIN_TOOL_NAME),
                        _tool_schema(ARCHERY_MCP_QUERY_TOOL_NAME, "sql_content"),
                    ]
                },
            )
        if body["method"] == "tools/call":
            tool_calls.append(body["params"])
            raise AssertionError("tools/call must not run for an incompatible schema")
        raise AssertionError(body["method"])

    client = _client(httpx.MockTransport(handler))

    with pytest.raises(ArcheryMCPConfigurationError, match="instance_ref, db_name"):
        await client.execute_slow_log_query(TEST_ALERT_OCCURRED_AT)

    assert tool_calls == []


def _archery_call_handler(
    *,
    login_result: dict[str, Any],
    query_result: dict[str, Any],
    tool_calls: list[str],
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
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
                {
                    "tools": [
                        _tool_schema(ARCHERY_MCP_LOGIN_TOOL_NAME),
                        _tool_schema(
                            ARCHERY_MCP_QUERY_TOOL_NAME,
                            "instance_ref",
                            "db_name",
                            "sql_content",
                            "limit_num",
                            "max_result_chars",
                        ),
                    ]
                },
            )
        if method == "tools/call":
            tool_name = body["params"]["name"]
            tool_calls.append(tool_name)
            result = (
                login_result
                if tool_name == ARCHERY_MCP_LOGIN_TOOL_NAME
                else query_result
            )
            return _json_response(request, body["id"], result)
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

    assert tool_calls == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]


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
    assert tool_calls == [
        "ensure_login_gymJPA",
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    assert captured.value.diagnostic_data["login_tool"] == "ensure_login_gymJPA"
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
            payload={"status": "ok", "rows": [{"id": 1}], "rowCount": 1},
            requested_sql=TEST_SLOW_LOG_QUERY,
            window_start=TEST_WINDOW_START,
            window_end=TEST_WINDOW_END,
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
    assert "返回 1 行" in summary
    assert data["sql"] == TEST_SLOW_LOG_QUERY
    assert data["login_confirmed"] is True
    assert data["login_tool"] == ARCHERY_MCP_LOGIN_TOOL_NAME
    assert data["actual_sql_verified"] is False
    assert data["target"] == {
        "instance_ref": TEST_INSTANCE_REF,
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
    assert data["result_bounds"]["truncation_possible"] is True
    assert data["root_cause_eligible"] is False
    assert data["result"]["rows"] == [{"id": 1}]

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


def _settings(tmp_path: Path) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=runbooks,
        archery_mcp_url="https://archery.example.test/mcp",
        archery_mcp_token="test-archery-token",
        archery_mcp_instance_ref=TEST_INSTANCE_REF,
        archery_mcp_db_name=TEST_DB_NAME,
    )


def test_factory_registers_configured_archery_tool(tmp_path: Path) -> None:
    runtime = build_runtime(_settings(tmp_path))

    tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)

    assert isinstance(tool, ArcherySlowLogEvidenceTool)
    assert tool.client.instance_ref == TEST_INSTANCE_REF
    assert tool.client.db_name == TEST_DB_NAME
    assert tool.client.window_seconds == 300


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
    assert evidence.structured_data["result"]["rowCount"] == 1
    assert evidence.structured_data["login_confirmed"] is True
    assert evidence.structured_data["sql"] == TEST_SLOW_LOG_QUERY
    assert evidence.structured_data["query_window"]["basis"] == "alert.occurred_at"
    assert evidence.structured_data["root_cause_eligible"] is False
    assert result.recommendation is not None
    assert result.recommendation.root_causes[0].status.value == "UNKNOWN"
    assert str(evidence.id) not in result.recommendation.root_causes[0].evidence_refs
    await runtime.repository.close()  # type: ignore[attr-defined]
