from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.archery_mcp import (
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_SLOW_LOG_DATABASE,
    ARCHERY_SLOW_LOG_INSTANCE_REF,
    ARCHERY_SLOW_LOG_LIMIT,
    ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
    ARCHERY_SLOW_LOG_QUERY,
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ArcheryMCPClient,
    ArcheryMCPConfigurationError,
    ArcheryMCPReadOnlyViolation,
    ArcherySlowLogEvidenceTool,
)
from app.adapters.investigation import (
    AlertContextTool,
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
)
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import InvestigationContext, InvestigationStrategy, ToolExecutionRequest


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


@pytest.mark.asyncio
async def test_archery_mcp_executes_fixed_query_and_parses_sse_result() -> None:
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
            assert body["params"] == {
                "name": ARCHERY_MCP_QUERY_TOOL_NAME,
                "arguments": {
                    "instance_ref": ARCHERY_SLOW_LOG_INSTANCE_REF,
                    "db_name": ARCHERY_SLOW_LOG_DATABASE,
                    "sql_content": ARCHERY_SLOW_LOG_QUERY,
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

    client = ArcheryMCPClient(
        "https://archery.example.test/mcp",
        "test-archery-token",
        transport=httpx.MockTransport(handler),
    )

    result = await client.execute_slow_log_query()

    assert result["rows"] == [[1, "select 1"]]
    assert result["rowCount"] == 1
    assert [item[0] for item in calls] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
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
                        _tool_schema(ARCHERY_MCP_QUERY_TOOL_NAME, "sql_content"),
                    ]
                },
            )
        if body["method"] == "tools/call":
            tool_calls.append(body["params"])
            raise AssertionError("tools/call must not run for an incompatible schema")
        raise AssertionError(body["method"])

    client = ArcheryMCPClient(
        "https://archery.example.test/mcp",
        "test-archery-token",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ArcheryMCPConfigurationError, match="instance_ref, db_name"):
        await client.execute_slow_log_query()

    assert tool_calls == []


class RecordingArcheryClient:
    query_tool_name = ARCHERY_MCP_QUERY_TOOL_NAME

    def __init__(self) -> None:
        self.calls = 0

    async def execute_slow_log_query(self) -> dict[str, Any]:
        self.calls += 1
        return {"status": "ok", "rows": [{"id": 1}], "rowCount": 1}


def _context(alert_type: str, *, title: str = "Database alert") -> InvestigationContext:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": f"archery-{alert_type}",
            "severity": "WARNING",
            "title": title,
            "reason": alert_type,
            "alert_type": alert_type,
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
async def test_archery_evidence_tool_is_restricted_to_slow_query_title_and_sql() -> None:
    client = RecordingArcheryClient()
    tool = ArcherySlowLogEvidenceTool(client)  # type: ignore[arg-type]

    summary, data = await tool.execute(
        ToolExecutionRequest(
            tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
            parameters={"sql": ARCHERY_SLOW_LOG_QUERY},
        ),
        _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306"),
    )

    assert client.calls == 1
    assert "返回 1 行" in summary
    assert data["sql"] == ARCHERY_SLOW_LOG_QUERY
    assert data["result"]["rows"] == [{"id": 1}]

    with pytest.raises(ArcheryMCPReadOnlyViolation):
        await tool.execute(
            ToolExecutionRequest(
                tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
                parameters={"sql": "select * from another_table"},
            ),
            _context("database_latency", title="MySQL/mysql_slow_query_400/db-1:3306"),
        )
    with pytest.raises(ArcheryMCPReadOnlyViolation):
        await tool.execute(
            ToolExecutionRequest(
                tool_name=ARCHERY_SLOW_LOG_TOOL_NAME,
                parameters={"sql": ARCHERY_SLOW_LOG_QUERY},
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
    assert request.parameters == {"sql": ARCHERY_SLOW_LOG_QUERY}
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
    )


def test_factory_registers_configured_archery_tool(tmp_path: Path) -> None:
    runtime = build_runtime(_settings(tmp_path))

    tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)

    assert isinstance(tool, ArcherySlowLogEvidenceTool)


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
    assert evidence.request == {"sql": ARCHERY_SLOW_LOG_QUERY}
    assert evidence.structured_data["result"]["rowCount"] == 1
    assert result.recommendation is not None
    assert str(evidence.id) in result.recommendation.root_causes[0].evidence_refs
    await runtime.repository.close()  # type: ignore[attr-defined]
