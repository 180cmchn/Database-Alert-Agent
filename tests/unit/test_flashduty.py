from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.adapters.flashduty import (
    FlashDutyAlertContextTool,
    FlashDutyAlertSourceAdapter,
    FlashDutyAPIError,
    FlashDutyClient,
    FlashDutyDatabaseDiagnosticsTool,
    FlashDutyDataSourceTool,
    FlashDutyReadOnlyViolation,
    FlashDutyResponse,
)
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import (
    InvestigationContext,
    InvestigationStrategy,
    Severity,
    ToolExecutionRequest,
)

ALERT_ID = "663a1b2c3d4e5f6789abcdef"
INCIDENT_ID = "69da451ef77b1b51f40e83ee"


async def no_sleep(_seconds: float) -> None:
    return None


@pytest.mark.asyncio
async def test_client_uses_query_app_key_and_rejects_write_operations() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"request_id": "req-1", "data": {"alert_id": ALERT_ID}},
        )

    client = FlashDutyClient(
        "test-app-key",
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )

    response = await client.alert_info(ALERT_ID)

    assert response.request_id == "req-1"
    assert requests[0].method == "POST"
    assert requests[0].url.path == "/alert/info"
    assert requests[0].url.params["app_key"] == "test-app-key"
    with pytest.raises(FlashDutyReadOnlyViolation, match="read-only allowlist"):
        await client.call("incident_ack", {"incident_id": INCIDENT_ID})
    with pytest.raises(FlashDutyReadOnlyViolation, match="not read-only"):
        await client.call(
            "monit_tools_invoke",
            {
                "target_locator": "db-prod-01",
                "tools": [{"tool": "mysql.kill_session", "params": {}}],
            },
        )
    with pytest.raises(FlashDutyReadOnlyViolation, match="SELECT/SHOW"):
        await client.call(
            "monit_query_rows",
            {"ds_type": "mysql", "ds_name": "prod", "expr": "DROP TABLE alerts"},
        )


@pytest.mark.asyncio
async def test_client_retries_rate_limit_and_redacts_secret_from_errors() -> None:
    attempts = 0

    def retry_handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0"},
                json={
                    "request_id": "req-rate",
                    "error": {"code": "RequestTooFrequently", "message": "slow down"},
                },
            )
        return httpx.Response(200, json={"request_id": "req-ok", "data": []})

    client = FlashDutyClient(
        "test-app-key",
        max_retries=1,
        transport=httpx.MockTransport(retry_handler),
        sleep=no_sleep,
    )
    response = await client.query_rows({"ds_type": "prometheus", "ds_name": "prod", "expr": "up"})
    assert response.request_id == "req-ok"
    assert attempts == 2

    def error_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "request_id": "req-error",
                "error": {
                    "code": "InvalidParameter",
                    "message": "super-secret must not be echoed",
                },
            },
        )

    failing = FlashDutyClient(
        "super-secret",
        transport=httpx.MockTransport(error_handler),
        sleep=no_sleep,
    )
    with pytest.raises(FlashDutyAPIError) as caught:
        await failing.alert_info(ALERT_ID)
    assert "super-secret" not in str(caught.value)
    assert "***REDACTED***" in str(caught.value)


@pytest.mark.asyncio
async def test_client_alert_list_uses_documented_updated_at_cursor_shape() -> None:
    request_body: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        request_body.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "request_id": "req-list",
                "data": {"items": [], "has_next_page": False},
            },
        )

    client = FlashDutyClient(
        "test-app-key", transport=httpx.MockTransport(handler), sleep=no_sleep
    )
    await client.list_alerts(
        start_time=1712650000,
        end_time=1712650300,
        channel_ids=[7],
        integration_ids=[42],
    )

    assert request_body == {
        "start_time": 1712650000,
        "end_time": 1712650300,
        "limit": 100,
        "orderby": "updated_at",
        "asc": True,
        "by_updated_at": True,
        "p": 1,
        "channel_ids": [7],
        "integration_ids": [42],
        "is_active": True,
    }


@pytest.mark.asyncio
async def test_client_treats_http_200_monitor_business_error_as_failure() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "request_id": "req-business",
                "data": {
                    "tools": [],
                    "error": {
                        "code": "target_unavailable",
                        "message": "target is offline",
                    },
                },
            },
        )

    client = FlashDutyClient(
        "test-app-key",
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )
    with pytest.raises(FlashDutyAPIError, match="target_unavailable"):
        await client.tool_catalog({"target_locator": "db-prod-01"})


def flashduty_alert_payload() -> dict[str, Any]:
    return {
        "request_id": "req-alert",
        "data": {
            "alert_id": ALERT_ID,
            "title": "MySQL connections exhausted",
            "description": "Connection usage reached 95%",
            "alert_severity": "Critical",
            "alert_status": "Critical",
            "alert_key": "mysql-connections",
            "start_time": 1712650000,
            "last_time": 1712650300,
            "end_time": 0,
            "event_cnt": 3,
            "integration_type": "monit.alert",
            "labels": {
                "env": "prd",
                "service": "orders-db",
                "engine": "mysql",
                "instance": "db-prod-01",
                "metric_name": "mysql_threads_connected",
            },
            "incident": {"incident_id": INCIDENT_ID, "progress": "Triggered"},
        },
    }


def test_flashduty_alert_adapter_normalizes_alert_info_envelope() -> None:
    adapter = FlashDutyAlertSourceAdapter({"production": ["prd"]})

    alert = adapter.normalize(flashduty_alert_payload())

    assert alert.source == "flashduty"
    assert alert.external_id == ALERT_ID
    assert alert.raw_severity == "Critical"
    assert alert.severity == Severity.CRITICAL
    assert alert.environment == "production"
    assert alert.service_name == "orders-db"
    assert alert.database is not None
    assert alert.database.engine == "mysql"
    assert alert.database.instance == "db-prod-01"
    assert alert.attributes["flashduty_incident_id"] == INCIDENT_ID
    assert alert.incident_fingerprint.startswith("incident-v1-")


def make_context() -> InvestigationContext:
    alert = FlashDutyAlertSourceAdapter({"production": ["prd"]}).normalize(
        flashduty_alert_payload()
    )
    return InvestigationContext(
        run_id=uuid4(),
        alert=alert,
        strategy=InvestigationStrategy(
            strategy_id="flashduty-test",
            title="FlashDuty test",
            description="test",
        ),
    )


@pytest.mark.asyncio
async def test_alert_context_reads_alert_and_incident_context() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        data: dict[str, Any]
        if request.url.path == "/alert/info":
            data = flashduty_alert_payload()["data"]
        elif request.url.path in {"/alert/event/list", "/alert/feed", "/incident/feed"}:
            data = {"items": [], "has_next_page": False}
        elif request.url.path == "/incident/info":
            data = {"incident_id": INCIDENT_ID, "title": "Database incident"}
        elif request.url.path == "/incident/alert/list":
            data = {"items": [], "total": 0}
        else:  # pragma: no cover - test route guard
            raise AssertionError(request.url.path)
        return httpx.Response(
            200,
            json={"request_id": f"req-{len(paths)}", "data": data},
        )

    client = FlashDutyClient(
        "test-app-key",
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )
    tool = FlashDutyAlertContextTool(client, item_limit=5)

    summary, data = await tool.execute(
        ToolExecutionRequest(tool_name="alert_context"), make_context()
    )

    assert "只读接口" in summary
    assert set(paths) == {
        "/alert/info",
        "/alert/event/list",
        "/alert/feed",
        "/incident/info",
        "/incident/feed",
        "/incident/alert/list",
    }
    assert data["flashduty"]["incident"]["info"]["incident_id"] == INCIDENT_ID


@pytest.mark.asyncio
async def test_alert_context_keeps_partial_data_when_auxiliary_feed_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/alert/info":
            data = flashduty_alert_payload()["data"]
        elif request.url.path == "/alert/feed":
            return httpx.Response(
                503,
                json={
                    "request_id": "req-feed-error",
                    "error": {"code": "Unavailable", "message": "try later"},
                },
            )
        elif request.url.path == "/incident/info":
            data = {"incident_id": INCIDENT_ID, "title": "Database incident"}
        else:
            data = {"items": [], "has_next_page": False}
        return httpx.Response(
            200, json={"request_id": f"req-{request.url.path}", "data": data}
        )

    client = FlashDutyClient(
        "test-app-key",
        max_retries=0,
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )

    summary, structured_data = await FlashDutyAlertContextTool(client).execute(
        ToolExecutionRequest(tool_name="alert_context"), make_context()
    )

    assert "部分辅助" in summary
    assert structured_data["flashduty"]["alert"]["alert_id"] == ALERT_ID
    assert structured_data["flashduty"]["events"] == {
        "items": [],
        "has_next_page": False,
    }
    assert structured_data["flashduty"]["feed"] is None
    assert structured_data["flashduty"]["partial_errors"] == {
        "alert_feed": "FlashDutyAPIError"
    }
    assert structured_data["flashduty"]["incident"]["info"]["incident_id"] == INCIDENT_ID


class RecordingMonitorClient:
    def __init__(self) -> None:
        self.diagnose_payload: dict[str, Any] | None = None
        self.invoke_payload: dict[str, Any] | None = None

    async def diagnose(self, payload: dict[str, Any]) -> Any:
        self.diagnose_payload = payload
        return FlashDutyResponse("req-diagnose", {"operation": "metric_trends"})

    async def tool_catalog(self, _payload: dict[str, Any]) -> Any:
        return FlashDutyResponse(
            "req-catalog",
            {
                "target": {"kind": "mysql", "locator": "db-prod-01"},
                "tools": [
                    {
                        "name": "mysql.connection_overview",
                        "description": "Shows connection sources and long sessions",
                        "input_schema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "mysql.kill_session",
                        "description": "terminates a session",
                        "input_schema": {"required": ["session_id"]},
                    },
                ],
            },
        )

    async def invoke_tools(self, payload: dict[str, Any]) -> Any:
        self.invoke_payload = payload
        return FlashDutyResponse(
            "req-invoke",
            {
                "target": {"kind": "mysql", "locator": "db-prod-01"},
                "results": [
                    {
                        "tool": "mysql.connection_overview",
                        "params": {},
                        "data": {"connections": 95},
                        "summary": "95 active connections",
                    }
                ],
            },
        )


class NoRowsClient:
    async def query_rows(self, _payload: dict[str, Any]) -> Any:
        raise AssertionError("write-shaped SQL must be rejected before the API call")


@pytest.mark.asyncio
async def test_metrics_tool_uses_documented_diagnose_shape() -> None:
    client = RecordingMonitorClient()
    tool = FlashDutyDataSourceTool(
        "query_metrics",
        client,  # type: ignore[arg-type]
        defaults={"ds_name": "prod-prom", "ds_type": "prometheus"},
    )

    summary, data = await tool.execute(
        ToolExecutionRequest(tool_name="query_metrics"), make_context()
    )

    assert "指标趋势" in summary
    assert client.diagnose_payload is not None
    assert client.diagnose_payload["operation"] == "metric_trends"
    assert client.diagnose_payload["input"] == {"query": "mysql_threads_connected"}
    assert client.diagnose_payload["ds_name"] == "prod-prom"
    assert data["request_id"] == "req-diagnose"


@pytest.mark.asyncio
async def test_raw_query_tool_rejects_write_shaped_sql() -> None:
    tool = FlashDutyDataSourceTool(
        "query_trace",
        NoRowsClient(),  # type: ignore[arg-type]
    )

    with pytest.raises(FlashDutyReadOnlyViolation, match="SELECT/SHOW"):
        await tool.execute(
            ToolExecutionRequest(
                tool_name="query_trace",
                parameters={
                    "ds_type": "mysql",
                    "ds_name": "prod-mysql",
                    "expr": "DELETE FROM sessions",
                },
            ),
            make_context(),
        )


@pytest.mark.asyncio
async def test_database_tool_discovers_and_invokes_only_compatible_tools() -> None:
    client = RecordingMonitorClient()
    tool = FlashDutyDatabaseDiagnosticsTool(client)  # type: ignore[arg-type]

    summary, data = await tool.execute(
        ToolExecutionRequest(
            tool_name="query_database_diagnostics",
            parameters={"diagnostics": ["connection_sources", "long_sessions"]},
        ),
        make_context(),
    )

    assert summary == "95 active connections"
    assert client.invoke_payload is not None
    assert client.invoke_payload["target_kind"] == "mysql"
    assert client.invoke_payload["tools"] == [{"tool": "mysql.connection_overview", "params": {}}]
    assert data["selected_tools"] == ["mysql.connection_overview"]

    with pytest.raises(FlashDutyReadOnlyViolation, match="not read-only"):
        await tool.execute(
            ToolExecutionRequest(
                tool_name="query_database_diagnostics",
                parameters={"tools": [{"tool": "mysql.kill_session", "params": {"session_id": 1}}]},
            ),
            make_context(),
        )


def test_factory_registers_flashduty_source_and_tools(tmp_path: Path) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        runbook_pdf_dir=runbooks,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_metrics_ds_name="prod-prom",
    )

    runtime = build_runtime(settings)

    normalized = runtime.service.source_registry.normalize("flashduty", flashduty_alert_payload())
    assert normalized.source == "flashduty"
    assert isinstance(runtime.service.tool_registry.get("query_metrics"), FlashDutyDataSourceTool)
    assert runtime.service.strategy_provider.external_tool_timeout_seconds == 120  # type: ignore[attr-defined]


def test_flashduty_settings_require_official_endpoint_and_key_when_enabled(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        runbook_pdf_dir=runbooks,
        flashduty_enabled=True,
    )
    assert any("FLASHDUTY_APP_KEY" in issue for issue in settings.readiness_issues())

    with pytest.raises(ValueError, match="official HTTPS FlashDuty"):
        Settings(
            _env_file=None,
            ai_provider="fake",
            runbook_pdf_dir=runbooks,
            flashduty_base_url="https://example.test",
        )
