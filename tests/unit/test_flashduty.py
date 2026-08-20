from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.adapters.flashduty import (
    FlashDutyAlertContextTool,
    FlashDutyAlertDetailEnricher,
    FlashDutyAlertSourceAdapter,
    FlashDutyAPIError,
    FlashDutyChangesTool,
    FlashDutyClient,
    FlashDutyConfigurationError,
    FlashDutyDatabaseDiagnosticsTool,
    FlashDutyDataSourceTool,
    FlashDutyResponse,
    FlashDutySimilarIncidentsTool,
)
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import (
    InvestigationContext,
    Severity,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)

ALERT_ID = "663a1b2c3d4e5f6789abcdef"
INCIDENT_ID = "69da451ef77b1b51f40e83ee"


async def no_sleep(_seconds: float) -> None:
    return None


@pytest.mark.asyncio
async def test_client_uses_query_app_key_and_reports_unsupported_operations() -> None:
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
    with pytest.raises(FlashDutyConfigurationError, match="Unsupported FlashDuty operation"):
        await client.call("incident_ack", {"incident_id": INCIDENT_ID})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_name",
    [
        "mysql.killSession",
        "terminateConnection",
        "mysql.killsession",
        "mysql.terminateconnection",
        "mysql.restartServerStatus",
        "mysql.writeConfigReport",
        "mysql.session_action",
    ],
)
async def test_client_forwards_dynamic_tool_names_without_local_classification(
    tool_name: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"request_id": "req-tool", "data": {}})

    client = FlashDutyClient(
        "test-app-key",
        transport=httpx.MockTransport(handler),
    )

    payload = {
        "target_locator": "db-prod-01",
        "tools": [{"tool": tool_name, "params": {}}],
    }
    response = await client.call("monit_tools_invoke", payload)

    assert response.request_id == "req-tool"
    assert requests[0].url.path == "/monit/tools/invoke"
    assert json.loads(requests[0].content) == payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_name",
    [
        "net.tcp_ping",
        "os.overview",
        "mysql.connection_overview",
        "mysql.showProcesslist",
        "postgres.replicationStatus",
        "redis.health-check",
    ],
)
async def test_client_forwards_query_shaped_dynamic_tool_names(
    tool_name: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"request_id": "req-tool", "data": {}})

    client = FlashDutyClient(
        "test-app-key",
        transport=httpx.MockTransport(handler),
    )

    response = await client.call(
        "monit_tools_invoke",
        {
            "target_locator": "db-prod-01",
            "tools": [{"tool": tool_name, "params": {}}],
        },
    )

    assert response.request_id == "req-tool"
    assert len(requests) == 1


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
async def test_analysis_call_retries_recoverable_errors_without_count_limit() -> None:
    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts <= 4:
            return httpx.Response(
                503,
                json={
                    "request_id": f"retry-{attempts}",
                    "error": {"code": "Unavailable", "message": "try later"},
                },
            )
        return httpx.Response(
            200,
            json={"request_id": "recovered", "data": {"alert_id": ALERT_ID}},
        )

    client = FlashDutyClient(
        "test-app-key",
        max_retries=1,
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )

    response = await client.alert_info(ALERT_ID)

    assert response.request_id == "recovered"
    assert attempts == 5


@pytest.mark.asyncio
async def test_poll_call_keeps_finite_cycle_retry_policy() -> None:
    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            503,
            json={
                "request_id": f"poll-{attempts}",
                "error": {"code": "Unavailable", "message": "try next poll"},
            },
        )

    client = FlashDutyClient(
        "test-app-key",
        max_retries=2,
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )

    with pytest.raises(FlashDutyAPIError, match="Unavailable"):
        await client.list_alerts(start_time=1712650000, end_time=1712650300)

    assert attempts == 3


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
async def test_client_alert_list_uses_stable_created_at_order_for_start_time_window() -> None:
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
        is_active=None,
        by_updated_at=False,
    )

    assert request_body["orderby"] == "created_at"
    assert request_body["asc"] is True
    assert request_body["by_updated_at"] is False
    assert "is_active" not in request_body


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
    assert alert.attributes["flashduty_target_locator"] == "db-prod-01"
    assert alert.attributes["flashduty_target_kind"] == "mysql"
    assert alert.incident_fingerprint.startswith("incident-v1-")


def test_flashduty_alert_detail_prefers_label_endpoint_and_normalizes_queries() -> None:
    payload = flashduty_alert_payload()
    payload["data"]["alarm_host"] = "pg-prod-01"
    payload["data"]["alarm_port"] = "5432"
    payload["data"]["labels"] = {
        "env": "prd",
        "app_type": "PostgreSQL",
        "alarm_host": "ignored-label-host",
        "alarm_port": "15432",
        "db_name": "orders",
        "promql": "pg_stat_activity_count",
        "logql": '{service="postgres"} |= "deadlock"',
        "value": "95",
        "threshold": "90",
    }

    alert = FlashDutyAlertSourceAdapter({"production": ["prd"]}).normalize_detail(payload)

    assert alert.database is not None
    assert alert.database.engine == "postgresql"
    assert alert.database.instance == "ignored-label-host"
    assert alert.database.host == "ignored-label-host"
    assert alert.database.port == 15432
    assert alert.database.database == "orders"
    assert "alarm_host" not in alert.labels
    assert "alarm_port" not in alert.labels
    assert alert.attributes["flashduty_target_locator"] == "ignored-label-host"
    assert alert.attributes["flashduty_target_kind"] == "postgres"
    assert alert.attributes["flashduty_metrics"] == {
        "expr": "pg_stat_activity_count"
    }
    assert alert.attributes["flashduty_logs"] == {
        "expr": '{service="postgres"} |= "deadlock"'
    }
    assert alert.features["observed_value"] == "95"
    assert alert.features["threshold"] == "90"


def test_flashduty_alert_detail_uses_nested_alarm_endpoint() -> None:
    payload = flashduty_alert_payload()
    payload["data"].pop("alarm_host", None)
    payload["data"].pop("alarm_port", None)
    payload["data"]["labels"].update(
        {
            "alarm_host": "detail-label-host",
            "alarm_port": "3307",
        }
    )

    alert = FlashDutyAlertSourceAdapter().normalize_detail(payload)

    assert alert.database is not None
    assert alert.database.host == "detail-label-host"
    assert alert.database.port == 3307
    assert "alarm_host" not in alert.labels
    assert "alarm_port" not in alert.labels


def test_flashduty_alert_detail_falls_back_to_legacy_top_level_endpoint() -> None:
    payload = flashduty_alert_payload()
    payload["data"]["alarm_host"] = "legacy-detail-host"
    payload["data"]["alarm_port"] = "3308"

    alert = FlashDutyAlertSourceAdapter().normalize_detail(payload)

    assert alert.database is not None
    assert alert.database.host == "legacy-detail-host"
    assert alert.database.port == 3308


def test_flashduty_alert_detail_does_not_replace_invalid_label_port_with_legacy_value(
) -> None:
    payload = flashduty_alert_payload()
    payload["data"]["alarm_port"] = "3308"
    payload["data"]["labels"]["alarm_port"] = "70000"

    alert = FlashDutyAlertSourceAdapter().normalize_detail(payload)

    assert alert.database is not None
    assert alert.database.port is None


def test_flashduty_poll_item_cannot_define_database_endpoint() -> None:
    payload = flashduty_alert_payload()
    payload["data"]["title"] = "MySQL/mysql_slow_query/db-list:3307"
    payload["data"]["labels"].update(
        {
            "alarm_host": "db-list",
            "alarm_port": "3307",
            "host": "generic-host",
            "host_ip": "192.0.2.10",
        }
    )

    alert = FlashDutyAlertSourceAdapter().normalize(payload)

    assert alert.database is not None
    assert alert.database.host is None
    assert alert.database.port is None
    assert not ({"alarm_host", "alarm_port", "host", "host_ip"} & alert.labels.keys())


@pytest.mark.asyncio
async def test_flashduty_detail_enricher_preserves_identity_and_detail_endpoint() -> None:
    polled = flashduty_alert_payload()
    polled["data"]["title"] = "MySQL/mysql_slow_query/list-host:3307"
    polled["data"]["labels"].update(
        {"alarm_host": "list-host", "alarm_port": "3307"}
    )
    adapter = FlashDutyAlertSourceAdapter()
    alert = adapter.normalize(polled)
    local_id = alert.id

    class DetailClient:
        async def alert_info(self, alert_id: str) -> FlashDutyResponse:
            assert alert_id == ALERT_ID
            detail = flashduty_alert_payload()["data"]
            detail["labels"].update(
                {"alarm_host": "detail-host", "alarm_port": "3306"}
            )
            return FlashDutyResponse(request_id="req-detail", data=detail)

    enriched = await FlashDutyAlertDetailEnricher(  # type: ignore[arg-type]
        DetailClient(), adapter
    ).enrich(alert)

    assert enriched.id == local_id
    assert enriched.database is not None
    assert enriched.database.host == "detail-host"
    assert enriched.database.port == 3306
    assert enriched.attributes["flashduty_detail_loaded"] is True


@pytest.mark.asyncio
async def test_flashduty_detail_enricher_rejects_identity_mismatch() -> None:
    adapter = FlashDutyAlertSourceAdapter()
    alert = adapter.normalize(flashduty_alert_payload())

    class MismatchedClient:
        async def alert_info(self, _alert_id: str) -> FlashDutyResponse:
            detail = flashduty_alert_payload()["data"]
            detail["alert_id"] = "1234567890abcdef12345678"
            return FlashDutyResponse(request_id="req-detail", data=detail)

    with pytest.raises(Exception, match="identity does not match"):
        await FlashDutyAlertDetailEnricher(  # type: ignore[arg-type]
            MismatchedClient(), adapter
        ).enrich(alert)


def test_flashduty_alert_adapter_removes_slow_query_filter_note() -> None:
    payload = flashduty_alert_payload()
    signal = "数据库慢查询过多，五分钟内超过500个慢查询，触发阈值告警的值为: 646个"
    filter_note = "（已排除640个数据库管理平台采集数据用sql）"
    raw_text = f"{signal}{filter_note}"
    payload["data"]["title"] = "MySQL slow_query threshold"
    payload["data"]["description"] = raw_text
    payload["data"]["labels"].update(
        {"check": raw_text, "alarm_content": raw_text}
    )

    alert = FlashDutyAlertSourceAdapter().normalize(payload)

    assert alert.reason == signal
    assert alert.description == signal
    assert alert.labels["check"] == signal
    assert alert.labels["alarm_content"] == signal
    assert alert.features["alarm_content"] == signal
    assert alert.raw_payload["data"]["description"] == raw_text


def make_context() -> InvestigationContext:
    alert = FlashDutyAlertSourceAdapter({"production": ["prd"]}).normalize(
        flashduty_alert_payload()
    )
    return InvestigationContext(
        run_id=uuid4(),
        alert=alert,
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
                400,
                json={
                    "request_id": "req-feed-error",
                    "error": {"code": "InvalidRequest", "message": "invalid feed query"},
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
        self.target_payload: dict[str, Any] | None = None
        self.catalog_payload: dict[str, Any] | None = None
        self.invoke_payload: dict[str, Any] | None = None

    async def diagnose(self, payload: dict[str, Any]) -> Any:
        self.diagnose_payload = payload
        return FlashDutyResponse("req-diagnose", {"operation": "metric_trends"})

    async def targets(self, payload: dict[str, Any]) -> Any:
        self.target_payload = payload
        return FlashDutyResponse(
            "req-targets",
            {
                "items": [
                    {
                        "target_kind": "mysql",
                        "target_locator": "db-prod-01",
                    }
                ],
                "total": 1,
            },
        )

    async def tool_catalog(self, payload: dict[str, Any]) -> Any:
        self.catalog_payload = payload
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
                    {
                        "name": "mysql.killSession",
                        "description": "terminates a session",
                        "input_schema": {"required": ["session_id"]},
                    },
                    {
                        "name": "terminateConnection",
                        "description": "terminates a connection",
                        "input_schema": {"required": ["connection_id"]},
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


class RecordingRowsClient:
    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None

    async def query_rows(self, payload: dict[str, Any]) -> Any:
        self.payload = payload
        return FlashDutyResponse("req-rows", [])


class EmptyPlatformClient:
    async def similar_incidents(self, _incident_id: str, *, limit: int) -> Any:
        return FlashDutyResponse("req-similar-empty", {"items": []})

    async def changes(self, _payload: dict[str, Any]) -> Any:
        return FlashDutyResponse("req-changes-empty", {"items": [], "total": 0})


class UnavailableMonitorClient:
    async def targets(self, _payload: dict[str, Any]) -> Any:
        return FlashDutyResponse("req-targets-empty", {"items": [], "total": 0})

    async def tool_catalog(self, _payload: dict[str, Any]) -> Any:
        raise FlashDutyAPIError(
            "target is unavailable",
            code="target_unavailable",
            request_id="req-target-unavailable",
            status_code=200,
        )


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
async def test_raw_query_tool_forwards_sql_without_local_content_review() -> None:
    client = RecordingRowsClient()
    tool = FlashDutyDataSourceTool(
        "query_trace",
        client,  # type: ignore[arg-type]
    )

    result = await tool.execute(
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

    assert isinstance(result, ToolExecutionResult)
    assert result.status == ToolStatus.NO_DATA
    assert client.payload == {
        "ds_type": "mysql",
        "ds_name": "prod-mysql",
        "expr": "DELETE FROM sessions",
    }


@pytest.mark.asyncio
async def test_database_tool_discovers_and_invokes_catalog_tools() -> None:
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
    assert client.target_payload == {"keyword": "db-prod-01", "limit": 50}
    assert client.catalog_payload == {
        "target_locator": "db-prod-01",
        "target_kind": "mysql",
    }
    assert client.invoke_payload is not None
    assert client.invoke_payload["target_kind"] == "mysql"
    assert client.invoke_payload["tools"] == [{"tool": "mysql.connection_overview", "params": {}}]
    assert data["target_request_ids"] == ["req-targets"]
    assert data["selected_tools"] == ["mysql.connection_overview"]

    for tool_name in ("mysql.kill_session", "mysql.killSession", "terminateConnection"):
        await tool.execute(
            ToolExecutionRequest(
                tool_name="query_database_diagnostics",
                parameters={
                    "tools": [
                        {
                            "tool": tool_name,
                            "params": {"session_id": 1},
                        }
                    ]
                },
            ),
            make_context(),
        )
        assert client.invoke_payload is not None
        assert client.invoke_payload["tools"] == [
            {"tool": tool_name, "params": {"session_id": 1}}
        ]


@pytest.mark.asyncio
async def test_empty_flashduty_results_are_not_success_evidence() -> None:
    client = EmptyPlatformClient()

    similar = await FlashDutySimilarIncidentsTool(client).execute(  # type: ignore[arg-type]
        ToolExecutionRequest(tool_name="query_similar_incidents"),
        make_context(),
    )
    changes = await FlashDutyChangesTool(  # type: ignore[arg-type]
        client,
        channel_ids=[7],
    ).execute(
        ToolExecutionRequest(tool_name="query_changes"),
        make_context(),
    )
    unscoped_changes = await FlashDutyChangesTool(  # type: ignore[arg-type]
        client
    ).execute(
        ToolExecutionRequest(tool_name="query_changes"),
        make_context(),
    )

    assert isinstance(similar, ToolExecutionResult)
    assert similar.status == ToolStatus.NO_DATA
    assert similar.structured_data["items"] == []
    assert isinstance(changes, ToolExecutionResult)
    assert changes.status == ToolStatus.NO_DATA
    assert changes.structured_data["items"] == []
    assert changes.structured_data["query_window"]["channel_ids"] == [7]
    assert isinstance(unscoped_changes, ToolExecutionResult)
    assert unscoped_changes.status == ToolStatus.SKIPPED
    assert unscoped_changes.structured_data["reason_code"] == "channel_scope_missing"


@pytest.mark.asyncio
async def test_unavailable_monitor_target_is_skipped_as_missing_capability() -> None:
    outcome = await FlashDutyDatabaseDiagnosticsTool(  # type: ignore[arg-type]
        UnavailableMonitorClient()
    ).execute(
        ToolExecutionRequest(tool_name="query_database_diagnostics"),
        make_context(),
    )

    assert isinstance(outcome, ToolExecutionResult)
    assert outcome.status == ToolStatus.SKIPPED
    assert outcome.structured_data == {
        "reason_code": "monitor_target_unavailable",
        "vendor_error_code": "target_unavailable",
        "request_id": "req-target-unavailable",
    }


def test_factory_registers_flashduty_source_and_tools(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_poll_channel_ids=[7],
        flashduty_monitors_enabled=True,
        flashduty_changes_enabled=True,
        flashduty_metrics_ds_name="prod-prom",
    )

    runtime = build_runtime(settings)

    normalized = runtime.service.source_registry.normalize("flashduty", flashduty_alert_payload())
    assert normalized.source == "flashduty"
    assert isinstance(runtime.service.tool_registry.get("query_metrics"), FlashDutyDataSourceTool)
    assert isinstance(runtime.service.tool_registry.get("query_changes"), FlashDutyChangesTool)
    visible_specs = {
        spec.name: spec for spec in runtime.service.tool_registry.available_specs()
    }
    assert not hasattr(visible_specs["query_metrics"], "read_only")
    assert not hasattr(visible_specs["query_changes"], "read_only")


def test_factory_disables_unaudited_flashduty_capabilities_by_default(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(
        Settings(
            _env_file=None,
            ai_provider="fake",
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'default-capabilities.db'}",
            flashduty_enabled=True,
            flashduty_app_key="test-app-key",
        )
    )

    available = runtime.service.tool_registry.available_names()
    assert "alert_context" in available
    assert "query_similar_incidents" in available
    assert "query_changes" not in available
    assert "query_database_diagnostics" not in available
    assert "query_metrics" not in available


def test_flashduty_settings_require_official_endpoint_and_key_when_enabled(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
    )
    assert any("FLASHDUTY_APP_KEY" in issue for issue in settings.readiness_issues())

    with pytest.raises(ValueError, match="official HTTPS FlashDuty"):
        Settings(
            _env_file=None,
            ai_provider="fake",
            flashduty_base_url="https://example.test",
        )
