from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

import httpx

from app.adapters.alert_sources import (
    CanonicalAlertPayload,
    CanonicalAlertSourceAdapter,
    incident_fingerprint,
)
from app.application.sanitization import sanitize_text
from app.domain.errors import InvalidAlertPayloadError
from app.domain.models import (
    DatabaseTarget,
    InvestigationContext,
    NormalizedAlert,
    ToolExecutionRequest,
)


class FlashDutyError(RuntimeError):
    """Base error for the read-only FlashDuty integration."""


class FlashDutyConfigurationError(FlashDutyError):
    """The alert or deployment is missing data required for a read query."""


class FlashDutyReadOnlyViolation(FlashDutyError):
    """A caller attempted to use an operation outside the read-only allowlist."""


class FlashDutyAPIError(FlashDutyError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "FlashDutyError",
        request_id: str | None = None,
        status_code: int | None = None,
    ) -> None:
        safe_message = sanitize_text(message)[:1000]
        details = [code]
        if request_id:
            details.append(f"request_id={request_id}")
        if status_code is not None:
            details.append(f"http_status={status_code}")
        super().__init__(f"FlashDuty {' '.join(details)}: {safe_message}")
        self.code = code
        self.request_id = request_id
        self.status_code = status_code


@dataclass(frozen=True)
class FlashDutyResponse:
    request_id: str
    data: Any


@dataclass(frozen=True)
class _ReadOperation:
    method: Literal["GET", "POST"]
    path: str


# FlashDuty query endpoints mostly use POST.  The allowlist is semantic rather
# than HTTP-verb based: no create/update/delete/ack/resolve operation can pass it.
READ_ONLY_OPERATIONS: Final[Mapping[str, _ReadOperation]] = {
    "incident_list": _ReadOperation("POST", "/incident/list"),
    "incident_info": _ReadOperation("POST", "/incident/info"),
    "incident_list_by_ids": _ReadOperation("POST", "/incident/list-by-ids"),
    "incident_alert_list": _ReadOperation("POST", "/incident/alert/list"),
    "incident_feed": _ReadOperation("POST", "/incident/feed"),
    "incident_past_list": _ReadOperation("POST", "/incident/past/list"),
    "alert_list": _ReadOperation("POST", "/alert/list"),
    "alert_info": _ReadOperation("POST", "/alert/info"),
    "alert_list_by_ids": _ReadOperation("POST", "/alert/list-by-ids"),
    "alert_event_list": _ReadOperation("POST", "/alert/event/list"),
    "alert_feed": _ReadOperation("POST", "/alert/feed"),
    "raw_alert_event_list": _ReadOperation("POST", "/alert-event/list"),
    "change_list": _ReadOperation("POST", "/change/list"),
    "monit_query_rows": _ReadOperation("POST", "/monit/query/rows"),
    "monit_query_diagnose": _ReadOperation("POST", "/monit/query/diagnose"),
    "monit_tools_catalog": _ReadOperation("POST", "/monit/tools/catalog"),
    "monit_tools_invoke": _ReadOperation("POST", "/monit/tools/invoke"),
    "monit_targets": _ReadOperation("POST", "/monit/targets"),
}

_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")
_METRIC_NAME = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")
_SUPPORTED_ROW_DATA_SOURCES = {
    "prometheus",
    "loki",
    "victorialogs",
    "sls",
    "elasticsearch",
    "mysql",
    "postgres",
    "oracle",
    "clickhouse",
}
_SQL_DATA_SOURCES = {"mysql", "postgres", "oracle", "clickhouse"}
_SQL_READ_PREFIX = re.compile(r"^(select|show|describe|desc|explain)\b", re.IGNORECASE)
_SQL_MUTATION = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|replace|merge|"
    r"call|execute|copy|vacuum|set|reset)\b",
    re.IGNORECASE,
)


class FlashDutyClient:
    """Minimal client for the project's explicitly approved read-only operations."""

    def __init__(
        self,
        app_key: str,
        *,
        base_url: str = "https://api.flashcat.cloud",
        timeout_seconds: float = 40,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not app_key.strip():
            raise FlashDutyConfigurationError("FLASHDUTY_APP_KEY is not configured")
        self._app_key = app_key.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._transport = transport
        self._sleep = sleep

    async def call(
        self, operation: str, payload: Mapping[str, Any] | None = None
    ) -> FlashDutyResponse:
        spec = READ_ONLY_OPERATIONS.get(operation)
        if spec is None:
            raise FlashDutyReadOnlyViolation(
                f"Operation {operation!r} is not in the FlashDuty read-only allowlist"
            )
        request_payload = dict(payload or {})
        self._validate_read_only_payload(operation, request_payload)

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout_seconds),
            transport=self._transport,
            follow_redirects=False,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        ) as client:
            response: httpx.Response | None = None
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.request(
                        spec.method,
                        spec.path,
                        params={"app_key": self._app_key},
                        json=request_payload,
                    )
                except httpx.TransportError as exc:
                    if attempt >= self.max_retries:
                        raise FlashDutyAPIError(type(exc).__name__, code="NetworkError") from exc
                    await self._sleep(min(2**attempt, 10))
                    continue

                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < self.max_retries:
                        await self._sleep(self._retry_delay(response, attempt))
                        continue
                break

        if response is None:  # pragma: no cover - loop contract guard
            raise FlashDutyAPIError("No response received", code="NetworkError")
        return self._decode_response(response)

    @staticmethod
    def _validate_read_only_payload(operation: str, payload: Mapping[str, Any]) -> None:
        if operation == "monit_query_rows":
            ds_type = payload.get("ds_type")
            expression = payload.get("expr")
            if isinstance(ds_type, str) and isinstance(expression, str):
                _validate_read_only_expression(ds_type, expression, payload.get("args"))
        if operation != "monit_tools_invoke":
            return
        tools = payload.get("tools")
        if not isinstance(tools, list):
            return
        for item in tools:
            name = item.get("tool") if isinstance(item, dict) else None
            if isinstance(name, str) and not _is_read_only_tool_name(name):
                raise FlashDutyReadOnlyViolation(f"monit-agent tool is not read-only: {name}")

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After", "")
        try:
            return min(max(float(retry_after), 0), 10)
        except ValueError:
            return min(2**attempt, 10)

    def _decode_response(self, response: httpx.Response) -> FlashDutyResponse:
        try:
            body = response.json()
        except ValueError as exc:
            raise FlashDutyAPIError(
                "Response was not valid JSON",
                code="InvalidResponse",
                status_code=response.status_code,
            ) from exc
        if not isinstance(body, dict):
            raise FlashDutyAPIError(
                "Response envelope was not an object",
                code="InvalidResponse",
                status_code=response.status_code,
            )

        request_id = str(
            body.get("request_id") or response.headers.get("Flashcat-Request-Id") or "unknown"
        )
        error = body.get("error")
        if response.is_error or isinstance(error, dict):
            error = error if isinstance(error, dict) else {}
            raise FlashDutyAPIError(
                self._safe_message(
                    str(error.get("message") or response.reason_phrase or "Request failed")
                ),
                code=str(error.get("code") or f"HTTP{response.status_code}"),
                request_id=request_id,
                status_code=response.status_code,
            )
        if "data" not in body:
            raise FlashDutyAPIError(
                "Success envelope did not contain data",
                code="InvalidResponse",
                request_id=request_id,
                status_code=response.status_code,
            )
        return FlashDutyResponse(request_id=request_id, data=body["data"])

    def _safe_message(self, value: str) -> str:
        return value.replace(self._app_key, "***REDACTED***")

    @staticmethod
    def _raise_business_error(response: FlashDutyResponse) -> FlashDutyResponse:
        if not isinstance(response.data, dict):
            return response
        error = response.data.get("error")
        if not isinstance(error, dict):
            return response
        raise FlashDutyAPIError(
            str(error.get("message") or "Read operation failed"),
            code=str(error.get("code") or "BusinessError"),
            request_id=response.request_id,
            status_code=200,
        )

    async def alert_info(self, alert_id: str) -> FlashDutyResponse:
        _require_object_id(alert_id, "alert_id")
        return await self.call("alert_info", {"alert_id": alert_id})

    async def list_alerts(
        self,
        *,
        start_time: int,
        end_time: int,
        limit: int = 100,
        search_after_ctx: str | None = None,
        channel_ids: list[int] | None = None,
        integration_ids: list[int] | None = None,
        is_active: bool | None = True,
        by_updated_at: bool = True,
    ) -> FlashDutyResponse:
        if end_time <= start_time:
            raise FlashDutyConfigurationError("end_time must be greater than start_time")
        if end_time - start_time > 31 * 86400:
            raise FlashDutyConfigurationError("FlashDuty alert list window cannot exceed 31 days")
        payload: dict[str, Any] = {
            "start_time": start_time,
            "end_time": end_time,
            "limit": min(max(limit, 1), 100),
            "orderby": "updated_at",
            "asc": True,
            "by_updated_at": by_updated_at,
        }
        if search_after_ctx:
            payload["search_after_ctx"] = search_after_ctx
        else:
            payload["p"] = 1
        if channel_ids:
            payload["channel_ids"] = channel_ids
        if integration_ids:
            payload["integration_ids"] = integration_ids
        if is_active is not None:
            payload["is_active"] = is_active
        return await self.call("alert_list", payload)

    async def alert_events(self, alert_id: str, *, limit: int = 20) -> FlashDutyResponse:
        _require_object_id(alert_id, "alert_id")
        return await self.call(
            "alert_event_list",
            {"alert_id": alert_id, "p": 1, "limit": min(max(limit, 1), 100), "asc": False},
        )

    async def alert_feed(self, alert_id: str, *, limit: int = 20) -> FlashDutyResponse:
        _require_object_id(alert_id, "alert_id")
        return await self.call(
            "alert_feed",
            {"alert_id": alert_id, "p": 1, "limit": min(max(limit, 1), 100), "asc": False},
        )

    async def incident_info(self, incident_id: str) -> FlashDutyResponse:
        _require_object_id(incident_id, "incident_id")
        return await self.call("incident_info", {"incident_id": incident_id})

    async def incident_feed(self, incident_id: str, *, limit: int = 20) -> FlashDutyResponse:
        _require_object_id(incident_id, "incident_id")
        return await self.call(
            "incident_feed",
            {"incident_id": incident_id, "p": 1, "limit": min(max(limit, 1), 100), "asc": False},
        )

    async def incident_alerts(self, incident_id: str, *, limit: int = 20) -> FlashDutyResponse:
        _require_object_id(incident_id, "incident_id")
        return await self.call(
            "incident_alert_list",
            {
                "incident_id": incident_id,
                "p": 1,
                "limit": min(max(limit, 1), 1000),
                "include_events": False,
            },
        )

    async def similar_incidents(self, incident_id: str, *, limit: int = 5) -> FlashDutyResponse:
        _require_object_id(incident_id, "incident_id")
        return await self.call(
            "incident_past_list",
            {"incident_id": incident_id, "limit": min(max(limit, 1), 100)},
        )

    async def changes(self, payload: Mapping[str, Any]) -> FlashDutyResponse:
        return await self.call("change_list", payload)

    async def query_rows(self, payload: Mapping[str, Any]) -> FlashDutyResponse:
        return self._raise_business_error(await self.call("monit_query_rows", payload))

    async def diagnose(self, payload: Mapping[str, Any]) -> FlashDutyResponse:
        return self._raise_business_error(await self.call("monit_query_diagnose", payload))

    async def targets(self, payload: Mapping[str, Any]) -> FlashDutyResponse:
        return self._raise_business_error(await self.call("monit_targets", payload))

    async def tool_catalog(self, payload: Mapping[str, Any]) -> FlashDutyResponse:
        return self._raise_business_error(await self.call("monit_tools_catalog", payload))

    async def invoke_tools(self, payload: Mapping[str, Any]) -> FlashDutyResponse:
        return self._raise_business_error(await self.call("monit_tools_invoke", payload))


def _require_object_id(value: str, field: str) -> None:
    if not _OBJECT_ID.fullmatch(value):
        raise FlashDutyConfigurationError(f"{field} must be a 24-character ObjectID")


def _validate_read_only_expression(ds_type: str, expression: str, args: Any = None) -> None:
    is_sql = ds_type in _SQL_DATA_SOURCES or (
        ds_type == "elasticsearch" and isinstance(args, dict) and args.get("es.type") == "sql"
    )
    if not is_sql:
        return
    statement = expression.strip()
    without_terminal_semicolon = statement[:-1].rstrip() if statement.endswith(";") else statement
    if ";" in without_terminal_semicolon:
        raise FlashDutyReadOnlyViolation("Multiple SQL statements are not allowed")
    if not _SQL_READ_PREFIX.match(without_terminal_semicolon) or _SQL_MUTATION.search(
        without_terminal_semicolon
    ):
        raise FlashDutyReadOnlyViolation(
            "FlashDuty SQL diagnostics allow SELECT/SHOW/DESCRIBE/EXPLAIN only"
        )


class FlashDutyAlertSourceAdapter:
    """Normalize `/alert/info`, `/alert/list`, or Alert Webhook data."""

    source = "flashduty"

    def __init__(self, environment_aliases: dict[str, list[str]] | None = None) -> None:
        self._canonical = CanonicalAlertSourceAdapter(environment_aliases)

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert:
        request_id: str | None = None
        item: Any = payload
        if isinstance(payload.get("error"), dict):
            raise InvalidAlertPayloadError("FlashDuty response contains an error")
        if "data" in payload:
            request_id = str(payload.get("request_id") or "") or None
            item = payload["data"]
        elif "alert" in payload:
            # Official Alert Webhook envelope. event_id is the delivery id used
            # for retry de-duplication; alert_id remains the stable local identity.
            request_id = str(payload.get("event_id") or "") or None
            item = payload["alert"]
        if not isinstance(item, dict):
            raise InvalidAlertPayloadError("FlashDuty alert payload must contain an object")

        alert_id = item.get("alert_id") or item.get("event_id")
        if not isinstance(alert_id, str) or not _OBJECT_ID.fullmatch(alert_id):
            raise InvalidAlertPayloadError("FlashDuty alert_id must be a 24-character ObjectID")
        title = str(item.get("title") or "").strip()
        if not title:
            raise InvalidAlertPayloadError("FlashDuty alert title is required")
        raw_severity = str(
            item.get("alert_severity")
            or item.get("event_severity")
            or item.get("alert_status")
            or item.get("event_status")
            or ""
        ).strip()
        severity = {
            "critical": "CRITICAL",
            "warning": "WARNING",
            "info": "INFO",
            # FlashDuty uses Ok for a recovery event. The local model deliberately
            # has only three levels, so recovery is retained in raw_severity/status
            # while its notification priority maps to INFO.
            "ok": "INFO",
        }.get(raw_severity.casefold())
        if severity is None:
            raise InvalidAlertPayloadError(
                "FlashDuty severity must be Critical, Warning, Info, or Ok"
            )

        raw_labels = item.get("labels") or {}
        if not isinstance(raw_labels, dict):
            raise InvalidAlertPayloadError("FlashDuty labels must be an object")
        labels = {str(key): str(value) for key, value in raw_labels.items()}
        incident = item.get("incident") if isinstance(item.get("incident"), dict) else {}
        incident_id = incident.get("incident_id") or item.get("incident_id")
        if incident_id is not None and (
            not isinstance(incident_id, str) or not _OBJECT_ID.fullmatch(incident_id)
        ):
            raise InvalidAlertPayloadError("FlashDuty incident_id must be a 24-character ObjectID")

        occurred_at = item.get("start_time") or item.get("event_time")
        if not isinstance(occurred_at, (int, float)):
            raise InvalidAlertPayloadError("FlashDuty start_time or event_time is required")

        database_values = {
            "engine": labels.get("database_engine")
            or labels.get("db_type")
            or labels.get("engine"),
            "instance": labels.get("instance") or labels.get("resource") or labels.get("host"),
            "database": labels.get("database") or labels.get("db"),
            "host": labels.get("host"),
        }
        database = (
            DatabaseTarget(**database_values)
            if any(value for value in database_values.values())
            else None
        )
        reason = (
            labels.get("check")
            or labels.get("alertname")
            or labels.get("reason")
            or str(item.get("alert_key") or title)
        )
        attributes: dict[str, Any] = {
            "flashduty_alert_id": alert_id,
            "flashduty_incident_id": incident_id,
            "flashduty_request_id": request_id,
            "integration_id": item.get("integration_id") or item.get("data_source_id"),
            "integration_name": item.get("integration_name")
            or item.get("data_source_name"),
            "integration_type": item.get("integration_type")
            or item.get("data_source_type"),
            "channel_id": item.get("channel_id"),
            "channel_name": item.get("channel_name"),
            "flashduty_webhook_event_id": payload.get("event_id"),
            "flashduty_webhook_event_type": payload.get("event_type"),
        }
        for key in (
            "flashduty_metrics",
            "flashduty_logs",
            "flashduty_trace",
            "flashduty_endpoint_errors",
        ):
            if isinstance(item.get(key), dict):
                attributes[key] = item[key]

        mapped = {
            "external_id": alert_id,
            "environment": labels.get("environment") or labels.get("env"),
            "service_name": (
                labels.get("service")
                or labels.get("app")
                or labels.get("application")
                or labels.get("resource")
            ),
            "alert_type": reason,
            "metric_name": labels.get("metric") or labels.get("metric_name"),
            "severity": severity,
            "alert_name": labels.get("alertname") or labels.get("alert_name") or reason,
            "resource_type": labels.get("resource_type")
            or item.get("integration_type")
            or item.get("data_source_type"),
            "cluster": labels.get("cluster"),
            "alarm_type": labels.get("alarm_type"),
            "title": title,
            "reason": reason,
            "description": str(item.get("description") or ""),
            "occurred_at": occurred_at,
            "database": database,
            "features": {
                "alert_status": item.get("alert_status") or item.get("event_status"),
                "event_count": item.get("event_cnt"),
                "last_time": item.get("last_time"),
                "end_time": item.get("end_time"),
            },
            "labels": labels,
            "attributes": attributes,
        }
        normalized = self._canonical.normalize(mapped)
        parsed = CanonicalAlertPayload.model_validate(mapped)
        fingerprint = incident_fingerprint(
            self.source,
            parsed,
            environment=normalized.environment,
            service_name=normalized.service_name,
            alert_type=normalized.alert_type,
        )
        return normalized.model_copy(
            update={
                "source": self.source,
                "raw_severity": raw_severity,
                "incident_fingerprint": fingerprint,
                "raw_payload": payload,
            }
        )


def _local_alert_context(alert: NormalizedAlert) -> dict[str, Any]:
    return {
        "severity": alert.severity.value,
        "raw_severity": alert.raw_severity,
        "environment": alert.environment,
        "service_name": alert.service_name,
        "alert_type": alert.alert_type,
        "metric_name": alert.metric_name,
        "features": alert.features,
        "database": alert.database.model_dump(mode="json") if alert.database else None,
        "occurred_at": alert.occurred_at.isoformat(),
    }


def _flashduty_identifier(alert: NormalizedAlert, name: str) -> str | None:
    value = alert.attributes.get(name)
    if isinstance(value, str) and value:
        return value
    if name == "flashduty_alert_id" and alert.source == "flashduty":
        return alert.external_id
    return None


class FlashDutyAlertContextTool:
    name = "alert_context"
    source_system = "alert_platform"

    def __init__(self, client: FlashDutyClient, *, item_limit: int = 20) -> None:
        self.client = client
        self.item_limit = min(max(item_limit, 1), 100)

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        alert = context.alert
        alert_id = _flashduty_identifier(alert, "flashduty_alert_id")
        if not alert_id:
            return (
                "已采集告警事件自带的上下文；当前事件没有 FlashDuty alert_id。",
                _local_alert_context(alert),
            )

        info = await self.client.alert_info(alert_id)
        events_result, feed_result = await asyncio.gather(
            self.client.alert_events(alert_id, limit=self.item_limit),
            self.client.alert_feed(alert_id, limit=self.item_limit),
            return_exceptions=True,
        )
        incident_id = _flashduty_identifier(alert, "flashduty_incident_id")
        if not incident_id and isinstance(info.data, dict):
            incident = info.data.get("incident")
            if isinstance(incident, dict) and isinstance(incident.get("incident_id"), str):
                incident_id = incident["incident_id"]

        incident_data: dict[str, Any] | None = None
        request_ids = {"alert_info": info.request_id}
        partial_errors: dict[str, str] = {}

        def optional_data(name: str, result: Any) -> Any:
            if isinstance(result, Exception):
                partial_errors[name] = type(result).__name__
                return None
            if not isinstance(result, FlashDutyResponse):
                partial_errors[name] = "InvalidResponse"
                return None
            request_ids[name] = result.request_id
            return result.data

        events_data = optional_data("alert_events", events_result)
        feed_data = optional_data("alert_feed", feed_result)
        if incident_id:
            incident_results = await asyncio.gather(
                self.client.incident_info(incident_id),
                self.client.incident_feed(incident_id, limit=self.item_limit),
                self.client.incident_alerts(incident_id, limit=self.item_limit),
                return_exceptions=True,
            )
            incident_data = {
                "info": optional_data("incident_info", incident_results[0]),
                "feed": optional_data("incident_feed", incident_results[1]),
                "alerts": optional_data("incident_alerts", incident_results[2]),
            }

        return (
            (
                "已通过 FlashDuty 只读接口补全告警和关联故障上下文。"
                if not partial_errors
                else "已取得 FlashDuty 核心告警详情；部分辅助只读查询暂不可用。"
            ),
            {
                "local": _local_alert_context(alert),
                "flashduty": {
                    "request_ids": request_ids,
                    "partial_errors": partial_errors,
                    "alert": info.data,
                    "events": events_data,
                    "feed": feed_data,
                    "incident": incident_data,
                },
            },
        )


class FlashDutySimilarIncidentsTool:
    name = "query_similar_incidents"
    source_system = "alert_platform"

    def __init__(self, client: FlashDutyClient) -> None:
        self.client = client

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        incident_id = request.parameters.get("incident_id") or _flashduty_identifier(
            context.alert, "flashduty_incident_id"
        )
        if not isinstance(incident_id, str):
            raise FlashDutyConfigurationError(
                "query_similar_incidents requires a FlashDuty incident_id"
            )
        limit = request.parameters.get("limit", 5)
        limit = int(limit) if isinstance(limit, (int, str)) else 5
        response = await self.client.similar_incidents(incident_id, limit=limit)
        items = response.data.get("items", []) if isinstance(response.data, dict) else []
        return (
            f"FlashDuty 返回 {len(items)} 条历史相似故障；历史记录仅作为调查线索。",
            {"request_id": response.request_id, "items": items},
        )


class FlashDutyChangesTool:
    name = "query_changes"
    source_system = "alert_platform"

    def __init__(self, client: FlashDutyClient) -> None:
        self.client = client

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        parameters = request.parameters
        occurred = int(context.alert.occurred_at.timestamp())
        window = int(parameters.get("window_seconds", 1800))
        payload: dict[str, Any] = {
            "start_time": occurred - min(max(window, 60), 21600),
            "end_time": occurred + min(max(window, 60), 21600),
            "p": 1,
            "limit": min(max(int(parameters.get("limit", 20)), 1), 100),
            "orderby": "start_time",
            "asc": False,
            "include_events": False,
        }
        query = parameters.get("query") or context.alert.service_name
        if isinstance(query, str) and query and query != "unknown":
            payload["query"] = query
        response = await self.client.changes(payload)
        items = response.data.get("items", []) if isinstance(response.data, dict) else []
        return (
            f"FlashDuty 在告警时间窗内返回 {len(items)} 条变更记录。",
            {"request_id": response.request_id, "query_window": payload, "items": items},
        )


def _merged_query_config(
    tool_name: str,
    request: ToolExecutionRequest,
    alert: NormalizedAlert,
    defaults: Mapping[str, Any],
) -> dict[str, Any]:
    suffix = {
        "query_metrics": "metrics",
        "query_logs": "logs",
        "query_trace": "trace",
        "query_endpoint_errors": "endpoint_errors",
    }[tool_name]
    config = dict(defaults)
    alert_config = alert.attributes.get(f"flashduty_{suffix}")
    if isinstance(alert_config, dict):
        config.update(alert_config)
    nested = request.parameters.get("flashduty")
    if isinstance(nested, dict):
        config.update(nested)
    config.update(request.parameters)
    return config


class FlashDutyDataSourceTool:
    source_system = "flashduty_monitors"

    def __init__(
        self,
        name: Literal["query_metrics", "query_logs", "query_trace", "query_endpoint_errors"],
        client: FlashDutyClient,
        *,
        defaults: Mapping[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.client = client
        self.defaults = dict(defaults or {})

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        config = _merged_query_config(self.name, request, context.alert, self.defaults)
        if self.name in {"query_metrics", "query_logs"}:
            return await self._diagnose(config, context)
        return await self._query_rows(config)

    async def _diagnose(
        self, config: Mapping[str, Any], context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        is_metrics = self.name == "query_metrics"
        ds_type = str(config.get("ds_type") or ("prometheus" if is_metrics else "loki"))
        ds_name = str(config.get("ds_name") or "").strip()
        query = config.get("expr") or config.get("query_expr")
        if not query and is_metrics and context.alert.metric_name:
            if _METRIC_NAME.fullmatch(context.alert.metric_name):
                query = context.alert.metric_name
        if not ds_name or not isinstance(query, str) or not query.strip():
            raise FlashDutyConfigurationError(
                f"{self.name} requires ds_name and expr (or a safe alert metric_name)"
            )
        if is_metrics and ds_type != "prometheus":
            raise FlashDutyConfigurationError("query_metrics supports ds_type=prometheus only")
        if not is_metrics and ds_type not in {"loki", "victorialogs"}:
            raise FlashDutyConfigurationError(
                "query_logs supports ds_type=loki or victorialogs only"
            )

        occurred = int(context.alert.occurred_at.timestamp())
        time_range = config.get("time_range")
        if not isinstance(time_range, dict):
            time_range = {"start": occurred - 900, "end": occurred + 300}
        payload: dict[str, Any] = {
            "ds_type": ds_type,
            "ds_name": ds_name,
            "operation": "metric_trends" if is_metrics else "log_patterns",
            "time_range": time_range,
            "input": {"query": query.strip()},
        }
        for key in ("methods", "options", "account_id"):
            if key in config:
                payload[key] = config[key]
        response = await self.client.diagnose(payload)
        return (
            (
                "FlashDuty Monitors 已返回只读指标趋势诊断。"
                if is_metrics
                else "FlashDuty Monitors 已返回只读日志模式诊断。"
            ),
            {
                "request_id": response.request_id,
                "operation": payload["operation"],
                "data": response.data,
            },
        )

    async def _query_rows(self, config: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        ds_type = str(config.get("ds_type") or "").strip()
        ds_name = str(config.get("ds_name") or "").strip()
        expr = config.get("expr") or config.get("query_expr")
        if (
            ds_type not in _SUPPORTED_ROW_DATA_SOURCES
            or not ds_name
            or not isinstance(expr, str)
            or not expr.strip()
        ):
            raise FlashDutyConfigurationError(
                f"{self.name} requires a supported ds_type, ds_name, and expr"
            )
        payload: dict[str, Any] = {
            "ds_type": ds_type,
            "ds_name": ds_name,
            "expr": expr.strip(),
        }
        for key in ("delay_seconds", "args", "account_id"):
            if key in config:
                payload[key] = config[key]
        _validate_read_only_expression(ds_type, payload["expr"], payload.get("args"))
        response = await self.client.query_rows(payload)
        row_count = len(response.data) if isinstance(response.data, list) else 0
        return (
            f"FlashDuty Monitors 已通过只读接口返回 {row_count} 行原始查询结果。",
            {"request_id": response.request_id, "rows": response.data},
        )


_DIAGNOSTIC_TERMS: Final[Mapping[str, set[str]]] = {
    "connection_sources": {"connection", "connections", "client", "processlist", "session"},
    "long_sessions": {"long", "processlist", "query", "session", "thread"},
    "locks": {"lock", "locks", "deadlock", "blocking"},
    "replication": {"replication", "replica", "slave", "lag"},
    "overview": {"overview", "health", "status"},
}
_MUTATING_TOOL_TOKENS: Final[set[str]] = {
    "alter",
    "create",
    "delete",
    "disable",
    "drop",
    "enable",
    "grant",
    "kill",
    "remove",
    "reset",
    "restart",
    "revoke",
    "set",
    "terminate",
    "truncate",
    "update",
    "write",
}


def _is_read_only_tool_name(name: str) -> bool:
    tokens = {item for item in re.split(r"[^a-z0-9]+", name.casefold()) if item}
    return not tokens.intersection(_MUTATING_TOOL_TOKENS)


class FlashDutyDatabaseDiagnosticsTool:
    name = "query_database_diagnostics"
    source_system = "flashduty_monitors"

    def __init__(self, client: FlashDutyClient) -> None:
        self.client = client

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        parameters = request.parameters
        alert = context.alert
        target_locator = (
            parameters.get("target_locator")
            or parameters.get("instance")
            or alert.attributes.get("flashduty_target_locator")
            or (alert.database.instance if alert.database else None)
            or (alert.database.host if alert.database else None)
        )
        if not isinstance(target_locator, str) or not target_locator.strip():
            raise FlashDutyConfigurationError(
                "query_database_diagnostics requires target_locator or database instance"
            )
        target_kind = parameters.get("target_kind") or alert.attributes.get("flashduty_target_kind")
        if not target_kind and alert.database and alert.database.engine:
            if alert.database.engine.casefold() == "mysql":
                target_kind = "mysql"

        catalog_payload: dict[str, Any] = {
            "target_locator": target_locator,
            "include_output_shape": False,
        }
        if isinstance(target_kind, str) and target_kind:
            catalog_payload["target_kind"] = target_kind
        catalog = await self.client.tool_catalog(catalog_payload)
        catalog_data = catalog.data if isinstance(catalog.data, dict) else {}
        tools = catalog_data.get("tools")
        if not isinstance(tools, list):
            raise FlashDutyAPIError(
                "Tool catalog did not contain tools",
                code="InvalidResponse",
                request_id=catalog.request_id,
            )

        calls = self._select_calls(parameters, tools)
        if not calls:
            raise FlashDutyConfigurationError(
                "No compatible read-only monit-agent tool matched the requested diagnostics"
            )
        invoke_payload: dict[str, Any] = {
            "target_locator": target_locator,
            "tools": calls[:8],
        }
        resolved_target = catalog_data.get("target")
        if isinstance(resolved_target, dict) and isinstance(resolved_target.get("kind"), str):
            invoke_payload["target_kind"] = resolved_target["kind"]
        elif isinstance(target_kind, str) and target_kind:
            invoke_payload["target_kind"] = target_kind

        invoked = await self.client.invoke_tools(invoke_payload)
        invoked_data = invoked.data if isinstance(invoked.data, dict) else {}
        results = invoked_data.get("results")
        if not isinstance(results, list):
            raise FlashDutyAPIError(
                "Tool invocation did not contain results",
                code="InvalidResponse",
                request_id=invoked.request_id,
            )
        successful = [
            item
            for item in results
            if isinstance(item, dict) and "error" not in item and "data" in item
        ]
        if not successful:
            first_error = next(
                (
                    item.get("error")
                    for item in results
                    if isinstance(item, dict) and isinstance(item.get("error"), dict)
                ),
                {},
            )
            raise FlashDutyAPIError(
                str(first_error.get("message") or "All monit-agent tools failed"),
                code=str(first_error.get("code") or "ToolInvocationFailed"),
                request_id=invoked.request_id,
                status_code=200,
            )
        summaries = [
            str(item["summary"]) for item in successful if isinstance(item.get("summary"), str)
        ]
        return (
            "；".join(summaries)[:2000]
            or f"FlashDuty Monitors 成功执行 {len(successful)} 个只读诊断工具。",
            {
                "catalog_request_id": catalog.request_id,
                "invoke_request_id": invoked.request_id,
                "target": invoked_data.get("target") or resolved_target,
                "selected_tools": [item["tool"] for item in calls],
                "results": results,
            },
        )

    @staticmethod
    def _select_calls(
        parameters: Mapping[str, Any], catalog_tools: list[Any]
    ) -> list[dict[str, Any]]:
        available = {
            str(item.get("name")): item
            for item in catalog_tools
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        explicit = parameters.get("tools")
        if isinstance(explicit, list) and explicit:
            calls: list[dict[str, Any]] = []
            for item in explicit[:8]:
                if isinstance(item, str):
                    name, params = item, {}
                elif isinstance(item, dict):
                    name, params = item.get("tool"), item.get("params", {})
                else:
                    raise FlashDutyConfigurationError("tools entries must be strings or objects")
                if not isinstance(name, str) or name not in available:
                    raise FlashDutyConfigurationError(
                        f"Requested monit-agent tool is unavailable: {name}"
                    )
                if not _is_read_only_tool_name(name):
                    raise FlashDutyReadOnlyViolation(f"monit-agent tool is not read-only: {name}")
                if not isinstance(params, dict):
                    raise FlashDutyConfigurationError("tool params must be an object")
                calls.append({"tool": name, "params": params})
            return calls

        diagnostics = parameters.get("diagnostics") or ["overview"]
        if not isinstance(diagnostics, list):
            diagnostics = [diagnostics]
        wanted: set[str] = set()
        for diagnostic in diagnostics:
            normalized = str(diagnostic).casefold()
            wanted.update(_DIAGNOSTIC_TERMS.get(normalized, {normalized}))

        ranked: list[tuple[int, str]] = []
        for name, metadata in available.items():
            if not _is_read_only_tool_name(name):
                continue
            input_schema = metadata.get("input_schema")
            if isinstance(input_schema, dict) and input_schema.get("required"):
                continue
            lowered_name = name.casefold().replace("_", " ").replace(".", " ")
            description = str(metadata.get("description") or "").casefold()
            score = sum(
                (3 if term in lowered_name else 0) + (1 if term in description else 0)
                for term in wanted
            )
            if score:
                ranked.append((score, name))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        return [{"tool": name, "params": {}} for _, name in ranked[:8]]


def build_flashduty_tools(
    client: FlashDutyClient,
    *,
    item_limit: int = 20,
    metrics_ds_name: str = "",
    logs_ds_name: str = "",
    logs_ds_type: str = "loki",
) -> list[Any]:
    return [
        FlashDutyAlertContextTool(client, item_limit=item_limit),
        FlashDutyDataSourceTool(
            "query_metrics",
            client,
            defaults={"ds_type": "prometheus", "ds_name": metrics_ds_name},
        ),
        FlashDutyDataSourceTool(
            "query_logs",
            client,
            defaults={"ds_type": logs_ds_type, "ds_name": logs_ds_name},
        ),
        FlashDutyDataSourceTool("query_trace", client),
        FlashDutyDataSourceTool("query_endpoint_errors", client),
        FlashDutyDatabaseDiagnosticsTool(client),
        FlashDutyChangesTool(client),
        FlashDutySimilarIncidentsTool(client),
    ]
