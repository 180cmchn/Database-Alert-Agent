from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from app.application.sanitization import sanitize_text
from app.domain.models import InvestigationContext, ToolExecutionRequest

ARCHERY_SLOW_LOG_QUERY: Final = "select * from t_slowlog_info"
ARCHERY_SLOW_LOG_TOOL_NAME: Final = "query_archery_slow_logs"
ARCHERY_MCP_QUERY_TOOL_NAME: Final = "archery_query_readonly"
ARCHERY_MCP_EXECUTE_TOOL_NAME: Final = "archery_execute_query"
EXCESSIVE_SLOW_QUERY_ALERT_TYPE: Final = "慢查询过多"

_MCP_PROTOCOL_VERSION: Final = "2025-11-25"
_SUPPORTED_PROTOCOL_VERSIONS: Final = {
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
}
_MAX_MCP_RESPONSE_BYTES: Final = 2_000_000
_TOOL_NAME: Final = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_ALLOWED_NORMALIZED_QUERY: Final = re.compile(
    r"^\s*select\s+\*\s+from\s+`?t_slowlog_info`?"
    r"(?:\s+limit\s+\d+)?\s*;?\s*$",
    re.IGNORECASE,
)
_SEMANTIC_FAILURE_STATUSES: Final = {
    "blocked",
    "business_not_available",
    "error",
    "failed",
    "missing_scope",
    "needs_user_input",
    "rejected",
}


class ArcheryMCPError(RuntimeError):
    """Base error for the read-only Archery MCP integration."""


class ArcheryMCPConfigurationError(ArcheryMCPError):
    """The MCP endpoint, token, or expected read-only tool is unavailable."""


class ArcheryMCPProtocolError(ArcheryMCPError):
    """The remote endpoint did not follow the negotiated MCP protocol."""


class ArcheryMCPToolError(ArcheryMCPError):
    """The Archery MCP tool rejected or failed the read-only query."""


class ArcheryMCPReadOnlyViolation(ArcheryMCPError):
    """A caller attempted to replace the approved fixed SELECT statement."""


def is_excessive_slow_query_alert(alert_type: str) -> bool:
    """Match only the normalized alert type, never fuzzy title/reason text."""

    normalized = unicodedata.normalize("NFKC", alert_type).strip().casefold()
    return normalized == EXCESSIVE_SLOW_QUERY_ALERT_TYPE.casefold()


def _is_approved_query(sql: str) -> bool:
    normalized = re.sub(r"\s+", " ", sql.strip().removesuffix(";").strip()).casefold()
    return normalized == ARCHERY_SLOW_LOG_QUERY


def _safe_error_detail(value: Any) -> str:
    return sanitize_text(str(value or "")).strip()[:1000]


class ArcheryMCPClient:
    """Minimal stateful Streamable HTTP client for the Archery read-only tool."""

    def __init__(
        self,
        mcp_url: str,
        token: str,
        *,
        query_tool_name: str = ARCHERY_MCP_QUERY_TOOL_NAME,
        timeout_seconds: float = 60,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(mcp_url.strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ArcheryMCPConfigurationError(
                "ARCHERY_MCP_URL must be an absolute HTTP(S) MCP endpoint "
                "without embedded credentials, query, or fragment"
            )
        if not token.strip():
            raise ArcheryMCPConfigurationError("ARCHERY_MCP_TOKEN is not configured")
        if not _TOOL_NAME.fullmatch(query_tool_name):
            raise ArcheryMCPConfigurationError(
                "Archery MCP query tool name contains unsupported characters"
            )

        self.mcp_url = mcp_url.strip()
        self.query_tool_name = query_tool_name
        self.timeout_seconds = timeout_seconds
        self._token = token.strip()
        self._transport = transport

    async def execute_slow_log_query(self) -> dict[str, Any]:
        """Execute the one approved slow-log SELECT and return its tool payload."""

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            transport=self._transport,
            follow_redirects=False,
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        ) as client:
            session_id: str | None = None
            protocol_version = _MCP_PROTOCOL_VERSION
            try:
                initialize, response = await self._send_request(
                    client,
                    request_id=1,
                    method="initialize",
                    params={
                        "protocolVersion": _MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "database-alert-agent",
                            "version": "0.1.0",
                        },
                    },
                )
                if not isinstance(initialize, dict):
                    raise ArcheryMCPProtocolError(
                        "Archery MCP initialize result was not an object"
                    )
                negotiated = initialize.get("protocolVersion")
                if not isinstance(negotiated, str) or (
                    negotiated not in _SUPPORTED_PROTOCOL_VERSIONS
                ):
                    raise ArcheryMCPProtocolError(
                        "Archery MCP returned an unsupported protocol version"
                    )
                protocol_version = negotiated
                session_id = response.headers.get("Mcp-Session-Id")

                await self._send_notification(
                    client,
                    method="notifications/initialized",
                    session_id=session_id,
                    protocol_version=protocol_version,
                )
                tools = await self._list_tools(
                    client,
                    session_id=session_id,
                    protocol_version=protocol_version,
                )
                self._validate_query_tool(tools)

                query_result = await self._call_tool(
                    client,
                    request_id=10,
                    tool_name=self.query_tool_name,
                    arguments={"sql": ARCHERY_SLOW_LOG_QUERY},
                    session_id=session_id,
                    protocol_version=protocol_version,
                )
                payload = self._extract_tool_payload(query_result)

                if self._requires_staged_execution(payload):
                    self._validate_execute_tool(tools)
                    payload = await self._execute_prepared_query(
                        client,
                        payload,
                        session_id=session_id,
                        protocol_version=protocol_version,
                    )

                self._validate_semantic_result(payload)
                normalized_sql = payload.get("normalizedSql")
                if isinstance(normalized_sql, str) and not _ALLOWED_NORMALIZED_QUERY.fullmatch(
                    normalized_sql
                ):
                    raise ArcheryMCPReadOnlyViolation(
                        "Archery MCP reported an unexpected normalized SQL statement"
                    )
                return payload
            finally:
                if session_id:
                    await self._close_session(
                        client,
                        session_id=session_id,
                        protocol_version=protocol_version,
                    )

    async def _list_tools(
        self,
        client: httpx.AsyncClient,
        *,
        session_id: str | None,
        protocol_version: str,
    ) -> dict[str, dict[str, Any]]:
        tools: dict[str, dict[str, Any]] = {}
        cursor: str | None = None
        for page in range(10):
            params = {"cursor": cursor} if cursor else {}
            result, _ = await self._send_request(
                client,
                request_id=2 + page,
                method="tools/list",
                params=params,
                session_id=session_id,
                protocol_version=protocol_version,
            )
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise ArcheryMCPProtocolError(
                    "Archery MCP tools/list result did not contain a tools array"
                )
            for item in result["tools"]:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if isinstance(name, str):
                    tools[name] = item
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                return tools
            cursor = next_cursor
        raise ArcheryMCPProtocolError("Archery MCP tools/list pagination exceeded 10 pages")

    def _validate_query_tool(self, tools: Mapping[str, dict[str, Any]]) -> None:
        tool = tools.get(self.query_tool_name)
        if tool is None:
            raise ArcheryMCPConfigurationError(
                f"Archery MCP does not expose the required tool {self.query_tool_name!r}"
            )
        schema = tool.get("inputSchema")
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(properties, dict) or "sql" not in properties:
            raise ArcheryMCPConfigurationError(
                f"Archery MCP tool {self.query_tool_name!r} does not accept a sql argument"
            )

    @staticmethod
    def _validate_execute_tool(tools: Mapping[str, dict[str, Any]]) -> None:
        tool = tools.get(ARCHERY_MCP_EXECUTE_TOOL_NAME)
        if tool is None:
            raise ArcheryMCPConfigurationError(
                "Archery MCP requested staged execution but does not expose "
                f"{ARCHERY_MCP_EXECUTE_TOOL_NAME!r}"
            )
        schema = tool.get("inputSchema")
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(properties, dict) or not {
            "prepareId",
            "confirmationToken",
        }.issubset(properties):
            raise ArcheryMCPConfigurationError(
                "Archery MCP execute tool is missing prepareId or confirmationToken"
            )

    async def _execute_prepared_query(
        self,
        client: httpx.AsyncClient,
        prepared: dict[str, Any],
        *,
        session_id: str | None,
        protocol_version: str,
    ) -> dict[str, Any]:
        prepare_id = prepared.get("prepareId")
        confirmation_token = prepared.get("confirmationToken")
        normalized_sql = prepared.get("normalizedSql")
        if (
            not isinstance(prepare_id, str)
            or not prepare_id
            or not isinstance(confirmation_token, str)
            or not confirmation_token
            or not isinstance(normalized_sql, str)
            or not _ALLOWED_NORMALIZED_QUERY.fullmatch(normalized_sql)
        ):
            raise ArcheryMCPReadOnlyViolation(
                "Archery MCP staged execution did not preserve the approved slow-log SELECT"
            )

        execute_result = await self._call_tool(
            client,
            request_id=20,
            tool_name=ARCHERY_MCP_EXECUTE_TOOL_NAME,
            arguments={
                "prepareId": prepare_id,
                "confirmationToken": confirmation_token,
            },
            session_id=session_id,
            protocol_version=protocol_version,
        )
        return self._extract_tool_payload(execute_result)

    async def _call_tool(
        self,
        client: httpx.AsyncClient,
        *,
        request_id: int,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str | None,
        protocol_version: str,
    ) -> dict[str, Any]:
        result, _ = await self._send_request(
            client,
            request_id=request_id,
            method="tools/call",
            params={"name": tool_name, "arguments": arguments},
            session_id=session_id,
            protocol_version=protocol_version,
        )
        if not isinstance(result, dict):
            raise ArcheryMCPProtocolError("Archery MCP tools/call result was not an object")
        return result

    @staticmethod
    def _extract_tool_payload(result: dict[str, Any]) -> dict[str, Any]:
        if result.get("isError") is True:
            raise ArcheryMCPToolError(
                ArcheryMCPClient._tool_content_summary(result)
                or "Archery MCP tool reported an execution error"
            )

        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        if structured is not None:
            raise ArcheryMCPProtocolError(
                "Archery MCP structuredContent was not an object"
            )

        text_blocks = [
            item["text"]
            for item in result.get("content", [])
            if isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        ]
        for text in text_blocks:
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                return decoded
            return {"result": decoded}
        if text_blocks:
            return {"content": text_blocks}
        raise ArcheryMCPProtocolError("Archery MCP tool returned no usable content")

    @staticmethod
    def _tool_content_summary(result: dict[str, Any]) -> str:
        values = [
            item.get("text")
            for item in result.get("content", [])
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        return _safe_error_detail(" ".join(str(value) for value in values if value))

    @staticmethod
    def _requires_staged_execution(payload: dict[str, Any]) -> bool:
        return payload.get("nextAction") == ARCHERY_MCP_EXECUTE_TOOL_NAME

    @staticmethod
    def _validate_semantic_result(payload: dict[str, Any]) -> None:
        status = payload.get("status")
        normalized_status = str(status).strip().casefold() if status is not None else ""
        next_action = str(payload.get("nextAction") or "").strip()
        if normalized_status in _SEMANTIC_FAILURE_STATUSES or (
            next_action and next_action != ARCHERY_MCP_EXECUTE_TOOL_NAME
        ):
            detail = (
                payload.get("message")
                or (
                    payload.get("scopeError", {}).get("message")
                    if isinstance(payload.get("scopeError"), dict)
                    else ""
                )
                or status
                or next_action
            )
            raise ArcheryMCPToolError(
                _safe_error_detail(detail) or "Archery MCP query did not execute"
            )

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        *,
        request_id: int,
        method: str,
        params: dict[str, Any],
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> tuple[Any, httpx.Response]:
        headers = self._session_headers(session_id, protocol_version)
        try:
            response = await client.post(
                self.mcp_url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                },
            )
        except httpx.TransportError as exc:
            raise ArcheryMCPProtocolError(
                f"Archery MCP network error: {type(exc).__name__}"
            ) from exc
        message = self._decode_response(response, expected_id=request_id)
        if "error" in message:
            error = message["error"]
            detail = error.get("message") if isinstance(error, dict) else error
            raise ArcheryMCPProtocolError(
                _safe_error_detail(detail) or "Archery MCP returned a JSON-RPC error"
            )
        if "result" not in message:
            raise ArcheryMCPProtocolError("Archery MCP response did not contain a result")
        return message["result"], response

    async def _send_notification(
        self,
        client: httpx.AsyncClient,
        *,
        method: str,
        session_id: str | None,
        protocol_version: str,
    ) -> None:
        try:
            response = await client.post(
                self.mcp_url,
                headers=self._session_headers(session_id, protocol_version),
                json={"jsonrpc": "2.0", "method": method},
            )
        except httpx.TransportError as exc:
            raise ArcheryMCPProtocolError(
                f"Archery MCP network error: {type(exc).__name__}"
            ) from exc
        if response.status_code != 202:
            self._raise_http_error(response)

    async def _close_session(
        self,
        client: httpx.AsyncClient,
        *,
        session_id: str,
        protocol_version: str,
    ) -> None:
        try:
            await client.delete(
                self.mcp_url,
                headers=self._session_headers(session_id, protocol_version),
            )
        except httpx.HTTPError:
            # Session cleanup is best-effort and must not replace collected evidence.
            return

    @staticmethod
    def _session_headers(
        session_id: str | None, protocol_version: str | None
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if protocol_version:
            headers["MCP-Protocol-Version"] = protocol_version
        return headers

    @staticmethod
    def _decode_response(
        response: httpx.Response, *, expected_id: int
    ) -> dict[str, Any]:
        if response.is_error:
            ArcheryMCPClient._raise_http_error(response)
        if len(response.content) > _MAX_MCP_RESPONSE_BYTES:
            raise ArcheryMCPProtocolError("Archery MCP response exceeded 2000000 bytes")

        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
        messages: list[Any] = []
        if content_type == "application/json":
            try:
                messages = [response.json()]
            except ValueError as exc:
                raise ArcheryMCPProtocolError(
                    "Archery MCP returned invalid JSON"
                ) from exc
        elif content_type == "text/event-stream":
            messages = ArcheryMCPClient._decode_sse(response.text)
        else:
            raise ArcheryMCPProtocolError(
                "Archery MCP returned an unsupported Content-Type"
            )

        for message in messages:
            if isinstance(message, dict) and message.get("id") == expected_id:
                if message.get("jsonrpc") != "2.0":
                    raise ArcheryMCPProtocolError(
                        "Archery MCP response had an invalid jsonrpc version"
                    )
                return message
        raise ArcheryMCPProtocolError(
            "Archery MCP response did not contain the matching JSON-RPC id"
        )

    @staticmethod
    def _decode_sse(value: str) -> list[Any]:
        messages: list[Any] = []
        data_lines: list[str] = []
        for line in [*value.splitlines(), ""]:
            if not line:
                if not data_lines:
                    continue
                raw = "\n".join(data_lines)
                data_lines = []
                try:
                    messages.append(json.loads(raw))
                except json.JSONDecodeError as exc:
                    raise ArcheryMCPProtocolError(
                        "Archery MCP returned invalid SSE JSON"
                    ) from exc
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        return messages

    @staticmethod
    def _raise_http_error(response: httpx.Response) -> None:
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                detail = _safe_error_detail(
                    body.get("detail") or body.get("message") or ""
                )
        except ValueError:
            pass
        suffix = f": {detail}" if detail else ""
        raise ArcheryMCPProtocolError(
            f"Archery MCP HTTP {response.status_code}{suffix}"
        )


class ArcherySlowLogEvidenceTool:
    """Investigation tool that exposes only the approved slow-log query."""

    name = ARCHERY_SLOW_LOG_TOOL_NAME
    source_system = "archery_mcp"

    def __init__(self, client: ArcheryMCPClient) -> None:
        self.client = client

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        if not is_excessive_slow_query_alert(context.alert.alert_type):
            raise ArcheryMCPReadOnlyViolation(
                "Archery slow-log evidence is restricted to alert_type=慢查询过多"
            )
        requested_sql = request.parameters.get("sql")
        if not isinstance(requested_sql, str) or not _is_approved_query(requested_sql):
            raise ArcheryMCPReadOnlyViolation(
                "Archery slow-log evidence accepts only the approved fixed SELECT"
            )

        result = await self.client.execute_slow_log_query()
        row_count = self._row_count(result)
        row_summary = f"，返回 {row_count} 行" if row_count is not None else ""
        return (
            f"Archery MCP 已执行慢查询记录只读查询{row_summary}；"
            "该结果作为本次告警的实时证据。",
            {
                "sql": ARCHERY_SLOW_LOG_QUERY,
                "mcp_tool": self.client.query_tool_name,
                "result": result,
            },
        )

    @staticmethod
    def _row_count(result: Mapping[str, Any]) -> int | None:
        for key in ("rowCount", "row_count", "total"):
            value = result.get(key)
            if isinstance(value, int) and value >= 0:
                return value
        rows = result.get("rows")
        if isinstance(rows, list):
            return len(rows)
        data = result.get("data")
        if isinstance(data, dict):
            return ArcherySlowLogEvidenceTool._row_count(data)
        return None
