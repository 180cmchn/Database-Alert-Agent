from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client

from app.application.sanitization import sanitize_text
from app.domain.models import InvestigationContext, ToolExecutionRequest

ARCHERY_SLOW_LOG_TABLE: Final = "t_slowlog_info"
ARCHERY_SLOW_LOG_TOOL_NAME: Final = "query_archery_slow_logs"
ARCHERY_MCP_LOGIN_TOOL_NAME: Final = "ensure_login_gymJPA"
ARCHERY_MCP_QUERY_TOOL_NAME: Final = "sql_query_gymJPA"
ARCHERY_SLOW_LOG_TIME_COLUMN: Final = "f_insert_time"
# Bound the global snapshot returned by Archery. The server can truncate at this
# character limit, so this is not a guarantee that the evidence is complete.
ARCHERY_SLOW_LOG_LIMIT: Final = 20
ARCHERY_SLOW_LOG_MAX_RESULT_CHARS: Final = 8_000
ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS: Final = 300
SLOW_QUERY_TITLE_IDENTIFIER: Final = "slow_query"

_TOOL_NAME: Final = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SLOW_QUERY_TITLE_IDENTIFIER: Final = re.compile(
    rf"(?<![a-z0-9]){SLOW_QUERY_TITLE_IDENTIFIER}(?![a-z0-9])", re.IGNORECASE
)
_BUSINESS_ERROR_TEXT: Final = re.compile(
    r"""
    实例不在白名单中，?已拒绝执行
    |您没有执行该\s*SQL\s*查询的权限
    |SQL\s*查询失败
    |登录已过期，?请重新登录后再试
    |需要先登录\s*Archery
    |未获取到用户名
    |请先调用\s*ensure_login(?:_gymJPA)?\s*\(\s*\)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_FAILURE_STATUSES: Final = {
    "error",
    "failed",
    "failure",
    "rejected",
    "unauthorized",
    "forbidden",
    "not_logged_in",
    "login_expired",
}
_QUERY_RESULT_KEYS: Final = {
    "columns",
    "data",
    "result",
    "rowCount",
    "row_count",
    "rows",
    "total",
}
_PAYLOAD_CONTAINER_KEYS: Final = {
    "data",
    "result",
    "query",
    "execution",
    "meta",
    "metadata",
}


class ArcheryMCPError(RuntimeError):
    """Base error for the read-only Archery MCP integration."""


class ArcheryMCPConfigurationError(ArcheryMCPError):
    """The MCP endpoint, token, or expected read-only tool is unavailable."""


class ArcheryMCPProtocolError(ArcheryMCPError):
    """The remote endpoint did not follow the negotiated MCP protocol."""


class ArcheryMCPToolError(ArcheryMCPError):
    """The Archery MCP tool rejected or failed the read-only query."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic_data = diagnostic_data or {}


class ArcheryMCPReadOnlyViolation(ArcheryMCPError):
    """A caller or server changed the controlled read-only query structure."""


@dataclass(frozen=True, slots=True)
class ArcherySlowLogQueryResult:
    """Result of the login-confirmed Archery slow-log query."""

    payload: dict[str, Any]
    requested_sql: str
    window_start: datetime
    window_end: datetime


def is_slow_query_alert_title(title: str) -> bool:
    """Match the controlled ``slow_query`` identifier in the alert title."""

    return bool(_SLOW_QUERY_TITLE_IDENTIFIER.search(title))


def _build_slow_log_query(
    occurred_at: datetime,
    *,
    window_seconds: int,
) -> tuple[str, datetime, datetime]:
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ArcheryMCPConfigurationError(
            "Alert occurred_at must include a timezone for Archery window filtering"
        )
    window_end = occurred_at.astimezone(UTC)
    window_start = window_end - timedelta(seconds=window_seconds)
    start_timestamp = int(window_start.timestamp())
    end_timestamp = int(window_end.timestamp())
    sql = (
        f"select * from {ARCHERY_SLOW_LOG_TABLE} "
        f"where `{ARCHERY_SLOW_LOG_TIME_COLUMN}` >= from_unixtime({start_timestamp}) "
        f"and `{ARCHERY_SLOW_LOG_TIME_COLUMN}` <= from_unixtime({end_timestamp}) "
        f"order by `{ARCHERY_SLOW_LOG_TIME_COLUMN}` desc"
    )
    return sql, window_start, window_end


def _safe_error_detail(value: Any) -> str:
    return sanitize_text(str(value or "")).strip()[:1000]


def _nested_archery_error(error: BaseException) -> ArcheryMCPError | None:
    if isinstance(error, ArcheryMCPError):
        return error
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            matched = _nested_archery_error(nested)
            if matched is not None:
                return matched
    return None


def _first_exception_leaf(error: BaseException) -> BaseException:
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


class ArcheryMCPClient:
    """Archery read-only client backed by the official MCP Python SDK."""

    def __init__(
        self,
        mcp_url: str,
        token: str,
        *,
        instance_ref: str,
        db_name: str,
        window_seconds: int = ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS,
        login_tool_name: str = ARCHERY_MCP_LOGIN_TOOL_NAME,
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
        if not instance_ref.strip():
            raise ArcheryMCPConfigurationError(
                "ARCHERY_MCP_INSTANCE_REF is not configured"
            )
        if not db_name.strip():
            raise ArcheryMCPConfigurationError("ARCHERY_MCP_DB_NAME is not configured")
        if any(
            len(value.strip()) > 255
            or any(ord(character) < 32 for character in value.strip())
            for value in (instance_ref, db_name)
        ):
            raise ArcheryMCPConfigurationError(
                "Archery instance_ref and db_name must be printable and at most 255 chars"
            )
        if not 60 <= window_seconds <= 86_400:
            raise ArcheryMCPConfigurationError(
                "Archery slow-log window must be between 60 and 86400 seconds"
            )
        if not _TOOL_NAME.fullmatch(login_tool_name) or not _TOOL_NAME.fullmatch(
            query_tool_name
        ):
            raise ArcheryMCPConfigurationError(
                "Archery MCP tool name contains unsupported characters"
            )

        self.mcp_url = mcp_url.strip()
        self.instance_ref = instance_ref.strip()
        self.db_name = db_name.strip()
        self.slow_log_time_column = ARCHERY_SLOW_LOG_TIME_COLUMN
        self.window_seconds = window_seconds
        self.login_tool_name = login_tool_name
        self.query_tool_name = query_tool_name
        self.timeout_seconds = timeout_seconds
        self._token = token.strip()
        self._transport = transport

    async def execute_slow_log_query(
        self, occurred_at: datetime
    ) -> ArcherySlowLogQueryResult:
        """Confirm login, then execute the alert-window slow-log SELECT."""

        requested_sql, window_start, window_end = _build_slow_log_query(
            occurred_at,
            window_seconds=self.window_seconds,
        )
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_seconds),
                transport=self._transport,
                follow_redirects=False,
                headers={"X-Archery-Token": self._token},
            ) as http_client:
                async with streamable_http_client(
                    self.mcp_url,
                    http_client=http_client,
                ) as (read_stream, write_stream, get_session_id):
                    async with ClientSession(
                        read_stream,
                        write_stream,
                        read_timeout_seconds=timedelta(seconds=self.timeout_seconds),
                        client_info=mcp_types.Implementation(
                            name="database-alert-agent",
                            version="0.1.0",
                        ),
                    ) as session:
                        await session.initialize()
                        tools = await self._list_tools(session)
                        self._validate_required_tools(tools)

                        login_result = await self._call_tool(
                            session,
                            tool_name=self.login_tool_name,
                            arguments={},
                        )
                        login_text = self._tool_text_blocks(login_result)
                        login_payload = self._extract_tool_payload(login_result)
                        self._validate_business_success(
                            login_payload,
                            tool_name=self.login_tool_name,
                            supplemental_text=login_text,
                        )

                        query_result = await self._call_tool(
                            session,
                            tool_name=self.query_tool_name,
                            arguments={
                                "instance_ref": self.instance_ref,
                                "db_name": self.db_name,
                                "sql_content": requested_sql,
                                "limit_num": ARCHERY_SLOW_LOG_LIMIT,
                                "max_result_chars": (
                                    ARCHERY_SLOW_LOG_MAX_RESULT_CHARS
                                ),
                            },
                        )
                        query_text = self._tool_text_blocks(query_result)
                        payload = self._extract_tool_payload(query_result)
                        try:
                            self._validate_business_success(
                                payload,
                                tool_name=self.query_tool_name,
                                supplemental_text=query_text,
                            )
                        except ArcheryMCPToolError as exc:
                            raise ArcheryMCPToolError(
                                str(exc),
                                diagnostic_data=self._login_diagnostic_data(
                                    login_payload,
                                    login_text,
                                    session_id=get_session_id(),
                                ),
                            ) from exc
                        return ArcherySlowLogQueryResult(
                            payload=payload,
                            requested_sql=requested_sql,
                            window_start=window_start,
                            window_end=window_end,
                        )
        except ArcheryMCPError:
            raise
        except ExceptionGroup as exc:
            nested = _nested_archery_error(exc)
            if nested is not None:
                raise nested from exc
            leaf = _first_exception_leaf(exc)
            detail = _safe_error_detail(leaf)
            suffix = f": {detail}" if detail else ""
            raise ArcheryMCPProtocolError(
                f"Archery MCP SDK client failed ({type(leaf).__name__}){suffix}"
            ) from exc
        except Exception as exc:
            detail = _safe_error_detail(exc)
            suffix = f": {detail}" if detail else ""
            raise ArcheryMCPProtocolError(
                f"Archery MCP SDK client failed ({type(exc).__name__}){suffix}"
            ) from exc

    async def _list_tools(
        self,
        session: ClientSession,
    ) -> dict[str, dict[str, Any]]:
        tools: dict[str, dict[str, Any]] = {}
        cursor: str | None = None
        for _page in range(10):
            result = await session.list_tools(
                params=(mcp_types.PaginatedRequestParams(cursor=cursor) if cursor else None)
            )
            for item in result.tools:
                tools[item.name] = item.model_dump(
                    by_alias=True,
                    mode="json",
                    exclude_none=True,
                )
            if not result.nextCursor:
                return tools
            cursor = result.nextCursor
        raise ArcheryMCPProtocolError("Archery MCP tools/list pagination exceeded 10 pages")

    def _validate_required_tools(
        self, tools: Mapping[str, dict[str, Any]]
    ) -> None:
        login_tool = tools.get(self.login_tool_name)
        if login_tool is None:
            raise ArcheryMCPConfigurationError(
                f"Archery MCP does not expose the required tool {self.login_tool_name!r}"
            )
        login_schema = login_tool.get("inputSchema")
        login_required = (
            login_schema.get("required") if isinstance(login_schema, dict) else None
        )
        if not isinstance(login_schema, dict) or (
            login_required is not None
            and (
                not isinstance(login_required, list)
                or bool(login_required)
            )
        ):
            raise ArcheryMCPConfigurationError(
                f"Archery MCP tool {self.login_tool_name!r} cannot be called "
                "without arguments"
            )

        tool = tools.get(self.query_tool_name)
        if tool is None:
            raise ArcheryMCPConfigurationError(
                f"Archery MCP does not expose the required tool {self.query_tool_name!r}"
            )
        schema = tool.get("inputSchema")
        properties = schema.get("properties") if isinstance(schema, dict) else None
        required_properties = {
            "instance_ref",
            "db_name",
            "sql_content",
            "limit_num",
            "max_result_chars",
        }
        if not isinstance(properties, dict) or not required_properties.issubset(properties):
            raise ArcheryMCPConfigurationError(
                f"Archery MCP tool {self.query_tool_name!r} does not accept the required "
                "instance_ref, db_name, sql_content, limit_num, and "
                "max_result_chars arguments"
            )

    async def _call_tool(
        self,
        session: ClientSession,
        *,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        result = await session.call_tool(
            tool_name,
            arguments,
            read_timeout_seconds=timedelta(seconds=self.timeout_seconds),
        )
        return result.model_dump(
            by_alias=True,
            mode="json",
            exclude_none=True,
        )

    @staticmethod
    def _extract_tool_payload(result: dict[str, Any]) -> dict[str, Any]:
        if result.get("isError") is True:
            raise ArcheryMCPToolError(
                ArcheryMCPClient._tool_content_summary(result)
                or "Archery MCP tool reported an execution error"
            )

        text_blocks = ArcheryMCPClient._tool_text_blocks(result)
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            for decoded in ArcheryMCPClient._decoded_text_payloads(text_blocks):
                merged = dict(decoded)
                merged.update(structured)
                return merged
            if text_blocks and not _QUERY_RESULT_KEYS.intersection(structured):
                return {**structured, "content": list(text_blocks)}
            return structured
        if structured is not None:
            raise ArcheryMCPProtocolError(
                "Archery MCP structuredContent was not an object"
            )

        for text in text_blocks:
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                return decoded
            return {"result": decoded}
        if text_blocks:
            return {"content": list(text_blocks)}
        raise ArcheryMCPProtocolError("Archery MCP tool returned no usable content")

    @staticmethod
    def _validate_business_success(
        payload: Mapping[str, Any],
        *,
        tool_name: str,
        supplemental_text: tuple[str, ...] = (),
    ) -> None:
        status = payload.get("status")
        if isinstance(status, str) and status.strip().casefold() in _FAILURE_STATUSES:
            detail = (
                payload.get("message")
                or payload.get("detail")
                or payload.get("error")
                or status
            )
            raise ArcheryMCPToolError(
                f"{tool_name} failed: {_safe_error_detail(detail)}"
            )
        if payload.get("success") is False:
            detail = (
                payload.get("message")
                or payload.get("detail")
                or payload.get("error")
                or "success=false"
            )
            raise ArcheryMCPToolError(
                f"{tool_name} failed: {_safe_error_detail(detail)}"
            )

        explicit_error = payload.get("error")
        if explicit_error not in (None, "", False, []):
            raise ArcheryMCPToolError(
                f"{tool_name} failed: {_safe_error_detail(explicit_error)}"
            )

        for decoded in ArcheryMCPClient._decoded_text_payloads(supplemental_text):
            ArcheryMCPClient._validate_business_success(
                decoded,
                tool_name=tool_name,
            )

        for text in [
            *ArcheryMCPClient._metadata_text(payload),
            *supplemental_text,
        ]:
            match = _BUSINESS_ERROR_TEXT.search(text)
            if match is not None:
                raise ArcheryMCPToolError(
                    f"{tool_name} failed: {_safe_error_detail(match.group(0))}"
                )

    @staticmethod
    def _tool_text_blocks(result: Mapping[str, Any]) -> tuple[str, ...]:
        content = result.get("content")
        if not isinstance(content, list):
            return ()
        return tuple(
            item["text"]
            for item in content
            if isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        )

    @staticmethod
    def _decoded_text_payloads(
        text_blocks: tuple[str, ...],
    ) -> list[Mapping[str, Any]]:
        payloads: list[Mapping[str, Any]] = []
        for text in text_blocks:
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, Mapping):
                payloads.append(decoded)
        return payloads

    def _login_diagnostic_data(
        self,
        payload: Mapping[str, Any],
        text_blocks: tuple[str, ...],
        *,
        session_id: str | None,
    ) -> dict[str, Any]:
        containers = self._metadata_containers(payload)
        username_field_present = any(
            re.sub(r"[\s_-]+", "", str(key)).casefold()
            in {"user", "username", "currentuser", "当前用户", "用户名"}
            and value not in (None, "", False)
            for container in containers
            for key, value in container.items()
        )
        diagnostic_data: dict[str, Any] = {
            "login_tool": self.login_tool_name,
            "mcp_client": "official_python_sdk",
            "mcp_transport": "streamable_http",
            "mcp_session_id_present": bool(session_id),
            "login_payload_keys": sorted(str(key) for key in payload)[:20],
            "login_text_block_count": len(text_blocks),
            "username_field_present": username_field_present,
        }
        status = payload.get("status")
        if isinstance(status, (str, bool, int, float)):
            diagnostic_data["login_status"] = _safe_error_detail(status)
        preview_parts = [*self._metadata_text(payload), *text_blocks]
        preview = _safe_error_detail(" ".join(preview_parts))
        if preview:
            diagnostic_data["login_response_preview"] = preview[:500]
        return diagnostic_data

    @staticmethod
    def _metadata_containers(
        payload: Mapping[str, Any],
    ) -> list[Mapping[str, Any]]:
        containers: list[Mapping[str, Any]] = [payload]
        index = 0
        while index < len(containers) and len(containers) < 20:
            container = containers[index]
            index += 1
            for key, value in container.items():
                if (
                    str(key).casefold() in _PAYLOAD_CONTAINER_KEYS
                    and isinstance(value, Mapping)
                    and value not in containers
                ):
                    containers.append(value)
        return containers

    @staticmethod
    def _metadata_text(payload: Mapping[str, Any]) -> list[str]:
        values: list[str] = []
        for container in ArcheryMCPClient._metadata_containers(payload):
            for key in ("message", "detail", "content", "result"):
                value = container.get(key)
                if isinstance(value, str):
                    values.append(value)
                elif isinstance(value, list):
                    values.extend(item for item in value if isinstance(item, str))
        return values

    @staticmethod
    def _tool_content_summary(result: dict[str, Any]) -> str:
        values = [
            item.get("text")
            for item in result.get("content", [])
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        return _safe_error_detail(" ".join(str(value) for value in values if value))


class ArcherySlowLogEvidenceTool:
    """Investigation tool that exposes only the approved slow-log query."""

    name = ARCHERY_SLOW_LOG_TOOL_NAME
    source_system = "archery_mcp"

    def __init__(self, client: ArcheryMCPClient) -> None:
        self.client = client

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]]:
        if not is_slow_query_alert_title(context.alert.title):
            raise ArcheryMCPReadOnlyViolation(
                "Archery slow-log evidence is restricted to titles containing "
                "the slow_query identifier"
            )
        if request.parameters:
            raise ArcheryMCPReadOnlyViolation(
                "Archery slow-log evidence parameters are derived only from deployment "
                "configuration and alert occurred_at"
            )

        result = await self.client.execute_slow_log_query(context.alert.occurred_at)
        row_count = self._row_count(result.payload)
        row_summary = f"，返回 {row_count} 行" if row_count is not None else ""
        return (
            f"Archery MCP 登录确认成功并执行慢查询记录只读查询{row_summary}；"
            "查询请求已按告警时间窗生成，但未校验 Archery 实际执行 SQL，"
            "且结果尚未按受影响数据库实例关联并可能被截断，只能作为排查线索，"
            "不能单独证明本次告警根因。",
            {
                "sql": result.requested_sql,
                "actual_sql_verified": False,
                "login_confirmed": True,
                "login_tool": self.client.login_tool_name,
                "mcp_tool": self.client.query_tool_name,
                "target": {
                    "instance_ref": self.client.instance_ref,
                    "db_name": self.client.db_name,
                },
                "query_window": {
                    "basis": "alert.occurred_at",
                    "alert_occurred_at": context.alert.occurred_at.isoformat(),
                    "start": result.window_start.isoformat(),
                    "end": result.window_end.isoformat(),
                    "duration_seconds": self.client.window_seconds,
                    "time_column": self.client.slow_log_time_column,
                },
                "scope": "requested_alert_time_window_global_slow_log_snapshot",
                "result_bounds": {
                    "row_limit": ARCHERY_SLOW_LOG_LIMIT,
                    "character_limit": ARCHERY_SLOW_LOG_MAX_RESULT_CHARS,
                    "truncation_possible": True,
                },
                "root_cause_eligible": False,
                "root_cause_ineligible_reason": (
                    "实际执行 SQL 未校验，结果尚未按受影响数据库实例关联，"
                    "且可能被字符上限截断"
                ),
                "result": result.payload,
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
