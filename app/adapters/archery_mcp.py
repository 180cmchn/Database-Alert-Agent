"""Archery MCP configuration, Provider policy/codec, facade, and evidence tool.

Session lifecycle, planning retries, budgets, checkpoints, and remote execution
belong exclusively to :mod:`app.adapters.archery_harness`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from app.application.sanitization import sanitize, sanitize_text
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.models import (
    InvestigationContext,
    NormalizedAlert,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall, MCPToolCallingModel
from app.mcp_catalog import (
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    load_mcp_catalog,
)

# Compatibility table identifiers used to recognize common Archery slow-log sources.
ARCHERY_SLOW_LOG_TABLE: Final = "t_slowlog_info"
ARCHERY_SLOW_QUERY_REVIEW_TABLE: Final = "mysql_slow_query_review_history"
ARCHERY_SLOW_LOG_TABLE_SEARCH_KEYWORD: Final = "slow"
ARCHERY_SLOW_LOG_TOOL_NAME: Final = "query_archery_slow_logs"
ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME: Final = "list_resource_groups_gymJPA"
ARCHERY_MCP_INSTANCES_TOOL_NAME: Final = "list_instances_gymJPA"
ARCHERY_MCP_DATABASES_TOOL_NAME: Final = "list_instance_databases_gymJPA"
ARCHERY_MCP_TABLES_TOOL_NAME: Final = "list_db_tables_gymJPA"
ARCHERY_MCP_COLUMNS_TOOL_NAME: Final = "list_table_columns_gymJPA"
# Compatibility hint only; dynamic probes use the discovered table's real columns.
ARCHERY_SLOW_LOG_TIME_COLUMN: Final = "f_insert_time"
ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS: Final = 300
# mysql_slow_query_review_history 的 ts_min/ts_max 列以北京时间（UTC+8）字符串
# 存储；窗口本身仍以 UTC 计算，仅在传给 MCP 内层 Agent 时投影为北京时区字面量。
ARCHERY_SLOW_LOG_TS_COLUMN_TIMEZONE: Final = timezone(timedelta(hours=8))
ARCHERY_MCP_SERVER_NAME: Final = "archery"
ARCHERY_SLOW_LOG_PROMPT_VERSION: Final = "archery-slow-log-mcp-agent-v26"
ARCHERY_SLOW_LOG_EVIDENCE_SCHEMA_VERSION: Final = "archery-slow-query-summary-v1"

_SLOW_QUERY_IDENTITY_FIELDS: Final = (
    "hostname_max",
    "client_max",
    "user_max",
    "db_max",
    "checksum",
    "sample",
    "ts_min",
    "ts_max",
)
_SLOW_QUERY_NUMERIC_FIELDS: Final = {"ts_cnt"}
_SLOW_QUERY_NUMERIC_PREFIXES: Final = (
    "query_time_",
    "lock_time_",
    "rows_",
    "merge_passes_",
    "innodb_",
    "qc_hit_",
    "full_scan_",
    "full_join_",
    "tmp_table_",
    "filesort_",
    "bytes_",
)

_ARCHERY_TRACE_SELECTED_ROWS: Final = 3
_ARCHERY_TRACE_TEXT_CHARS: Final = 400
_ARCHERY_TABULAR_ROW_KEYS: Final = ("rows", "result", "results", "data")

_ENV_REFERENCE: Final = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
_QUERY_TIMEOUT_TEXT: Final = re.compile(
    r"查询超时(?:被\s*)?kill|执行超时|query\s+timeout|timed?\s+out|\btimeout\b"
    r"|query\s+execution\s+was\s+interrupted"
    r"|maximum\s+statement\s+execution\s+time\s+exceeded",
    re.IGNORECASE,
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
    "results",
    "rowCount",
    "row_count",
    "rows",
    "total",
}
_PAYLOAD_CONTAINER_KEYS: Final = {
    "data",
    "result",
    "response",
    "payload",
    "query",
    "execution",
    "meta",
    "metadata",
}
_TABLE_NAME_KEYS: Final = {"name", "table", "tablename", "tbname"}
_NO_MATCHING_TABLE_TEXT: Final = re.compile(
    r"未找到|没有.*表|无匹配|不存在|(?:返回|共)\s*0\s*(?:个)?\s*表|"
    r"not\s+found|no\s+(?:matching\s+)?tables?|\b0\s+tables?\b",
    re.IGNORECASE,
)
_SLOW_LOG_TABLE_TEXT: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9_$])"
    r"(?P<name>[A-Za-z0-9_$-]*slow(?:[_$-]*query)?(?:[_$-]*log|[_$-]*review[_$-]*history)[A-Za-z0-9_$-]*)"
    r"(?![A-Za-z0-9_$])"
)
_SQL_IDENTIFIER_PART: Final = r"(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$-]*)"
_SQL_TABLE_REFERENCE: Final = re.compile(
    rf"(?is)\b(?:from|join)\s+"
    rf"(?P<table>{_SQL_IDENTIFIER_PART}(?:\s*\.\s*{_SQL_IDENTIFIER_PART})?)"
)
class ArcheryMCPError(RuntimeError):
    """Base error for the Archery MCP integration."""


class ArcheryMCPConfigurationError(ArcheryMCPError):
    """The MCP endpoint or transport configuration is unavailable."""


class ArcheryMCPProtocolError(ArcheryMCPError):
    """The remote endpoint did not follow the negotiated MCP protocol."""


class ArcheryMCPToolError(ArcheryMCPError):
    """The Archery MCP tool reported an execution failure."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic_data = diagnostic_data or {}


class ArcheryMCPModelError(ArcheryMCPError):
    """The model did not produce the required bounded MCP tool call."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic_data = diagnostic_data or {}


@dataclass(frozen=True, slots=True)
class MCPServerSettings:
    """Resolved connection settings for one remote MCP server."""

    url: str
    headers: dict[str, str]
    prompts: MCPPromptBundle


@dataclass(frozen=True, slots=True)
class ArcherySlowLogQueryResult:
    """Result of the model-driven Archery slow-log investigation."""

    payload: dict[str, Any]
    requested_sql: str
    window_start: datetime
    window_end: datetime
    model_tool_calls: tuple[str, ...] = ()
    model_request_ids: tuple[str, ...] = ()
    executed_sql: str | None = None
    actual_sql_verified: bool = False
    instance_id: int | None = None
    db_name: str | None = None
    table_name: str | None = None
    query_time_column: str | None = None
    metadata_resolution_tables: tuple[str, ...] = ()
    diagnostics: dict[str, Any] | None = None
    query_completed: bool = True


def load_mcp_server_settings(
    path: Path,
    *,
    server_name: str,
    environment: Mapping[str, str],
) -> MCPServerSettings:
    """Load one project MCP server without ever persisting resolved secrets."""

    try:
        descriptor = load_mcp_catalog(path).require(server_name)
        connection = descriptor.resolve_connection(environment)
    except MCPCatalogConfigurationError as exc:
        raise ArcheryMCPConfigurationError(str(exc)) from exc
    return MCPServerSettings(
        url=connection.url,
        headers=dict(connection.headers),
        prompts=descriptor.prompts,
    )


def slow_log_window(
    occurred_at: datetime,
    *,
    window_seconds: int,
) -> tuple[datetime, datetime]:
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ArcheryMCPConfigurationError(
            "Alert occurred_at must include a timezone for Archery window filtering"
        )
    window_end = occurred_at.astimezone(UTC)
    window_start = window_end - timedelta(seconds=window_seconds)
    return window_start, window_end


def safe_error_detail(value: Any) -> str:
    return sanitize_text(str(value or "")).strip()[:1000]


def nested_archery_error(error: BaseException) -> ArcheryMCPError | None:
    if isinstance(error, ArcheryMCPError):
        return error
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            matched = nested_archery_error(nested)
            if matched is not None:
                return matched
    return None


def first_exception_leaf(error: BaseException) -> BaseException:
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


class ArcheryMCPClient:
    """Public Archery Provider facade backed exclusively by the shared Harness."""

    def __init__(
        self,
        server: MCPServerSettings,
        model: MCPToolCallingModel,
        *,
        window_seconds: int = ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS,
        timeout_seconds: float = 60,
        transport: httpx.AsyncBaseTransport | None = None,
        harness_connector: Any | None = None,
        harness_runtime_dependencies: Any | None = None,
    ) -> None:
        parsed = urlsplit(server.url.strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ArcheryMCPConfigurationError(
                "The Archery MCP settings URL must be an absolute HTTP(S) endpoint "
                "without embedded credentials, query, or fragment"
            )
        if not 60 <= window_seconds <= 86_400:
            raise ArcheryMCPConfigurationError(
                "Archery slow-log window must be between 60 and 86400 seconds"
            )
        self.mcp_url = server.url.strip()
        self.slow_log_time_column = ARCHERY_SLOW_LOG_TIME_COLUMN
        self.window_seconds = window_seconds
        self.timeout_seconds = timeout_seconds
        self.model = model
        self.prompts = server.prompts
        self._headers = dict(server.headers)
        self._transport = transport
        self._harness_connector = harness_connector
        self._harness_runtime_dependencies = harness_runtime_dependencies

    @property
    def headers(self) -> Mapping[str, str]:
        """Resolved transport headers exposed read-only to the Harness connector."""

        return self._headers

    @property
    def transport(self) -> httpx.AsyncBaseTransport | None:
        """Optional HTTP transport override used by deterministic tests."""

        return self._transport

    @classmethod
    def from_settings(
        cls,
        settings_path: Path,
        model: MCPToolCallingModel,
        *,
        environment: Mapping[str, str],
        window_seconds: int = ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS,
        timeout_seconds: float = 60,
        transport: httpx.AsyncBaseTransport | None = None,
        harness_runtime_dependencies: Any | None = None,
    ) -> ArcheryMCPClient:
        server = load_mcp_server_settings(
            settings_path,
            server_name=ARCHERY_MCP_SERVER_NAME,
            environment=environment,
        )
        return cls(
            server,
            model,
            window_seconds=window_seconds,
            timeout_seconds=timeout_seconds,
            transport=transport,
            harness_runtime_dependencies=harness_runtime_dependencies,
        )

    async def execute_slow_log_query(
        self,
        occurred_at: datetime,
        *,
        alert_context: Mapping[str, Any] | None = None,
        run_id: UUID | None = None,
        outer_dispatch_id: UUID | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ArcherySlowLogQueryResult:
        from app.adapters.archery_harness import execute_archery_harness

        return await execute_archery_harness(
            self,
            occurred_at,
            alert_context=alert_context or {},
            run_id=run_id,
            outer_dispatch_id=outer_dispatch_id,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
            connector=self._harness_connector,
            runtime_dependencies=self._harness_runtime_dependencies,
        )

    def agent_messages(
        self,
        *,
        occurred_at: datetime,
        window_start: datetime,
        window_end: datetime,
        alert_context: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        window_start_epoch = int(window_start.timestamp())
        window_end_epoch = int(window_end.timestamp())

        def beijing(value: datetime) -> str:
            return value.astimezone(ARCHERY_SLOW_LOG_TS_COLUMN_TIMEZONE).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        task = {
            "prompt_version": ARCHERY_SLOW_LOG_PROMPT_VERSION,
            "alert": sanitize(dict(alert_context)),
            "occurred_at": occurred_at.isoformat(),
            "required_window": {
                "start": window_start.isoformat(),
                "end": window_end.isoformat(),
                "start_unix_seconds": window_start_epoch,
                "end_unix_seconds": window_end_epoch,
                "duration_seconds": self.window_seconds,
                "ts_column_timezone": "UTC+8",
                "start_beijing": beijing(window_start),
                "end_beijing": beijing(window_end),
                "ts_min_lower_bound_beijing": beijing(
                    window_start - timedelta(hours=1)
                ),
            },
            "investigation_context": {
                "read_only": True,
                "one_tool_per_turn": True,
                "authentication_tools_are_agent_selected": True,
                "target_source": "FlashDuty alert detail alarm_host and alarm_port",
                "finish_action": "finish_archery_investigation",
            },
        }
        return [
            {
                "role": "system",
                "content": self.prompts.execution_instructions,
            },
            {
                "role": "user",
                "content": json.dumps(task, ensure_ascii=False, separators=(",", ":")),
            },
        ]

    @staticmethod
    def _sql_without_comments(sql: str) -> str | None:
        """Remove SQL comments while retaining literals used by completion checks."""

        if re.search(r"/\*(?:!|m!)", sql, re.IGNORECASE) is not None:
            return None
        output: list[str] = []
        index = 0
        while index < len(sql):
            character = sql[index]
            if character in {"'", '"', "`"}:
                quote = character
                output.append(character)
                index += 1
                while index < len(sql):
                    output.append(sql[index])
                    if sql[index] == "\\":
                        index += 1
                        if index < len(sql):
                            output.append(sql[index])
                            index += 1
                        continue
                    if sql[index] == quote:
                        if index + 1 < len(sql) and sql[index + 1] == quote:
                            output.append(sql[index + 1])
                            index += 2
                            continue
                        index += 1
                        break
                    index += 1
                else:
                    return None
                continue
            if sql.startswith("--", index) or character == "#":
                newline = sql.find("\n", index)
                if newline < 0:
                    break
                output.append("\n")
                index = newline + 1
                continue
            if sql.startswith("/*", index):
                comment_end = sql.find("*/", index + 2)
                if comment_end < 0:
                    return None
                output.append(" ")
                index = comment_end + 2
                continue
            output.append(character)
            index += 1
        return "".join(output)

    @classmethod
    def is_slow_log_select(cls, sql: str) -> bool:
        statement = cls._without_leading_sql_comments(sql.strip())
        if re.match(r"(?is)^(?:select|with)\b", statement) is None:
            return False
        return any(
            cls._is_slow_log_table_name(name) for name in cls.sql_table_references(statement)
        )

    @classmethod
    def _is_slow_query_review_history_select(cls, sql: str) -> bool:
        """Identify the final history source after a call has already completed."""

        statement = cls._without_leading_sql_comments(sql.strip())
        if re.match(r"(?is)^(?:select|with)\b", statement) is None:
            return False
        return ARCHERY_SLOW_QUERY_REVIEW_TABLE.casefold() in {
            cls.clean_table_name(name).casefold() for name in cls.sql_table_references(statement)
        }

    @classmethod
    def is_history_result_query(cls, sql: str) -> bool:
        """Recognize the only Archery result with main-Agent evidence semantics.

        This is a post-result classifier. It never accepts, rejects, or rewrites an
        MCP call and deliberately does not inspect target, predicates, ordering, or
        row limits. Those choices belong to the Agent and the MCP server.
        """

        return cls._is_slow_query_review_history_select(sql)

    @staticmethod
    def clean_table_name(value: str) -> str:
        part = re.split(r"\s*\.\s*", value.strip())[-1]
        return part.strip().strip("`\"'[]")

    @classmethod
    def _is_slow_log_table_name(cls, value: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]+", "", cls.clean_table_name(value).casefold())
        return (
            re.search(r"slow(?:query)?log", normalized) is not None
            or re.search(r"slowqueryreviewhistory", normalized) is not None
        )

    @classmethod
    def sql_table_references(cls, sql: str) -> set[str]:
        uncommented = cls._sql_without_comments(sql)
        if uncommented is None:
            return set()
        return {
            cls.clean_table_name(match.group("table"))
            for match in _SQL_TABLE_REFERENCE.finditer(uncommented)
        }

    @classmethod
    def matching_discovered_table(
        cls,
        sql: str,
        discovered_tables: set[str],
    ) -> str | None:
        referenced = {
            cls.clean_table_name(name).casefold() for name in cls.sql_table_references(sql)
        }
        return next(
            (
                table
                for table in sorted(discovered_tables)
                if cls.clean_table_name(table).casefold() in referenced
            ),
            None,
        )

    @classmethod
    def first_slow_log_table(cls, sql: str) -> str | None:
        return next(
            (
                table
                for table in sorted(cls.sql_table_references(sql))
                if cls._is_slow_log_table_name(table)
            ),
            None,
        )

    @classmethod
    def slow_log_tables_from_discovery(
        cls,
        payload: Mapping[str, Any],
    ) -> set[str]:
        discovered: set[str] = set()
        pending: list[Any] = [payload]
        visited_containers: set[int] = set()
        while pending:
            current = pending.pop()
            if isinstance(current, Mapping):
                marker = id(current)
                if marker in visited_containers:
                    continue
                visited_containers.add(marker)
                for key, value in current.items():
                    normalized_key = re.sub(r"[^a-z0-9]+", "", str(key).casefold())
                    if (
                        normalized_key in _TABLE_NAME_KEYS
                        and isinstance(value, str)
                        and cls._is_slow_log_table_name(value)
                    ):
                        discovered.add(cls.clean_table_name(value))
                    pending.append(value)
                continue
            if isinstance(current, list):
                marker = id(current)
                if marker in visited_containers:
                    continue
                visited_containers.add(marker)
                pending.extend(current)
                continue
            if not isinstance(current, str) or _NO_MATCHING_TABLE_TEXT.search(current):
                continue
            for match in _SLOW_LOG_TABLE_TEXT.finditer(current):
                candidate = cls.clean_table_name(match.group("name"))
                if cls._is_slow_log_table_name(candidate):
                    discovered.add(candidate)
        return discovered

    @classmethod
    def target_key(cls, arguments: Mapping[str, Any]) -> tuple[int, str] | None:
        instance_id = cls._coerce_positive_integer(arguments.get("instance_id"))
        db_name = arguments.get("db_name")
        if instance_id is None or not isinstance(db_name, str) or not db_name.strip():
            return None
        return instance_id, db_name.strip().casefold()

    @classmethod
    def _metadata_resolution_step_from_sql(cls, sql: str) -> str | None:
        """Return a single prescribed relational hop, never infer host values."""

        tables = {
            cls.clean_table_name(name).casefold()
            for name in cls.sql_table_references(sql)
            if cls.clean_table_name(name).casefold() in {"t_instance_member", "sql_instance"}
        }
        return next(iter(tables)) if len(tables) == 1 else None

    @classmethod
    def record_metadata_resolution_evidence(
        cls,
        *,
        resolution_steps: dict[tuple[int, str], list[str]],
        member_instance_ids: dict[tuple[int, str], set[int]],
        resolved_endpoints: dict[tuple[int, str], set[str]],
        target: tuple[int, str],
        sql: str,
        payload: Mapping[str, Any],
        alert_endpoint: str | None,
        table_columns: Mapping[tuple[int, str], Mapping[str, set[str]]],
    ) -> None:
        """Record only metadata evidence that can be traced to the prior hop."""

        step = cls._metadata_resolution_step_from_sql(sql)
        if step == "t_instance_member":
            columns = table_columns.get(target, {}).get(step, set())
            if not cls._member_query_selects_instance_id(sql, columns):
                return
            if alert_endpoint is None:
                instance_ids = cls._member_instance_ids_from_payload(payload)
            elif cls._member_query_matches_alert_endpoint(sql, alert_endpoint):
                instance_ids = cls._member_instance_ids_from_payload(payload)
            elif cls._member_query_matches_alert_host(sql, alert_endpoint):
                # Archery's member table can have several ports for one host.
                # A host-scoped lookup is sufficient only when its returned row
                # itself supplies the exact alert host:port and its paired ID.
                instance_ids = cls._member_instance_ids_for_endpoint(
                    payload,
                    alert_endpoint,
                )
            else:
                return
            if instance_ids:
                member_instance_ids.setdefault(target, set()).update(instance_ids)
                resolution_steps.setdefault(target, []).append(step)
            return
        if step != "sql_instance":
            return
        columns = table_columns.get(target, {}).get(step, set())
        known_ids = member_instance_ids.get(target, set())
        if (
            not known_ids
            or not cls._sql_instance_query_uses_id(sql, known_ids)
            or not cls._sql_instance_query_selects_endpoint(sql, columns)
        ):
            return
        endpoints = cls._instance_endpoints_from_payload(payload)
        if endpoints:
            resolved_endpoints.setdefault(target, set()).update(endpoints)
            resolution_steps.setdefault(target, []).append(step)

    @classmethod
    def table_columns_from_payload(cls, payload: Mapping[str, Any]) -> set[str]:
        """Extract the real column names returned by list_table_columns."""

        columns: set[str] = set()
        pending: list[Any] = [payload]
        visited_containers: set[int] = set()
        while pending:
            current = pending.pop()
            if isinstance(current, Mapping):
                marker = id(current)
                if marker in visited_containers:
                    continue
                visited_containers.add(marker)
                for key, value in current.items():
                    normalized = cls._normalized_column_name(str(key))
                    if normalized in {
                        "name",
                        "column",
                        "columnname",
                        "field",
                    } and isinstance(value, str):
                        columns.add(value.strip())
                    elif isinstance(value, (Mapping, list, tuple)):
                        pending.append(value)
            elif isinstance(current, (list, tuple)):
                marker = id(current)
                if marker in visited_containers:
                    continue
                visited_containers.add(marker)
                pending.extend(current)
        return {column for column in columns if column}

    @staticmethod
    def _normalized_column_name(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", value.casefold())

    @classmethod
    def metadata_resolution_stage(
        cls,
        *,
        target: tuple[int, str] | None,
        alert_endpoint: str | None,
        member_instance_ids: Mapping[tuple[int, str], set[int]],
        resolved_endpoints: Mapping[tuple[int, str], set[str]],
        table_columns: Mapping[tuple[int, str], Mapping[str, set[str]]],
        query_trace: list[dict[str, Any]],
        history_query_completed: bool = False,
    ) -> str:
        """Return the next safe metadata hop; this is diagnostic, never authority."""

        if history_query_completed:
            return "history 查询已完成"
        if alert_endpoint is None:
            return "缺少告警端点"
        if target is None or not member_instance_ids.get(target):
            return "等待 t_instance_member"
        if not resolved_endpoints.get(target):
            return "等待 sql_instance"
        if any(
            entry.get("chain_stage") == "history"
            and entry.get("outcome") == "tool_error"
            and cls._is_query_timeout_detail(entry.get("error_detail"))
            for entry in query_trace
        ):
            return "等待优化后的 history 查询"
        history_columns = table_columns.get(target, {}).get(
            ARCHERY_SLOW_QUERY_REVIEW_TABLE.casefold(),
            set(),
        )
        if history_columns:
            return "等待 history 查询成功"
        return "等待 history 表字段"

    @classmethod
    def query_trace_entry(cls, call: MCPModelToolCall) -> dict[str, Any]:
        """Create a compact, sanitized audit record before a SQL call is sent."""

        sql = str(call.arguments.get("sql_content", ""))
        referenced_tables = sorted(cls.sql_table_references(sql))
        metadata_table = cls._metadata_resolution_step_from_sql(sql)
        return {
            "target": {
                "instance_id": cls._coerce_positive_integer(call.arguments.get("instance_id")),
                "db_name": (
                    str(call.arguments["db_name"]).strip()
                    if isinstance(call.arguments.get("db_name"), str)
                    else None
                ),
            },
            "referenced_tables": referenced_tables,
            "metadata_table": metadata_table,
            "chain_stage": (
                metadata_table
                if metadata_table is not None
                else "history"
                if cls._is_slow_query_review_history_select(sql)
                else "auxiliary"
            ),
            "sql_summary": cls._redacted_sql_summary(sql),
            "sent_to_mcp": False,
            "outcome": "pending",
        }

    @staticmethod
    def _redacted_sql_summary(sql: str) -> str:
        """Retain query shape for diagnostics without persisting literal values."""

        summary = re.sub(r"'(?:''|[^'])*'", "'?'", sanitize_text(sql))
        summary = re.sub(r"\b\d{3,}\b", "?", summary)
        return re.sub(r"\s+", " ", summary).strip()[:1_000]

    @classmethod
    def evidence_insufficient_result(
        cls,
        *,
        window_start: datetime,
        window_end: datetime,
        target: tuple[int, str] | None,
        attempted_model_calls: list[str],
        model_calls: list[MCPModelToolCall],
        mcp_roundtrip_count: int,
        alert_endpoint: str | None,
        query_trace: list[dict[str, Any]],
        metadata_resolution_steps: Mapping[tuple[int, str], list[str]],
        member_instance_ids: Mapping[tuple[int, str], set[int]],
        resolved_endpoints: Mapping[tuple[int, str], set[str]],
        table_columns: Mapping[tuple[int, str], Mapping[str, set[str]]],
        reason: str,
    ) -> ArcherySlowLogQueryResult:
        """Preserve an auditable partial investigation instead of raising model failure."""

        stage = cls.metadata_resolution_stage(
            target=target,
            alert_endpoint=alert_endpoint,
            member_instance_ids=member_instance_ids,
            resolved_endpoints=resolved_endpoints,
            table_columns=table_columns,
            query_trace=query_trace,
        )
        return ArcherySlowLogQueryResult(
            payload={"status": "evidence_insufficient", "reason": reason},
            requested_sql="",
            window_start=window_start,
            window_end=window_end,
            model_tool_calls=tuple(item.name for item in model_calls),
            model_request_ids=tuple(item.request_id for item in model_calls if item.request_id),
            instance_id=target[0] if target is not None else None,
            db_name=target[1] if target is not None else None,
            metadata_resolution_tables=tuple(
                metadata_resolution_steps.get(target, []) if target is not None else []
            ),
            diagnostics={
                "outcome": "evidence_insufficient",
                "reason": reason,
                "next_stage": stage,
                "alert_endpoint": alert_endpoint,
                "model_attempted_tool_calls": attempted_model_calls,
                "model_executed_tool_calls": [item.name for item in model_calls],
                "model_decision_count": len(attempted_model_calls),
                "mcp_tool_call_count": len(model_calls),
                "mcp_roundtrip_count": mcp_roundtrip_count,
                "query_trace": query_trace,
            },
            query_completed=False,
        )

    @staticmethod
    def payload_row_count(payload: Mapping[str, Any]) -> int | None:
        for container in ArcheryMCPClient._metadata_containers(payload):
            rows = ArcheryMCPClient._tabular_row_list(container)
            if rows is not None:
                return len(rows)
            for key in ("rowCount", "row_count", "total"):
                value = container.get(key)
                if type(value) is int and value >= 0:
                    return value
        return None

    @classmethod
    def _member_instance_ids_from_payload(cls, payload: Mapping[str, Any]) -> set[int]:
        return {
            value
            for row in cls._tabular_rows(payload)
            for key, raw_value in row.items()
            if re.sub(r"[^a-z0-9]+", "", key.casefold()) in {"finstanceid", "instanceid"}
            and (value := cls._coerce_positive_integer(raw_value)) is not None
        }

    @classmethod
    def _member_instance_ids_for_endpoint(
        cls,
        payload: Mapping[str, Any],
        alert_endpoint: str,
    ) -> set[int]:
        """Return only member IDs paired with the exact endpoint in result rows."""

        instance_ids: set[int] = set()
        for row in cls._tabular_rows(payload):
            normalized = {
                re.sub(r"[^a-z0-9]+", "", key.casefold()): value for key, value in row.items()
            }
            instance_id = next(
                (
                    cls._coerce_positive_integer(normalized.get(key))
                    for key in ("finstanceid", "instanceid")
                    if cls._coerce_positive_integer(normalized.get(key)) is not None
                ),
                None,
            )
            host = next(
                (
                    normalized[key]
                    for key in ("host", "hostname", "hostip", "ip", "fip")
                    if isinstance(normalized.get(key), str) and normalized[key].strip()
                ),
                None,
            )
            port = next(
                (
                    cls._coerce_positive_integer(normalized.get(key))
                    for key in ("port", "mysqlport", "fport")
                    if cls._coerce_positive_integer(normalized.get(key)) is not None
                ),
                None,
            )
            if (
                instance_id is not None
                and isinstance(host, str)
                and port is not None
                and port <= 65_535
                and cls._normalize_endpoint(f"{host.strip()}:{port}") == alert_endpoint
            ):
                instance_ids.add(instance_id)
        return instance_ids

    @classmethod
    def _instance_endpoints_from_payload(cls, payload: Mapping[str, Any]) -> set[str]:
        endpoints: set[str] = set()
        for row in cls._tabular_rows(payload):
            normalized = {
                re.sub(r"[^a-z0-9]+", "", key.casefold()): value for key, value in row.items()
            }
            host = next(
                (
                    normalized[key]
                    for key in ("host", "hostname", "hostip", "ip")
                    if isinstance(normalized.get(key), str) and normalized[key].strip()
                ),
                None,
            )
            port = next(
                (
                    cls._coerce_positive_integer(normalized.get(key))
                    for key in ("port", "mysqlport")
                    if cls._coerce_positive_integer(normalized.get(key)) is not None
                ),
                None,
            )
            if isinstance(host, str) and port is not None and port <= 65_535:
                endpoints.add(f"{host.strip()}:{port}")
        return endpoints

    @staticmethod
    def alert_endpoint_from_context(alert_context: Mapping[str, Any]) -> str | None:
        endpoint = alert_context.get("alert_endpoint")
        normalized = ArcheryMCPClient._normalize_endpoint(endpoint)
        if normalized is not None:
            return normalized
        host = alert_context.get("alert_host")
        port = alert_context.get("alert_port")
        normalized = ArcheryMCPClient._normalize_endpoint(
            f"{host.strip()}:{str(port).strip()}"
            if isinstance(host, str) and host.strip() and port not in (None, "")
            else None
        )
        if normalized is not None:
            return normalized
        return None

    @staticmethod
    def _normalize_endpoint(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if ":" not in candidate:
            return None
        host, port = candidate.rsplit(":", 1)
        if (
            not host
            or len(host) > 253
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host)
            or not port.isdecimal()
            or not 0 < int(port) <= 65_535
        ):
            return None
        return f"{host}:{int(port)}"

    @staticmethod
    def _member_query_matches_alert_endpoint(
        sql: str,
        alert_endpoint: str | None,
    ) -> bool:
        """Require the member lookup to be scoped to the alert host and port.

        The model must not obtain an arbitrary ``f_instance_id`` and then use its
        endpoint to authorize a history query.  This deliberately checks values,
        not assumed physical column names: deployments may expose aliased columns
        that were discovered through ``list_table_columns``.
        """

        if not alert_endpoint or ":" not in alert_endpoint:
            return False
        host, port = alert_endpoint.rsplit(":", 1)
        if not host or not port.isdecimal() or not 0 < int(port) <= 65_535:
            return False
        if not ArcheryMCPClient._member_query_matches_alert_host(sql, alert_endpoint):
            return False
        port_match = re.search(
            rf"(?is)=\s*(?:{int(port)}|'0*{int(port)}')(?![\d'])",
            sql,
        )
        return port_match is not None

    @staticmethod
    def _member_query_matches_alert_host(
        sql: str,
        alert_endpoint: str | None,
    ) -> bool:
        """Require a member lookup to be constrained to the alert host."""

        if not alert_endpoint or ":" not in alert_endpoint:
            return False
        host, _port = alert_endpoint.rsplit(":", 1)
        if not host:
            return False
        escaped_host = re.escape(host).replace("'", "''")
        host_match = re.search(
            rf"(?is)=\s*'{escaped_host}'(?:\s|\)|$)",
            sql,
        )
        return host_match is not None

    @classmethod
    def _member_query_selects_instance_id(
        cls,
        sql: str,
        discovered_columns: set[str],
    ) -> bool:
        select = re.search(r"(?is)\bselect\b(?P<body>.*?)\bfrom\b", sql)
        if select is None:
            return False
        selected = cls._normalized_column_name(select.group("body"))
        if discovered_columns:
            return any(
                cls._normalized_column_name(column) in {"finstanceid", "instanceid"}
                and cls._normalized_column_name(column) in selected
                for column in discovered_columns
            )
        # list_table_columns is preferred, but a completed read-only query can
        # independently confirm an explicitly selected conventional ID column.
        # Do not accept SELECT * here: the query must expose its lineage.
        return (
            re.search(
                r"(?i)(?<![A-Za-z0-9_$])`?(?:f_instance_id|instance_id)`?"
                r"(?![A-Za-z0-9_$])",
                select.group("body"),
            )
            is not None
        )

    @classmethod
    def _sql_instance_query_selects_endpoint(
        cls,
        sql: str,
        discovered_columns: set[str],
    ) -> bool:
        select = re.search(r"(?is)\bselect\b(?P<body>.*?)\bfrom\b", sql)
        if select is None:
            return False
        selected = cls._normalized_column_name(select.group("body"))
        normalized_columns = {cls._normalized_column_name(column) for column in discovered_columns}
        if normalized_columns:
            return any(
                ("host" in column or column.endswith("ip")) and column in selected
                for column in normalized_columns
            ) and any("port" in column and column in selected for column in normalized_columns)
        # As above, permit a result-backed explicit projection when schema
        # discovery is unavailable, without relying on SELECT * or prose.
        return bool(re.search(r"(?i)(?:host|hostname|hostip|ip)", selected)) and "port" in selected

    @staticmethod
    def _tabular_row_list(container: Mapping[str, Any]) -> list[Any] | None:
        for key in _ARCHERY_TABULAR_ROW_KEYS:
            value = container.get(key)
            if isinstance(value, list):
                return value
        return None

    @classmethod
    def _tabular_rows(cls, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Read common Archery tabular result shapes without trusting prose fields."""

        for container in cls._metadata_containers(payload):
            columns = container.get("columns") or container.get("column_list")
            rows = cls._tabular_row_list(container)
            if rows is None:
                continue
            if all(isinstance(row, Mapping) for row in rows):
                return [dict(row) for row in rows if isinstance(row, Mapping)]
            if isinstance(columns, list) and all(isinstance(column, str) for column in columns):
                return [
                    {column: value for column, value in zip(columns, row, strict=False)}
                    for row in rows
                    if isinstance(row, (list, tuple))
                ]
            return []
        return []

    @staticmethod
    def _sql_instance_query_uses_id(sql: str, known_ids: set[int]) -> bool:
        return any(
            re.search(
                rf"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?`?id`?\s*=\s*{instance_id}(?!\d)",
                sql,
            )
            is not None
            for instance_id in known_ids
        )

    @staticmethod
    def _without_leading_sql_comments(sql: str) -> str:
        statement = sql.lstrip()
        while True:
            comment = re.match(
                r"(?is)^(?:--[^\r\n]*(?:\r?\n|$)|\#[^\r\n]*(?:\r?\n|$)|"
                r"/\*.*?\*/)\s*",
                statement,
            )
            if comment is None:
                return statement
            statement = statement[comment.end() :]

    @staticmethod
    def _coerce_positive_integer(value: Any) -> int | None:
        if type(value) is int:
            return value if 0 < value <= 9_223_372_036_854_775_807 else None
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if not candidate or len(candidate) > 19 or not candidate.isascii():
            return None
        if not candidate.isdecimal():
            return None
        parsed = int(candidate)
        return parsed if 0 < parsed <= 9_223_372_036_854_775_807 else None

    @staticmethod
    def _is_query_timeout_detail(value: Any) -> bool:
        """Classify an observed server error for diagnostic stage reporting only."""

        return _QUERY_TIMEOUT_TEXT.search(str(value)) is not None

    @staticmethod
    def model_tool_error_result(
        error: ArcheryMCPToolError,
    ) -> str:
        detail = safe_error_detail(error)
        return (
            "上一 MCP 工具调用失败。以下是 MCP 返回的实际错误，"
            "它只是本轮 observation；请根据真实错误和已取得证据自主决定"
            "下一步调用或结束调查：\n" + detail
        )

    @classmethod
    def trace_projection(
        cls,
        tool_name: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Build the bounded final-history UI observation."""

        rows = cls._tabular_rows(payload)
        projection: dict[str, Any] = {
            "tool_name": sanitize_text(tool_name),
            "outcome": "result",
            "row_count": cls.payload_row_count(payload),
            "projection_kind": "mysql_slow_query_review_history",
        }
        semantic_rows = [cls._trace_slow_query_row(row) for row in rows]
        semantic_rows = [row for row in semantic_rows if row]
        semantic_rows.sort(key=cls._trace_slow_query_rank, reverse=True)
        projection.update(
            {
                "semantic_row_count": len(semantic_rows),
                "selected_row_count": min(
                    len(semantic_rows),
                    _ARCHERY_TRACE_SELECTED_ROWS,
                ),
                "rows": semantic_rows[:_ARCHERY_TRACE_SELECTED_ROWS],
            }
        )
        return sanitize(projection)

    @classmethod
    def _trace_slow_query_row(cls, row: Mapping[str, Any]) -> dict[str, Any]:
        casefolded = {str(key).casefold(): value for key, value in row.items()}
        projected: dict[str, Any] = {}
        for field in _SLOW_QUERY_IDENTITY_FIELDS:
            value = casefolded.get(field)
            if value is None:
                continue
            if field == "sample" and isinstance(value, str):
                projected["sample_sha256"] = sha256(value.encode("utf-8")).hexdigest()
                projected["sample_snippet"] = value[:_ARCHERY_TRACE_TEXT_CHARS]
            else:
                projected[field] = value
        for key, value in row.items():
            field = str(key)
            if field.casefold() in _SLOW_QUERY_IDENTITY_FIELDS:
                continue
            if cls._is_slow_query_metric_field(field) and value is not None:
                projected[field] = value
        return projected

    @staticmethod
    def _trace_slow_query_rank(row: Mapping[str, Any]) -> tuple[float, str]:
        scores: list[float] = []
        for key, value in row.items():
            if not str(key).casefold().startswith("query_time_") or isinstance(value, bool):
                continue
            try:
                scores.append(float(value))
            except (TypeError, ValueError):
                continue
        stable = json.dumps(
            sanitize(dict(row)),
            ensure_ascii=True,
            sort_keys=True,
            default=str,
        )
        return (max(scores, default=0.0), stable)

    @staticmethod
    def _is_slow_query_metric_field(field: str) -> bool:
        normalized = field.casefold()
        return normalized in _SLOW_QUERY_NUMERIC_FIELDS or normalized.startswith(
            _SLOW_QUERY_NUMERIC_PREFIXES
        )

    @staticmethod
    def extract_tool_payload(result: dict[str, Any]) -> dict[str, Any]:
        if result.get("isError") is True:
            raise ArcheryMCPToolError(
                ArcheryMCPClient._tool_content_summary(result)
                or "Archery MCP tool reported an execution error"
            )

        text_blocks = ArcheryMCPClient.tool_text_blocks(result)
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
            raise ArcheryMCPProtocolError("Archery MCP structuredContent was not an object")

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

    @classmethod
    def normalize_query_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        requested_sql: str,
    ) -> tuple[dict[str, Any], str | None, bool]:
        """Extract Archery's text-wrapped SQL result without constraining the Agent."""

        normalized_payload = dict(payload)
        echoed_sql: str | None = None
        reported_row_count: int | None = None
        for text in cls._metadata_text(payload):
            echoed_sql = echoed_sql or cls._executed_sql_from_text(text)
            if reported_row_count is None:
                reported_row_count = cls._reported_row_count_from_text(text)
            embedded_result = cls._embedded_result_object(text)
            if embedded_result is not None:
                normalized_payload = embedded_result
                break

        parsed_row_count = cls.payload_row_count(normalized_payload)
        if reported_row_count is not None:
            if parsed_row_count is None:
                normalized_payload["rowCount"] = reported_row_count
                normalized_payload["row_count_source"] = "archery_text"
            elif reported_row_count > parsed_row_count:
                normalized_payload["mcp_reported_row_count"] = reported_row_count
                normalized_payload["parsed_row_count"] = parsed_row_count

        executed_sql = next(
            (
                value.strip()
                for container in cls._metadata_containers(normalized_payload)
                for key in ("full_sql", "executed_sql", "sql_content")
                if isinstance((value := container.get(key)), str) and value.strip()
            ),
            echoed_sql,
        )
        actual_sql_verified = bool(
            executed_sql and cls._canonical_sql(executed_sql) == cls._canonical_sql(requested_sql)
        )
        if actual_sql_verified:
            normalized_payload = cls._with_inferred_query_columns(
                normalized_payload,
                sql=requested_sql,
            )
        return normalized_payload, executed_sql, actual_sql_verified

    @staticmethod
    def _reported_row_count_from_text(text: str) -> int | None:
        match = re.search(r"返回\s*(?P<count>\d+)\s*行", text)
        return int(match.group("count")) if match is not None else None

    @classmethod
    def _with_inferred_query_columns(
        cls,
        payload: Mapping[str, Any],
        *,
        sql: str,
    ) -> dict[str, Any]:
        """Label positional rows from a verified projection when Archery omits columns."""

        normalized = dict(payload)
        rows = normalized.get("rows")
        has_columns = isinstance(
            normalized.get("columns") or normalized.get("column_list"),
            list,
        )
        projected_columns = cls._simple_select_columns(sql)
        if (
            not has_columns
            and projected_columns
            and isinstance(rows, list)
            and rows
            and all(
                isinstance(row, (list, tuple)) and len(row) == len(projected_columns)
                for row in rows
            )
        ):
            normalized["columns"] = list(projected_columns)
            normalized["columns_source"] = "verified_sql_projection"
            return normalized
        for key, value in list(normalized.items()):
            if str(key).casefold() in _PAYLOAD_CONTAINER_KEYS and isinstance(value, Mapping):
                normalized[key] = cls._with_inferred_query_columns(value, sql=sql)
        return normalized

    @staticmethod
    def _simple_select_columns(sql: str) -> tuple[str, ...]:
        select = re.search(r"(?is)\bselect\b(?P<body>.*?)\bfrom\b", sql)
        if select is None:
            return ()
        columns: list[str] = []
        for expression in select.group("body").split(","):
            match = re.fullmatch(
                r"(?is)\s*(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                r"`?(?P<source>[A-Za-z_][A-Za-z0-9_$]*)`?"
                r"(?:\s+(?:as\s+)?`?(?P<alias>[A-Za-z_][A-Za-z0-9_$]*)`?)?\s*",
                expression,
            )
            if match is None:
                return ()
            columns.append(match.group("alias") or match.group("source"))
        return tuple(columns)

    @classmethod
    def _embedded_result_object(cls, text: str) -> dict[str, Any] | None:
        markers = list(re.finditer(r"结果\s*[：:]", text))
        decoder = json.JSONDecoder()
        for marker in reversed(markers):
            starts = sorted(
                start
                for start in (
                    text.find("[", marker.end()),
                    text.find("{", marker.end()),
                )
                if start >= 0
            )
            for start in starts:
                try:
                    decoded, _end = decoder.raw_decode(text[start:])
                except json.JSONDecodeError:
                    continue
                if isinstance(decoded, dict):
                    return decoded
                if isinstance(decoded, list):
                    return {"rows": decoded}
            recovered = cls._recover_complete_rows_from_json_prefix(text[marker.end() :])
            if recovered is not None:
                return recovered
        return None

    @classmethod
    def _recover_complete_rows_from_json_prefix(
        cls,
        fragment: str,
    ) -> dict[str, Any] | None:
        """Recover only complete row values from a character-truncated JSON result."""

        row_candidates: list[list[Any]] = []
        stripped_offset = len(fragment) - len(fragment.lstrip())
        if stripped_offset < len(fragment) and fragment[stripped_offset] == "[":
            rows, _closed = cls._decode_json_array_prefix(
                fragment,
                stripped_offset,
            )
            row_candidates.append(rows)

        for match in re.finditer(
            r'(?<!\\)"(?:rows|result|data)"\s*:\s*(?P<array>\[)',
            fragment,
            re.IGNORECASE,
        ):
            rows, _closed = cls._decode_json_array_prefix(
                fragment,
                match.start("array"),
            )
            row_candidates.append(rows)

        valid_candidates = [
            rows
            for rows in row_candidates
            if rows
            and all(isinstance(row, (Mapping, list, tuple)) for row in rows)
        ]
        if not valid_candidates:
            return None
        recovered_rows = max(valid_candidates, key=len)
        recovered: dict[str, Any] = {
            "rows": recovered_rows,
            "rows_recovered_from_truncated_json": True,
        }

        for match in re.finditer(
            r'(?<!\\)"(?:columns|column_list)"\s*:\s*(?P<array>\[)',
            fragment,
            re.IGNORECASE,
        ):
            columns, closed = cls._decode_json_array_prefix(
                fragment,
                match.start("array"),
            )
            if closed and columns and all(isinstance(column, str) for column in columns):
                recovered["columns"] = columns
                break
        return recovered

    @staticmethod
    def _decode_json_array_prefix(
        text: str,
        array_start: int,
        *,
        limit: int | None = None,
    ) -> tuple[list[Any], bool]:
        """Decode complete array items and stop before the first incomplete value."""

        decoder = json.JSONDecoder()
        items: list[Any] = []
        index = array_start + 1
        while limit is None or len(items) < limit:
            while index < len(text) and text[index].isspace():
                index += 1
            if index >= len(text):
                return items, False
            if text[index] == "]":
                return items, True
            try:
                item, index = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                return items, False
            items.append(item)
            while index < len(text) and text[index].isspace():
                index += 1
            if index >= len(text):
                return items, False
            if text[index] == "]":
                return items, True
            if text[index] != ",":
                return items, False
            index += 1
        return items, False

    @staticmethod
    def _executed_sql_from_text(text: str) -> str | None:
        match = re.search(
            r"(?is)执行的SQL\s*[：:]\s*(?P<sql>.*?)"
            r"(?:\r?\n\s*\r?\n|\r?\n\s*返回\s*\d+\s*行|"
            r"\r?\n\s*结果\s*[：:]|$)",
            text,
        )
        if match is None:
            return None
        sql = match.group("sql").strip()
        return sql or None

    @staticmethod
    def _canonical_sql(sql: str) -> str:
        candidate = sql.strip()
        while candidate.endswith(";"):
            candidate = candidate[:-1].rstrip()
        return re.sub(r"\s+", " ", candidate).casefold()

    @staticmethod
    def _where_body(sql: str) -> str | None:
        uncommented = ArcheryMCPClient._sql_without_comments(sql)
        if uncommented is None:
            return None
        where = re.search(
            r"(?is)\bwhere\b(?P<body>.*?)(?:\border\s+by\b|\blimit\b|$)",
            uncommented,
        )
        return where.group("body") if where is not None else None

    @classmethod
    def _query_range_time_column(cls, sql: str) -> str | None:
        where_body = cls._where_body(sql)
        if where_body is None:
            return None
        column_pattern = (
            r"(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?(?P<column>[A-Za-z_][A-Za-z0-9_$]*)`?\s*"
        )
        range_comparison = re.search(
            column_pattern + r"(?:>=|<=|>|<|\bbetween\b)",
            where_body,
            re.IGNORECASE,
        )
        return range_comparison.group("column") if range_comparison is not None else None

    @classmethod
    def query_time_column(cls, sql: str) -> str | None:
        range_column = cls._query_range_time_column(sql)
        if range_column is not None:
            return range_column
        where_body = cls._where_body(sql)
        if where_body is None:
            return None
        column_pattern = (
            r"(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?(?P<column>[A-Za-z_][A-Za-z0-9_$]*)`?\s*"
        )
        comparison = re.search(
            column_pattern + r"=",
            where_body,
            re.IGNORECASE,
        )
        return comparison.group("column") if comparison is not None else None

    @staticmethod
    def validate_business_success(
        payload: Mapping[str, Any],
        *,
        tool_name: str,
        supplemental_text: tuple[str, ...] = (),
    ) -> None:
        status = payload.get("status")
        if isinstance(status, str) and status.strip().casefold() in _FAILURE_STATUSES:
            detail = (
                payload.get("message") or payload.get("detail") or payload.get("error") or status
            )
            raise ArcheryMCPToolError(f"{tool_name} failed: {safe_error_detail(detail)}")
        if payload.get("success") is False:
            detail = (
                payload.get("message")
                or payload.get("detail")
                or payload.get("error")
                or "success=false"
            )
            raise ArcheryMCPToolError(f"{tool_name} failed: {safe_error_detail(detail)}")

        explicit_error = payload.get("error") or payload.get("errors")
        if explicit_error not in (None, "", False, [], {}):
            raise ArcheryMCPToolError(f"{tool_name} failed: {safe_error_detail(explicit_error)}")

        for decoded in ArcheryMCPClient._decoded_text_payloads(supplemental_text):
            ArcheryMCPClient.validate_business_success(
                decoded,
                tool_name=tool_name,
            )

    @staticmethod
    def tool_text_blocks(result: Mapping[str, Any]) -> tuple[str, ...]:
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
        return safe_error_detail(" ".join(str(value) for value in values if value))


class ArcherySlowLogEvidenceTool:
    """Run the configured Archery MCP evidence investigation."""

    name = ARCHERY_SLOW_LOG_TOOL_NAME
    source_system = "archery_mcp"
    input_schema = {
        "type": "object",
        "properties": {},
        "additionalProperties": True,
    }

    def __init__(
        self,
        client: ArcheryMCPClient,
        *,
        default_timeout_seconds: float = 30,
    ) -> None:
        self.client = client
        self.default_timeout_seconds = default_timeout_seconds
        self.role = client.prompts.role
        self.capability = client.prompts.purpose
        self.workflow = client.prompts.workflow
        self.safety = client.prompts.safety

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> tuple[str, dict[str, Any]] | ToolExecutionResult:
        del request
        alert_target_context = self._alert_target_context(context.alert)
        session_attempts = 1
        run_arguments = (
            {
                "run_id": context.run_id,
                "outer_dispatch_id": context.outer_dispatch_id,
                "lease_owner": context.lease_owner,
                "fencing_token": context.fencing_token,
            }
            if isinstance(self.client, ArcheryMCPClient)
            else {}
        )
        result = await self.client.execute_slow_log_query(
            context.alert.occurred_at,
            alert_context=alert_target_context,
            **run_arguments,
        )
        diagnostics = result.diagnostics or {}
        recorded_session_attempts = diagnostics.get("mcp_session_attempts")
        if type(recorded_session_attempts) is int and recorded_session_attempts > 0:
            session_attempts = max(session_attempts, recorded_session_attempts)
        if not result.query_completed:
            reason = str(diagnostics.get("reason") or "慢查询证据不足")
            next_stage = str(diagnostics.get("next_stage") or "等待补充可用证据")
            query_trace = diagnostics.get("query_trace")
            history_attempted = isinstance(query_trace, list) and any(
                isinstance(entry, Mapping)
                and entry.get("chain_stage") == "history"
                and entry.get("sent_to_mcp") is True
                for entry in query_trace
            )
            summary_prefix = (
                "Archery 最终 history 查询未成功"
                if history_attempted
                else "Archery 慢查询未执行最终 history 查询"
            )
            ineligible_reason = (
                "最终慢查询 SQL 未成功；当前证据不足"
                if history_attempted
                else "未执行最终慢查询 SQL；当前证据不足"
            )
            structured_data = self._build_slow_query_evidence(
                result,
                session_attempts=session_attempts,
                root_cause_ineligible_reason=ineligible_reason,
            )
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=(
                    f"{summary_prefix}：{reason}；"
                    f"下一阶段：{next_stage}。"
                    "已保留只读 MCP 调用轨迹，告警分析可继续但当前结论不充分。"
                ),
                structured_data=structured_data,
            )
        parsed_rows = ArcheryMCPClient._tabular_rows(result.payload)
        row_count = self._reported_row_count(result.payload)
        has_log_content = any(self._semantic_slow_query_row(row) for row in parsed_rows)
        remote_result_partial = (
            result.payload.get("rows_recovered_from_truncated_json") is True
        )
        if has_log_content and row_count is not None:
            row_summary = f"返回 {row_count} 行"
        elif row_count is not None and row_count > 0:
            row_summary = f"MCP 报告 {row_count} 行，但日志行未能解析"
        elif row_count == 0:
            row_summary = "返回 0 行"
        else:
            row_summary = "返回行数未能从 MCP 响应中解析"
        instance_summary = (
            f"实例 ID {result.instance_id}" if result.instance_id is not None else "实例 ID 未解析"
        )
        database_summary = result.db_name or "数据库名未解析"
        table_summary = result.table_name or "慢日志表名未解析"
        sql_summary = (
            "实际执行 SQL 已由 Archery 回显并与模型提交一致"
            if result.actual_sql_verified
            else "Archery 未返回可与模型提交内容核对的实际执行 SQL"
        )
        evidence_summary = (
            "慢查询日志已作为本次告警窗口的实时证据进入分析"
            if has_log_content
            else "当前没有可解析的慢查询日志，采集结果不完整"
        )
        summary = (
            f"Archery 慢查询只读查询成功：{instance_summary}，数据库 "
            f"{database_summary}，慢日志表 {table_summary}，{row_summary}；{sql_summary}；"
            f"{evidence_summary}。"
            "具体根因仍须结合日志内容和其他实时信号判断。"
        )
        ineligible_reason = (
            ""
            if has_log_content
            else (
                "慢查询结果为空，未返回可分析的日志内容"
                if row_count == 0
                else (
                    "MCP仅报告存在慢查询记录，但未返回可解析的日志行"
                    if row_count is not None and row_count > 0
                    else "无法解析慢查询返回行数"
                )
            )
        )
        structured_data = self._build_slow_query_evidence(
            result,
            session_attempts=session_attempts,
            parsed_rows=parsed_rows,
            root_cause_ineligible_reason=(
                "remote_result_character_truncated"
                if remote_result_partial
                else ineligible_reason
            ),
        )
        if remote_result_partial:
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=(
                    "Archery MCP 返回发生字符截断；已保留完整收到的原始信封和可解析行，"
                    "但部分结果不能用于支持根因。"
                ),
                structured_data=structured_data,
            )
        if not has_log_content:
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=summary,
                structured_data=structured_data,
            )
        return summary, structured_data

    def _final_result_passthrough(
        self,
        payload: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Return the format-converted final result, or its raw text when unparseable.

        The program only converts the JSON embedded in the Archery ``result`` text
        into a JSON object: positional rows are labeled with ``column_list`` and
        every other field is kept unchanged. No row is filtered, reordered,
        aggregated, or truncated, and no size limit is applied. When the embedded
        JSON cannot be parsed, the original text is returned verbatim so the main
        Agent still sees it while the record stays ineligible for root causes.
        """

        rows = payload.get("rows")
        if isinstance(rows, list):
            passthrough = {
                str(key): value for key, value in payload.items() if str(key) != "rows"
            }
            tabular = ArcheryMCPClient._tabular_rows(payload)
            if tabular:
                passthrough["rows"] = tabular
            else:
                # No column mapping is available; keep positional rows unchanged
                # so no fact is dropped or invented by the program.
                passthrough["rows"] = rows
            return passthrough, None
        raw_text = "\n".join(ArcheryMCPClient._metadata_text(payload))
        if raw_text.strip():
            return None, raw_text
        return None, None

    def _build_slow_query_evidence(
        self,
        result: ArcherySlowLogQueryResult,
        *,
        session_attempts: int,
        root_cause_ineligible_reason: str,
        parsed_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return complete sanitized evidence without application-layer truncation."""

        source_rows = parsed_rows or []
        semantic_rows = [self._semantic_slow_query_row(row) for row in source_rows]
        semantic_rows = [row for row in semantic_rows if row]
        reported_row_count = self._reported_row_count(result.payload)
        total_row_count = max(reported_row_count or 0, len(source_rows))
        partial = result.payload.get("rows_recovered_from_truncated_json") is True
        final_result_payload, final_result_text = self._final_result_passthrough(
            result.payload
        )
        structured_data: dict[str, Any] = {
            "schema_version": ARCHERY_SLOW_LOG_EVIDENCE_SCHEMA_VERSION,
            "query_completed": result.query_completed,
            "actual_sql_verified": result.actual_sql_verified,
            "allow_followup_dispatch": False,
            "mcp_session_attempts": session_attempts,
            "target": {
                "instance_id": result.instance_id,
                "db_name": sanitize(result.db_name),
                "table_name": sanitize(result.table_name),
            },
            "query_window": {
                "start": result.window_start.isoformat(),
                "end": result.window_end.isoformat(),
                "duration_seconds": self.client.window_seconds,
                "time_column": sanitize(result.query_time_column),
            },
            "reported_row_count": reported_row_count,
            "parsed_row_count": len(source_rows),
            "included_row_count": len(semantic_rows),
            "omitted_row_count": max(total_row_count - len(semantic_rows), 0),
            "rows": semantic_rows,
            "partial": partial,
            "root_cause_eligible": bool(semantic_rows) and not partial,
            "root_cause_ineligible_reason": root_cause_ineligible_reason,
        }
        if final_result_payload is not None:
            structured_data["final_result_payload"] = final_result_payload
        if final_result_text is not None:
            structured_data["final_result_parse_failed"] = True
            structured_data["final_result_text"] = final_result_text
        return sanitize(structured_data)

    @classmethod
    def _semantic_slow_query_row(cls, row: Mapping[str, Any]) -> dict[str, Any]:
        casefolded = {str(key).casefold(): value for key, value in row.items()}
        semantic: dict[str, Any] = {}
        for field in _SLOW_QUERY_IDENTITY_FIELDS:
            if field in casefolded:
                semantic[field] = sanitize(casefolded[field])
        for key, value in row.items():
            field = str(key)
            if field.casefold() in _SLOW_QUERY_IDENTITY_FIELDS:
                continue
            if cls._is_numeric_metric_field(field) and value is not None:
                semantic[field] = sanitize(value)
        return semantic

    @staticmethod
    def _is_numeric_metric_field(field: str) -> bool:
        return ArcheryMCPClient._is_slow_query_metric_field(field)

    @staticmethod
    def _reported_row_count(result: Mapping[str, Any]) -> int | None:
        for container in ArcheryMCPClient._metadata_containers(result):
            for key in (
                "mcp_reported_row_count",
                "rowCount",
                "row_count",
                "total",
            ):
                value = container.get(key)
                if type(value) is int and value >= 0:
                    return value
            rows = ArcheryMCPClient._tabular_row_list(container)
            if rows is not None:
                return len(rows)
        return None

    @staticmethod
    def _alert_target_context(alert: NormalizedAlert) -> dict[str, Any]:
        alert = preprocess_normalized_alert(alert)
        database = (
            alert.database.model_dump(mode="json", exclude_none=True)
            if alert.database is not None
            else {}
        )
        def candidates(*values: Any) -> list[str]:
            unique: list[str] = []
            for value in values:
                if not isinstance(value, str):
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        value = str(value)
                    else:
                        continue
                normalized = value.strip()
                if not normalized or normalized.casefold() == "unknown":
                    continue
                if normalized not in unique:
                    unique.append(normalized)
            return unique

        alert_host = next(iter(candidates(database.get("host"))), None)
        alert_port = next(iter(candidates(database.get("port"))), None)
        return {
            "reason": alert.reason,
            "alert_type": alert.alert_type,
            "environment": alert.environment,
            "service_name": alert.service_name,
            "cluster": alert.cluster,
            "resource_type": alert.resource_type,
            "database": database,
            "target_labels": {},
            "alert_host": alert_host,
            "alert_port": alert_port,
            "alert_endpoint": (f"{alert_host}:{alert_port}" if alert_host and alert_port else None),
            "instance_candidates": candidates(
                database.get("instance"),
                database.get("host"),
            ),
            "database_candidates": candidates(database.get("database")),
        }

    @staticmethod
    def _row_count(result: Mapping[str, Any]) -> int | None:
        for key in ("rowCount", "row_count", "total", "affected_rows"):
            value = result.get(key)
            if type(value) is int and value >= 0:
                return value
        for key in ("rows", "result"):
            rows = result.get(key)
            if isinstance(rows, list):
                return len(rows)
        data = result.get("data")
        if isinstance(data, dict):
            return ArcherySlowLogEvidenceTool._row_count(data)
        if isinstance(data, list):
            return len(data)
        return None

    @staticmethod
    def _has_parsed_log_rows(result: Mapping[str, Any]) -> bool:
        for key in ("rows", "result"):
            rows = result.get(key)
            if isinstance(rows, list) and rows:
                return all(isinstance(row, (Mapping, list, tuple)) for row in rows)
        data = result.get("data")
        if isinstance(data, Mapping):
            return ArcherySlowLogEvidenceTool._has_parsed_log_rows(data)
        if isinstance(data, list) and data:
            return all(isinstance(row, (Mapping, list, tuple)) for row in data)
        return False
