"""Archery MCP configuration, Provider policy/codec, facade, and evidence tool.

Session lifecycle, planning retries, budgets, checkpoints, and remote execution
belong exclusively to :mod:`app.adapters.archery_harness`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from math import isfinite
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from sqlglot import Dialect, exp, parse
from sqlglot.errors import ParseError, TokenError
from sqlglot.tokens import Token, TokenType

from app.adapters.archery_sql import (
    SQLTableReference,
    canonical_sql,
    is_simple_single_table_select,
    mysql_identifier_paths,
    mysql_table_references,
    strip_mysql_comments,
    unquoted_words,
)
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
    MCP_TRANSPORTS,
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    MCPTransport,
    load_mcp_catalog,
)

# Compatibility table identifiers used to recognize common Archery slow-log sources.
ARCHERY_SLOW_LOG_TABLE: Final = "t_slowlog_info"
ARCHERY_SLOW_QUERY_REVIEW_TABLE: Final = "mysql_slow_query_review_history"
ARCHERY_SLOW_LOG_TABLE_SEARCH_KEYWORD: Final = "slow"
ARCHERY_SLOW_LOG_TOOL_NAME: Final = "query_archery_slow_logs"
ARCHERY_SLOW_LOG_CAPABILITY: Final = "database.slow_query"
ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME: Final = "list_resource_groups_gymJPA"
ARCHERY_MCP_INSTANCES_TOOL_NAME: Final = "list_instances_gymJPA"
ARCHERY_MCP_DATABASES_TOOL_NAME: Final = "list_instance_databases_gymJPA"
ARCHERY_MCP_TABLES_TOOL_NAME: Final = "list_db_tables_gymJPA"
ARCHERY_MCP_COLUMNS_TOOL_NAME: Final = "list_table_columns_gymJPA"
ARCHERY_MCP_QUERY_TOOL_NAME: Final = "sql_query_gymJPA"
# Compatibility hint only; dynamic probes use the discovered table's real columns.
ARCHERY_SLOW_LOG_TIME_COLUMN: Final = "f_insert_time"
ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS: Final = 300
# mysql_slow_query_review_history 的 ts_min/ts_max 列以北京时间（UTC+8）字符串
# 存储；窗口本身仍以 UTC 计算，仅在传给 MCP 内层 Agent 时投影为北京时区字面量。
ARCHERY_SLOW_LOG_TS_COLUMN_TIMEZONE: Final = timezone(timedelta(hours=8))
ARCHERY_MCP_SERVER_NAME: Final = "archery"
ARCHERY_SLOW_LOG_PROMPT_VERSION: Final = "archery-slow-log-mcp-agent-v33"
ARCHERY_SLOW_LOG_EVIDENCE_SCHEMA_VERSION: Final = "archery-slow-query-summary-v7"
ARCHERY_HISTORY_PAGE_SIZE: Final = 100
ARCHERY_HISTORY_RESULT_CHARS: Final = 12_000
ARCHERY_SAMPLE_FULL_LENGTH_LIMIT: Final = 12_000
ARCHERY_SAMPLE_CHUNK_RESULT_CHARS: Final = 12_000
ARCHERY_SAMPLE_CHUNK_RESERVE_CHARS: Final = 2_000
ARCHERY_SAMPLE_CHUNK_MIN_CHARS: Final = 1_000
ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS: Final = "__history_sample_octet_length"
_MISSING: Final = object()

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
_SLOW_QUERY_PIPELINE_FIELDS: Final = (
    "id",
    "sample_full_length",
    "sample_representation",
    "sample_structure_executable",
    "sample_source_reconstructed",
    "sample_sha256",
    "sample_statement_type",
    "sample_table_references",
    "sample_in_lists",
    "sample_recovery_status",
    "priority",
    "query_time_max_rank",
    "query_time_sum_rank",
    "explain_status",
    "explain_source_sql_exact",
    "explain_reused_from_history_id",
    "explain_failure_reason",
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
_HISTORY_SAMPLE_PROJECTION_EXPRESSIONS: Final = (
    "id",
    "hostname_max",
    "client_max",
    "user_max",
    "db_max",
    "checksum",
    "ts_min",
    "ts_max",
    "ts_cnt",
    "Query_time_sum",
    "Query_time_min",
    "Query_time_max",
    "Query_time_pct_95",
    "Query_time_median",
    "Lock_time_sum",
    "Lock_time_max",
    "Rows_sent_sum",
    "Rows_examined_sum",
    "Full_scan_cnt",
    "Tmp_table_cnt",
    "Filesort_cnt",
    "Bytes_sum",
    "LEFT(sample, '4000') AS sample",
    "LENGTH(sample) AS sample_full_length",
)
_HISTORY_RANKING_PROJECTION_EXPRESSIONS: Final = (
    "id",
    "Query_time_max",
    "Query_time_sum",
)
_HISTORY_COMPACT_PROJECTION_EXPRESSIONS: Final = (
    *_HISTORY_SAMPLE_PROJECTION_EXPRESSIONS[:-2],
    "LENGTH(sample) AS sample_full_length",
)

_ARCHERY_TRACE_SELECTED_ROWS: Final = 3
_ARCHERY_TRACE_TEXT_CHARS: Final = 400
_ARCHERY_TABULAR_ROW_KEYS: Final = ("rows", "result", "results", "data")
_ENDPOINT_HOST_COLUMN_NAMES: Final = frozenset({"fip", "host", "hostip", "hostname", "ip"})
_ENDPOINT_PORT_COLUMN_NAMES: Final = frozenset({"fport", "hostport", "port"})

_ENV_REFERENCE: Final = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
_QUERY_TIMEOUT_TEXT: Final = re.compile(
    r"查询超时(?:被\s*)?kill|执行超时|query\s+timeout|timed?\s+out|\btimeout\b"
    r"|query\s+execution\s+was\s+interrupted"
    r"|maximum\s+statement\s+execution\s+time\s+exceeded",
    re.IGNORECASE,
)
_TABLE_COLUMNS_TEXT_HEADER: Final = re.compile(
    r"^\s*实例\s+\d+\s*/\s*数据库\s+\S+\s*/\s*表\s+\S+\s*"
    r"的字段(?:（数据字典）|\(数据字典\))?\s*[：:]\s*$"
)
_TABLE_COLUMNS_TEXT_ITEM: Final = re.compile(
    r"^\s*-\s+(?P<column>`[^`\r\n]+`|[A-Za-z_][A-Za-z0-9_$]*)\s*$"
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
_INSTANCE_LIST_HEADER_TEXT: Final = re.compile(r"^\s*实例清单（第\s*\d+\s*页）[：:]\s*$")
_INSTANCE_LIST_ROW_TEXT: Final = re.compile(
    r"^\s*\d+\.\s*\[ID:(?P<instance_id>[1-9]\d*)\]\s+"
    r"(?P<instance_ref>\S+)\s+(?P<endpoint>\S+:\d{1,5})\s+"
    r"资源组:\[[^\]\r\n]*\]\s*$"
)
_DATABASE_LIST_HEADER_TEXT: Final = re.compile(
    r"^\s*实例\s+(?P<instance_id>[1-9]\d*)\s+的数据库清单[：:]\s*$"
)
_DATABASE_LIST_ROW_TEXT: Final = re.compile(r"^\s*\d+\.\s+(?P<db_name>\S+)\s*$")
_ALLOWLIST_REJECTION_TEXT: Final = re.compile(
    r"^\s*(?:"
    r"未在\s*allowlist\.json\s*中找到实例引用|"
    r"实例不在白名单中?[，,\s]*(?:已)?拒绝执行|"
    r"实例不在\s*allowlist[，,\s]*(?:已)?拒绝执行|"
    r"instance\b[^\r\n]{0,200}\b(?:not|isn't)\b[^\r\n]{0,100}\ballowlist\b"
    r")",
    re.IGNORECASE | re.MULTILINE,
)
_SQL_QUERY_FAILURE_TEXT: Final = re.compile(
    r"^\s*SQL\s*查询失败[：:]",
    re.MULTILINE,
)
_INFORMATION_SCHEMA_PROJECTION_FIELDS: Final = {
    "columns": {
        "character_maximum_length",
        "column_comment",
        "column_default",
        "column_key",
        "column_name",
        "column_type",
        "data_type",
        "extra",
        "generation_expression",
        "is_nullable",
        "numeric_precision",
        "numeric_scale",
        "ordinal_position",
        "privileges",
        "srs_id",
        "table_name",
        "table_schema",
    },
    "statistics": {
        "cardinality",
        "collation",
        "column_name",
        "comment",
        "expression",
        "index_comment",
        "index_name",
        "index_schema",
        "index_type",
        "is_visible",
        "non_unique",
        "nullable",
        "packed",
        "seq_in_index",
        "sub_part",
        "table_name",
        "table_schema",
    },
}


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
    transport: MCPTransport


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
    slow_query_analysis: dict[str, Any] | None = None
    # ``None`` preserves compatibility for model-driven legacy results. The
    # deterministic pipeline sets this explicitly and never infers completeness
    # from a compact or truncated payload.
    history_complete: bool | None = None
    history_incomplete_reasons: tuple[str, ...] = ()
    enrichment_partial: bool = False
    enrichment_stop_reason: str | None = None
    enrichment_unfinished_ids: tuple[int, ...] = ()


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
        transport=connection.transport,
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
        investigation_budget_seconds: float = 150,
        deterministic_history_pipeline: bool = True,
        http_transport: httpx.AsyncBaseTransport | None = None,
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
        if server.transport not in MCP_TRANSPORTS:
            raise ArcheryMCPConfigurationError(
                "Archery MCP transport must be sse or streamable_http"
            )
        if not 60 <= window_seconds <= 86_400:
            raise ArcheryMCPConfigurationError(
                "Archery slow-log window must be between 60 and 86400 seconds"
            )
        if investigation_budget_seconds <= 0:
            raise ArcheryMCPConfigurationError(
                "Archery investigation budget must be greater than zero"
            )
        self.mcp_transport = server.transport
        self.mcp_url = server.url.strip()
        self.slow_log_time_column = ARCHERY_SLOW_LOG_TIME_COLUMN
        self.window_seconds = window_seconds
        self.timeout_seconds = timeout_seconds
        self.investigation_budget_seconds = investigation_budget_seconds
        self.deterministic_history_pipeline = deterministic_history_pipeline
        self.model = model
        self.prompts = server.prompts
        self._headers = dict(server.headers)
        self._http_transport = http_transport
        self._harness_connector = harness_connector
        self._harness_runtime_dependencies = harness_runtime_dependencies

    @property
    def headers(self) -> Mapping[str, str]:
        """Resolved transport headers exposed read-only to the Harness connector."""

        return self._headers

    @property
    def http_transport(self) -> httpx.AsyncBaseTransport | None:
        """Optional HTTP transport override used by deterministic tests."""

        return self._http_transport

    @classmethod
    def from_settings(
        cls,
        settings_path: Path,
        model: MCPToolCallingModel,
        *,
        environment: Mapping[str, str],
        window_seconds: int = ARCHERY_SLOW_LOG_DEFAULT_WINDOW_SECONDS,
        timeout_seconds: float = 60,
        investigation_budget_seconds: float = 150,
        deterministic_history_pipeline: bool = True,
        http_transport: httpx.AsyncBaseTransport | None = None,
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
            investigation_budget_seconds=investigation_budget_seconds,
            deterministic_history_pipeline=deterministic_history_pipeline,
            http_transport=http_transport,
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
                "ts_min_lower_bound_beijing": beijing(window_start - timedelta(hours=1)),
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

        return strip_mysql_comments(sql)

    @classmethod
    def is_slow_log_select(cls, sql: str) -> bool:
        statement = cls._without_leading_sql_comments(sql.strip())
        if re.match(r"(?is)^(?:select|with)\b", statement) is None:
            return False
        return any(
            cls._is_slow_log_table_name(reference.table)
            for reference in cls.explainable_physical_table_references(statement)
        )

    @classmethod
    def has_slow_log_reference(cls, sql: str) -> bool:
        """Return whether a lexically valid statement names a slow-log source."""

        references = cls.explainable_physical_table_reference_sequence(sql)
        return references is not None and any(
            cls._is_slow_log_table_name(reference.table) for reference in references
        )

    @classmethod
    def _is_slow_query_review_history_select(cls, sql: str) -> bool:
        """Identify the final history source after a call has already completed."""

        statement = cls._without_leading_sql_comments(sql.strip())
        if re.match(r"(?is)^(?:select|with)\b", statement) is None:
            return False
        return ARCHERY_SLOW_QUERY_REVIEW_TABLE.casefold() in {
            reference.table.casefold()
            for reference in cls.explainable_physical_table_references(statement)
        }

    @classmethod
    def is_history_result_query(cls, sql: str) -> bool:
        """Recognize the only Archery result with main-Agent evidence semantics.

        This is a post-result classifier. It never accepts, rejects, or rewrites an
        MCP call and deliberately does not inspect target, predicates, ordering, or
        row limits. Those choices belong to the Agent and the MCP server.
        """

        return cls._is_slow_query_review_history_select(sql)

    @classmethod
    def is_history_recovery_query(cls, sql: str) -> bool:
        """Allow only a single SELECT whose physical source is the history table."""

        statement = cls._single_sql_statement(sql)
        if statement is None or re.match(r"(?is)^\s*(?:select|with)\b", statement) is None:
            return False
        references = cls.explainable_physical_table_references(statement)
        return bool(references) and all(
            reference.table.casefold() == ARCHERY_SLOW_QUERY_REVIEW_TABLE.casefold()
            for reference in references
        )

    @classmethod
    def is_history_id_only_projection(cls, sql: str) -> bool:
        """Classify id-only listing queries issued after result truncation.

        This is a post-result classifier in the same spirit as
        ``is_history_result_query``: it never accepts, rejects, or rewrites a
        call. An id listing navigates the follow-up per-id retrieval and is
        never itself the final slow-log result.
        """

        return cls._simple_select_columns(sql) == ("id",)

    @classmethod
    def has_safe_direct_select_projection(cls, sql: str) -> bool:
        """Accept only ``*`` or direct column references in a SELECT list."""

        statement = cls._single_sql_statement(sql)
        if statement is None:
            return False
        select = re.match(r"(?is)^\s*select\s+(?P<body>.*?)\s+from\s+", statement)
        if select is None:
            return False
        expressions = cls._split_top_level_expressions(select.group("body"))
        if expressions == ("*",):
            return True
        return bool(expressions) and all(
            re.fullmatch(
                r"(?is)\s*(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                r"`?[A-Za-z_][A-Za-z0-9_$]*`?"
                r"(?:\s+(?:as\s+)?`?[A-Za-z_][A-Za-z0-9_$]*`?)?\s*",
                expression,
            )
            is not None
            for expression in expressions
        )

    @classmethod
    def is_simple_metadata_select(cls, sql: str) -> bool:
        """Recognize the closed, expression-free pre-history SELECT shape."""

        return is_simple_single_table_select(sql) and cls.has_safe_direct_select_projection(sql)

    @classmethod
    def is_history_id_retrieval_query(cls, sql: str) -> bool:
        """Classify one of the two closed per-id recovery projections."""

        return cls.history_id_retrieval(sql) is not None

    @classmethod
    def history_id_retrieval(cls, sql: str) -> tuple[int, str] | None:
        """Return ``(id, projection)`` for one semantically safe recovery query."""

        retrieval, _reason_code = cls.history_id_retrieval_validation(sql)
        return retrieval

    @classmethod
    def history_sample_chunk_retrieval(
        cls,
        sql: str,
    ) -> tuple[int, int, int] | None:
        retrieval = cls.history_id_retrieval(sql)
        if retrieval is None or not retrieval[1].startswith("sample_chunk:"):
            return None
        try:
            _, raw_offset, raw_size = retrieval[1].split(":", 2)
            return retrieval[0], int(raw_offset), int(raw_size)
        except (TypeError, ValueError):
            return None

    @classmethod
    def history_id_retrieval_validation(
        cls,
        sql: str,
    ) -> tuple[tuple[int, str] | None, str | None]:
        """Validate one per-id query through sqlglot's MySQL AST.

        Formatting, quoting, aliases, an id-only ORDER BY, and a plain top-level
        LIMIT with any value are immaterial. Additional data sources, predicates,
        projections, offsets, or query operators fail closed before transport.
        """

        parser_input = cls._sql_without_comments(sql)
        if parser_input is None:
            return None, "history_recovery_sql_parse_failed"
        try:
            statements = parse(parser_input, read="mysql")
        except (ParseError, TokenError):
            return None, "history_recovery_sql_parse_failed"
        if len(statements) != 1 or statements[0] is None:
            return None, "history_recovery_not_single_statement"
        tree = statements[0]
        if not isinstance(tree, exp.Select) or len(list(tree.find_all(exp.Select))) != 1:
            return None, "history_recovery_not_single_select"
        allowed_args = {
            "distinct",
            "exclude",
            "expressions",
            "from_",
            "hint",
            "kind",
            "limit",
            "offset",
            "operation_modifiers",
            "order",
            "where",
        }
        if any(
            value not in (None, False, (), [])
            for key, value in tree.args.items()
            if key not in allowed_args
        ) or any(
            tree.args.get(key) not in (None, False, (), [])
            for key in ("distinct", "exclude", "hint", "operation_modifiers")
        ):
            return None, "history_recovery_query_shape_forbidden"

        tables = list(tree.find_all(exp.Table))
        from_clause = tree.args.get("from_")
        if (
            len(tables) != 1
            or not isinstance(from_clause, exp.From)
            or from_clause.this is not tables[0]
        ):
            return None, "history_recovery_data_source_forbidden"
        table = tables[0]
        table_name = cls._ascii_identifier(table.name)
        schema_name = cls._ascii_identifier(table.db) if table.db else None
        if (
            table_name != ARCHERY_SLOW_QUERY_REVIEW_TABLE
            or bool(table.catalog)
            or (table.db and schema_name != "archery")
        ):
            return None, "history_recovery_target_forbidden"
        if any(
            value not in (None, False, (), [])
            for key, value in table.args.items()
            if key not in {"alias", "catalog", "db", "this"}
        ):
            return None, "history_recovery_query_shape_forbidden"
        table_alias = table.args.get("alias")
        if isinstance(table_alias, exp.TableAlias) and table_alias.columns:
            return None, "history_recovery_query_shape_forbidden"
        qualifier = cls._ascii_identifier(table.alias or table.name)
        if qualifier is None:
            return None, "history_recovery_query_shape_forbidden"

        def is_column(value: exp.Expression, name: str) -> bool:
            column_name = (
                cls._ascii_identifier(value.name) if isinstance(value, exp.Column) else None
            )
            column_table = (
                cls._ascii_identifier(value.table)
                if isinstance(value, exp.Column) and value.table
                else None
            )
            return bool(
                isinstance(value, exp.Column)
                and not isinstance(value.this, exp.Star)
                and column_name == name.lower()
                and not value.db
                and not value.catalog
                and (not value.table or column_table == qualifier)
            )

        def is_id_column(value: exp.Expression) -> bool:
            return is_column(value, "id")

        projections = list(tree.expressions)
        projection_kind: str | None = None
        if len(projections) == 1 and (
            isinstance(projections[0], exp.Star)
            or (
                isinstance(projections[0], exp.Column)
                and isinstance(projections[0].this, exp.Star)
                and not projections[0].db
                and not projections[0].catalog
                and (
                    not projections[0].table
                    or cls._ascii_identifier(projections[0].table) == qualifier
                )
            )
        ):
            projection_kind = "full"
        elif cls._is_history_sample_prefix_projection(
            projections,
            qualifier=qualifier,
        ):
            projection_kind = "sample_prefix"
        elif len(projections) == 1 and is_column(projections[0], "sample"):
            projection_kind = "sample"
        elif (
            chunk := cls._history_sample_chunk_projection(
                projections,
                qualifier=qualifier,
            )
        ) is not None:
            projection_kind = f"sample_chunk:{chunk[0]}:{chunk[1]}"
        if projection_kind is None:
            return None, "history_recovery_projection_forbidden"

        where = tree.args.get("where")
        condition = where.this if isinstance(where, exp.Where) else None
        while isinstance(condition, exp.Paren):
            condition = condition.this
        if not isinstance(condition, exp.EQ):
            return None, "history_recovery_id_predicate_required"
        operands = ((condition.this, condition.expression), (condition.expression, condition.this))
        literal = next(
            (
                candidate
                for column, candidate in operands
                if is_id_column(column) and isinstance(candidate, exp.Literal) and candidate.is_int
            ),
            None,
        )
        row_id = (
            cls._coerce_positive_integer(literal.this) if isinstance(literal, exp.Literal) else None
        )
        if row_id is None:
            return None, "history_recovery_id_predicate_required"

        order = tree.args.get("order")
        if order is not None:
            ordered = list(order.expressions) if isinstance(order, exp.Order) else []
            try:
                order_tokens = Dialect.get_or_raise("mysql").tokenize(parser_input)
            except TokenError:
                return None, "history_recovery_sql_parse_failed"
            if (
                len(ordered) != 1
                or not isinstance(ordered[0], exp.Ordered)
                or not is_id_column(ordered[0].this)
                or ordered[0].args.get("with_fill") not in (None, False)
                or cls._has_explicit_order_nulls_modifier(order_tokens)
            ):
                return None, "history_recovery_order_forbidden"

        if tree.args.get("offset") is not None:
            return None, "history_recovery_offset_forbidden"
        return (row_id, projection_kind), None

    @staticmethod
    def _has_explicit_order_nulls_modifier(tokens: Sequence[Token]) -> bool:
        """Reject non-MySQL NULLS FIRST/LAST syntax retained by sqlglot."""

        order_seen = False
        for index, token in enumerate(tokens[:-1]):
            if token.token_type is TokenType.ORDER_BY:
                order_seen = True
                continue
            if (
                order_seen
                and token.text.casefold() == "nulls"
                and tokens[index + 1].text.casefold() in {"first", "last"}
            ):
                return True
        return False

    @classmethod
    def _is_history_sample_prefix_projection(
        cls,
        projections: Sequence[exp.Expression],
        *,
        qualifier: str,
    ) -> bool:
        """Match the fixed truncation projection by AST, including table aliases."""

        if len(projections) != len(_HISTORY_SAMPLE_PROJECTION_EXPRESSIONS):
            return False

        def column_matches(value: exp.Expression, expected_name: str) -> bool:
            if isinstance(value, exp.Alias):
                if cls._ascii_identifier(value.alias) != expected_name.lower():
                    return False
                value = value.this
            column_name = (
                cls._ascii_identifier(value.name) if isinstance(value, exp.Column) else None
            )
            column_table = (
                cls._ascii_identifier(value.table)
                if isinstance(value, exp.Column) and value.table
                else None
            )
            return bool(
                isinstance(value, exp.Column)
                and not isinstance(value.this, exp.Star)
                and column_name == expected_name.lower()
                and not value.db
                and not value.catalog
                and (not value.table or column_table == qualifier)
            )

        direct_names = _HISTORY_SAMPLE_PROJECTION_EXPRESSIONS[:-2]
        if any(
            not column_matches(expression, expected_name)
            for expression, expected_name in zip(
                projections[:-2],
                direct_names,
                strict=True,
            )
        ):
            return False

        sample_prefix = projections[-2]
        if (
            not isinstance(sample_prefix, exp.Alias)
            or cls._ascii_identifier(sample_prefix.alias) != "sample"
            or not isinstance(sample_prefix.this, exp.Left)
            or not column_matches(sample_prefix.this.this, "sample")
            or not isinstance(sample_prefix.this.expression, exp.Literal)
            or not sample_prefix.this.expression.is_string
            or sample_prefix.this.expression.this != "4000"
        ):
            return False

        sample_length = projections[-1]
        return bool(
            isinstance(sample_length, exp.Alias)
            and cls._ascii_identifier(sample_length.alias) == "sample_full_length"
            and isinstance(sample_length.this, exp.Length)
            and sample_length.this.args.get("binary") is True
            and column_matches(sample_length.this.this, "sample")
        )

    @staticmethod
    def _ascii_identifier(value: str) -> str | None:
        """Canonicalize only the ASCII identifiers used by the closed query shape."""

        return value.lower() if value and value.isascii() else None

    @staticmethod
    def _split_top_level_expressions(sql: str) -> tuple[str, ...]:
        expressions: list[str] = []
        start = 0
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(sql):
            character = sql[index]
            if quote is not None:
                if character == "\\" and quote != "`":
                    index += 2
                    continue
                if character == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if character in {"'", '"', "`"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth < 0:
                    return ()
            elif character == "," and depth == 0:
                expression = sql[start:index].strip()
                if not expression:
                    return ()
                expressions.append(expression)
                start = index + 1
            index += 1
        if quote is not None or depth != 0:
            return ()
        expression = sql[start:].strip()
        if not expression:
            return ()
        expressions.append(expression)
        return tuple(expressions)

    @classmethod
    def _history_sample_chunk_projection(
        cls,
        projections: Sequence[exp.Expression],
        *,
        qualifier: str,
    ) -> tuple[int, int] | None:
        if len(projections) != 1 or not isinstance(projections[0], exp.Alias):
            return None
        projection = projections[0]
        if cls._ascii_identifier(projection.alias) != "sample_chunk":
            return None
        substring = projection.this
        if not isinstance(substring, exp.Substring):
            return None
        sample = substring.this
        column_name = cls._ascii_identifier(sample.name) if isinstance(sample, exp.Column) else None
        column_table = (
            cls._ascii_identifier(sample.table)
            if isinstance(sample, exp.Column) and sample.table
            else None
        )
        if not (
            isinstance(sample, exp.Column)
            and column_name == "sample"
            and not sample.db
            and not sample.catalog
            and (not sample.table or column_table == qualifier)
        ):
            return None
        start = substring.args.get("start")
        length = substring.args.get("length")
        if not (
            isinstance(start, exp.Literal)
            and start.is_int
            and isinstance(length, exp.Literal)
            and length.is_int
        ):
            return None
        offset = cls._coerce_positive_integer(start.this)
        size = cls._coerce_positive_integer(length.this)
        if offset is None or size is None or size > cls.history_sample_chunk_size():
            return None
        return offset, size

    @staticmethod
    def history_sample_chunk_size(
        max_result_chars: int = ARCHERY_SAMPLE_CHUNK_RESULT_CHARS,
    ) -> int:
        """Use most of the MCP envelope while reserving room for JSON metadata."""

        return max(
            ARCHERY_SAMPLE_CHUNK_MIN_CHARS,
            max_result_chars - ARCHERY_SAMPLE_CHUNK_RESERVE_CHARS,
        )

    @staticmethod
    def history_sample_sql(row_id: int) -> str:
        return f"SELECT sample FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"

    @staticmethod
    def history_sample_chunk_sql(row_id: int, offset: int, size: int) -> str:
        return (
            f"SELECT SUBSTRING(sample, {offset}, {size}) AS sample_chunk FROM "
            f"{ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"
        )

    @staticmethod
    def history_ranking_projection_sql() -> str:
        return ", ".join(_HISTORY_RANKING_PROJECTION_EXPRESSIONS)

    @classmethod
    def history_base_projection_columns(
        cls,
        columns: Sequence[str],
    ) -> tuple[str, ...]:
        """Return every discovered History column in a deterministic safe order."""

        normalized: dict[str, str] = {}
        for raw_column in columns:
            column = str(raw_column).strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", column) is None:
                raise ValueError("history column is not a safe MySQL identifier")
            folded = column.casefold()
            if folded in normalized:
                raise ValueError("history columns are ambiguous after case folding")
            normalized[folded] = column
        if "id" not in normalized or "sample" not in normalized:
            raise ValueError("history columns must include id and sample")
        if ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS.casefold() in normalized:
            raise ValueError("history columns collide with the Host-only sample length alias")
        return tuple(sorted(normalized.values(), key=lambda item: (item.casefold(), item)))

    @classmethod
    def history_compact_projection_sql(
        cls,
        columns: Sequence[str] | None = None,
    ) -> str:
        """Build the lossless non-sample projection used before sample chunking.

        The no-argument form remains only for validating legacy checkpoints.
        New deterministic runs supply the complete discovered table schema.
        """

        if columns is None:
            return ", ".join(_HISTORY_COMPACT_PROJECTION_EXPRESSIONS)
        ordered = cls.history_base_projection_columns(columns)
        direct = [f"`{column}`" for column in ordered if column.casefold() != "sample"]
        direct.append(
            "LENGTH(`sample`) AS " f"`{ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS}`"
        )
        return ", ".join(direct)

    @classmethod
    def is_history_ranking_projection(cls, sql: str) -> bool:
        columns = cls._simple_select_columns(sql)
        return tuple(column.casefold() for column in columns) == tuple(
            item.casefold() for item in _HISTORY_RANKING_PROJECTION_EXPRESSIONS
        )

    @classmethod
    def is_history_compact_projection(
        cls,
        sql: str,
        columns: Sequence[str] | None = None,
    ) -> bool:
        parser_input = cls._sql_without_comments(sql)
        if parser_input is None:
            return False
        try:
            statements = parse(parser_input, read="mysql")
        except (ParseError, TokenError):
            return False
        if len(statements) != 1 or not isinstance(statements[0], exp.Select):
            return False
        tree = statements[0]
        tables = list(tree.find_all(exp.Table))
        if len(tables) != 1:
            return False
        qualifier = cls._ascii_identifier(tables[0].alias or tables[0].name)
        if qualifier is None:
            return False
        if columns is None:
            expected_columns = tuple(_HISTORY_COMPACT_PROJECTION_EXPRESSIONS[:-1])
            expected_alias = "sample_full_length"
        else:
            try:
                expected_columns = tuple(
                    column
                    for column in cls.history_base_projection_columns(columns)
                    if column.casefold() != "sample"
                )
            except ValueError:
                return False
            expected_alias = ARCHERY_HISTORY_SAMPLE_LENGTH_ALIAS
        projections = list(tree.expressions)
        if len(projections) != len(expected_columns) + 1:
            return False

        def direct_column(value: exp.Expression, expected: str) -> bool:
            if isinstance(value, exp.Alias):
                if cls._ascii_identifier(value.alias) != expected.casefold():
                    return False
                value = value.this
            return bool(
                isinstance(value, exp.Column)
                and cls._ascii_identifier(value.name) == expected.casefold()
                and not value.db
                and not value.catalog
                and (not value.table or cls._ascii_identifier(value.table) == qualifier)
            )

        if any(
            not direct_column(value, expected)
            for value, expected in zip(
                projections[:-1],
                expected_columns,
                strict=True,
            )
        ):
            return False
        length_projection = projections[-1]
        return bool(
            isinstance(length_projection, exp.Alias)
            and cls._ascii_identifier(length_projection.alias) == expected_alias.casefold()
            and isinstance(length_projection.this, exp.Length)
            and length_projection.this.args.get("binary") is True
            and direct_column(length_projection.this.this, "sample")
        )

    @staticmethod
    def history_sample_projection_sql(row_id: int) -> str:
        """Build the only field-level recovery projection accepted by policy."""

        return (
            f"SELECT {', '.join(_HISTORY_SAMPLE_PROJECTION_EXPRESSIONS)} FROM "
            f"{ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"
        )

    @classmethod
    def classify_explainable_statement(cls, sql: str) -> str | None:
        """Return the top-level statement type accepted by a plain EXPLAIN.

        This classifier deliberately differs from a read-only classifier. MySQL
        and compatible engines can explain INSERT, UPDATE, DELETE, and REPLACE
        without executing them. The Host still rejects the sample itself and
        always rejects EXPLAIN ANALYZE, which does execute its inner statement.
        """

        statement = cls._single_sql_statement(sql)
        if statement is None:
            return None
        first = re.match(r"(?is)^\s*([a-z]+)\b", statement)
        if first is None:
            return None
        keyword = first.group(1).casefold()
        if keyword in {"select", "insert", "update", "delete", "replace"}:
            return keyword
        if keyword != "with":
            return None
        return cls._with_terminal_statement_type(statement)

    @classmethod
    def classify_plain_explain(cls, sql: str) -> str | None:
        """Return a safe, single inner statement from plain EXPLAIN SQL."""

        statement = cls._single_sql_statement(sql)
        if statement is None:
            return None
        match = re.match(r"(?is)^\s*explain\b(?P<tail>.*)$", statement)
        if match is None:
            return None
        tail = match.group("tail").lstrip()
        # MySQL EXPLAIN options may precede the statement. Skip only known,
        # non-executing options and never accept an unknown prefix.
        while True:
            if re.match(r"(?is)^analyze\b", tail):
                return None
            option = re.match(
                r"(?is)^(?:format\s*=\s*(?:traditional|json|tree)|partitions|extended)\b\s*",
                tail,
            )
            if option is None:
                break
            tail = tail[option.end() :].lstrip()
        return tail if cls.classify_explainable_statement(tail) is not None else None

    @classmethod
    def is_single_statement(cls, sql: str) -> bool:
        """Return whether SQL contains exactly one complete statement."""

        return cls._single_sql_statement(sql) is not None

    # Backward-compatible descriptive aliases retained for callers that used
    # the first implementation names.
    explainable_statement_type = classify_explainable_statement
    plain_explain_inner_sql = classify_plain_explain

    @classmethod
    def is_explain_analyze_query(cls, sql: str) -> bool:
        statement = cls._single_sql_statement(sql)
        if statement is None:
            return False
        match = re.match(r"(?is)^\s*explain\b(?P<tail>.*)$", statement)
        if match is None:
            return False
        tail = match.group("tail").lstrip()
        while True:
            if re.match(r"(?is)^analyze\b", tail):
                return True
            option = re.match(
                r"(?is)^(?:format\s*=\s*(?:traditional|json|tree)|partitions|extended)\b\s*",
                tail,
            )
            if option is None:
                return False
            tail = tail[option.end() :].lstrip()

    @classmethod
    def is_information_schema_columns_query(cls, sql: str) -> bool:
        return cls._is_information_schema_query(sql, "columns")

    @classmethod
    def is_information_schema_statistics_query(cls, sql: str) -> bool:
        return cls._is_information_schema_query(sql, "statistics")

    @classmethod
    def prioritize_history_rows(
        cls,
        rows: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Rank all rows twice and return the deterministic Top-20%-first order."""

        normalized: list[dict[str, Any]] = []
        for source_index, row in enumerate(rows):
            row_id = cls._coerce_positive_integer(cls._casefolded_value(row, "id"))
            if row_id is None:
                continue
            normalized.append(
                {
                    "id": row_id,
                    "source_index": source_index,
                    "query_time_max": cls._numeric_or_negative_infinity(
                        cls._casefolded_value(row, "query_time_max")
                    ),
                    "query_time_sum": cls._numeric_or_negative_infinity(
                        cls._casefolded_value(row, "query_time_sum")
                    ),
                }
            )
        if not normalized:
            return {"ordered_ids": [], "high_priority_ids": [], "ranks": {}}

        def ranked(field: str) -> list[dict[str, Any]]:
            return sorted(
                normalized,
                key=lambda item: (
                    item[field],
                    item["id"],
                    -item["source_index"],
                ),
                reverse=True,
            )

        max_rows = ranked("query_time_max")
        sum_rows = ranked("query_time_sum")
        top_count = max(1, (len(normalized) + 4) // 5)
        max_top = [item["id"] for item in max_rows[:top_count]]
        sum_top = [item["id"] for item in sum_rows[:top_count]]
        max_ranks = {item["id"]: index for index, item in enumerate(max_rows, 1)}
        sum_ranks = {item["id"]: index for index, item in enumerate(sum_rows, 1)}
        high_ids = set(max_top) | set(sum_top)
        both = sorted(
            set(max_top) & set(sum_top),
            key=lambda row_id: (
                min(max_ranks[row_id], sum_ranks[row_id]),
                max(max_ranks[row_id], sum_ranks[row_id]),
                -row_id,
            ),
        )
        ordered_high = list(both)
        seen = set(ordered_high)
        for index in range(top_count):
            for queue in (max_top, sum_top):
                row_id = queue[index]
                if row_id not in seen:
                    seen.add(row_id)
                    ordered_high.append(row_id)
        ordered_low = sorted(
            (item["id"] for item in normalized if item["id"] not in high_ids),
            key=lambda row_id: (
                min(max_ranks[row_id], sum_ranks[row_id]),
                max(max_ranks[row_id], sum_ranks[row_id]),
                -row_id,
            ),
        )
        return {
            "ordered_ids": [*ordered_high, *ordered_low],
            "high_priority_ids": ordered_high,
            "ranks": {
                str(row_id): {
                    "query_time_max_rank": max_ranks[row_id],
                    "query_time_sum_rank": sum_ranks[row_id],
                    "priority": "high" if row_id in high_ids else "normal",
                }
                for row_id in max_ranks
            },
        }

    @staticmethod
    def _numeric_or_negative_infinity(value: Any) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return float("-inf")
        return numeric if isfinite(numeric) else float("-inf")


    @classmethod
    def select_explainable_history_rows(
        cls,
        payload: Mapping[str, Any],
        *,
        sample_prefix_ids: set[int] | None = None,
    ) -> list[dict[str, Any]]:
        """Select one explainable row per checksum in deterministic priority order."""

        blocked_ids = sample_prefix_ids or set()
        candidates: list[dict[str, Any]] = []
        for source_index, row in enumerate(cls._tabular_rows(payload)):
            sample = cls._casefolded_value(row, "sample")
            row_id = cls._coerce_positive_integer(cls._casefolded_value(row, "id"))
            reconstructed = cls._casefolded_value(
                row, "sample_source_reconstructed"
            ) is True and isinstance(cls._casefolded_value(row, "sample_sha256"), str)
            statement_type = cls._casefolded_value(row, "sample_statement_type")
            safely_classified = cls.classify_explainable_statement(sample or "")
            if (
                not isinstance(sample, str)
                or row_id in blocked_ids
                or (not reconstructed and not cls._history_sample_is_complete(row, sample))
                or (
                    safely_classified is None
                    and statement_type not in {"select", "insert", "update", "delete", "replace"}
                )
            ):
                continue
            candidate = dict(row)
            candidate["__source_index"] = source_index
            candidates.append(candidate)

        def numeric(value: Any) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return float("-inf")

        candidates.sort(
            key=lambda row: (
                numeric(cls._casefolded_value(row, "query_time_max")),
                numeric(cls._casefolded_value(row, "id")),
                -int(row["__source_index"]),
            ),
            reverse=True,
        )
        selected: list[dict[str, Any]] = []
        checksums: set[str] = set()
        for candidate in candidates:
            checksum_value = cls._casefolded_value(candidate, "checksum")
            checksum = str(checksum_value).strip().casefold() if checksum_value is not None else ""
            endpoint = (
                str(cls._casefolded_value(candidate, "hostname_max") or "").strip().casefold()
            )
            db_name = str(cls._casefolded_value(candidate, "db_max") or "").strip().casefold()
            sql_key = checksum or cls._canonical_sql(
                str(cls._casefolded_value(candidate, "sample"))
            )
            dedupe_key = json.dumps(
                [endpoint, db_name, sql_key],
                ensure_ascii=True,
                separators=(",", ":"),
                default=str,
            )
            if dedupe_key in checksums:
                continue
            checksums.add(dedupe_key)
            candidate.pop("__source_index", None)
            selected.append(candidate)
        return selected

    @classmethod
    def _history_sample_is_complete(
        cls,
        row: Mapping[str, Any],
        sample: str,
    ) -> bool:
        """Accept an absent length marker or one exact positive byte length."""

        marker = next(
            (value for key, value in row.items() if str(key).casefold() == "sample_full_length"),
            _MISSING,
        )
        if marker is _MISSING:
            return True
        full_length = cls._coerce_positive_integer(marker)
        return full_length is not None and full_length == len(sample.encode("utf-8"))

    @classmethod
    def history_row_for_explain(
        cls,
        explain_sql: str,
        history_payload: Mapping[str, Any],
        *,
        sample_prefix_ids: set[int] | None = None,
    ) -> dict[str, Any] | None:
        inner_sql = cls.classify_plain_explain(explain_sql)
        if inner_sql is None:
            return None
        canonical_inner = cls._canonical_sql(inner_sql)
        return next(
            (
                row
                for row in cls.select_explainable_history_rows(
                    history_payload,
                    sample_prefix_ids=sample_prefix_ids,
                )
                if cls._casefolded_value(row, "sample_representation") != "structured"
                and cls._canonical_sql(str(cls._casefolded_value(row, "sample") or ""))
                == canonical_inner
                and cls.sql_equivalent(str(cls._casefolded_value(row, "sample") or ""), inner_sql)
            ),
            None,
        )

    @classmethod
    def slow_query_source_row(cls, row: Mapping[str, Any]) -> dict[str, Any]:
        """Project only stable history identity and prioritization fields."""

        projected: dict[str, Any] = {}
        for field in (
            "id",
            "checksum",
            "sample",
            "Query_time_max",
            "Query_time_sum",
            "hostname_max",
            "db_max",
            "sample_full_length",
            "sample_representation",
            "sample_source_reconstructed",
            "sample_sha256",
            "sample_statement_type",
            "sample_table_references",
            "priority",
            "query_time_max_rank",
            "query_time_sum_rank",
        ):
            value = cls._casefolded_value(row, field.casefold())
            if value is not None:
                projected[field] = sanitize(value)
        return projected

    @classmethod
    def structured_sql_result(cls, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Project one SQL result without remote envelope or audit provenance."""

        rows = cls._tabular_rows(payload)
        columns = next(
            (
                [str(item) for item in value]
                for container in cls._metadata_containers(payload)
                for key in ("column_list", "columns")
                if isinstance((value := container.get(key)), list)
            ),
            [],
        )
        return sanitize(
            {
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
            }
        )

    @staticmethod
    def information_schema_target(sql: str) -> dict[str, str]:
        """Extract literal schema/table filters used by metadata projections."""

        target: dict[str, str] = {}
        for field, output in (("table_schema", "db_name"), ("table_name", "table_name")):
            match = re.search(
                rf"(?is)\b`?{field}`?\s*=\s*'(?P<value>(?:''|[^'])*)'",
                sql,
            )
            if match is not None:
                target[output] = match.group("value").replace("''", "'")
        return target

    @classmethod
    def has_exact_information_schema_target_filters(cls, sql: str) -> bool:
        """Require exactly one schema equality and one table equality predicate."""

        where_body = cls._where_body(sql)
        if where_body is None:
            return False
        remainder = where_body
        for field in ("table_schema", "table_name"):
            pattern = re.compile(
                rf"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                rf"`?{field}`?\s*=\s*'(?:''|[^'])*'"
            )
            matches = list(pattern.finditer(remainder))
            if len(matches) != 1:
                return False
            match = matches[0]
            remainder = remainder[: match.start()] + " " + remainder[match.end() :]
        remainder = re.sub(r"(?is)\band\b", " ", remainder)
        remainder = re.sub(r"[\s()]+", "", remainder)
        return not remainder

    @classmethod
    def explainable_table_references(cls, sql: str) -> set[str]:
        """Return traceable table references, including DML target tables."""

        return {reference.table for reference in cls.explainable_physical_table_references(sql)}

    @classmethod
    def explainable_qualified_table_references(cls, sql: str) -> set[str]:
        """Return physical table references while retaining explicit schemas."""

        return {
            (
                f"{reference.schema}.{reference.table}"
                if reference.schema is not None
                else reference.table
            ).casefold()
            for reference in cls.explainable_physical_table_references(sql)
        }

    @classmethod
    def explainable_physical_table_references(
        cls,
        sql: str,
    ) -> set[SQLTableReference]:
        """Return non-CTE physical references with identifier case preserved."""

        return set(cls.explainable_physical_table_reference_sequence(sql) or ())

    @classmethod
    def explainable_physical_table_reference_sequence(
        cls,
        sql: str,
    ) -> tuple[SQLTableReference, ...] | None:
        """Return ordered non-CTE references for SQL identity checks."""

        references = mysql_table_references(sql)
        if references is None:
            return None
        cte_names = cls._with_cte_names(sql)
        return tuple(
            reference
            for reference in references
            if reference.schema is not None or reference.table.casefold() not in cte_names
        )

    @classmethod
    def _with_cte_names(cls, sql: str) -> set[str]:
        statement = cls._single_sql_statement(sql)
        if statement is None:
            return set()
        with_match = re.match(r"(?is)^\s*with\b(?:\s+recursive\b)?", statement)
        terminal = cls._with_terminal_statement(statement)
        if with_match is None or terminal is None:
            return set()
        names: set[str] = set()
        index = with_match.end()
        terminal_offset = terminal[1]
        while index < terminal_offset:
            while index < terminal_offset and statement[index].isspace():
                index += 1
            name_match = re.match(
                r"(?:`(?P<quoted>(?:``|[^`])+)`|"
                r'"(?P<double>(?:""|[^"])+)"|'
                r"(?P<bare>[A-Za-z_][A-Za-z0-9_$]*))",
                statement[index:terminal_offset],
            )
            if name_match is None:
                return set()
            name = (
                name_match.group("quoted") or name_match.group("double") or name_match.group("bare")
            )
            name = (
                name.replace('""', '"') if name_match.group("double") else name.replace("``", "`")
            )
            names.add(name.casefold())
            index += name_match.end()
            body_start = cls._cte_body_start(statement, index, terminal_offset)
            if body_start is None:
                return set()
            body_end = cls._matching_parenthesis_end(statement, body_start)
            if body_end is None or body_end > terminal_offset:
                return set()
            index = body_end + 1
            while index < terminal_offset and statement[index].isspace():
                index += 1
            if index < terminal_offset and statement[index] == ",":
                index += 1
                continue
            break
        return names

    @staticmethod
    def _cte_body_start(sql: str, start: int, limit: int) -> int | None:
        prefix = sql[start:limit]
        match = re.match(
            r"(?is)\s*(?:\([^)]*\)\s*)?as\s*(?P<body>\()",
            prefix,
        )
        return start + match.start("body") if match is not None else None

    @staticmethod
    def _matching_parenthesis_end(sql: str, start: int) -> int | None:
        depth = 0
        quote: str | None = None
        index = start
        while index < len(sql):
            character = sql[index]
            if quote is not None:
                if character == "\\" and quote != "`":
                    index += 2
                    continue
                if character == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if character in {"'", '"', "`"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    @staticmethod
    def _casefolded_value(row: Mapping[str, Any], field: str) -> Any:
        expected = field.casefold()
        return next((value for key, value in row.items() if str(key).casefold() == expected), None)

    @classmethod
    def _is_information_schema_query(cls, sql: str, table: str) -> bool:
        statement = cls._single_sql_statement(sql)
        if statement is None or re.match(r"(?is)^\s*select\b", statement) is None:
            return False
        if not cls.is_simple_metadata_select(statement):
            return False
        if cls.sql_qualified_table_references(statement) != {
            f"information_schema.{table.casefold()}"
        }:
            return False
        words = unquoted_words(statement)
        if words is None or {
            "benchmark",
            "get_lock",
            "into",
            "procedure",
            "release_lock",
            "sleep",
        }.intersection(words):
            return False
        projection = re.match(
            r"(?is)^\s*select\s+(?P<body>.*?)\s+from\s+",
            statement,
        )
        if projection is None:
            return False
        allowed = _INFORMATION_SCHEMA_PROJECTION_FIELDS[table.casefold()]
        for expression in projection.group("body").split(","):
            match = re.fullmatch(
                r"(?is)\s*(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                r"(?P<source>\*|`?[A-Za-z_][A-Za-z0-9_$]*`?)\s*",
                expression,
            )
            if match is None:
                return False
            source = match.group("source").strip("`").casefold()
            if source != "*" and source not in allowed:
                return False
        return True

    @classmethod
    def _single_sql_statement(cls, sql: str) -> str | None:
        uncommented = cls._sql_without_comments(sql)
        if uncommented is None:
            return None
        candidate = uncommented.strip()
        while candidate.endswith(";"):
            candidate = candidate[:-1].rstrip()
        if not candidate or cls._contains_unquoted_semicolon(candidate):
            return None
        return candidate

    @staticmethod
    def _contains_unquoted_semicolon(sql: str) -> bool:
        quote: str | None = None
        index = 0
        while index < len(sql):
            character = sql[index]
            if quote is None:
                if character in {"'", '"', "`"}:
                    quote = character
                elif character == ";":
                    return True
                index += 1
                continue
            if character == "\\" and quote != "`":
                index += 2
                continue
            if character == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
        return quote is not None

    @staticmethod
    def _with_terminal_statement_type(sql: str) -> str | None:
        """Find the first top-level DML keyword after one or more CTE bodies."""

        terminal = ArcheryMCPClient._with_terminal_statement(sql)
        return terminal[0] if terminal is not None else None

    @staticmethod
    def _with_terminal_statement(sql: str) -> tuple[str, int] | None:
        """Return the first top-level DML keyword and its offset after CTE bodies."""

        depth = 0
        quote: str | None = None
        index = 0
        while index < len(sql):
            character = sql[index]
            if quote is not None:
                if character == "\\" and quote != "`":
                    index += 2
                    continue
                if character == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if character in {"'", '"', "`"}:
                quote = character
                index += 1
                continue
            if character == "(":
                depth += 1
            elif character == ")":
                depth = max(depth - 1, 0)
            elif depth == 0 and (character.isalpha() or character == "_"):
                end = index + 1
                while end < len(sql) and (sql[end].isalnum() or sql[end] in {"_", "$"}):
                    end += 1
                keyword = sql[index:end].casefold()
                if keyword in {"select", "insert", "update", "delete", "replace"}:
                    return keyword, index
                index = end
                continue
            index += 1
        return None

    @classmethod
    def truncation_row_shortfall(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[int, int] | None:
        """Return ``(declared, recovered)`` when MCP truncation lost rows.

        Two payload shapes signal truncation: a recovered JSON prefix whose
        ``mcp_reported_row_count`` exceeds the recovered ``rows`` length, and a
        payload that only carries Archery's textual row-count claim without
        any parsable rows (``row_count_source == "archery_text"``).
        """

        containers = cls._metadata_containers(payload)
        rows = next(
            (
                candidate
                for container in containers
                if (candidate := cls._tabular_row_list(container)) is not None
            ),
            None,
        )
        recovered = len(rows) if rows is not None else None
        declared: int | None = None
        reported = next(
            (
                value
                for container in containers
                if type(value := container.get("mcp_reported_row_count")) is int
            ),
            None,
        )
        if reported is not None:
            declared = reported
        else:
            declared = next(
                (
                    value
                    for container in containers
                    for key in ("rowCount", "row_count", "total")
                    if type(value := container.get(key)) is int and value >= 0
                ),
                None,
            )
        if declared is None:
            return None
        if recovered is None:
            return (declared, 0) if declared > 0 else None
        if declared > recovered:
            return declared, recovered
        return None

    @classmethod
    def result_incomplete_reasons(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[str, ...]:
        """Return deterministic reasons why a query payload is not complete."""

        if payload.get("result_completeness_assessment") == "complete":
            return ()
        reasons: list[str] = []
        if payload.get("rows_recovered_from_truncated_json") is True:
            reasons.append("character_truncated")
        if cls.truncation_row_shortfall(payload) is not None:
            reasons.append("row_count_shortfall")
        if shape_issue := cls.tabular_shape_issue(payload):
            reasons.append(shape_issue)
        if payload.get("history_recovery_complete") is False:
            reasons.append("history_recovery_incomplete")
        declared_reasons = payload.get("result_incomplete_reasons")
        if isinstance(declared_reasons, list):
            reasons.extend(
                str(reason) for reason in declared_reasons if isinstance(reason, str) and reason
            )
        return tuple(dict.fromkeys(reasons))

    @classmethod
    def is_result_incomplete(cls, payload: Mapping[str, Any]) -> bool:
        """Use one fail-closed completeness decision across harness and evidence."""

        return payload.get("result_incomplete") is True or bool(
            cls.result_incomplete_reasons(payload)
        )

    @classmethod
    def with_result_completeness(
        cls,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Annotate an incomplete result without modifying its original rows."""

        projected = dict(payload)
        reasons = cls.result_incomplete_reasons(projected)
        if reasons:
            projected["result_incomplete"] = True
            projected["result_incomplete_reasons"] = list(reasons)
        return projected

    @classmethod
    def accumulate_history_rows(
        cls,
        rows_by_id: dict[int, dict[str, Any]],
        merge_sources: list[Mapping[str, Any]],
        payload: Mapping[str, Any],
        *,
        sql: str,
        include_source: bool,
        projection: str | None = None,
    ) -> None:
        """Accumulate history rows keyed by id with projection-aware precedence.

        Mechanical union only: rows without a usable id stay in their own
        query result but cannot join the merge, no row is invented, reordered,
        or filtered, and per-query source metadata is recorded for tracing. A
        sample-prefix recovery may add missing fields but cannot replace an
        already complete sample. A later full-row recovery replaces the prefix
        and removes its stale ``sample_full_length`` marker.
        """

        rows = cls._tabular_rows(payload)
        for row in rows:
            row_id = cls._coerce_positive_integer(row.get("id"))
            if row_id is None:
                continue
            merged = dict(rows_by_id.get(row_id) or {})
            if projection in {"sample_prefix", "unverified_full"}:
                incoming = dict(row)
                existing_sample = cls._casefolded_value(merged, "sample")
                if isinstance(existing_sample, str) and (
                    projection == "unverified_full"
                    or cls._history_sample_is_complete(merged, existing_sample)
                ):
                    incoming = {
                        key: value
                        for key, value in incoming.items()
                        if key.casefold() not in {"sample", "sample_full_length"}
                    }
                merged.update(incoming)
            else:
                if projection == "full":
                    merged = {
                        key: value
                        for key, value in merged.items()
                        if key.casefold() != "sample_full_length"
                    }
                merged.update(row)
            rows_by_id[row_id] = merged
        if include_source:
            merge_sources.append({"full_sql": sql, "row_count": len(rows)})

    @classmethod
    def history_row_ids(cls, payload: Mapping[str, Any]) -> set[int]:
        """Collect the ids an id-listing or history result claims to contain."""

        ids: set[int] = set()
        for row in cls._tabular_rows(payload):
            if isinstance(row, Mapping):
                row_id = cls._coerce_positive_integer(row.get("id"))
                if row_id is not None:
                    ids.add(row_id)
        if not ids:
            rows = payload.get("rows")
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, (list, tuple)) and row:
                        row_id = cls._coerce_positive_integer(row[0])
                        if row_id is not None:
                            ids.add(row_id)
        return ids

    @classmethod
    def merge_positional_rows_with_reference(
        cls,
        rows_by_id: dict[int, dict[str, Any]],
        positional_rows: Sequence[Any],
        reference_columns: Sequence[str],
        *,
        allowed_ids: set[int],
        trusted_full_row_ids: set[int],
        sample_prefix_ids: set[int],
    ) -> list[Any]:
        """Decode deferred positional rows using a verified ``SELECT *`` order.

        Each row is decoded only when its width exactly matches the trusted
        column order and its id belongs to the complete window id listing.
        Unresolved rows are returned verbatim. A row may be discarded without
        decoding only after the same id was recovered by a trusted full per-id
        response.
        """

        columns = [str(column) for column in reference_columns]
        normalized_columns = [column.casefold() for column in columns]
        columns_are_usable = bool(columns) and len(set(normalized_columns)) == len(
            normalized_columns
        )
        unresolved: list[Any] = []
        for row in positional_rows:
            row_id: int | None = None
            if isinstance(row, Mapping):
                row_id = cls._coerce_positive_integer(cls._casefolded_value(row, "id"))
            elif isinstance(row, (list, tuple)) and row:
                row_id = cls._coerce_positive_integer(row[0])
            if row_id is not None and row_id in trusted_full_row_ids:
                continue
            if (
                not columns_are_usable
                or not isinstance(row, (list, tuple))
                or len(row) != len(columns)
                or row_id is None
                or row_id not in allowed_ids
            ):
                unresolved.append(row)
                continue
            decoded = dict(zip(columns, row, strict=True))
            merged = dict(rows_by_id.get(row_id) or {})
            decoded_sample = cls._casefolded_value(decoded, "sample")
            if isinstance(decoded_sample, str):
                merged = {
                    key: value
                    for key, value in merged.items()
                    if str(key).casefold() not in {"sample", "sample_full_length"}
                }
                sample_prefix_ids.discard(row_id)
                trusted_full_row_ids.add(row_id)
            rows_by_id[row_id] = {**decoded, **merged}
        return unresolved

    @classmethod
    def merged_history_payload(
        cls,
        rows_by_id: Mapping[int, Mapping[str, Any]],
        merge_sources: list[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Build the merged final payload from per-id retrieval accumulation.

        Rows keep first-seen order and every field of every contributing query
        survives the id-keyed union. The payload deliberately does not carry
        ``rows_recovered_from_truncated_json``: the per-id rows themselves were
        received complete, so the merged result is not character-truncated.
        """

        return {
            "rows": [dict(row) for row in rows_by_id.values()],
            "rows_merged_from_per_id_queries": True,
            "merged_query_count": len(merge_sources),
            "merged_full_sqls": [str(source.get("full_sql") or "") for source in merge_sources],
        }

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
        references = mysql_table_references(sql)
        if references is None:
            return set()
        return {reference.table for reference in references}

    @classmethod
    def sql_qualified_table_references(cls, sql: str) -> set[str]:
        """Return normalized physical table references, retaining a schema prefix."""

        references = mysql_table_references(sql)
        if references is None:
            return set()
        return {
            (
                f"{reference.schema}.{reference.table}"
                if reference.schema is not None
                else reference.table
            ).casefold()
            for reference in references
        }

    @classmethod
    def sql_equivalent(cls, expected: str, actual: str) -> bool:
        """Compare SQL identity while ignoring a plain top-level LIMIT value."""

        expected_identity = canonical_sql(expected)
        actual_identity = canonical_sql(actual)
        expected_paths = mysql_identifier_paths(expected)
        actual_paths = mysql_identifier_paths(actual)
        expected_tables = cls.explainable_physical_table_reference_sequence(expected)
        actual_tables = cls.explainable_physical_table_reference_sequence(actual)
        if (
            expected_identity is None
            or actual_identity is None
            or expected_paths is None
            or actual_paths is None
            or expected_tables is None
            or actual_tables is None
        ):
            return False
        return (
            expected_identity == actual_identity
            and expected_tables == actual_tables
            and expected_paths == actual_paths
        )

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
    def instance_directory_references(
        cls,
        payload: Mapping[str, Any],
        *,
        supplemental_text: Sequence[str] = (),
    ) -> dict[str, str]:
        """Return endpoint-to-ref navigation hints without granting authorization."""

        references: dict[str, str] = {}
        for row in cls._tabular_rows(payload):
            normalized = {
                cls._normalized_column_name(str(key)): value for key, value in row.items()
            }
            instance_id = next(
                (
                    cls._coerce_positive_integer(normalized.get(key))
                    for key in ("id", "instanceid")
                    if cls._coerce_positive_integer(normalized.get(key)) is not None
                ),
                None,
            )
            instance_ref = next(
                (
                    normalized[key].strip()
                    for key in ("name", "instancename", "instanceref")
                    if isinstance(normalized.get(key), str) and normalized[key].strip()
                ),
                str(instance_id) if instance_id is not None else None,
            )
            endpoints = cls.allowlisted_instance_endpoints(
                {"rows": [row]},
                expected_instance_ref=None,
            ).values()
            if instance_ref is not None:
                for endpoint_set in endpoints:
                    for endpoint in endpoint_set:
                        references[endpoint.casefold()] = instance_ref
        for text in cls._discovery_text_blocks(payload, supplemental_text):
            in_instance_list = False
            for line in text.splitlines():
                if _INSTANCE_LIST_HEADER_TEXT.fullmatch(line):
                    in_instance_list = True
                    continue
                if not in_instance_list:
                    continue
                match = _INSTANCE_LIST_ROW_TEXT.fullmatch(line)
                if match is None:
                    if line.strip():
                        in_instance_list = False
                    continue
                endpoint = cls._normalize_endpoint(match.group("endpoint"))
                if endpoint is not None:
                    references[endpoint.casefold()] = match.group("instance_ref")
        return references

    @classmethod
    def allowlisted_instance_endpoints(
        cls,
        payload: Mapping[str, Any],
        *,
        expected_instance_ref: str | None = None,
        supplemental_text: Sequence[str] = (),
    ) -> dict[int, set[str]]:
        """Extract only explicit allowlist instance/endpoint pairs.

        Current Archery MCP deployments return discovery rows either as normal
        tabular data or as a strictly formatted numbered list. Prose without the
        provider's list header is never treated as authorization data.
        """

        discovered: dict[int, set[str]] = {}
        for row in cls._tabular_rows(payload):
            normalized = {
                cls._normalized_column_name(str(key)): value for key, value in row.items()
            }
            instance_id = next(
                (
                    cls._coerce_positive_integer(normalized.get(key))
                    for key in ("id", "instanceid")
                    if cls._coerce_positive_integer(normalized.get(key)) is not None
                ),
                None,
            )
            if instance_id is None:
                continue
            instance_name = next(
                (
                    normalized[key].strip()
                    for key in ("name", "instancename", "instanceref")
                    if isinstance(normalized.get(key), str) and normalized[key].strip()
                ),
                None,
            )
            if not cls._instance_ref_matches(
                expected_instance_ref,
                instance_id=instance_id,
                instance_name=instance_name,
            ):
                continue
            endpoints: set[str] = set()
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
                endpoint = cls._normalize_endpoint(f"{host.strip()}:{port}")
                if endpoint is not None:
                    endpoints.add(endpoint.casefold())
            for key in ("endpoint", "address", "instanceref"):
                endpoint = cls._normalize_endpoint(normalized.get(key))
                if endpoint is not None:
                    endpoints.add(endpoint.casefold())
            if endpoints:
                discovered.setdefault(instance_id, set()).update(endpoints)
        for text in cls._discovery_text_blocks(payload, supplemental_text):
            lines = text.splitlines()
            in_instance_list = False
            for line in lines:
                if _INSTANCE_LIST_HEADER_TEXT.fullmatch(line):
                    in_instance_list = True
                    continue
                if not in_instance_list:
                    continue
                match = _INSTANCE_LIST_ROW_TEXT.fullmatch(line)
                if match is None:
                    if line.strip():
                        in_instance_list = False
                    continue
                instance_id = cls._coerce_positive_integer(match.group("instance_id"))
                if instance_id is None or not cls._instance_ref_matches(
                    expected_instance_ref,
                    instance_id=instance_id,
                    instance_name=match.group("instance_ref"),
                ):
                    continue
                endpoint = cls._normalize_endpoint(match.group("endpoint"))
                if endpoint is not None:
                    discovered.setdefault(instance_id, set()).add(endpoint.casefold())
        return discovered

    @staticmethod
    def _instance_ref_matches(
        expected: str | None,
        *,
        instance_id: int,
        instance_name: str | None,
    ) -> bool:
        if expected is None or not expected.strip():
            return True
        normalized = expected.strip().casefold()
        return normalized == str(instance_id) or bool(
            instance_name and normalized == instance_name.strip().casefold()
        )

    @classmethod
    def allowlisted_database_names(
        cls,
        payload: Mapping[str, Any],
        *,
        expected_instance_id: int | None = None,
        supplemental_text: Sequence[str] = (),
    ) -> set[str]:
        """Extract database names only from explicit discovery rows."""

        names: set[str] = set()
        for row in cls._tabular_rows(payload):
            normalized = {
                cls._normalized_column_name(str(key)): value for key, value in row.items()
            }
            for key in ("name", "dbname", "database", "schema"):
                value = normalized.get(key)
                if isinstance(value, str) and value.strip():
                    names.add(value.strip())
        for text in cls._discovery_text_blocks(payload, supplemental_text):
            lines = text.splitlines()
            active_instance_id: int | None = None
            for line in lines:
                header = _DATABASE_LIST_HEADER_TEXT.fullmatch(line)
                if header is not None:
                    active_instance_id = cls._coerce_positive_integer(header.group("instance_id"))
                    continue
                if active_instance_id is None:
                    continue
                match = _DATABASE_LIST_ROW_TEXT.fullmatch(line)
                if match is None:
                    if line.strip():
                        active_instance_id = None
                    continue
                if expected_instance_id is not None and active_instance_id != expected_instance_id:
                    continue
                candidate = match.group("db_name")
                if cls._safe_discovered_database_name(candidate):
                    names.add(candidate)
        return names

    @classmethod
    def _discovery_text_blocks(
        cls,
        payload: Mapping[str, Any],
        supplemental_text: Sequence[str],
    ) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                [
                    *cls._metadata_text(payload),
                    *(item for item in supplemental_text if isinstance(item, str)),
                ]
            )
        )

    @staticmethod
    def _safe_discovered_database_name(value: str) -> bool:
        candidate = value.strip()
        return bool(
            candidate
            and len(candidate.encode("utf-8")) <= 64
            and all(character.isalnum() or character in {"_", "$", "-"} for character in candidate)
        )

    @classmethod
    def reported_execution_target_values(
        cls,
        payload: Mapping[str, Any],
        *,
        supplemental_text: Sequence[str] = (),
    ) -> dict[str, set[Any]]:
        """Collect every explicit execution-target echo outside tabular rows."""

        values: dict[str, set[Any]] = {
            "instance_id": set(),
            "db_name": set(),
            "table_name": set(),
            "endpoint": set(),
        }
        payloads = [payload, *cls._mapping_payloads_from_text(supplemental_text)]
        for candidate in payloads:
            for container in cls._metadata_containers(candidate):
                normalized_items = [
                    (cls._normalized_column_name(str(key)), value)
                    for key, value in container.items()
                    if key not in _ARCHERY_TABULAR_ROW_KEYS
                ]
                for key, value in normalized_items:
                    if key == "instanceid":
                        instance_id = cls._coerce_positive_integer(value)
                        if instance_id is not None:
                            values["instance_id"].add(instance_id)
                    elif key in {"dbname", "database", "schema"}:
                        if isinstance(value, str) and value.strip():
                            values["db_name"].add(value.strip())
                    elif key in {"tablename", "tbname", "targettable"}:
                        if isinstance(value, str) and value.strip():
                            values["table_name"].add(value.strip().strip("`"))
                    elif key in {"endpoint", "address", "instanceref"}:
                        endpoint = cls._normalize_endpoint(value)
                        if endpoint is not None:
                            values["endpoint"].add(endpoint.casefold())
                hosts = {
                    value.strip()
                    for key, value in normalized_items
                    if key in {"host", "hostname", "hostip", "ip"}
                    and isinstance(value, str)
                    and value.strip()
                }
                ports = {
                    port
                    for key, value in normalized_items
                    if key in {"port", "mysqlport"}
                    and (port := cls._coerce_positive_integer(value)) is not None
                    and port <= 65_535
                }
                for host in hosts:
                    for port in ports:
                        endpoint = cls._normalize_endpoint(f"{host}:{port}")
                        if endpoint is not None:
                            values["endpoint"].add(endpoint.casefold())
        return {key: found for key, found in values.items() if found}

    @classmethod
    def reported_metadata_row_target_values(
        cls,
        payload: Mapping[str, Any],
        *,
        supplemental_text: Sequence[str] = (),
    ) -> dict[str, set[str]]:
        """Collect physical targets explicitly returned by information_schema rows."""

        values: dict[str, set[str]] = {
            "db_name": set(),
            "table_name": set(),
        }
        payloads = [payload, *cls._mapping_payloads_from_text(supplemental_text)]
        for candidate in payloads:
            for row in cls._tabular_rows(candidate):
                normalized = {
                    cls._normalized_column_name(str(key)): value for key, value in row.items()
                }
                schema = normalized.get("tableschema")
                if isinstance(schema, str) and schema.strip():
                    values["db_name"].add(schema.strip().strip('`"'))
                table = normalized.get("tablename")
                if isinstance(table, str) and table.strip():
                    values["table_name"].add(cls.clean_table_name(table))
        return {key: found for key, found in values.items() if found}

    @staticmethod
    def _mapping_payloads_from_text(
        text_blocks: Sequence[str],
    ) -> list[Mapping[str, Any]]:
        """Decode mapping payloads even when MCP wraps JSON in explanatory text."""

        decoder = json.JSONDecoder()
        payloads: list[Mapping[str, Any]] = []
        for text in text_blocks:
            cursor = 0
            while (start := text.find("{", cursor)) >= 0:
                try:
                    decoded, consumed = decoder.raw_decode(text[start:])
                except json.JSONDecodeError:
                    cursor = start + 1
                    continue
                if isinstance(decoded, Mapping):
                    payloads.append(decoded)
                cursor = start + max(consumed, 1)
        return payloads

    @classmethod
    def reported_execution_target(
        cls,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return only unambiguous execution-target echoes for compatibility."""

        return {
            key: next(iter(values))
            for key, values in cls.reported_execution_target_values(payload).items()
            if len(values) == 1
        }

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
            if not cls._member_query_selects_instance_id(
                sql, columns
            ) or not cls.is_exact_member_endpoint_lookup(
                sql,
                alert_endpoint=alert_endpoint,
                discovered_columns=columns,
            ):
                return
            instance_ids = cls._member_instance_ids_from_payload(payload)
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
            or not cls.is_exact_sql_instance_lookup(
                sql,
                known_ids=known_ids,
                discovered_columns=columns,
            )
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
                    if isinstance(value, (Mapping, list, tuple, str)):
                        pending.append(value)
            elif isinstance(current, (list, tuple)):
                marker = id(current)
                if marker in visited_containers:
                    continue
                visited_containers.add(marker)
                pending.extend(current)
            elif isinstance(current, str):
                columns.update(cls._table_columns_from_text(current))
        return {column for column in columns if column}

    @staticmethod
    def _table_columns_from_text(text: str) -> set[str]:
        """Parse the live MCP's bound data-dictionary bullet-list response."""

        columns: set[str] = set()
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if _TABLE_COLUMNS_TEXT_HEADER.fullmatch(line) is None:
                continue
            for candidate in lines[index + 1 :]:
                if not candidate.strip() and not columns:
                    continue
                match = _TABLE_COLUMNS_TEXT_ITEM.fullmatch(candidate)
                if match is None:
                    break
                columns.add(match.group("column").strip("`"))
        return columns

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

    @classmethod
    def is_exact_member_endpoint_lookup(
        cls,
        sql: str,
        *,
        alert_endpoint: str | None,
        discovered_columns: set[str],
    ) -> bool:
        """Bind the member hop to exactly the alert host and port predicates."""

        if not alert_endpoint or ":" not in alert_endpoint:
            return False
        host, port_text = alert_endpoint.rsplit(":", 1)
        if not host or not port_text.isdecimal():
            return False
        predicates = cls._exact_simple_equality_predicates(sql)
        if predicates is None or len(predicates) != 2:
            return False
        host_columns, port_columns = cls._endpoint_lookup_columns(
            discovered_columns,
            default_host={"f_ip", "host", "host_ip", "hostname", "ip"},
            default_port={"f_port", "host_port", "port"},
        )
        host_matches = [
            value
            for column, kind, value in predicates
            if column in host_columns and kind == "literal"
        ]
        port_matches = [
            value
            for column, kind, value in predicates
            if column in port_columns and kind in {"literal", "number"}
        ]
        return bool(
            len(host_matches) == 1
            and host_matches[0].casefold() == host.casefold()
            and len(port_matches) == 1
            and port_matches[0].isdecimal()
            and int(port_matches[0]) == int(port_text)
        )

    @classmethod
    def is_exact_sql_instance_lookup(
        cls,
        sql: str,
        *,
        known_ids: set[int],
        discovered_columns: set[str],
    ) -> bool:
        """Bind the endpoint hop to one exact returned member-id equality."""

        predicates = cls._exact_simple_equality_predicates(sql)
        if predicates is None or len(predicates) != 1:
            return False
        id_columns = {
            column.casefold()
            for column in discovered_columns
            if cls._normalized_column_name(column) == "id"
        } or {"id"}
        column, kind, value = predicates[0]
        instance_id = cls._coerce_positive_integer(value)
        return bool(
            column in id_columns and kind in {"literal", "number"} and instance_id in known_ids
        )

    @classmethod
    def _endpoint_lookup_columns(
        cls,
        discovered_columns: set[str],
        *,
        default_host: set[str],
        default_port: set[str],
    ) -> tuple[set[str], set[str]]:
        if not discovered_columns:
            return default_host, default_port
        return (
            {
                column.casefold()
                for column in discovered_columns
                if cls._normalized_column_name(column) in _ENDPOINT_HOST_COLUMN_NAMES
            },
            {
                column.casefold()
                for column in discovered_columns
                if cls._normalized_column_name(column) in _ENDPOINT_PORT_COLUMN_NAMES
            },
        )

    @classmethod
    def _exact_simple_equality_predicates(
        cls,
        sql: str,
    ) -> tuple[tuple[str, str, str], ...] | None:
        """Parse the tiny WHERE grammar used by the two metadata lineage hops."""

        statement = cls._single_sql_statement(sql)
        if statement is None:
            return None
        where = re.search(r"(?is)\bwhere\b(?P<body>.*)$", statement)
        if where is None:
            return None
        body = where.group("body").strip()
        limit = re.search(r"(?is)\s+limit\s+\d+\s*$", body)
        if limit is not None:
            body = body[: limit.start()].strip()
        elif re.search(r"(?i)\blimit\b", body):
            return None
        parts = re.split(r"(?i)\s+and\s+", body)
        predicates: list[tuple[str, str, str]] = []
        comparison = re.compile(
            r"(?is)(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
            r"`?(?P<column>[A-Za-z_][A-Za-z0-9_$]*)`?\s*=\s*"
            r"(?:'(?P<literal>(?:''|[^'])*)'|(?P<number>\d+))"
        )
        for part in parts:
            candidate = part.strip()
            while candidate.startswith("(") and candidate.endswith(")"):
                candidate = candidate[1:-1].strip()
            match = comparison.fullmatch(candidate)
            if match is None:
                return None
            literal = match.group("literal")
            predicates.append(
                (
                    match.group("column").casefold(),
                    "literal" if literal is not None else "number",
                    literal.replace("''", "'") if literal is not None else match.group("number"),
                )
            )
        return tuple(predicates) if predicates else None

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
        selected = {
            cls._normalized_column_name(column) for column in cls._simple_select_source_columns(sql)
        }
        if discovered_columns:
            return any(
                cls._normalized_column_name(column) in {"finstanceid", "instanceid"}
                and cls._normalized_column_name(column) in selected
                for column in discovered_columns
            )
        return bool(selected.intersection({"finstanceid", "instanceid"}))

    @classmethod
    def _sql_instance_query_selects_endpoint(
        cls,
        sql: str,
        discovered_columns: set[str],
    ) -> bool:
        selected = {
            cls._normalized_column_name(column) for column in cls._simple_select_source_columns(sql)
        }
        normalized_columns = {cls._normalized_column_name(column) for column in discovered_columns}
        if normalized_columns:
            selected = selected.intersection(normalized_columns)
        return bool(selected.intersection(_ENDPOINT_HOST_COLUMN_NAMES)) and bool(
            selected.intersection(_ENDPOINT_PORT_COLUMN_NAMES)
        )

    @staticmethod
    def _tabular_row_list(container: Mapping[str, Any]) -> list[Any] | None:
        for key in _ARCHERY_TABULAR_ROW_KEYS:
            value = container.get(key)
            if isinstance(value, list):
                return value
        return None

    @classmethod
    def tabular_shape_issue(cls, payload: Mapping[str, Any]) -> str | None:
        """Validate the first concrete tabular row set without coercing it.

        Mapping rows do not require column metadata. Positional rows do: mixed
        row representations, ambiguous/invalid columns, and any width mismatch
        fail closed so callers retain the raw rows instead of inventing a
        partial field mapping.
        """

        for container in cls._metadata_containers(payload):
            rows = cls._tabular_row_list(container)
            if rows is None:
                continue
            if not rows or all(isinstance(row, Mapping) for row in rows):
                return None
            positional = [isinstance(row, (list, tuple)) for row in rows]
            if any(isinstance(row, Mapping) for row in rows) and any(positional):
                return "mixed_tabular_row_shapes"
            if not all(positional):
                return "invalid_tabular_row_shape"

            declared_columns = [
                container[key]
                for key in ("columns", "column_list")
                if key in container and container[key] is not None
            ]
            if not declared_columns:
                return "missing_tabular_columns"
            if any(
                not isinstance(columns, list)
                or not columns
                or not all(isinstance(column, str) and column for column in columns)
                for columns in declared_columns
            ):
                return "invalid_tabular_columns"
            canonical_column_sets = [
                tuple(column.casefold() for column in columns) for columns in declared_columns
            ]
            if len(set(canonical_column_sets)) != 1:
                return "ambiguous_tabular_columns"
            columns = declared_columns[0]
            canonical_columns = canonical_column_sets[0]
            if len(set(canonical_columns)) != len(canonical_columns):
                return "duplicate_tabular_columns"
            if any(len(row) != len(columns) for row in rows):
                return "positional_row_width_mismatch"
            return None
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
            if cls.tabular_shape_issue(container) is not None:
                return []
            if isinstance(columns, list) and all(isinstance(column, str) for column in columns):
                return [
                    dict(zip(columns, row, strict=True))
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
        uncommented = strip_mysql_comments(sql)
        return uncommented.lstrip() if uncommented is not None else ""

    @staticmethod
    def _coerce_nonnegative_integer(value: Any) -> int | None:
        if type(value) is int:
            return value if 0 <= value <= 9_223_372_036_854_775_807 else None
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if not candidate or len(candidate) > 19 or not candidate.isascii():
            return None
        if not candidate.isdecimal():
            return None
        parsed = int(candidate)
        return parsed if parsed <= 9_223_372_036_854_775_807 else None

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

    @classmethod
    def top_level_limit_value(cls, sql: str) -> int | None:
        """Return a literal top-level LIMIT for pagination mechanics only."""

        parser_input = cls._sql_without_comments(sql)
        if parser_input is None:
            return None
        try:
            statements = parse(parser_input, read="mysql")
        except (ParseError, TokenError):
            return None
        if len(statements) != 1:
            return None
        limit = statements[0].args.get("limit")
        value = limit.expression if isinstance(limit, exp.Limit) else None
        return (
            cls._coerce_nonnegative_integer(value.this)
            if isinstance(value, exp.Literal) and value.is_int
            else None
        )

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
        supplemental_text: Sequence[str] = (),
    ) -> tuple[dict[str, Any], str | None, bool]:
        """Extract Archery's text-wrapped SQL result without constraining the Agent."""

        normalized_payload = dict(payload)
        embedded_payload_selected = False
        reported_row_count: int | None = None
        texts = [*cls._metadata_text(payload), *supplemental_text]
        embedded_payloads: list[Mapping[str, Any]] = []
        for text in texts:
            if reported_row_count is None:
                reported_row_count = cls._reported_row_count_from_text(text)
            embedded_result = cls._embedded_result_object(text)
            if embedded_result is not None:
                embedded_payloads.append(embedded_result)
                if not embedded_payload_selected:
                    normalized_payload = embedded_result
                    embedded_payload_selected = True

        text_payloads = cls._mapping_payloads_from_text(texts)

        parsed_row_count = cls.payload_row_count(normalized_payload)
        if reported_row_count is not None:
            if parsed_row_count is None:
                normalized_payload["rowCount"] = reported_row_count
                normalized_payload["row_count_source"] = "archery_text"
            elif reported_row_count > parsed_row_count:
                normalized_payload["mcp_reported_row_count"] = reported_row_count
                normalized_payload["parsed_row_count"] = parsed_row_count

        declared_sqls: list[str] = []

        def record_sql(value: Any) -> None:
            if isinstance(value, str) and value.strip():
                sql = value.strip()
                if sql not in declared_sqls:
                    declared_sqls.append(sql)

        for candidate in [
            payload,
            normalized_payload,
            *embedded_payloads,
            *text_payloads,
        ]:
            for container in cls._metadata_containers(candidate):
                for key, value in container.items():
                    if str(key).casefold() in {
                        "full_sql",
                        "executed_sql",
                        "sql_content",
                    }:
                        record_sql(value)
        for text in texts:
            for declared_sql in cls._executed_sqls_from_text(text):
                record_sql(declared_sql)

        executed_sql = declared_sqls[0] if declared_sqls else None
        actual_sql_verified = bool(declared_sqls) and all(
            cls.sql_equivalent(requested_sql, actual_sql) for actual_sql in declared_sqls
        )
        if actual_sql_verified:
            normalized_payload = cls._with_inferred_query_columns(
                normalized_payload,
                sql=requested_sql,
            )
        normalized_payload = cls.with_result_completeness(normalized_payload)
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
        return tuple(
            alias or source for source, alias in ArcheryMCPClient._simple_select_projection(sql)
        )

    @staticmethod
    def _simple_select_source_columns(sql: str) -> tuple[str, ...]:
        return tuple(source for source, _alias in ArcheryMCPClient._simple_select_projection(sql))

    @staticmethod
    def _simple_select_projection(sql: str) -> tuple[tuple[str, str | None], ...]:
        select = re.search(r"(?is)\bselect\b(?P<body>.*?)\bfrom\b", sql)
        if select is None:
            return ()
        columns: list[tuple[str, str | None]] = []
        for expression in select.group("body").split(","):
            match = re.fullmatch(
                r"(?is)\s*(?:`?[A-Za-z_][A-Za-z0-9_$]*`?\s*\.\s*)?"
                r"`?(?P<source>[A-Za-z_][A-Za-z0-9_$]*)`?"
                r"(?:\s+(?:as\s+)?`?(?P<alias>[A-Za-z_][A-Za-z0-9_$]*)`?)?\s*",
                expression,
            )
            if match is None:
                return ()
            columns.append((match.group("source"), match.group("alias")))
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
            if rows and all(isinstance(row, (Mapping, list, tuple)) for row in rows)
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
    def _executed_sqls_from_text(text: str) -> tuple[str, ...]:
        matches = re.finditer(
            r"(?is)执行的SQL\s*[：:]\s*(?P<sql>.*?)"
            r"(?=\r?\n(?:[^\S\r\n]*\r?\n)?[^\S\r\n]*"
            r"(?:执行的SQL\s*[：:]|返回\s*\d+\s*行|结果\s*[：:])|$)",
            text,
        )
        return tuple(sql for match in matches if (sql := match.group("sql").strip()))

    @staticmethod
    def _canonical_sql(sql: str) -> str:
        identity = canonical_sql(sql)
        if identity is not None:
            return identity
        return "invalid:" + sha256(sql.encode("utf-8", errors="replace")).hexdigest()

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
        for text in ArcheryMCPClient._discovery_text_blocks(
            payload,
            supplemental_text,
        ):
            if _ALLOWLIST_REJECTION_TEXT.search(text):
                raise ArcheryMCPToolError(f"{tool_name} failed: {safe_error_detail(text)}")
            if _SQL_QUERY_FAILURE_TEXT.search(text):
                raise ArcheryMCPToolError(f"{tool_name} failed: {safe_error_detail(text)}")

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
    capability = ARCHERY_SLOW_LOG_CAPABILITY
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
            result.history_complete is False
            or ArcheryMCPClient.is_result_incomplete(result.payload)
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
            "实际执行 SQL 已由 Archery 回显并通过 provider 执行契约核验"
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
        if result.enrichment_partial or result.payload.get("enrichment_partial") is True:
            unfinished_ids = (
                result.enrichment_unfinished_ids
                or tuple(result.payload.get("enrichment_unfinished_ids") or ())
            )
            unfinished_count = len(unfinished_ids)
            stop_reason = str(
                result.enrichment_stop_reason
                or result.payload.get("enrichment_stop_reason")
                or ""
            ).upper()
            stop_summary = (
                "内部调查预算到期"
                if stop_reason in {"BUDGET_EXHAUSTED", "DEADLINE_EXCEEDED"}
                else "内部深度调查提前终止"
            )
            summary += (
                f"{stop_summary}，仍有 {unfinished_count} 条 supplemental 调查未完成；"
                "完整 History 不受影响，已完成补充结果继续保留。"
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
                if result.payload.get("rows_recovered_from_truncated_json") is True
                else "remote_result_incomplete"
                if remote_result_partial and has_log_content
                else ineligible_reason
            ),
        )
        if remote_result_partial:
            partial_summary = (
                "Archery MCP 返回发生字符截断"
                if result.payload.get("rows_recovered_from_truncated_json") is True
                else "Archery MCP 返回不完整"
            )
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=(
                    summary
                    if not has_log_content
                    else (
                        partial_summary + "；已保留完整收到的原始信封和可解析行，"
                        "但部分结果不能用于支持根因。"
                    )
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
            passthrough = {str(key): value for key, value in payload.items() if str(key) != "rows"}
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
        partial = (
            result.history_complete is False
            or ArcheryMCPClient.is_result_incomplete(result.payload)
        )
        history_scan_complete = (
            result.history_complete
            if result.history_complete is not None
            else result.payload.get("history_scan_complete") is not False
        )
        enrichment_partial = (
            result.enrichment_partial
            or result.payload.get("enrichment_partial") is True
        )
        final_result_payload, final_result_text = self._final_result_passthrough(result.payload)
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
            "history_scan_complete": history_scan_complete,
            "enrichment_partial": enrichment_partial,
            "enrichment_stop_reason": sanitize(
                result.enrichment_stop_reason
                or result.payload.get("enrichment_stop_reason")
            ),
            "enrichment_unfinished_ids": sanitize(
                list(result.enrichment_unfinished_ids)
                or result.payload.get("enrichment_unfinished_ids")
                or []
            ),
            "root_cause_eligible": bool(semantic_rows) and history_scan_complete and not partial,
            "root_cause_ineligible_reason": root_cause_ineligible_reason,
        }
        if final_result_payload is not None:
            structured_data["final_result_payload"] = final_result_payload
        if result.slow_query_analysis is not None:
            structured_data["slow_query_analysis"] = result.slow_query_analysis
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
        for field in _SLOW_QUERY_PIPELINE_FIELDS:
            if field in casefolded:
                semantic[field] = sanitize(casefolded[field])
        retained_fields = {
            *_SLOW_QUERY_IDENTITY_FIELDS,
            *_SLOW_QUERY_PIPELINE_FIELDS,
        }
        for key, value in row.items():
            field = str(key)
            if field.casefold() in retained_fields:
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
