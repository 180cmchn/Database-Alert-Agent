"""Facade and result codec for Harness-owned Prometheus MCP evidence collection."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from app.application.sanitization import sanitize, sanitize_text
from app.domain.alert_preprocessing import preprocess_alert_payload
from app.domain.models import (
    InvestigationContext,
    NormalizedAlert,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.tool_calling import (
    MCPModelToolCall,
    MCPToolCallingModel,
    mcp_tool_result_messages,
)
from app.mcp_catalog import (
    MCP_TRANSPORTS,
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    MCPTransport,
    load_mcp_catalog,
)

PROMETHEUS_MCP_SERVER_NAME: Final = "prometheus"
PROMETHEUS_METRICS_TOOL_NAME: Final = "query_prometheus_metrics"
PROMETHEUS_ALERT_WINDOW_SECONDS: Final = 300
PROMETHEUS_MCP_PROMPT_VERSION: Final = "prometheus-mcp-agent-v18"
PROMETHEUS_MCP_EVIDENCE_SCHEMA_VERSION: Final = "prometheus-evidence-v5"
# China Standard Time has no daylight-saving transitions. A fixed offset keeps
# model-facing timestamps stable on Windows images without an IANA tzdata package.
PROMETHEUS_MCP_MODEL_TIMEZONE: Final = timezone(
    timedelta(hours=8),
    name="Asia/Shanghai",
)
_ENV_REFERENCE: Final = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
_FINISH_TOOL_NAME: Final = "finish_prometheus_investigation"
_OBSERVATION_KEYS: Final = {
    "data",
    "datapoint",
    "datapoints",
    "matrix",
    "result",
    "sample",
    "samples",
    "series",
    "timeseries",
    "value",
    "values",
    "vector",
}
_PROMETHEUS_METRIC_IDENTIFIER: Final = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")
_ALERT_THRESHOLD_SUFFIX: Final = re.compile(
    r"(?i)_(?:more|less|greater|higher|lower)_than_\d+(?:\.\d+)?%?$"
)
_UNKNOWN_METRIC_IDENTIFIERS: Final = {"n/a", "none", "null", "unknown"}
_PROJECTED_METRIC_LABEL_KEYS: Final = (
    "__name__",
    "metric",
    "command",
    "operation",
    "pool",
    "quantile",
    "state",
    "type",
)
_PROMQL_ARGUMENT_KEYS: Final = ("promql", "query", "expr", "expression")
_PROMQL_FUNCTION_PATTERN: Final = re.compile(r"(?<![A-Za-z0-9_:])([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PROMQL_RATE_FUNCTIONS: Final = {"irate", "rate"}
_PROMQL_AGGREGATE_FUNCTIONS: Final = {
    "avg",
    "avg_over_time",
    "bottomk",
    "count",
    "count_over_time",
    "histogram_quantile",
    "max",
    "max_over_time",
    "min",
    "min_over_time",
    "quantile",
    "quantile_over_time",
    "stddev",
    "stdvar",
    "sum",
    "sum_over_time",
    "topk",
}
_RANGE_WINDOW_FIELD_PAIRS: Final = (
    ("start_time", "end_time"),
    ("start", "end"),
    ("start_unix_seconds", "end_unix_seconds"),
)
_TARGET_HOST_LABEL_KEYS: Final = {
    "addr",
    "address",
    "alarmhost",
    "endpoint",
    "host",
    "hostname",
    "instance",
    "ip",
    "observerip",
    "server",
    "serverip",
    "svrip",
    "target",
}
_TARGET_INSTANCE_LABEL_KEYS: Final = {
    "databaseinstance",
    "dbinstance",
    "instance",
}
# These labels identify the monitored database endpoint with higher confidence than
# exporter-oriented labels such as `instance` or inventory labels such as `server`.
_TARGET_ENDPOINT_LABEL_KEYS: Final = {
    "endpoint",
    "target",
}
_TARGET_PORT_LABEL_KEYS: Final = {
    "alarmport",
    "databaseport",
    "dbport",
    "observerport",
    "port",
    "serverport",
    "svrport",
}
_TARGET_CLUSTER_LABEL_KEYS: Final = {
    "cluster",
    "clusterid",
    "clustername",
    "obcluster",
    "obclusterid",
    "obclustername",
}
_TARGET_DATABASE_LABEL_KEYS: Final = {
    "database",
    "databasename",
    "datname",
    "db",
    "dbname",
    "schema",
}
_CATALOG_METRIC_CONTAINER_KEYS: Final = {
    "metriclist",
    "metricnames",
    "metrics",
}
_CATALOG_METRIC_NAME_KEYS: Final = {
    "metric",
    "metricname",
    "name",
}
_CATALOG_METADATA_KEYS: Final = {
    "description",
    "help",
    "metadata",
    "type",
    "unit",
}
_BINDING_LABEL_KEYS: Final = {
    "__name__",
    "addr",
    "address",
    "bi",
    "cluster",
    "endpoint",
    "group",
    "host",
    "hostname",
    "id",
    "instance",
    "job",
    "kube_cluster_alias",
    "metric",
    "port",
    "server",
    "service",
    "target",
    "umon_id",
}
_METRIC_TERM_STOPWORDS: Final = {
    "alert",
    "alarm",
    "count",
    "database",
    "db",
    "greater",
    "high",
    "higher",
    "less",
    "low",
    "lower",
    "metric",
    "metrics",
    "more",
    "mysql",
    "mysqld",
    "oceanbase",
    "postgres",
    "postgresql",
    "rate",
    "than",
    "tidb",
    "total",
    "usage",
}


class PrometheusMCPError(RuntimeError):
    """Base error for Prometheus MCP evidence collection."""


class PrometheusMCPConfigurationError(PrometheusMCPError):
    """The MCP endpoint or its deployment settings are invalid."""


class PrometheusMCPProtocolError(PrometheusMCPError):
    """The remote MCP server did not return a usable protocol payload."""


class PrometheusMCPToolError(PrometheusMCPError):
    """A standard MCP tool result reported an execution error."""

    def __init__(
        self,
        message: str,
        *,
        raw_call_result: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.raw_call_result = deepcopy(raw_call_result)
        self.details = (
            {"raw_call_result": deepcopy(raw_call_result)} if raw_call_result is not None else {}
        )


class PrometheusMCPModelError(PrometheusMCPError):
    """The model failed to select a valid MCP tool call."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic_data = diagnostic_data or {}


@dataclass(frozen=True, slots=True)
class PrometheusMCPServerSettings:
    url: str
    headers: dict[str, str]
    prompts: MCPPromptBundle
    transport: MCPTransport


@dataclass(frozen=True, slots=True)
class PrometheusMCPCallResult:
    """Keep the normalized business payload beside the complete protocol result."""

    payload: Any | None
    raw_call_result: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PrometheusMCPQueryResult:
    responses: tuple[dict[str, Any], ...]
    window_start: datetime
    window_end: datetime
    model_tool_calls: tuple[str, ...]
    model_request_ids: tuple[str, ...]
    finished_by_model: bool
    tool_attempts: tuple[dict[str, Any], ...] = ()
    termination_reason: str = "unknown"
    partial: bool = False
    termination_error_type: str | None = None
    termination_error_detail: str | None = None
    mcp_session_attempts: int = 1
    reconnect_error_type: str | None = None
    inconclusive_reason: str | None = None
    monitoring_scope_status: Literal[
        "not_checked", "investigating", "in_scope", "out_of_scope", "unknown"
    ] = "not_checked"
    monitoring_scope_reason: str | None = None
    monitored_database_engines: tuple[str, ...] = ()
    monitoring_target_identifiers: tuple[str, ...] = ()
    tool_catalog_names: tuple[str, ...] = ()
    tool_catalog_digest: str = ""
    prompt_revision: str = ""
    model_declared_scope_status: Literal[
        "not_checked", "investigating", "in_scope", "out_of_scope", "unknown"
    ] = "not_checked"
    model_declared_scope_reason: str | None = None
    scope_declaration_verified: bool = False
    target_bindings: tuple[dict[str, Any], ...] = ()

    @property
    def has_monitoring_data(self) -> bool:
        return PrometheusMCPClient.responses_have_monitoring_data(list(self.responses))


def has_monitoring_observation(value: Any, *, observation_context: bool = False) -> bool:
    """Conservatively distinguish samples from catalog or status-only results."""

    if value in (None, "", [], {}):
        return False
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return observation_context
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            # Metric names, labels, status messages and catalog entries are often
            # plain strings. They are context for a later query, not observations.
            return False
        if not isinstance(decoded, (dict, list)):
            return False
        return has_monitoring_observation(decoded, observation_context=observation_context)
    if isinstance(value, list):
        return any(
            has_monitoring_observation(
                item,
                observation_context=(observation_context and not isinstance(item, dict)),
            )
            for item in value
        )
    if not isinstance(value, dict):
        return False

    for key, nested in value.items():
        normalized_key = re.sub(r"[^a-z0-9]", "", str(key).casefold())
        nested_context = normalized_key in _OBSERVATION_KEYS
        if has_monitoring_observation(nested, observation_context=nested_context):
            return True
    return False


def load_prometheus_mcp_server_settings(
    path: Path, *, environment: Mapping[str, str]
) -> PrometheusMCPServerSettings:
    """Resolve one MCP server configuration without persisting its secrets."""

    try:
        descriptor = load_mcp_catalog(path).require(PROMETHEUS_MCP_SERVER_NAME)
        connection = descriptor.resolve_connection(environment)
    except MCPCatalogConfigurationError as exc:
        raise PrometheusMCPConfigurationError(str(exc)) from exc
    return PrometheusMCPServerSettings(
        url=connection.url,
        headers=dict(connection.headers),
        prompts=descriptor.prompts,
        transport=connection.transport,
    )


class PrometheusMCPClient:
    """Public Prometheus Provider facade backed exclusively by the shared Harness."""

    def __init__(
        self,
        server: PrometheusMCPServerSettings,
        model: MCPToolCallingModel,
        *,
        timeout_seconds: float = 60,
        investigation_budget_seconds: float = 180,
        sse_read_timeout_seconds: float | None = None,
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
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP URL must be an absolute HTTP(S) endpoint without "
                "embedded credentials, query, or fragment"
            )
        if server.transport not in MCP_TRANSPORTS:
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP transport must be sse or streamable_http"
            )
        if not timeout_seconds > 0:
            raise PrometheusMCPConfigurationError("Prometheus MCP timeout must be positive")
        if sse_read_timeout_seconds is not None and not sse_read_timeout_seconds > 0:
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP SSE read timeout must be positive"
            )
        if investigation_budget_seconds <= 0:
            raise PrometheusMCPConfigurationError(
                "Prometheus investigation budget must be positive"
            )
        self.mcp_transport = server.transport
        self.mcp_url = server.url.strip()
        self._headers = dict(server.headers)
        self.model = model
        self.prompts = server.prompts
        self.prompt_revision = hashlib.sha256(
            server.prompts.execution_instructions.encode("utf-8")
        ).hexdigest()
        self.timeout_seconds = timeout_seconds
        self.investigation_budget_seconds = investigation_budget_seconds
        self.sse_read_timeout_seconds = (
            sse_read_timeout_seconds if sse_read_timeout_seconds is not None else timeout_seconds
        )
        self.harness_runtime_dependencies = harness_runtime_dependencies

    @property
    def headers(self) -> Mapping[str, str]:
        """Resolved transport headers exposed read-only to the Harness connector."""

        return self._headers

    @classmethod
    def from_settings(
        cls,
        settings_path: Path,
        model: MCPToolCallingModel,
        *,
        environment: Mapping[str, str],
        timeout_seconds: float = 60,
        investigation_budget_seconds: float = 180,
        sse_read_timeout_seconds: float | None = None,
        harness_runtime_dependencies: Any | None = None,
    ) -> PrometheusMCPClient:
        return cls(
            load_prometheus_mcp_server_settings(settings_path, environment=environment),
            model,
            timeout_seconds=timeout_seconds,
            investigation_budget_seconds=investigation_budget_seconds,
            sse_read_timeout_seconds=sse_read_timeout_seconds,
            harness_runtime_dependencies=harness_runtime_dependencies,
        )

    async def collect_alert_window(
        self,
        context: InvestigationContext,
        *,
        request: ToolExecutionRequest | None = None,
    ) -> PrometheusMCPQueryResult:
        from app.adapters.prometheus_harness import collect_prometheus_with_harness

        return await collect_prometheus_with_harness(self, context, request=request)

    def model_tools_for_state(
        self,
        *,
        model_tool_list: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Expose every discovered tool and let the model choose the workflow."""

        return [*deepcopy(model_tool_list), self._finish_tool()]

    def host_control_feedback(
        self,
        *,
        remote_calls_used: int,
        outcome: str,
        instruction: str,
        capability: str | None = None,
    ) -> dict[str, Any]:
        feedback: dict[str, Any] = {
            "outcome": outcome,
            "remote_calls_used": remote_calls_used,
            "instruction": instruction,
        }
        if capability is not None:
            feedback["capability"] = capability
        return feedback

    @classmethod
    def project_model_observation(
        cls,
        payload: Any,
        *,
        alert: NormalizedAlert,
    ) -> dict[str, Any]:
        """Build a bounded time-series projection without auxiliary response values."""

        del alert
        series = [
            (metric, samples)
            for metric, samples, samples_valid in cls._range_series(payload)
            if samples_valid and samples
        ]
        return cls._project_numeric_series(series)

    @classmethod
    def _project_numeric_series(
        cls,
        series: list[tuple[Mapping[str, Any], list[tuple[Any, float]]]],
        *,
        value_semantics: str = "unknown",
    ) -> dict[str, Any]:
        summaries: list[dict[str, Any]] = []
        for metric, samples in series:
            values = [value for _, value in samples]
            summaries.append(
                {
                    "metric": cls._project_metric_labels(metric),
                    "value_semantics": value_semantics,
                    "sample_count": len(values),
                    "min": cls._display_number(min(values)),
                    "max": cls._display_number(max(values)),
                    "avg": cls._display_number(sum(values) / len(values)),
                    "latest": cls._display_number(values[-1]),
                    "delta": cls._display_number(values[-1] - values[0]),
                }
            )
        summaries.sort(
            key=lambda item: (
                -int(item["sample_count"]),
                json.dumps(item["metric"], ensure_ascii=True, sort_keys=True),
            )
        )
        return {
            "has_numeric_samples": bool(series),
            "series_count": len(series),
            "sample_count": sum(len(samples) for _, samples in series),
            "series": summaries[:20],
            "omitted_series_count": max(len(summaries) - 20, 0),
        }

    @classmethod
    def project_alert_window_range(
        cls,
        payload: Any,
        *,
        arguments: Mapping[str, Any],
        alert: NormalizedAlert,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any] | None:
        """Project only identity-safe, target-scoped data for the authoritative window."""

        argument_window = cls._argument_window(arguments)
        if argument_window != (
            window_start.astimezone(UTC),
            window_end.astimezone(UTC),
        ):
            return None
        value_semantics = cls._query_value_semantics(arguments)
        all_series = cls._range_series(payload)
        candidates: list[tuple[dict[str, Any], list[tuple[Any, float]], list[str]]] = []
        identity_missing_count = 0
        for metric, samples, samples_valid in all_series:
            series_match = cls._metric_alert_target_fields(metric, alert=alert)
            if (
                not series_match
                or not samples_valid
                or not samples
                or not cls._samples_within_window(
                    samples,
                    window_start=window_start,
                    window_end=window_end,
                )
            ):
                continue
            public_metric = cls._project_metric_labels(metric)
            if not public_metric:
                identity_missing_count += 1
                continue
            candidates.append((public_metric, samples, series_match))

        identity_counts = Counter(
            json.dumps(metric, ensure_ascii=True, sort_keys=True)
            for metric, _samples, _matched_fields in candidates
        )
        colliding_identities = {
            identity for identity, count in identity_counts.items() if count > 1
        }
        collision_count = sum(identity_counts[identity] for identity in colliding_identities)
        selected = [
            (metric, samples, matched_fields)
            for metric, samples, matched_fields in candidates
            if json.dumps(metric, ensure_ascii=True, sort_keys=True) not in colliding_identities
        ]
        if not selected:
            return None

        projection = cls._project_numeric_series(
            [(metric, samples) for metric, samples, _matched_fields in selected],
            value_semantics=value_semantics,
        )
        if projection["has_numeric_samples"] is not True:
            return None
        projection["excluded_metric_identity_missing_count"] = identity_missing_count
        projection["excluded_metric_identity_collision_count"] = collision_count
        matched_fields = [field for _metric, _samples, fields in selected for field in fields]
        return {
            "projection_kind": "alert_window_range",
            "window": {
                "start": window_start.astimezone(UTC).isoformat(),
                "end": window_end.astimezone(UTC).isoformat(),
            },
            "target_match": {
                "matched": True,
                "authoritative_fields": list(dict.fromkeys(matched_fields)),
            },
            "timeseries": projection,
            "excluded_series_count": max(len(all_series) - len(selected), 0),
        }

    @staticmethod
    def _query_value_semantics(arguments: Mapping[str, Any]) -> str:
        query = next(
            (
                candidate.strip()
                for key in _PROMQL_ARGUMENT_KEYS
                if isinstance((candidate := arguments.get(key)), str) and candidate.strip()
            ),
            "",
        )
        if not query:
            return "unknown"
        normalized = query.casefold()
        functions = {
            match.group(1).casefold() for match in _PROMQL_FUNCTION_PATTERN.finditer(normalized)
        }
        if "increase" in functions:
            return "increase"
        if functions & _PROMQL_RATE_FUNCTIONS:
            return "rate"
        if functions & _PROMQL_AGGREGATE_FUNCTIONS or any(
            re.search(rf"\b{function}\s+(?:by|without)\s*\(", normalized)
            for function in _PROMQL_AGGREGATE_FUNCTIONS
        ):
            return "aggregate"
        if functions:
            return "expression"
        if re.fullmatch(r"[a-z_:][a-z0-9_:]*(?:\{.*\})?", normalized, flags=re.DOTALL):
            return "raw"
        return "expression"

    @classmethod
    def target_series_bindings(
        cls,
        payload: Any,
        *,
        alert: NormalizedAlert,
    ) -> list[dict[str, Any]]:
        """Project bounded target/metric bindings from positively matched series labels."""

        bindings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for labels in cls._series_metric_labels(payload):
            matched_fields = cls._metric_alert_target_fields(labels, alert=alert)
            if not matched_fields:
                continue
            physical_metric = labels.get("__name__")
            if not isinstance(physical_metric, str) or not _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(
                physical_metric
            ):
                continue
            projected_labels = {
                str(key): sanitize_text(str(value))[:200]
                for key, value in sorted(labels.items(), key=lambda item: str(item[0]))
                if str(key).casefold() in _BINDING_LABEL_KEYS
                and isinstance(value, (str, int, float))
                and not isinstance(value, bool)
            }
            binding = {
                "physical_metric": physical_metric,
                "semantic_metric": (
                    labels.get("metric") if isinstance(labels.get("metric"), str) else None
                ),
                "matched_fields": list(matched_fields),
                "labels": projected_labels,
            }
            identity = json.dumps(binding, ensure_ascii=True, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            bindings.append(binding)
            if len(bindings) == 20:
                break
        return bindings

    @classmethod
    def _series_metric_labels(cls, value: Any) -> list[Mapping[str, Any]]:
        found: list[Mapping[str, Any]] = []
        if isinstance(value, Mapping):
            metric = value.get("metric")
            if isinstance(metric, Mapping):
                found.append(metric)
            if isinstance(value.get("__name__"), str):
                found.append(value)
            for key, nested in value.items():
                if key == "metric":
                    continue
                if isinstance(nested, (Mapping, list)):
                    found.extend(cls._series_metric_labels(nested))
        elif isinstance(value, list):
            for nested in value:
                if isinstance(nested, (Mapping, list)):
                    found.extend(cls._series_metric_labels(nested))
        return found

    @classmethod
    def range_query_is_empty(cls, payload: Any) -> bool:
        """Return true only when a complete successful payload explicitly reports zero series."""

        counts: list[int] = []
        incomplete = False

        def collect(value: Any) -> None:
            nonlocal incomplete
            if isinstance(value, Mapping):
                if value.get("partial") is True or value.get("truncated") is True:
                    incomplete = True
                result_type = value.get("resultType") or value.get("result_type")
                result = value.get("result")
                if (
                    isinstance(result_type, str)
                    and result_type.casefold()
                    in {
                        "matrix",
                        "vector",
                    }
                    and isinstance(result, list)
                ):
                    counts.append(len(result))
                for field_name in ("returned_series", "total_series"):
                    series_count = value.get(field_name)
                    if isinstance(series_count, int) and not isinstance(series_count, bool):
                        counts.append(max(series_count, 0))
                for nested in value.values():
                    if isinstance(nested, (Mapping, list)):
                        collect(nested)
            elif isinstance(value, list):
                for nested in value:
                    if isinstance(nested, (Mapping, list)):
                        collect(nested)

        collect(payload)
        return not incomplete and bool(counts) and all(count == 0 for count in counts)

    @classmethod
    def _range_series(
        cls,
        value: Any,
    ) -> list[tuple[Mapping[str, Any], list[tuple[Any, float]], bool]]:
        found: list[tuple[Mapping[str, Any], list[tuple[Any, float]], bool]] = []
        if isinstance(value, Mapping):
            if "values" in value:
                metric = value.get("metric")
                metric = metric if isinstance(metric, Mapping) else {}
                samples, samples_valid = cls._range_numeric_samples(value.get("values"))
                found.append((metric, samples, samples_valid))
            for key, nested in value.items():
                if key in {"metric", "value", "values"}:
                    continue
                if isinstance(nested, (Mapping, list)):
                    found.extend(cls._range_series(nested))
        elif isinstance(value, list):
            for nested in value:
                if isinstance(nested, (Mapping, list)):
                    found.extend(cls._range_series(nested))
        return found

    @classmethod
    def _project_metric_labels(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            return {}
        projected: dict[str, Any] = {}
        for key in _PROJECTED_METRIC_LABEL_KEYS:
            label = value.get(key)
            if not isinstance(label, str) or not label.strip():
                continue
            if key == "__name__" and not _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(label):
                continue
            projected[key] = sanitize_text(label)[:200]
        return projected

    @classmethod
    def _argument_window(
        cls,
        arguments: Mapping[str, Any],
    ) -> tuple[datetime, datetime] | None:
        for start_name, end_name in _RANGE_WINDOW_FIELD_PAIRS:
            if start_name not in arguments or end_name not in arguments:
                continue
            start = cls._timestamp(arguments.get(start_name))
            end = cls._timestamp(arguments.get(end_name))
            if start is not None and end is not None:
                return start, end
        return None

    @classmethod
    def _samples_within_window(
        cls,
        samples: list[tuple[Any, float]],
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> bool:
        lower = window_start.astimezone(UTC)
        upper = window_end.astimezone(UTC)
        timestamps = [cls._timestamp(timestamp) for timestamp, _ in samples]
        return bool(timestamps) and all(
            timestamp is not None and lower <= timestamp <= upper for timestamp in timestamps
        )

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            seconds = float(value)
        elif isinstance(value, str):
            candidate = value.strip()
            try:
                seconds = float(candidate)
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                except ValueError:
                    return None
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    return None
                return parsed.astimezone(UTC)
        else:
            return None
        if not math.isfinite(seconds):
            return None
        if abs(seconds) >= 100_000_000_000:
            seconds /= 1000
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    @classmethod
    def _metric_alert_target_fields(
        cls,
        metric: Mapping[str, Any],
        *,
        alert: NormalizedAlert,
    ) -> list[str]:
        labels = {
            re.sub(r"[^a-z0-9]", "", str(key).casefold()): value for key, value in metric.items()
        }
        database = alert.database
        matched: list[str] = []
        host_values = cls._label_values(labels, _TARGET_HOST_LABEL_KEYS)
        preferred_endpoint_values = cls._label_values(labels, _TARGET_ENDPOINT_LABEL_KEYS)
        preferred_endpoint_matched = False

        if database is not None and database.host:
            expected_host = database.host.strip().casefold()
            preferred_endpoints = [
                endpoint
                for value in preferred_endpoint_values
                if (endpoint := cls._label_endpoint(value)) is not None
            ]
            if preferred_endpoints:
                if any(endpoint[0].casefold() != expected_host for endpoint in preferred_endpoints):
                    return []
                if database.port is not None:
                    endpoint_ports = {
                        port for _host, port in preferred_endpoints if port is not None
                    }
                    if any(port != database.port for port in endpoint_ports):
                        return []
                    if database.port in endpoint_ports:
                        matched.append("database.endpoint")
                matched.append("database.host")
                preferred_endpoint_matched = True
            else:
                for value in host_values:
                    endpoint = cls._label_endpoint(value)
                    if endpoint is not None and endpoint[0].casefold() != expected_host:
                        return []
                    if cls._label_matches_host(value, database.host):
                        matched.append("database.host")
                if "database.host" not in matched:
                    return []

        if database is not None and database.port is not None:
            if not preferred_endpoint_matched:
                for value in host_values:
                    endpoint = cls._label_endpoint(value)
                    if endpoint is not None and endpoint[1] is not None:
                        if endpoint[1] != database.port:
                            return []
                        matched.append("database.endpoint")
            for value in cls._label_values(labels, _TARGET_PORT_LABEL_KEYS):
                port = cls._label_port(value)
                if port is not None and port != database.port:
                    return []

        # A target/endpoint label that matches the authoritative database endpoint
        # outranks `instance`, which commonly identifies the exporter scrape port.
        if database is not None and database.instance and not preferred_endpoint_matched:
            for key in _TARGET_INSTANCE_LABEL_KEYS:
                value = labels.get(key)
                if not cls._has_label_value(value):
                    continue
                if not cls._label_matches_instance(value, database.instance):
                    return []
                matched.append("database.instance")
            if any(cls._label_equals(value, database.instance) for value in host_values):
                matched.append("database.instance")

        cluster_values = cls._label_values(labels, _TARGET_CLUSTER_LABEL_KEYS)
        if alert.cluster and cluster_values:
            if any(not cls._label_equals(value, alert.cluster) for value in cluster_values):
                return []
            matched.append("cluster")

        if database is not None and database.database:
            database_values = cls._label_values(labels, _TARGET_DATABASE_LABEL_KEYS)
            if database_values:
                if any(
                    not cls._label_equals(value, database.database) for value in database_values
                ):
                    return []
                matched.append("database.database")

        return list(dict.fromkeys(matched))

    @classmethod
    def _label_values(
        cls,
        labels: Mapping[str, Any],
        keys: set[str],
    ) -> list[Any]:
        return [value for key in keys if cls._has_label_value(value := labels.get(key))]

    @staticmethod
    def _has_label_value(value: Any) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _label_equals(value: Any, expected: str) -> bool:
        return isinstance(value, str) and value.strip().casefold() == expected.strip().casefold()

    @classmethod
    def _label_matches_host(cls, value: Any, expected_host: str) -> bool:
        endpoint = cls._label_endpoint(value)
        if endpoint is None:
            return False
        return endpoint[0].casefold() == expected_host.strip().casefold()

    @classmethod
    def _label_matches_instance(cls, value: Any, expected: str) -> bool:
        if cls._label_equals(value, expected):
            return True
        candidate_endpoint = cls._label_endpoint(value)
        expected_endpoint = cls._label_endpoint(expected)
        if candidate_endpoint is None or expected_endpoint is None:
            return False
        if candidate_endpoint[0].casefold() != expected_endpoint[0].casefold():
            return False
        return expected_endpoint[1] is None or (candidate_endpoint[1] == expected_endpoint[1])

    @staticmethod
    def _label_endpoint(value: Any) -> tuple[str, int | None] | None:
        if not isinstance(value, str) or not value.strip():
            return None
        candidate = value.strip()
        try:
            parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
            parsed_host = parsed.hostname
            parsed_port = parsed.port
        except ValueError:
            return None
        if not isinstance(parsed_host, str) or not parsed_host:
            return None
        return parsed_host, parsed_port

    @staticmethod
    def _label_port(value: Any) -> int | None:
        if not isinstance(value, str):
            return None
        try:
            port = int(value.strip())
        except ValueError:
            return None
        return port if 1 <= port <= 65_535 else None

    @classmethod
    def _scalar_fact_fragments(
        cls,
        value: Any,
        *,
        path: tuple[str, ...] = (),
        sample_context: bool = False,
    ) -> list[dict[str, Any]]:
        if isinstance(value, Mapping):
            facts: list[dict[str, Any]] = []
            for raw_key, nested in value.items():
                key = str(raw_key)
                normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
                facts.extend(
                    cls._scalar_fact_fragments(
                        nested,
                        path=(*path, key),
                        sample_context=(
                            sample_context
                            or normalized
                            in {"datapoint", "datapoints", "sample", "samples", "value", "values"}
                        ),
                    )
                )
            return cls._rank_scalar_facts(facts)
        if isinstance(value, list):
            facts = []
            for index, nested in enumerate(value):
                facts.extend(
                    cls._scalar_fact_fragments(
                        nested,
                        path=(*path, str(index)),
                        sample_context=sample_context,
                    )
                )
            return cls._rank_scalar_facts(facts)
        if sample_context or value is None or isinstance(value, (Mapping, list)):
            return []
        if not isinstance(value, (str, int, float, bool)):
            return []
        return [{"path": "/" + "/".join(path), "value": cls._bounded_scalar(value)}]

    @staticmethod
    def _rank_scalar_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        markers = (
            "target",
            "engine",
            "database",
            "cluster",
            "host",
            "instance",
            "endpoint",
            "address",
            "job",
            "metric",
            "scrape",
            "pool",
        )
        unique = {
            (str(item["path"]), json.dumps(item["value"], ensure_ascii=True, sort_keys=True)): item
            for item in facts
        }
        return sorted(
            unique.values(),
            key=lambda item: (
                -sum(marker in str(item["path"]).casefold() for marker in markers),
                str(item["path"]),
                json.dumps(item["value"], ensure_ascii=True, sort_keys=True),
            ),
        )

    @staticmethod
    def _bounded_scalar(value: Any) -> Any:
        if not isinstance(value, str) or len(value) <= 300:
            return sanitize(value)
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
        return f"{value[:300]}...[sha256:{digest},total_chars:{len(value)}]"

    @classmethod
    def _range_numeric_samples(
        cls,
        raw_samples: Any,
    ) -> tuple[list[tuple[Any, float]], bool]:
        if not isinstance(raw_samples, list):
            return [], False
        samples: list[tuple[Any, float]] = []
        valid = True
        for item in raw_samples:
            if not isinstance(item, list) or len(item) < 2:
                valid = False
                continue
            number = cls._finite_number(item[1])
            if number is None or cls._timestamp(item[0]) is None:
                valid = False
                continue
            samples.append((item[0], number))
        samples.sort(
            key=lambda item: (
                cls._timestamp(item[0]) or datetime.max.replace(tzinfo=UTC),
                str(item[0]),
            )
        )
        return samples, valid

    @staticmethod
    def _finite_number(value: Any) -> float | None:
        if isinstance(value, bool):
            return None
        try:
            result = float(value)
        except (TypeError, ValueError):
            return None
        return result if math.isfinite(result) else None

    @staticmethod
    def _display_number(value: float) -> int | float:
        return int(value) if value.is_integer() else round(value, 6)

    @classmethod
    def _value_kind_counts(cls, value: Any) -> Counter[str]:
        counts: Counter[str] = Counter()
        if isinstance(value, Mapping):
            counts["objects"] += 1
            for nested in value.values():
                counts.update(cls._value_kind_counts(nested))
        elif isinstance(value, list):
            counts["arrays"] += 1
            for nested in value:
                counts.update(cls._value_kind_counts(nested))
        elif value is None:
            counts["nulls"] += 1
        elif isinstance(value, bool):
            counts["booleans"] += 1
        elif isinstance(value, (int, float)):
            counts["numbers"] += 1
        elif isinstance(value, str):
            counts["strings"] += 1
        return counts

    @staticmethod
    def responses_have_monitoring_data(responses: list[dict[str, Any]]) -> bool:
        return any(
            response.get("projection_kind") == "alert_window_range"
            and response.get("has_monitoring_observation") is True
            and isinstance(response.get("projection"), dict)
            for response in responses
        )

    @staticmethod
    def alert_metric_candidates(alert: NormalizedAlert) -> list[str]:
        """Return literal or threshold-stripped metrics suitable for a first range query."""

        candidates: list[str] = []
        configured = alert.attributes.get("flashduty_metrics")
        if isinstance(configured, Mapping):
            expression = configured.get("expr") or configured.get("query_expr")
            if isinstance(expression, str) and expression.strip():
                candidates.append(expression.strip())
        for raw in (
            alert.metric_name,
            alert.title,
            alert.alert_type,
            alert.alert_name,
            alert.reason,
        ):
            if not isinstance(raw, str):
                continue
            candidate = _ALERT_THRESHOLD_SUFFIX.sub("", raw.strip())
            if (
                candidate.casefold() not in _UNKNOWN_METRIC_IDENTIFIERS
                and _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(candidate)
            ):
                candidates.append(candidate)
        return list(dict.fromkeys(candidates))

    @classmethod
    def catalog_metric_relevance(
        cls,
        alert: NormalizedAlert,
        responses: list[dict[str, Any]],
    ) -> Literal["relevant", "irrelevant", "unknown"]:
        """Classify an explicit metric inventory against the alert signal semantics."""

        inventory_seen, metric_names = cls.catalog_metric_inventory(responses)
        term_groups = cls._alert_metric_term_groups(alert)
        if not inventory_seen or not term_groups or cls._catalog_inventory_incomplete(responses):
            return "unknown"
        for metric_name in metric_names:
            metric_terms = cls._metric_identifier_terms(metric_name)
            if any(group <= metric_terms for group in term_groups):
                return "relevant"
        return "irrelevant"

    @classmethod
    def catalog_metric_inventory(
        cls,
        responses: list[dict[str, Any]],
    ) -> tuple[bool, list[str]]:
        inventory_seen = False
        metric_names: set[str] = set()
        for response in responses:
            if response.get("capability") != "catalog":
                continue
            seen, names = cls._catalog_metrics_from_payload(response.get("result"))
            inventory_seen = inventory_seen or seen
            metric_names.update(names)
        return inventory_seen, sorted(metric_names)

    @classmethod
    def _catalog_metrics_from_payload(cls, value: Any) -> tuple[bool, set[str]]:
        if isinstance(value, str):
            decoded = cls._decode_json_text(value)
            if decoded is None:
                return False, set()
            return cls._catalog_metrics_from_payload(decoded)
        if isinstance(value, list):
            seen = False
            names: set[str] = set()
            for item in value:
                nested_seen, nested_names = cls._catalog_metrics_from_payload(item)
                seen = seen or nested_seen
                names.update(nested_names)
            return seen, names
        if not isinstance(value, Mapping):
            return False, set()

        seen = False
        names: set[str] = set()
        for raw_key, nested in value.items():
            key = re.sub(r"[^a-z0-9]", "", str(raw_key).casefold())
            if key in _CATALOG_METRIC_CONTAINER_KEYS:
                seen = True
                names.update(cls._metric_names_from_inventory(nested))
                continue
            nested_seen, nested_names = cls._catalog_metrics_from_payload(nested)
            seen = seen or nested_seen
            names.update(nested_names)
        return seen, names

    @classmethod
    def _metric_names_from_inventory(cls, value: Any) -> set[str]:
        if isinstance(value, str):
            candidate = value.strip()
            return {candidate} if _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(candidate) else set()
        if isinstance(value, list):
            return {name for item in value for name in cls._metric_names_from_inventory(item)}
        if not isinstance(value, Mapping):
            return set()

        names: set[str] = set()
        for raw_key, nested in value.items():
            key = re.sub(r"[^a-z0-9]", "", str(raw_key).casefold())
            if key in _CATALOG_METRIC_NAME_KEYS and isinstance(nested, str):
                candidate = nested.strip()
                if _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(candidate):
                    names.add(candidate)
            elif key not in _CATALOG_METADATA_KEYS and _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(
                str(raw_key)
            ):
                names.add(str(raw_key))
            if isinstance(nested, (Mapping, list)):
                names.update(cls._metric_names_from_inventory(nested))
        return names

    @classmethod
    def _catalog_inventory_incomplete(
        cls,
        responses: list[dict[str, Any]],
    ) -> bool:
        return any(
            response.get("capability") == "catalog"
            and cls._payload_has_more_inventory(response.get("result"))
            for response in responses
        )

    @classmethod
    def _payload_has_more_inventory(cls, value: Any) -> bool:
        if isinstance(value, str):
            decoded = cls._decode_json_text(value)
            return False if decoded is None else cls._payload_has_more_inventory(decoded)
        if isinstance(value, list):
            return any(cls._payload_has_more_inventory(item) for item in value)
        if not isinstance(value, Mapping):
            return False

        normalized = {
            re.sub(r"[^a-z0-9]", "", str(key).casefold()): nested for key, nested in value.items()
        }
        if normalized.get("hasmore") is True:
            return True
        for key in ("nextcursor", "nextoffset", "nextpage"):
            if normalized.get(key) not in (None, "", 0, False):
                return True
        total = normalized.get("totalcount")
        returned = normalized.get("returnedcount")
        offset = normalized.get("offset", 0)
        if (
            type(total) is int
            and type(returned) is int
            and type(offset) is int
            and offset + returned < total
        ):
            return True
        return any(
            cls._payload_has_more_inventory(nested)
            for nested in value.values()
            if isinstance(nested, (Mapping, list, str))
        )

    @classmethod
    def _alert_metric_term_groups(cls, alert: NormalizedAlert) -> list[set[str]]:
        groups: list[set[str]] = []
        for candidate in cls.alert_metric_candidates(alert):
            if not _PROMETHEUS_METRIC_IDENTIFIER.fullmatch(candidate):
                continue
            terms = cls._metric_identifier_terms(candidate)
            if terms:
                groups.append(terms)
        alert_text = " ".join(
            value
            for value in (
                alert.title,
                alert.alert_type,
                alert.alert_name,
                alert.reason,
            )
            if isinstance(value, str)
        )
        if "慢查询" in alert_text:
            groups.append({"slow", "query"})
        unique: list[set[str]] = []
        for group in groups:
            if group not in unique:
                unique.append(group)
        return unique

    @staticmethod
    def _metric_identifier_terms(value: str) -> set[str]:
        terms: set[str] = set()
        for token in re.findall(r"[a-z]+|\d+", value.casefold()):
            if token.isdigit():
                continue
            if token.endswith("ies") and len(token) > 4:
                token = f"{token[:-3]}y"
            elif token.endswith("s") and len(token) > 4:
                token = token[:-1]
            if token not in _METRIC_TERM_STOPWORDS:
                terms.add(token)
        return terms

    @staticmethod
    def monitoring_target_context(alert: NormalizedAlert) -> dict[str, Any]:
        database = alert.database
        flashduty_detail = alert.source.casefold() == "flashduty"
        candidates = [
            value.strip()
            for value in (
                database.instance if database else None,
                database.host if database else None,
            )
            if isinstance(value, str) and value.strip()
        ]
        metric_term_groups = PrometheusMCPClient._alert_metric_term_groups(alert)
        return {
            "database_engine": database.engine if database else None,
            "database": database.database if database else None,
            "host": database.host if database else None,
            "port": database.port if database else None,
            "host_source": (
                "flashduty_alert_detail.alarm_host"
                if flashduty_detail and database and database.host
                else "canonical_alert.database.host"
                if database and database.host
                else None
            ),
            "port_source": (
                "flashduty_alert_detail.alarm_port"
                if flashduty_detail and database and database.port
                else "canonical_alert.database.port"
                if database and database.port
                else None
            ),
            "endpoint": (
                f"{database.host}:{database.port}"
                if database and database.host and database.port
                else None
            ),
            "cluster": alert.cluster,
            "instance_candidates": list(dict.fromkeys(candidates)),
            "target_label_candidates": ["target", "endpoint", "host", "instance"],
            "metric_candidates": PrometheusMCPClient.alert_metric_candidates(alert),
            "metric_semantic_term_groups": [sorted(group) for group in metric_term_groups],
        }

    @staticmethod
    def first_exception_leaf(error: BaseException) -> BaseException:
        while isinstance(error, BaseExceptionGroup) and error.exceptions:
            error = error.exceptions[0]
        return error

    def discovered_model_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        """Convert remote discovery records without applying Host policy gates."""

        converted: dict[str, dict[str, Any]] = {}
        for tool in tools:
            raw = tool.model_dump(mode="json") if hasattr(tool, "model_dump") else tool
            if not isinstance(raw, dict):
                raise PrometheusMCPProtocolError("Prometheus MCP tool schema is not an object")
            name = raw.get("name")
            schema = raw.get("inputSchema") or raw.get("input_schema") or {"type": "object"}
            if not isinstance(name, str) or not name or not isinstance(schema, dict):
                raise PrometheusMCPProtocolError("Prometheus MCP returned an invalid tool schema")
            converted[name] = {
                "type": "function",
                "function": {
                    "name": name,
                    "description": str(raw.get("description") or f"Prometheus MCP tool {name}"),
                    "parameters": deepcopy(schema),
                },
            }
        if not converted:
            raise PrometheusMCPProtocolError("Prometheus MCP exposed no valid tools")
        return [converted[name] for name in sorted(converted)]

    def host_investigation_state_message(
        self,
        *,
        remote_calls_used: int,
        monitoring_scope_status: str = "unknown",
        monitoring_scope_reason: str | None = None,
        model_declared_scope_status: str = "not_checked",
        scope_declaration_verified: bool = False,
        target_bindings: Sequence[Mapping[str, Any]] = (),
        range_query_success_count: int = 0,
    ) -> dict[str, Any]:
        return {
            "role": "user",
            "content": json.dumps(
                {
                    "host_event": "prometheus_investigation_state",
                    "remote_calls_used": remote_calls_used,
                    "host_verified_monitoring_scope_status": monitoring_scope_status,
                    "host_verified_monitoring_scope_reason": monitoring_scope_reason,
                    "model_declared_scope_status": model_declared_scope_status,
                    "scope_declaration_verified": scope_declaration_verified,
                    "host_verified_target_bindings": list(target_bindings),
                    "successful_range_query_count": range_query_success_count,
                    "instruction": (
                        "先以权威数据库 endpoint 做目标优先的序列发现；若工具支持标签匹配，"
                        "在首次发现时不要限定 __name__，并优先尝试 target/endpoint，再按真实返回"
                        "建立物理指标、语义标签、目标标签和 scope 标签绑定。metric_candidates 和 "
                        "promql_candidates 仅是语义提示，不能直接视为物理指标。使用同一目标序列"
                        "返回的 scope 值构造严格窗口范围查询。空查询、错误、单一指标缺失、"
                        "裁剪目录或全局标签值均不能证明 out_of_scope。只有 Host 明确标记 scope "
                        "declaration verified 时才能作该结论。"
                    ),
                },
                ensure_ascii=False,
            ),
        }

    @staticmethod
    def _finish_tool() -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": _FINISH_TOOL_NAME,
                "description": (
                    "结束 Prometheus MCP 调查并记录模型建议的监控范围结论。Host 会独立验证；"
                    "in_scope 需要目标匹配的真实序列，out_of_scope 需要完整权威范围明确排除"
                    "告警数据库，空查询、错误或裁剪目录只能声明 unknown。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "monitoring_scope_status": {
                            "type": "string",
                            "enum": ["in_scope", "out_of_scope", "unknown"],
                        },
                        "reason": {"type": "string", "minLength": 1},
                        "monitored_database_engines": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "monitoring_target_identifiers": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["monitoring_scope_status", "reason"],
                    "additionalProperties": False,
                },
            },
        }

    @staticmethod
    def result_payload(raw_result: Any) -> Any | None:
        raw = PrometheusMCPClient.raw_call_result(raw_result)
        return PrometheusMCPClient._result_payload_from_raw(raw)

    @staticmethod
    def call_result(raw_result: Any) -> PrometheusMCPCallResult:
        """Decode one result while retaining its complete unmodified MCP envelope."""

        raw = PrometheusMCPClient.raw_call_result(raw_result)
        payload = PrometheusMCPClient._result_payload_from_raw(raw)
        return PrometheusMCPCallResult(
            payload=payload,
            raw_call_result=raw,
        )

    @staticmethod
    def raw_call_result(raw_result: Any) -> dict[str, Any]:
        """Return the complete MCP envelope without filtering or rewriting it."""

        raw = (
            raw_result.model_dump(mode="json", by_alias=True)
            if hasattr(raw_result, "model_dump")
            else raw_result
        )
        if not isinstance(raw, dict):
            raise PrometheusMCPProtocolError("Prometheus MCP tool result is not an object")
        return deepcopy(raw)

    @staticmethod
    def _result_payload_from_raw(raw: dict[str, Any]) -> Any | None:
        if raw.get("isError") is True:
            raise PrometheusMCPToolError(
                PrometheusMCPClient._tool_error_detail(raw)
                or "Prometheus MCP tool reported an execution error"
            )
        structured = raw.get("structuredContent")
        if structured not in (None, "", [], {}):
            payload = sanitize(structured)
        else:
            content = raw.get("content")
            if content in (None, "", [], {}):
                return None
            payload = PrometheusMCPClient._normalize_content_payload(sanitize(content))
        business_error = PrometheusMCPClient._business_error_detail(payload)
        if business_error is not None:
            raise PrometheusMCPToolError(business_error)
        return payload

    @staticmethod
    def _business_error_detail(payload: Any) -> str | None:
        candidates = payload if isinstance(payload, list) else [payload]
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            status = candidate.get("status")
            if not isinstance(status, str) or status.casefold() not in {
                "error",
                "failed",
                "failure",
            }:
                continue
            parts: list[str] = []
            errors = candidate.get("errors")
            errors = errors if isinstance(errors, list) else [errors]
            for error in errors:
                if isinstance(error, Mapping):
                    code = error.get("code")
                    message = error.get("message") or error.get("detail")
                    if isinstance(code, str) and code:
                        parts.append(code)
                    if isinstance(message, str) and message:
                        parts.append(message)
                elif isinstance(error, str) and error:
                    parts.append(error)
            for field_name in ("error", "message", "detail"):
                direct_error = candidate.get(field_name)
                if isinstance(direct_error, str) and direct_error:
                    parts.append(direct_error)
            if not parts:
                parts.append(f"Prometheus MCP business status was {status}")
            return sanitize_text(": ".join(parts))[:500]
        return None

    @staticmethod
    def _normalize_content_payload(payload: Any) -> Any:
        """Decode standard MCP text blocks when their complete body is JSON."""

        if isinstance(payload, str):
            decoded = PrometheusMCPClient._decode_json_text(payload)
            return payload if decoded is None else decoded
        if not isinstance(payload, list):
            return payload
        normalized: list[Any] = []
        for item in payload:
            if (
                isinstance(item, dict)
                and item.get("type") == "text"
                and isinstance(item.get("text"), str)
            ):
                decoded = PrometheusMCPClient._decode_json_text(item["text"])
                normalized.append(item if decoded is None else decoded)
            else:
                normalized.append(item)
        return normalized[0] if len(normalized) == 1 else normalized

    @staticmethod
    def _decode_json_text(value: str) -> Any | None:
        candidate = value.strip()
        if candidate.startswith("```") and candidate.endswith("```"):
            first_newline = candidate.find("\n")
            if first_newline >= 0:
                candidate = candidate[first_newline + 1 : -3].strip()
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, (dict, list)) else None

    @staticmethod
    def _tool_error_detail(raw: dict[str, Any]) -> str:
        parts: list[str] = []
        content = raw.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
        elif isinstance(content, str):
            parts.append(content)
        structured = raw.get("structuredContent")
        if structured not in (None, "", [], {}):
            parts.append(json.dumps(sanitize(structured), ensure_ascii=False, default=str))
        return sanitize_text(" ".join(parts))[:500]

    @staticmethod
    def completed_tool_messages(
        call: MCPModelToolCall,
        payload: Any | None,
        *,
        host_control: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        content = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        messages = mcp_tool_result_messages(
            call,
            output=content,
            fallback_messages=[
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": call.call_id,
                            "type": "function",
                            "function": {
                                "name": call.name,
                                "arguments": json.dumps(call.arguments, ensure_ascii=False),
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": call.call_id, "content": content},
            ],
        )
        if host_control is not None:
            messages.append(
                {
                    "role": "user",
                    "content": json.dumps(
                        {"host_control": sanitize(dict(host_control))},
                        ensure_ascii=False,
                        separators=(",", ":"),
                        default=str,
                    ),
                }
            )
        return messages

    @staticmethod
    def required_window_context(
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        local_start = window_start.astimezone(PROMETHEUS_MCP_MODEL_TIMEZONE)
        local_end = window_end.astimezone(PROMETHEUS_MCP_MODEL_TIMEZONE)
        start_unix_seconds = window_start.timestamp()
        end_unix_seconds = window_end.timestamp()
        return {
            "timezone": "Asia/Shanghai",
            "start": local_start.isoformat(),
            "end": local_end.isoformat(),
            "start_unix_seconds": (
                int(start_unix_seconds) if start_unix_seconds.is_integer() else start_unix_seconds
            ),
            "end_unix_seconds": (
                int(end_unix_seconds) if end_unix_seconds.is_integer() else end_unix_seconds
            ),
            "duration_seconds": PROMETHEUS_ALERT_WINDOW_SECONDS,
        }

    @staticmethod
    def query_request_context(request: ToolExecutionRequest) -> dict[str, Any]:
        """Project the outer Agent's bounded query intent into the inner loop."""

        parameters: dict[str, Any] = {}
        focus = request.parameters.get("investigation_focus")
        if isinstance(focus, str) and focus.strip():
            parameters["investigation_focus"] = sanitize_text(focus)[:2000]
        for key, limit, item_limit in (
            ("metric_candidates", 20, 300),
            ("promql_candidates", 10, 4000),
        ):
            values = request.parameters.get(key)
            if isinstance(values, list):
                parameters[key] = [
                    sanitize_text(value)[:item_limit]
                    for value in values[:limit]
                    if isinstance(value, str) and value.strip()
                ]
        return {
            "objective": sanitize_text(request.objective)[:2000],
            "parameters": parameters,
            "hypothesis_ids": [
                sanitize_text(value)[:200]
                for value in request.hypothesis_ids[:20]
                if isinstance(value, str) and value.strip()
            ],
        }

    def agent_messages(
        self,
        context: InvestigationContext,
        window_start: datetime,
        window_end: datetime,
        *,
        request: ToolExecutionRequest | None = None,
    ) -> list[dict[str, Any]]:
        alert = context.alert.model_dump(mode="json", exclude={"raw_payload"})
        alert["occurred_at"] = context.alert.occurred_at.astimezone(
            PROMETHEUS_MCP_MODEL_TIMEZONE
        ).isoformat()
        task = {
            "prompt_version": PROMETHEUS_MCP_PROMPT_VERSION,
            "prompt_revision": self.prompt_revision,
            "alert": preprocess_alert_payload(alert),
            "required_window": self.required_window_context(window_start, window_end),
            "required_target": self.monitoring_target_context(context.alert),
            "agent_contract": {
                "read_only": True,
                "one_tool_per_turn": True,
                "arguments_forwarded_unchanged": True,
                "range_window_preflight": "exact_match_before_transport",
                "target_first_discovery_before_negative_scope": True,
                "candidate_metrics_are_semantic_hints": True,
                "negative_scope_requires_complete_authoritative_inventory": True,
                "finish_scope_is_host_verified": True,
                "finish_tool": _FINISH_TOOL_NAME,
            },
        }
        if request is not None:
            task["query_request"] = self.query_request_context(request)
        return [
            {
                "role": "system",
                "content": self.prompts.execution_instructions,
            },
            {
                "role": "user",
                "content": json.dumps(task, ensure_ascii=False),
            },
        ]


class PrometheusMCPEvidenceTool:
    """Expose the complete Prometheus MCP investigation as one evidence tool."""

    name = PROMETHEUS_METRICS_TOOL_NAME
    source_system = "prometheus_mcp"
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {
            "investigation_focus": {"type": "string", "maxLength": 2000},
            "metric_candidates": {
                "type": "array",
                "items": {"type": "string", "maxLength": 300},
                "maxItems": 20,
            },
            "promql_candidates": {
                "type": "array",
                "items": {"type": "string", "maxLength": 4000},
                "maxItems": 10,
            },
        },
        "additionalProperties": False,
    }

    def __init__(
        self,
        client: PrometheusMCPClient,
        *,
        default_timeout_seconds: float = 30,
    ) -> None:
        self.client = client
        self.default_timeout_seconds = default_timeout_seconds
        self.role = client.prompts.role
        self.capability = client.prompts.purpose
        self.workflow = client.prompts.workflow
        self.safety = client.prompts.safety
        prompt_revision = (
            getattr(client, "prompt_revision", None)
            or hashlib.sha256(client.prompts.execution_instructions.encode("utf-8")).hexdigest()
        )
        self.prompt_revision = prompt_revision
        self.policy_version = f"{PROMETHEUS_MCP_PROMPT_VERSION}:sha256:{prompt_revision}"
        self.schema_version = PROMETHEUS_MCP_EVIDENCE_SCHEMA_VERSION

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> ToolExecutionResult:
        result = await self.client.collect_alert_window(context, request=request)
        required_target = PrometheusMCPClient.monitoring_target_context(context.alert)
        monitoring_results = self._public_monitoring_results(result)
        has_monitoring_data = bool(monitoring_results)
        range_query_attempt_count, range_query_success_count, range_query_empty_count = (
            self._range_query_counts(result)
        )
        range_query_completed = range_query_success_count > 0
        unverified_scope_declaration = (
            result.model_declared_scope_status == "out_of_scope"
            and not result.scope_declaration_verified
        )
        structured_data = {
            "schema_version": PROMETHEUS_MCP_EVIDENCE_SCHEMA_VERSION,
            "prompt_version": PROMETHEUS_MCP_PROMPT_VERSION,
            "prompt_revision": result.prompt_revision or self.prompt_revision,
            "tool_catalog_names": list(result.tool_catalog_names),
            "tool_catalog_digest": result.tool_catalog_digest,
            "investigation_budget_seconds": getattr(
                self.client, "investigation_budget_seconds", None
            ),
            "window_start": result.window_start.isoformat(),
            "window_end": result.window_end.isoformat(),
            "window_seconds": PROMETHEUS_ALERT_WINDOW_SECONDS,
            "mcp_invocation": "shared_agent_harness",
            "allow_followup_dispatch": False,
            "model_tool_call_count": len(result.model_tool_calls),
            "tool_attempt_count": len(result.tool_attempts),
            "finished_by_model": result.finished_by_model,
            "termination_reason": result.termination_reason,
            "partial": result.partial,
            "termination_error_type": result.termination_error_type,
            "mcp_session_attempts": result.mcp_session_attempts,
            "reconnect_error_type": result.reconnect_error_type,
            "required_target": required_target,
            "monitoring_scope_status": result.monitoring_scope_status,
            "monitoring_scope_reason": self._public_scope_reason(result),
            "model_declared_scope_status": result.model_declared_scope_status,
            "scope_declaration_verified": result.scope_declaration_verified,
            "unverified_scope_declaration": unverified_scope_declaration,
            "target_binding_count": len(result.target_bindings),
            "monitoring_result_count": len(monitoring_results),
            "monitoring_results": monitoring_results,
            "range_query_attempt_count": range_query_attempt_count,
            "range_query_success_count": range_query_success_count,
            "range_query_empty_count": range_query_empty_count,
            "range_query_completed": range_query_completed,
            "query_completed": range_query_completed,
            "root_cause_eligible": has_monitoring_data and not result.partial,
        }
        if result.partial:
            structured_data["root_cause_ineligible_reason"] = "partial_evidence"
        if has_monitoring_data:
            suffix = "；后续调查未完整结束，已保留此前取得的可用监控返回" if result.partial else ""
            return ToolExecutionResult(
                status=ToolStatus.SUCCESS,
                summary=(
                    "Prometheus MCP 已由 Host 确认告警数据库在监控范围内，并取得告警发生前"
                    f"五分钟的实时监控证据（{len(monitoring_results)} 条合格范围投影）{suffix}。"
                ),
                structured_data=structured_data,
            )

        structured_data["root_cause_eligible"] = False
        if result.termination_reason in {"deadline_exceeded", "budget_exhausted"}:
            structured_data["reason_code"] = "prometheus_investigation_timeout"
            structured_data["root_cause_ineligible_reason"] = "prometheus_investigation_timeout"
            structured_data = self._with_missing_evidence_inventory(structured_data, result)
            return ToolExecutionResult(
                status=ToolStatus.TIMEOUT,
                summary=("Prometheus MCP 调查在取得合格告警窗口范围时序前达到时间预算。"),
                structured_data=structured_data,
            )

        if range_query_completed:
            explicitly_empty = range_query_empty_count > 0
            structured_data["reason_code"] = (
                "prometheus_range_query_empty"
                if explicitly_empty
                else "prometheus_range_query_unusable"
            )
            structured_data["root_cause_ineligible_reason"] = "no_usable_monitoring_result"
            structured_data = self._with_missing_evidence_inventory(structured_data, result)
            summary = (
                "Prometheus MCP 已完成告警窗口范围查询"
                f"（业务成功 {range_query_success_count} 次，其中明确空结果 "
                f"{range_query_empty_count} 次），但没有取得严格归属于告警目标的数值时序；"
                "空结果不证明目标未被监控。"
                if explicitly_empty
                else "Prometheus MCP 已成功完成告警窗口范围查询，但返回未形成严格归属于"
                "告警目标和窗口的数值投影；该返回不能证明目标未被监控。"
            )
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=summary,
                structured_data=structured_data,
            )

        failed_attempt = any(
            attempt.get("outcome") in {"tool_error", "transport_error"}
            for attempt in result.tool_attempts
        )
        if failed_attempt or result.termination_error_type is not None:
            structured_data["reason_code"] = "prometheus_investigation_failed"
            structured_data["root_cause_ineligible_reason"] = "prometheus_investigation_failed"
            structured_data = self._with_missing_evidence_inventory(structured_data, result)
            return ToolExecutionResult(
                status=ToolStatus.FAILED,
                summary=("Prometheus MCP 未成功执行严格匹配告警目标和窗口的范围查询。"),
                structured_data=structured_data,
            )

        if result.monitoring_scope_status == "out_of_scope":
            structured_data["reason_code"] = "database_not_monitored"
            structured_data["root_cause_ineligible_reason"] = "database_not_monitored"
            structured_data = self._with_missing_evidence_inventory(structured_data, result)
            return ToolExecutionResult(
                status=ToolStatus.SKIPPED,
                summary=(
                    "Host 已通过完整监控范围证据确认告警数据库未被当前 Prometheus 覆盖，"
                    "已跳过后续指标查询。"
                ),
                structured_data=structured_data,
            )

        structured_data["reason_code"] = "prometheus_range_query_not_executed"
        structured_data["root_cause_ineligible_reason"] = "prometheus_range_query_not_executed"
        structured_data = self._with_missing_evidence_inventory(structured_data, result)
        return ToolExecutionResult(
            status=ToolStatus.FAILED,
            summary=("Prometheus MCP 未成功执行严格匹配告警目标和窗口的范围查询。"),
            structured_data=structured_data,
        )

    @staticmethod
    def _range_query_counts(result: PrometheusMCPQueryResult) -> tuple[int, int, int]:
        attempts = [
            attempt
            for attempt in result.tool_attempts
            if attempt.get("capability") == "range_query"
        ]
        successful = [
            attempt for attempt in attempts if attempt.get("outcome") in {"result", "no_data"}
        ]
        return (
            len(attempts),
            len(successful),
            sum(attempt.get("outcome") == "no_data" for attempt in successful),
        )

    @classmethod
    def _range_query_completed(cls, result: PrometheusMCPQueryResult) -> bool:
        return cls._range_query_counts(result)[1] > 0

    def _with_missing_evidence_inventory(
        self,
        structured_data: dict[str, Any],
        result: PrometheusMCPQueryResult,
    ) -> dict[str, Any]:
        """Return public limitations without exposing discovery or catalog values."""

        del result
        complete = deepcopy(structured_data)
        return sanitize(complete)

    @staticmethod
    def _public_monitoring_results(
        result: PrometheusMCPQueryResult,
    ) -> list[dict[str, Any]]:
        public: list[dict[str, Any]] = []
        for response in result.responses:
            projection = response.get("projection")
            if (
                response.get("projection_kind") != "alert_window_range"
                or response.get("root_cause_eligible") is not True
                or not isinstance(projection, dict)
            ):
                continue
            public.append(
                {
                    "tool_name": str(response.get("tool_name") or "prometheus_range"),
                    "projection_kind": "alert_window_range",
                    "projection": deepcopy(projection),
                }
            )
        return public

    @staticmethod
    def _public_scope_reason(result: PrometheusMCPQueryResult) -> str | None:
        if result.monitoring_scope_status == "out_of_scope":
            return "Prometheus MCP 中没有配置告警数据库对应的监控信息"
        if result.monitoring_scope_status == "unknown":
            return "Prometheus MCP 无法确认告警数据库是否在当前监控范围内"
        if result.monitoring_scope_status == "in_scope":
            return "Prometheus MCP 已确认告警数据库在监控范围内"
        return None
