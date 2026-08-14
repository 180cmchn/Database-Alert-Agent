"""Facade and result codec for Harness-owned Prometheus MCP evidence collection."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from app.application.sanitization import sanitize, sanitize_text
from app.domain.alert_preprocessing import preprocess_alert_data
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
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    load_mcp_catalog,
)

PROMETHEUS_MCP_SERVER_NAME: Final = "prometheus"
PROMETHEUS_METRICS_TOOL_NAME: Final = "query_prometheus_metrics"
PROMETHEUS_ALERT_WINDOW_SECONDS: Final = 300
PROMETHEUS_MCP_PROMPT_VERSION: Final = "prometheus-sse-mcp-agent-v9"
PROMETHEUS_MCP_EVIDENCE_SCHEMA_VERSION: Final = "prometheus-evidence-v2"
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
    """The SSE endpoint or its deployment settings are invalid."""


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
            {"raw_call_result": deepcopy(raw_call_result)}
            if raw_call_result is not None
            else {}
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
        return has_monitoring_observation(
            decoded, observation_context=observation_context
        )
    if isinstance(value, list):
        return any(
            has_monitoring_observation(
                item,
                observation_context=(
                    observation_context and not isinstance(item, dict)
                ),
            )
            for item in value
        )
    if not isinstance(value, dict):
        return False

    for key, nested in value.items():
        normalized_key = re.sub(r"[^a-z0-9]", "", str(key).casefold())
        nested_context = normalized_key in _OBSERVATION_KEYS
        if has_monitoring_observation(
            nested, observation_context=nested_context
        ):
            return True
    return False


def load_prometheus_mcp_server_settings(
    path: Path, *, environment: Mapping[str, str]
) -> PrometheusMCPServerSettings:
    """Resolve one SSE server configuration without persisting its secrets."""

    try:
        descriptor = load_mcp_catalog(path).require(PROMETHEUS_MCP_SERVER_NAME)
        connection = descriptor.resolve_connection(environment)
    except MCPCatalogConfigurationError as exc:
        raise PrometheusMCPConfigurationError(str(exc)) from exc
    return PrometheusMCPServerSettings(
        url=connection.url,
        headers=dict(connection.headers),
        prompts=descriptor.prompts,
    )


class PrometheusMCPClient:
    """Public Prometheus Provider facade backed exclusively by the shared Harness."""

    def __init__(
        self,
        server: PrometheusMCPServerSettings,
        model: MCPToolCallingModel,
        *,
        timeout_seconds: float = 60,
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
                "Prometheus MCP SSE URL must be an absolute HTTP(S) endpoint without "
                "embedded credentials, query, or fragment"
            )
        if not timeout_seconds > 0:
            raise PrometheusMCPConfigurationError("Prometheus MCP timeout must be positive")
        if sse_read_timeout_seconds is not None and not sse_read_timeout_seconds > 0:
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP SSE read timeout must be positive"
            )
        self.mcp_url = server.url.strip()
        self._headers = dict(server.headers)
        self.model = model
        self.prompts = server.prompts
        self.timeout_seconds = timeout_seconds
        self.sse_read_timeout_seconds = (
            sse_read_timeout_seconds
            if sse_read_timeout_seconds is not None
            else timeout_seconds
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
        sse_read_timeout_seconds: float | None = None,
        harness_runtime_dependencies: Any | None = None,
    ) -> PrometheusMCPClient:
        return cls(
            load_prometheus_mcp_server_settings(
                settings_path, environment=environment
            ),
            model,
            timeout_seconds=timeout_seconds,
            sse_read_timeout_seconds=sse_read_timeout_seconds,
            harness_runtime_dependencies=harness_runtime_dependencies,
        )

    async def collect_alert_window(
        self, context: InvestigationContext
    ) -> PrometheusMCPQueryResult:
        from app.adapters.prometheus_harness import collect_prometheus_with_harness

        return await collect_prometheus_with_harness(self, context)

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
        """Build a bounded deterministic fact projection for the next model turn."""

        del alert
        series = cls._numeric_series(payload)
        summaries: list[dict[str, Any]] = []
        for metric, samples in series:
            values = [value for _, value in samples]
            summaries.append(
                {
                    "metric": metric,
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
        kind_counts = cls._value_kind_counts(payload)
        facts = cls._scalar_fact_fragments(payload)
        return {
            "has_numeric_samples": bool(series),
            "series_count": len(series),
            "sample_count": sum(len(samples) for _, samples in series),
            "series": summaries[:20],
            "omitted_series_count": max(len(summaries) - 20, 0),
            "scalar_facts": facts[:40],
            "omitted_scalar_fact_count": max(len(facts) - 40, 0),
            "payload_shape": dict(sorted(kind_counts.items())),
        }

    @classmethod
    def _numeric_series(
        cls,
        value: Any,
    ) -> list[tuple[dict[str, Any], list[tuple[Any, float]]]]:
        found: list[tuple[dict[str, Any], list[tuple[Any, float]]]] = []
        if isinstance(value, Mapping):
            metric = value.get("metric")
            metric = cls._project_metric_labels(metric)
            samples = cls._numeric_samples(value)
            if samples:
                found.append((metric, samples))
            for nested in value.values():
                if isinstance(nested, (Mapping, list)):
                    found.extend(cls._numeric_series(nested))
        elif isinstance(value, list):
            for nested in value:
                if isinstance(nested, (Mapping, list)):
                    found.extend(cls._numeric_series(nested))
        return found

    @classmethod
    def _project_metric_labels(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            return {}
        labels: dict[str, Any] = {}
        for raw_key, raw_value in sorted(value.items(), key=lambda item: str(item[0])):
            if isinstance(raw_value, (str, int, float, bool)) or raw_value is None:
                labels[str(raw_key)] = cls._bounded_scalar(raw_value)
        return labels

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
    def _numeric_samples(cls, value: Mapping[str, Any]) -> list[tuple[Any, float]]:
        raw_samples = value.get("values")
        if not isinstance(raw_samples, list):
            raw_sample = value.get("value")
            raw_samples = [raw_sample] if isinstance(raw_sample, list) else []
        samples: list[tuple[Any, float]] = []
        for item in raw_samples:
            if not isinstance(item, list) or len(item) < 2:
                continue
            number = cls._finite_number(item[1])
            if number is not None:
                samples.append((item[0], number))
        return samples

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
            response.get("has_monitoring_observation") is True
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
            "metric_candidates": PrometheusMCPClient.alert_metric_candidates(alert),
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
            raw = (
                tool.model_dump(mode="json") if hasattr(tool, "model_dump") else tool
            )
            if not isinstance(raw, dict):
                raise PrometheusMCPProtocolError(
                    "Prometheus MCP tool schema is not an object"
                )
            name = raw.get("name")
            schema = (
                raw.get("inputSchema")
                or raw.get("input_schema")
                or {"type": "object"}
            )
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(schema, dict)
            ):
                raise PrometheusMCPProtocolError(
                    "Prometheus MCP returned an invalid tool schema"
                )
            converted[name] = {
                "type": "function",
                "function": {
                    "name": name,
                    "description": str(
                        raw.get("description") or f"Prometheus MCP tool {name}"
                    ),
                    "parameters": deepcopy(schema),
                },
            }
        if not converted:
            raise PrometheusMCPProtocolError(
                "Prometheus MCP exposed no valid tools"
            )
        return [converted[name] for name in sorted(converted)]

    def host_investigation_state_message(
        self,
        *,
        remote_calls_used: int,
        monitoring_scope_status: str = "not_checked",
        monitoring_scope_reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "role": "user",
            "content": json.dumps(
                {
                    "host_event": "prometheus_investigation_state",
                    "remote_calls_used": remote_calls_used,
                    "monitoring_scope_status": monitoring_scope_status,
                    "monitoring_scope_reason": monitoring_scope_reason,
                    "instruction": (
                        "先用远端工具确认 Prometheus 配置的数据库监控范围；若告警数据库"
                        "在范围内，再查询 required_window 内对应监控指标。根据工具描述和 "
                        "Schema 自主选择下一步，调用参数由你完整提供且 Host 原样转发。"
                        "完成后调用结束工具声明 monitoring_scope_status 和依据。"
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
                    "结束 Prometheus MCP 调查并记录监控范围结论。in_scope 表示告警数据库"
                    "在配置范围内；out_of_scope 表示未配置对应监控；证据不足时用 unknown。"
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
        """Decode one result while retaining its complete sanitized MCP envelope."""

        raw = PrometheusMCPClient.raw_call_result(raw_result)
        payload = PrometheusMCPClient._result_payload_from_raw(raw)
        return PrometheusMCPCallResult(
            payload=payload,
            raw_call_result=raw,
        )

    @staticmethod
    def raw_call_result(raw_result: Any) -> dict[str, Any]:
        """Return the complete sanitized ``CallToolResult.model_dump`` payload."""

        raw = (
            raw_result.model_dump(mode="json", by_alias=True)
            if hasattr(raw_result, "model_dump")
            else raw_result
        )
        if not isinstance(raw, dict):
            raise PrometheusMCPProtocolError(
                "Prometheus MCP tool result is not an object"
            )
        complete = sanitize(raw)
        if not isinstance(complete, dict):
            raise PrometheusMCPProtocolError(
                "Prometheus MCP tool result could not be sanitized as an object"
            )
        return complete

    @staticmethod
    def _result_payload_from_raw(raw: dict[str, Any]) -> Any | None:
        if raw.get("isError") is True:
            raise PrometheusMCPToolError(
                PrometheusMCPClient._tool_error_detail(raw)
                or "Prometheus MCP tool reported an execution error"
            )
        structured = raw.get("structuredContent")
        if structured not in (None, "", [], {}):
            return sanitize(structured)
        content = raw.get("content")
        if content in (None, "", [], {}):
            return None
        payload = sanitize(content)
        return PrometheusMCPClient._normalize_content_payload(payload)

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
        result_content: dict[str, Any] = {
            "monitoring_result": payload if payload is not None else "no usable data"
        }
        if host_control is not None:
            result_content["host_control"] = sanitize(dict(host_control))
        content = json.dumps(
            result_content,
            ensure_ascii=False,
            default=str,
        )
        return mcp_tool_result_messages(
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

    def agent_messages(
        self,
        context: InvestigationContext,
        window_start: datetime,
        window_end: datetime,
    ) -> list[dict[str, Any]]:
        return [
            {
                "role": "system",
                "content": self.prompts.execution_instructions,
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "prompt_version": PROMETHEUS_MCP_PROMPT_VERSION,
                        "alert": preprocess_alert_data(
                            context.alert.model_dump(
                                mode="json", exclude={"raw_payload"}
                            )
                        ),
                        "required_window": {
                            "start": window_start.isoformat(),
                            "end": window_end.isoformat(),
                            "duration_seconds": PROMETHEUS_ALERT_WINDOW_SECONDS,
                        },
                        "required_target": self.monitoring_target_context(context.alert),
                        "agent_contract": {
                            "read_only": True,
                            "one_tool_per_turn": True,
                            "arguments_forwarded_unchanged": True,
                            "finish_tool": _FINISH_TOOL_NAME,
                        },
                    },
                    ensure_ascii=False,
                ),
            },
        ]


class PrometheusMCPEvidenceTool:
    """Expose the complete Prometheus MCP investigation as one evidence tool."""

    name = PROMETHEUS_METRICS_TOOL_NAME
    source_system = "prometheus_mcp"
    read_only = True
    input_schema = {
        "type": "object",
        "properties": {},
        "additionalProperties": True,
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

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> ToolExecutionResult:
        del request
        result = await self.client.collect_alert_window(context)
        required_target = PrometheusMCPClient.monitoring_target_context(context.alert)
        structured_data = {
            "schema_version": PROMETHEUS_MCP_EVIDENCE_SCHEMA_VERSION,
            "window_start": result.window_start.isoformat(),
            "window_end": result.window_end.isoformat(),
            "window_seconds": PROMETHEUS_ALERT_WINDOW_SECONDS,
            "mcp_invocation": "shared_agent_harness",
            "allow_followup_dispatch": False,
            "model_tool_calls": list(result.model_tool_calls),
            "model_request_ids": list(result.model_request_ids),
            "tool_attempts": list(result.tool_attempts),
            "finished_by_model": result.finished_by_model,
            "termination_reason": result.termination_reason,
            "partial": result.partial,
            "termination_error_type": result.termination_error_type,
            "termination_error_detail": result.termination_error_detail,
            "mcp_session_attempts": result.mcp_session_attempts,
            "reconnect_error_type": result.reconnect_error_type,
            "inconclusive_reason": result.inconclusive_reason,
            "required_target": required_target,
            "monitoring_scope_status": result.monitoring_scope_status,
            "monitoring_scope_reason": result.monitoring_scope_reason,
            "monitored_database_engines": list(result.monitored_database_engines),
            "monitoring_target_identifiers": list(result.monitoring_target_identifiers),
            "monitoring_result_count": len(result.responses),
            "monitoring_results": list(result.responses),
            "query_completed": result.has_monitoring_data,
            "root_cause_eligible": result.has_monitoring_data and not result.partial,
        }
        if result.partial:
            structured_data["root_cause_ineligible_reason"] = "partial_evidence"
        if result.monitoring_scope_status == "out_of_scope":
            structured_data["reason_code"] = "database_not_monitored"
            structured_data["root_cause_eligible"] = False
            structured_data["root_cause_ineligible_reason"] = "database_not_monitored"
            structured_data = self._with_missing_evidence_inventory(
                structured_data, result
            )
            return ToolExecutionResult(
                status=ToolStatus.SKIPPED,
                summary=(
                    "Prometheus MCP 已完成监控范围发现："
                    f"{result.monitoring_scope_reason or '告警数据库不在当前监控范围内'}"
                    "已跳过后续指标查询。"
                ),
                structured_data=structured_data,
            )
        if result.has_monitoring_data:
            if result.partial:
                suffix = "；后续调查未完整结束，已保留此前取得的可用监控返回"
            else:
                suffix = ""
            coverage_prefix = (
                "Prometheus MCP 已确认告警数据库在监控范围内，并"
                if result.monitoring_scope_status == "in_scope"
                else "Prometheus MCP "
            )
            return ToolExecutionResult(
                status=ToolStatus.SUCCESS,
                summary=(
                    f"{coverage_prefix}已取得告警发生前五分钟的实时监控证据"
                    f"（{len(result.responses)} 条工具返回）{suffix}。"
                ),
                structured_data=structured_data,
            )
        if result.monitoring_scope_status == "unknown":
            reason = (
                "Prometheus MCP 无法确认告警数据库是否在当前监控范围内，"
                "未继续执行指标查询："
                f"{result.monitoring_scope_reason or '目标发现结果不足'}"
            )
        elif result.termination_reason == "no_discriminating_evidence":
            reason = (
                "Prometheus MCP 已停止无效探测，未取得完整的告警信号事实："
                f"{result.inconclusive_reason or '没有可归属的告警窗口监控样本'}"
            )
        else:
            reason = "Prometheus MCP 未返回可用监控结果，实时证据不足。"
        structured_data["root_cause_eligible"] = False
        structured_data["root_cause_ineligible_reason"] = (
            "monitoring_scope_unknown"
            if result.monitoring_scope_status == "unknown"
            else (
                "no_discriminating_evidence"
                if result.termination_reason == "no_discriminating_evidence"
                else "no_usable_monitoring_result"
            )
        )
        structured_data = self._with_missing_evidence_inventory(structured_data, result)
        return ToolExecutionResult(
            status=ToolStatus.NO_DATA,
            summary=reason,
            structured_data=structured_data,
        )

    def _with_missing_evidence_inventory(
        self,
        structured_data: dict[str, Any],
        result: PrometheusMCPQueryResult,
    ) -> dict[str, Any]:
        """Add derived inventory without dropping any MCP result or trace field."""

        inventory_seen, metric_names = PrometheusMCPClient.catalog_metric_inventory(
            list(result.responses)
        )
        complete = deepcopy(structured_data)
        complete.update(
            {
                "model_tool_call_count": len(result.model_tool_calls),
                "catalog_inventory": {
                    "observed": inventory_seen,
                    "metric_count": len(metric_names),
                    "metrics": metric_names,
                },
            }
        )
        return sanitize(complete)
