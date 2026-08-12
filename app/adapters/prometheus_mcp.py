"""Policy and facade for Harness-owned Prometheus MCP evidence collection.

The model plans queries from the subset of discovered tools authorized by local
deployment policy. The Host binds trusted range-query windows, enforces a finite
budget, and preserves usable partial evidence after a later failure.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
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
from app.domain.tool_calling import MCPModelToolCall, MCPToolCallingModel
from app.mcp_catalog import (
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    load_mcp_catalog,
)

PROMETHEUS_MCP_SERVER_NAME: Final = "prometheus"
PROMETHEUS_METRICS_TOOL_NAME: Final = "query_prometheus_metrics"
PROMETHEUS_MCP_DEFAULT_MAX_AGENT_STEPS: Final = 8
PROMETHEUS_MCP_DECISION_LIMIT_MULTIPLIER: Final = 2
PROMETHEUS_MCP_MIN_RANGE_CALL_RESERVE: Final = 2
PROMETHEUS_MCP_MAX_CATALOG_CALLS: Final = 2
PROMETHEUS_MCP_MAX_EMPTY_RANGE_CALLS: Final = 3
PROMETHEUS_MCP_MAX_TARGET_MISMATCH_CALLS: Final = 2
PROMETHEUS_ALERT_WINDOW_SECONDS: Final = 300
PROMETHEUS_MCP_PROMPT_VERSION: Final = "prometheus-sse-mcp-agent-v9"
PROMETHEUS_MCP_EVIDENCE_SCHEMA_VERSION: Final = "prometheus-evidence-v2"
_ENV_REFERENCE: Final = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
_FINISH_TOOL_NAME: Final = "finish_prometheus_investigation"
_SCOPE_AUDIT_ARGUMENT_NAMES: Final = (
    "monitoring_scope_reason",
    "monitored_database_engines",
    "monitoring_target_identifiers",
)
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
_FAILURE_STATUSES: Final = {
    "error",
    "failed",
    "failure",
    "forbidden",
    "rejected",
    "unauthorized",
}
_SAMPLE_CONTAINER_KEYS: Final = {
    "datapoint",
    "datapoints",
    "sample",
    "samples",
    "value",
    "values",
}
_PROMETHEUS_METRIC_IDENTIFIER: Final = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")
_ALERT_THRESHOLD_SUFFIX: Final = re.compile(
    r"(?i)_(?:more|less|greater|higher|lower)_than_\d+(?:\.\d+)?%?$"
)
_MONITORING_IDENTITY_CONTAINERS: Final = {
    "labels",
    "labelset",
    "metric",
    "tags",
}
_MONITORING_IDENTITY_KEYS: Final = {
    "__name__",
    "address",
    "addr",
    "cluster",
    "clusterid",
    "clustername",
    "dbengine",
    "dbtype",
    "endpoint",
    "engine",
    "host",
    "hostname",
    "instance",
    "ip",
    "job",
    "server",
    "target",
}
_ENGINE_FAMILY_MARKERS: Final = {
    "oceanbase": ("oceanbase", "obcluster", "obproxy"),
    "tidb": ("tidb", "tikv", "tiflash"),
    "postgresql": ("postgres", "postgresql"),
    "mysql": ("mysql", "mysqld"),
}
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
    """The model failed twice to select a valid MCP tool call."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic_data = diagnostic_data or {}


class PrometheusMCPReadOnlyViolation(PrometheusMCPError):
    """A caller attempted to override Host-owned Prometheus query inputs."""


@dataclass(frozen=True, slots=True)
class PrometheusMCPToolPolicy:
    """Deployment-owned authorization and execution contract for one MCP tool."""

    name: str
    capability: Literal["target_discovery", "catalog", "range_query"]
    start_argument_path: tuple[str, ...] = ()
    end_argument_path: tuple[str, ...] = ()
    timestamp_encoding: Literal["rfc3339", "unix_seconds", "unix_millis"] | None = None
    fixed_arguments: dict[str, Any] | None = None
    schema_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class PrometheusMCPServerSettings:
    url: str
    headers: dict[str, str]
    prompts: MCPPromptBundle
    tool_policies: tuple[PrometheusMCPToolPolicy, ...] = ()


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
    call_limit_reached: bool
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
    raw_call_results: tuple[dict[str, Any], ...] = ()

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
        tool_policies=_parse_tool_policies(
            descriptor.provider_options.get("toolPolicies", {})
        ),
    )


def _parse_argument_path(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        parts = (value.strip(),)
    elif isinstance(value, list):
        parts = tuple(item.strip() for item in value if isinstance(item, str))
        if len(parts) != len(value):
            parts = ()
    else:
        parts = ()
    if not parts or any(not part for part in parts):
        raise PrometheusMCPConfigurationError(
            f"Prometheus MCP {field_name} must be a non-empty string or string array"
        )
    return parts


def _parse_tool_policies(raw: Any) -> tuple[PrometheusMCPToolPolicy, ...]:
    if not isinstance(raw, dict):
        raise PrometheusMCPConfigurationError(
            "Prometheus MCP toolPolicies must be an object"
        )
    policies: list[PrometheusMCPToolPolicy] = []
    for name, value in raw.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(value, dict):
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP toolPolicies entries must map tool names to objects"
            )
        capability = value.get("capability")
        if capability not in {"target_discovery", "catalog", "range_query"}:
            raise PrometheusMCPConfigurationError(
                f"Prometheus MCP policy {name!r} has an unsupported capability"
            )
        fixed_arguments = value.get("fixedArguments", {})
        if not isinstance(fixed_arguments, dict):
            raise PrometheusMCPConfigurationError(
                f"Prometheus MCP policy {name!r} fixedArguments must be an object"
            )
        schema_fingerprint = value.get("schemaSha256")
        if schema_fingerprint is not None and (
            not isinstance(schema_fingerprint, str)
            or re.fullmatch(r"[a-fA-F0-9]{64}", schema_fingerprint.strip()) is None
        ):
            raise PrometheusMCPConfigurationError(
                f"Prometheus MCP policy {name!r} schemaSha256 must be 64 hex characters"
            )
        if capability == "range_query":
            start_path = _parse_argument_path(
                value.get("startArgument"), field_name=f"policy {name!r} startArgument"
            )
            end_path = _parse_argument_path(
                value.get("endArgument"), field_name=f"policy {name!r} endArgument"
            )
            encoding = value.get("timestampEncoding")
            if encoding not in {"rfc3339", "unix_seconds", "unix_millis"}:
                raise PrometheusMCPConfigurationError(
                    f"Prometheus MCP policy {name!r} has an unsupported timestampEncoding"
                )
            if start_path[:-1] != end_path[:-1] or start_path == end_path:
                raise PrometheusMCPConfigurationError(
                    f"Prometheus MCP policy {name!r} window arguments must be distinct "
                    "siblings in the same object"
                )
        else:
            start_path = ()
            end_path = ()
            encoding = None
        policies.append(
            PrometheusMCPToolPolicy(
                name=name.strip(),
                capability=capability,
                start_argument_path=start_path,
                end_argument_path=end_path,
                timestamp_encoding=encoding,
                fixed_arguments=deepcopy(fixed_arguments),
                schema_sha256=(
                    schema_fingerprint.strip().casefold()
                    if isinstance(schema_fingerprint, str)
                    else None
                ),
            )
        )
    return tuple(policies)


class PrometheusMCPClient:
    """Public Prometheus Provider facade backed exclusively by the shared Harness."""

    def __init__(
        self,
        server: PrometheusMCPServerSettings,
        model: MCPToolCallingModel,
        *,
        max_agent_steps: int = PROMETHEUS_MCP_DEFAULT_MAX_AGENT_STEPS,
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
        if (
            isinstance(max_agent_steps, bool)
            or not isinstance(max_agent_steps, int)
            or not 1 <= max_agent_steps <= 100
        ):
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP max agent steps must be between 1 and 100"
            )
        if not timeout_seconds > 0:
            raise PrometheusMCPConfigurationError("Prometheus MCP timeout must be positive")
        if sse_read_timeout_seconds is not None and not sse_read_timeout_seconds > 0:
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP SSE read timeout must be positive"
            )
        self.mcp_url = server.url.strip()
        self._headers = dict(server.headers)
        self._tool_policies = {policy.name: policy for policy in server.tool_policies}
        if len(self._tool_policies) != len(server.tool_policies):
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP toolPolicies contain duplicate tool names"
            )
        if not self._tool_policies:
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP requires at least one locally authorized toolPolicy"
            )
        self.model = model
        self.prompts = server.prompts
        self.max_agent_steps = max_agent_steps
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
        max_agent_steps: int = PROMETHEUS_MCP_DEFAULT_MAX_AGENT_STEPS,
        timeout_seconds: float = 60,
        sse_read_timeout_seconds: float | None = None,
        harness_runtime_dependencies: Any | None = None,
    ) -> PrometheusMCPClient:
        return cls(
            load_prometheus_mcp_server_settings(
                settings_path, environment=environment
            ),
            model,
            max_agent_steps=max_agent_steps,
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
        authorized_policies: Mapping[str, PrometheusMCPToolPolicy],
        calls: list[MCPModelToolCall],
        responses: list[dict[str, Any]],
        alert: NormalizedAlert | None = None,
        monitoring_scope_status: str = "not_checked",
    ) -> list[dict[str, Any]]:
        """Stage semantic scope discovery before alert-window evidence collection."""

        target_discovery_names = {
            name
            for name, policy in authorized_policies.items()
            if policy.capability == "target_discovery"
        }
        if target_discovery_names and monitoring_scope_status == "not_checked":
            return [
                tool
                for tool in model_tool_list
                if tool.get("function", {}).get("name") in target_discovery_names
            ]
        if target_discovery_names and monitoring_scope_status == "investigating":
            remaining = max(self.max_agent_steps - len(calls), 0)
            catalog_calls = sum(
                1
                for call in calls
                if (
                    policy := authorized_policies.get(call.name)
                ) is not None
                and policy.capability == "catalog"
            )
            allow_scope_discovery = (
                catalog_calls < self.catalog_call_limit()
                and remaining > PROMETHEUS_MCP_MIN_RANGE_CALL_RESERVE
            )
            selected: list[dict[str, Any]] = []
            for tool in model_tool_list:
                policy = authorized_policies.get(
                    str(tool.get("function", {}).get("name") or "")
                )
                if policy is None:
                    continue
                if (
                    allow_scope_discovery
                    and policy.capability in {"target_discovery", "catalog"}
                ):
                    selected.append(tool)
                elif policy.capability == "range_query":
                    selected.append(self._scope_aware_range_tool(tool))
            selected.append(self._scope_finish_tool())
            return selected
        if target_discovery_names and monitoring_scope_status != "in_scope":
            return []
        if target_discovery_names:
            model_tool_list = [
                tool
                for tool in model_tool_list
                if tool.get("function", {}).get("name") not in target_discovery_names
            ]

        has_monitoring_data = self.responses_have_monitoring_data(responses)
        range_names = {
            name
            for name, policy in authorized_policies.items()
            if policy.capability == "range_query"
        }
        remaining = max(self.max_agent_steps - len(calls), 0)
        range_call_reserve = min(
            PROMETHEUS_MCP_MIN_RANGE_CALL_RESERVE,
            self.max_agent_steps,
        )
        catalog_call_limit = self.catalog_call_limit()
        catalog_calls = sum(
            1
            for call in calls
            if (
                policy := authorized_policies.get(call.name)
            ) is not None
            and policy.capability == "catalog"
        )
        evidence_calls = [
            call
            for call in calls
            if (
                policy := authorized_policies.get(call.name)
            ) is not None
            and policy.capability != "target_discovery"
        ]
        direct_range_first = (
            not evidence_calls
            and alert is not None
            and bool(self.alert_metric_candidates(alert))
        )
        require_range = (
            bool(range_names)
            and not has_monitoring_data
            and (
                direct_range_first
                or catalog_calls >= catalog_call_limit
                or remaining <= range_call_reserve
            )
        )
        selected = [
            tool
            for tool in model_tool_list
            if not require_range or tool.get("function", {}).get("name") in range_names
        ]
        if has_monitoring_data:
            selected.append(self._finish_tool())
        return selected

    def catalog_call_limit(self) -> int:
        range_call_reserve = min(
            PROMETHEUS_MCP_MIN_RANGE_CALL_RESERVE,
            self.max_agent_steps,
        )
        return min(
            PROMETHEUS_MCP_MAX_CATALOG_CALLS,
            max(self.max_agent_steps - range_call_reserve, 0),
        )

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
            "remote_call_limit": self.max_agent_steps,
            "remote_calls_remaining": max(self.max_agent_steps - remote_calls_used, 0),
            "instruction": instruction,
        }
        if capability is not None:
            feedback["capability"] = capability
        return feedback

    @staticmethod
    def responses_have_monitoring_data(responses: list[dict[str, Any]]) -> bool:
        return any(
            response.get("has_monitoring_observation") is True
            and response.get("window_verification") == "exact"
            and response.get("target_verification") != "mismatch"
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
            "endpoint": (
                f"{database.host}:{database.port}"
                if database and database.host and database.port
                else None
            ),
            "cluster": alert.cluster,
            "instance_candidates": list(dict.fromkeys(candidates)),
            "metric_candidates": PrometheusMCPClient.alert_metric_candidates(alert),
        }

    @classmethod
    def target_verification(
        cls,
        alert: NormalizedAlert,
        payload: Any,
    ) -> tuple[str, list[str]]:
        """Reject explicit cross-engine series without guessing target ownership."""

        expected_engine = cls._engine_family(
            alert.database.engine if alert.database else None
        )
        identity_values = cls._monitoring_identity_values(payload)
        returned_families = {
            family
            for value in identity_values
            if (family := cls._engine_family(value)) is not None
        }
        if expected_engine == "mysql":
            conflicts = returned_families.intersection(
                {"oceanbase", "postgresql", "tidb"}
            )
        elif expected_engine == "oceanbase":
            conflicts = returned_families.intersection({"postgresql", "tidb"})
        elif expected_engine is not None:
            conflicts = returned_families - {expected_engine}
        else:
            conflicts = set()
        if conflicts:
            returned = "、".join(sorted(conflicts))
            return (
                "mismatch",
                [f"监控序列标识为 {returned}，与告警引擎 {expected_engine} 不一致"],
            )
        if expected_engine is not None and expected_engine in returned_families:
            return "compatible", []
        return "unknown", []

    @staticmethod
    def _engine_family(value: str | None) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.strip().casefold()
        compact = re.sub(r"[^a-z0-9_]+", "", normalized)
        if (
            compact.startswith("ob_")
            or compact.startswith(("obagent", "obmonitor"))
            or re.search(r"(?:^|[^a-z0-9])ob(?:[^a-z0-9]|$)", normalized)
        ):
            return "oceanbase"
        if compact.startswith("pg_"):
            return "postgresql"
        for family, markers in _ENGINE_FAMILY_MARKERS.items():
            if any(marker in compact for marker in markers):
                return family
        return None

    @classmethod
    def _monitoring_identity_values(
        cls,
        value: Any,
        *,
        identity_context: bool = False,
    ) -> list[str]:
        if isinstance(value, Mapping):
            identities: list[str] = []
            for raw_key, nested in value.items():
                key = re.sub(r"[^a-z0-9_]+", "", str(raw_key).casefold())
                nested_context = identity_context or key in _MONITORING_IDENTITY_CONTAINERS
                if isinstance(nested, (str, int, float)) and not isinstance(nested, bool):
                    if nested_context or key in _MONITORING_IDENTITY_KEYS:
                        identities.extend((str(raw_key), str(nested)))
                    continue
                identities.extend(
                    cls._monitoring_identity_values(
                        nested,
                        identity_context=nested_context,
                    )
                )
            return identities
        if isinstance(value, list):
            return [
                identity
                for nested in value
                for identity in cls._monitoring_identity_values(
                    nested,
                    identity_context=identity_context,
                )
            ]
        if isinstance(value, str):
            decoded = cls._decode_json_text(value)
            if decoded is not None:
                return cls._monitoring_identity_values(
                    decoded,
                    identity_context=identity_context,
                )
        return []

    @classmethod
    def window_verification(
        cls,
        *,
        policy: PrometheusMCPToolPolicy,
        payload: Any,
        window_start: datetime,
        window_end: datetime,
    ) -> str:
        if policy.capability != "range_query":
            return "unknown"
        sample_result = cls._sample_window_verification(
            payload,
            window_start=window_start,
            window_end=window_end,
        )
        if sample_result == "mismatch":
            return "mismatch"
        # A deployment-owned range policy defines the server-side time semantics,
        # and effective_arguments always binds both endpoints before the call.
        # Returned timestamps can contradict that contract but cannot establish it.
        return "exact"

    @staticmethod
    def effective_arguments(
        arguments: Mapping[str, Any],
        *,
        policy: PrometheusMCPToolPolicy,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        effective = deepcopy(dict(arguments))
        for key, value in (policy.fixed_arguments or {}).items():
            effective[key] = deepcopy(value)
        if policy.capability != "range_query":
            return effective
        assert policy.timestamp_encoding is not None
        start_value = PrometheusMCPClient._encode_timestamp(
            window_start, policy.timestamp_encoding
        )
        end_value = PrometheusMCPClient._encode_timestamp(
            window_end, policy.timestamp_encoding
        )
        PrometheusMCPClient._set_argument_path(
            effective, policy.start_argument_path, start_value
        )
        PrometheusMCPClient._set_argument_path(
            effective, policy.end_argument_path, end_value
        )
        return effective

    @staticmethod
    def _set_argument_path(
        arguments: dict[str, Any], path: tuple[str, ...], value: Any
    ) -> None:
        current = arguments
        for part in path[:-1]:
            nested = current.get(part)
            if not isinstance(nested, dict):
                nested = {}
                current[part] = nested
            current = nested
        current[path[-1]] = value

    @staticmethod
    def _encode_timestamp(
        value: datetime,
        encoding: Literal["rfc3339", "unix_seconds", "unix_millis"],
    ) -> str | int:
        normalized = value.astimezone(UTC)
        if encoding == "rfc3339":
            return normalized.isoformat()
        if encoding == "unix_millis":
            return int(normalized.timestamp() * 1000)
        return int(normalized.timestamp())

    @classmethod
    def _sample_window_verification(
        cls,
        payload: Any,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> str:
        timestamps = cls._sample_timestamps(payload)
        if not timestamps:
            return "unknown"
        start = window_start.astimezone(UTC)
        end = window_end.astimezone(UTC)
        return "exact" if all(start <= item <= end for item in timestamps) else "mismatch"

    @classmethod
    def _sample_timestamps(
        cls,
        value: Any,
        *,
        sample_context: bool = False,
    ) -> list[datetime]:
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                return []
            if isinstance(decoded, (dict, list)):
                return cls._sample_timestamps(
                    decoded,
                    sample_context=sample_context,
                )
            return []
        if isinstance(value, Mapping):
            timestamps: list[datetime] = []
            for raw_key, nested in value.items():
                key = re.sub(r"[^a-z0-9]", "", str(raw_key).casefold())
                timestamps.extend(
                    cls._sample_timestamps(
                        nested,
                        sample_context=key in _SAMPLE_CONTAINER_KEYS,
                    )
                )
            return timestamps
        if not isinstance(value, list):
            return []
        if sample_context and len(value) >= 2:
            timestamp = cls._coerce_timestamp(value[0], require_plausible_epoch=True)
            if timestamp is not None:
                return [timestamp]
        timestamps: list[datetime] = []
        for item in value:
            timestamps.extend(
                cls._sample_timestamps(item, sample_context=sample_context)
            )
        return timestamps

    @staticmethod
    def _coerce_timestamp(
        value: Any,
        *,
        require_plausible_epoch: bool = False,
    ) -> datetime | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            timestamp = float(value)
        elif isinstance(value, str):
            candidate = value.strip()
            try:
                timestamp = float(candidate)
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
        if abs(timestamp) >= 10_000_000_000:
            timestamp /= 1000
        if require_plausible_epoch and timestamp < 946_684_800:
            return None
        try:
            return datetime.fromtimestamp(timestamp, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def first_exception_leaf(error: BaseException) -> BaseException:
        while isinstance(error, BaseExceptionGroup) and error.exceptions:
            error = error.exceptions[0]
        return error

    def authorized_model_tools(
        self, tools: list[Any]
    ) -> tuple[list[dict[str, Any]], dict[str, PrometheusMCPToolPolicy]]:
        converted: list[dict[str, Any]] = []
        authorized: dict[str, PrometheusMCPToolPolicy] = {}
        names: set[str] = set()
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
                or name in names
            ):
                raise PrometheusMCPProtocolError(
                    "Prometheus MCP returned an invalid tool schema"
                )
            names.add(name)
            policy = self._tool_policies.get(name)
            if policy is None:
                continue
            annotations = raw.get("annotations")
            if (
                not isinstance(annotations, dict)
                or annotations.get("readOnlyHint") is not True
                or annotations.get("destructiveHint") is True
            ):
                raise PrometheusMCPConfigurationError(
                    "Prometheus MCP toolPolicies require every matching tool to declare "
                    "annotations.readOnlyHint=true and not destructiveHint=true; "
                    f"no tool authorized because the read-only contract failed for: {name}"
                )
            self._validate_policy_schema(policy, schema)
            authorized[name] = policy
            converted.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": self._policy_aware_tool_description(
                            policy,
                            str(
                                raw.get("description") or f"Prometheus MCP tool {name}"
                            ),
                        ),
                        "parameters": schema,
                    },
                }
            )
        if not converted:
            raise PrometheusMCPConfigurationError(
                "Prometheus MCP exposed no tool authorized by local toolPolicies"
            )
        return converted, authorized

    @staticmethod
    def _policy_aware_tool_description(
        policy: PrometheusMCPToolPolicy,
        remote_description: str,
    ) -> str:
        if policy.capability == "target_discovery":
            host_contract = (
                "Host policy capability=target_discovery. This tool must be called before "
                "catalog or range_query tools to discover which database targets are monitored. "
                "Its result is semantic scope evidence for the Agent, not root-cause evidence; "
                "a filtered empty page alone must not be treated as a global empty inventory."
            )
        elif policy.capability == "range_query":
            start_path = ".".join(policy.start_argument_path)
            end_path = ".".join(policy.end_argument_path)
            host_contract = (
                "Host policy capability=range_query. This capability can produce "
                "root-cause-eligible alert-window samples. The Host overwrites "
                f"{start_path!r} and {end_path!r} with required_window using "
                f"{policy.timestamp_encoding}; choose the metric, labels and PromQL, "
                "but do not use an instant/current-time query."
            )
        else:
            host_contract = (
                "Host policy capability=catalog. This tool is auxiliary semantic discovery "
                "for monitoring ownership, metrics, labels, and metadata; it is not root-cause "
                "evidence. Use it sparingly, then submit a scope conclusion or select a "
                "capability=range_query tool for alert-window samples."
            )
        return f"{host_contract} Remote description: {remote_description}"

    def host_investigation_state_message(
        self,
        *,
        authorized_policies: Mapping[str, PrometheusMCPToolPolicy],
        remote_calls_used: int,
        monitoring_scope_status: str = "not_checked",
        monitoring_scope_reason: str | None = None,
    ) -> dict[str, Any]:
        requires_target_discovery = any(
            policy.capability == "target_discovery"
            for policy in authorized_policies.values()
        )
        return {
            "role": "user",
            "content": json.dumps(
                {
                    "host_event": "prometheus_investigation_state",
                    "remote_calls_used": remote_calls_used,
                    "remote_call_limit": self.max_agent_steps,
                    "remote_calls_remaining": max(
                        self.max_agent_steps - remote_calls_used, 0
                    ),
                    "authorized_tool_capabilities": {
                        name: policy.capability
                        for name, policy in sorted(authorized_policies.items())
                    },
                    "monitoring_scope_status": monitoring_scope_status,
                    "monitoring_scope_reason": monitoring_scope_reason,
                    "host_window_binding": (
                        "range_query 的起止参数由 Host 覆盖为 required_window；"
                        "catalog 结果不能作为实时证据。"
                    ),
                    "instruction": (
                        (
                            "先调用 target_discovery。之后由 Agent 综合目标标签、服务发现 URL、"
                            "抓取路径、job、指标目录和元数据判断监控归属；需要时调用 catalog，"
                            "再通过首个 range_query 提交 in_scope 结论和依据，或通过 "
                            "finish_prometheus_investigation 提交 out_of_scope 或 unknown。"
                            "筛选后的空结果不能单独证明未监控，并至少为 range_query 保留两次"
                            "调用额度。"
                        )
                        if requires_target_discovery
                        else (
                            "只做必要的 catalog 发现，并至少为 range_query 保留两次调用"
                            "额度；优先选择与告警目标、信号和时间窗最相关的范围查询。"
                        )
                    ),
                },
                ensure_ascii=False,
            ),
        }

    @classmethod
    def _validate_policy_schema(
        cls,
        policy: PrometheusMCPToolPolicy,
        schema: Mapping[str, Any],
    ) -> None:
        canonical_schema = json.dumps(
            schema,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        actual_fingerprint = sha256(canonical_schema.encode("utf-8")).hexdigest()
        if policy.schema_sha256 is not None and actual_fingerprint != policy.schema_sha256:
            raise PrometheusMCPConfigurationError(
                f"Prometheus MCP schema fingerprint changed for authorized tool {policy.name!r}"
            )
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            properties = {}
        for key in (policy.fixed_arguments or {}):
            if key not in properties:
                raise PrometheusMCPConfigurationError(
                    f"Prometheus MCP fixed argument {key!r} is absent from the schema "
                    f"for {policy.name!r}"
                )
        if policy.capability != "range_query":
            return
        start_schema = cls._schema_at_path(schema, policy.start_argument_path)
        end_schema = cls._schema_at_path(schema, policy.end_argument_path)
        for field_schema, field_name in (
            (start_schema, "startArgument"),
            (end_schema, "endArgument"),
        ):
            raw_types = field_schema.get("type")
            schema_types = (
                {raw_types}
                if isinstance(raw_types, str)
                else set(raw_types) if isinstance(raw_types, list) else set()
            )
            expected_types = (
                {"string"}
                if policy.timestamp_encoding == "rfc3339"
                else {"integer", "number"}
            )
            if not schema_types.intersection(expected_types):
                raise PrometheusMCPConfigurationError(
                    f"Prometheus MCP {field_name} type is incompatible with "
                    f"{policy.timestamp_encoding} for {policy.name!r}"
                )

    @staticmethod
    def _schema_at_path(
        schema: Mapping[str, Any], path: tuple[str, ...]
    ) -> Mapping[str, Any]:
        current: Mapping[str, Any] = schema
        for part in path:
            properties = current.get("properties")
            nested = properties.get(part) if isinstance(properties, Mapping) else None
            if not isinstance(nested, Mapping):
                raise PrometheusMCPConfigurationError(
                    f"Prometheus MCP policy argument path {list(path)!r} is absent "
                    "from the discovered schema"
                )
            current = nested
        return current

    @staticmethod
    def _scope_aware_range_tool(tool: dict[str, Any]) -> dict[str, Any]:
        scoped = deepcopy(tool)
        function = scoped.get("function")
        if not isinstance(function, dict):
            return scoped
        parameters = function.get("parameters")
        if not isinstance(parameters, dict):
            return scoped
        raw_properties = parameters.get("properties")
        properties = (
            dict(raw_properties) if isinstance(raw_properties, Mapping) else {}
        )
        properties.update(
            {
                "monitoring_scope_reason": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1000,
                    "description": (
                        "基于已返回目标、服务发现、指标目录或元数据，说明为何告警数据库"
                        "属于当前 Prometheus 监控范围。"
                    ),
                },
                "monitored_database_engines": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 500},
                    "minItems": 1,
                    "maxItems": 20,
                    "description": "已从工具返回中识别出的数据库类型。",
                },
                "monitoring_target_identifiers": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 500},
                    "minItems": 1,
                    "maxItems": 100,
                    "description": "支持监控归属判断的有界目标、路径、job 或服务发现标识。",
                },
            }
        )
        parameters["properties"] = properties
        raw_required = parameters.get("required")
        required = list(raw_required) if isinstance(raw_required, list) else []
        parameters["required"] = list(
            dict.fromkeys([*required, *_SCOPE_AUDIT_ARGUMENT_NAMES])
        )
        function["description"] = (
            f"{str(function.get('description') or '')} "
            "选择此范围查询即声明告警数据库在监控范围内；同时提交多项返回证据形成的"
            "范围判断理由、数据库类型和目标标识。Host 只转发远端工具原有参数。"
        ).strip()
        return scoped

    @staticmethod
    def _scope_finish_tool() -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": _FINISH_TOOL_NAME,
                "description": (
                    "结束 Prometheus 监控范围判断。只有工具返回能支持排除结论时选择 "
                    "out_of_scope；筛选后的空结果、证据不足或冲突时选择 unknown。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "monitoring_scope_status": {
                            "type": "string",
                            "enum": ["out_of_scope", "unknown"],
                        },
                        "reason": {"type": "string", "minLength": 1},
                        "monitored_database_engines": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 20,
                        },
                        "monitoring_target_identifiers": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 100,
                        },
                    },
                    "required": ["monitoring_scope_status", "reason"],
                    "additionalProperties": False,
                },
            },
        }

    @staticmethod
    def _finish_tool() -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": _FINISH_TOOL_NAME,
                "description": "已取得足够的监控返回，结束 Prometheus MCP 调查。",
                "parameters": {
                    "type": "object",
                    "properties": {},
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
        try:
            payload = PrometheusMCPClient._result_payload_from_raw(raw)
        except PrometheusMCPToolError as exc:
            raise PrometheusMCPToolError(
                str(exc),
                raw_call_result=raw,
            ) from exc
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
            payload = sanitize(structured)
            PrometheusMCPClient._validate_business_result(payload)
            return payload
        content = raw.get("content")
        if content in (None, "", [], {}):
            return None
        payload = sanitize(content)
        PrometheusMCPClient._validate_content_business_results(payload)
        normalized = PrometheusMCPClient._normalize_content_payload(payload)
        PrometheusMCPClient._validate_business_result(normalized)
        return normalized

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
    def _validate_content_business_results(payload: Any) -> None:
        candidates: list[Any] = []
        if isinstance(payload, str):
            candidates.append(payload)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, str):
                    candidates.append(item)
                elif isinstance(item, dict) and isinstance(item.get("text"), str):
                    candidates.append(item["text"])
        elif isinstance(payload, dict):
            candidates.append(payload)

        for candidate in candidates:
            decoded = candidate
            if isinstance(candidate, str):
                decoded = PrometheusMCPClient._decode_json_text(candidate)
                if decoded is None:
                    continue
            PrometheusMCPClient._validate_business_result(decoded)

    @staticmethod
    def _validate_business_result(payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        status = payload.get("status")
        explicit_error = payload.get("error") or payload.get("errors")
        failed = (
            isinstance(status, str)
            and status.strip().casefold() in _FAILURE_STATUSES
        ) or payload.get("success") is False
        if not failed and explicit_error in (None, "", False, [], {}):
            return
        detail = (
            explicit_error
            or payload.get("message")
            or payload.get("detail")
            or status
            or "Prometheus MCP business error"
        )
        raise PrometheusMCPToolError(sanitize_text(str(detail))[:500])

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
        return [
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
        ]

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
                        "remote_call_budget": {
                            "used": 0,
                            "limit": self.max_agent_steps,
                            "remaining": self.max_agent_steps,
                        },
                        "host_contract": {
                            "read_only": True,
                            "one_tool_per_turn": True,
                            "requires_target_discovery": any(
                                policy.capability == "target_discovery"
                                for policy in self._tool_policies.values()
                            ),
                            "range_query_window_is_host_bound": True,
                            "range_query_target_is_host_verified": True,
                            "max_empty_range_calls": (
                                PROMETHEUS_MCP_MAX_EMPTY_RANGE_CALLS
                            ),
                            "max_target_mismatch_calls": (
                                PROMETHEUS_MCP_MAX_TARGET_MISMATCH_CALLS
                            ),
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
        "additionalProperties": False,
    }

    def __init__(self, client: PrometheusMCPClient) -> None:
        self.client = client
        # The second outer attempt resumes the same durable child checkpoint.
        self.max_attempts = 2

    async def execute(
        self, request: ToolExecutionRequest, context: InvestigationContext
    ) -> ToolExecutionResult:
        # The embedded Agent receives only the normalized alert. The Host binds
        # trusted range arguments before each remote call, so callers cannot
        # override its query scope through the outer tool contract.
        if request.parameters:
            raise PrometheusMCPReadOnlyViolation(
                "Prometheus evidence parameters are derived only from the alert context"
            )
        result = await self.client.collect_alert_window(context)
        required_target = PrometheusMCPClient.monitoring_target_context(context.alert)
        target_mismatch_count = sum(
            response.get("target_verification") == "mismatch"
            for response in result.responses
        )
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
            "call_limit_reached": result.call_limit_reached,
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
            "target_mismatch_count": target_mismatch_count,
            "monitoring_result_count": len(result.responses),
            "monitoring_results": list(result.responses),
            "raw_call_results": list(result.raw_call_results),
            "query_completed": result.has_monitoring_data,
            "root_cause_eligible": result.has_monitoring_data and not result.partial,
        }
        if result.partial:
            structured_data["root_cause_ineligible_reason"] = "partial_evidence"
        if result.has_monitoring_data:
            if result.partial:
                suffix = "；后续调查未完整结束，已保留此前取得的可用监控返回"
            elif result.call_limit_reached:
                suffix = "；已达到 MCP 调用上限，但已取得可用监控返回"
            else:
                suffix = ""
            if target_mismatch_count:
                suffix += f"；另有 {target_mismatch_count} 条目标不匹配返回已排除"
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
        if result.monitoring_scope_status == "unknown":
            reason = (
                "Prometheus MCP 无法确认告警数据库是否在当前监控范围内，"
                "未继续执行指标查询："
                f"{result.monitoring_scope_reason or '目标发现结果不足'}"
            )
        elif target_mismatch_count:
            reason = (
                f"Prometheus MCP 返回 {target_mismatch_count} 条与告警目标不一致的监控结果，"
                "未取得告警目标的可用实时证据。"
            )
        elif result.call_limit_reached:
            reason = "Prometheus MCP 调用次数达到上限，实时证据不足。"
        elif result.termination_reason == "no_discriminating_evidence":
            reason = (
                "Prometheus MCP 已停止无效探测，未取得完整的告警信号事实："
                f"{result.inconclusive_reason or '没有可归属的告警窗口监控样本'}"
            )
        elif result.termination_reason == "model_error_no_result":
            reason = "Prometheus MCP 模型连续两次未能选择有效工具，未取得实时证据。"
        else:
            reason = "Prometheus MCP 未返回可用监控结果，实时证据不足。"
        structured_data["root_cause_eligible"] = False
        structured_data["root_cause_ineligible_reason"] = (
            "monitoring_scope_unknown"
            if result.monitoring_scope_status == "unknown"
            else (
                "target_mismatch"
                if target_mismatch_count
                else (
                    "no_discriminating_evidence"
                    if result.termination_reason == "no_discriminating_evidence"
                    else "no_usable_monitoring_result"
                )
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
        mismatch_reasons = list(
            dict.fromkeys(
                str(reason)
                for response in result.responses
                for reason in response.get("target_mismatch_reasons", [])
                if isinstance(reason, str) and reason
            )
        )
        complete = deepcopy(structured_data)
        complete.update(
            {
                "model_tool_call_count": len(result.model_tool_calls),
                "target_mismatch_reasons": mismatch_reasons,
                "catalog_inventory": {
                    "observed": inventory_seen,
                    "metric_count": len(metric_names),
                    "metrics": metric_names,
                },
            }
        )
        return sanitize(complete)
