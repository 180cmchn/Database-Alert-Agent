from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import app.adapters.prometheus_harness as prometheus_harness_module
import app.application.factory as factory_module
from app.adapters.investigation import (
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
    ToolExecutor,
)
from app.adapters.prometheus_mcp import (
    PROMETHEUS_METRICS_TOOL_NAME,
    PrometheusMCPClient,
    PrometheusMCPConfigurationError,
    PrometheusMCPEvidenceTool,
    PrometheusMCPModelError,
    PrometheusMCPProtocolError,
    PrometheusMCPQueryResult,
    PrometheusMCPReadOnlyViolation,
    PrometheusMCPServerSettings,
    PrometheusMCPToolError,
    PrometheusMCPToolPolicy,
    has_monitoring_observation,
    load_prometheus_mcp_server_settings,
)
from app.config import RUNTIME_SETTINGS_KEYS, Settings
from app.domain.models import (
    DatabaseTarget,
    InvestigationContext,
    InvestigationStrategy,
    NormalizedAlert,
    Severity,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import MCPPromptBundle, load_mcp_catalog

ALERT_TIME = datetime(2026, 8, 7, 2, 0, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS_PROMPTS = load_mcp_catalog(
    PROJECT_ROOT / "config/mcp/settings.json"
).require("prometheus").prompts
_FAKE_RANGE_POLICY = PrometheusMCPToolPolicy(
    name="arbitrary_monitoring_tool",
    capability="range_query",
    start_argument_path=("start",),
    end_argument_path=("end",),
    timestamp_encoding="rfc3339",
)


def _write_prompt_files(
    directory: Path,
    server_name: str,
    prompts: MCPPromptBundle = PROMETHEUS_PROMPTS,
) -> dict[str, str]:
    prompt_directory = directory / "prompts" / server_name
    prompt_directory.mkdir(parents=True, exist_ok=True)
    references: dict[str, str] = {}
    for prompt_name in ("role", "purpose", "workflow", "safety"):
        path = prompt_directory / f"{prompt_name}.md"
        path.write_text(getattr(prompts, prompt_name), encoding="utf-8")
        references[prompt_name] = str(path.relative_to(directory))
    return references


def _server_settings(
    *,
    headers: dict[str, str] | None = None,
    tool_policies: tuple[PrometheusMCPToolPolicy, ...] = (_FAKE_RANGE_POLICY,),
) -> PrometheusMCPServerSettings:
    return PrometheusMCPServerSettings(
        url="https://prometheus.example.test/sse",
        headers=headers or {},
        prompts=PROMETHEUS_PROMPTS,
        tool_policies=tool_policies,
    )


def _context() -> InvestigationContext:
    return InvestigationContext(
        run_id=uuid4(),
        alert=NormalizedAlert(
            external_id="prometheus-test-alert",
            source="canonical",
            raw_severity="WARNING",
            severity=Severity.WARNING,
            title="Database latency elevated",
            reason="database_latency",
            occurred_at=ALERT_TIME,
        ),
        strategy=InvestigationStrategy(
            strategy_id="prometheus-test",
            title="Prometheus test",
            description="test",
        ),
    )


def _mysql_context() -> InvestigationContext:
    context = _context()
    return context.model_copy(
        update={
            "alert": context.alert.model_copy(
                update={
                    "title": "mysql_cpu_usage_more_than_90%",
                    "reason": "mysql_cpu_usage_more_than_90%",
                    "alert_type": "mysql_cpu_usage_more_than_90%",
                    "metric_name": "mysql_cpu_usage",
                    "database": DatabaseTarget(
                        engine="mysql",
                        instance="mysql-17:3306",
                        host="mysql-17",
                    ),
                }
            )
        }
    )


def _oceanbase_context() -> InvestigationContext:
    context = _context()
    return context.model_copy(
        update={
            "alert": context.alert.model_copy(
                update={
                    "title": "OCEANBASE/sc_store_prod-OceanBase服务器数据盘使用率超限",
                    "reason": "OceanBase服务器数据盘使用率超限",
                    "alert_type": "oceanbase_disk_usage",
                    "metric_name": None,
                    "cluster": "sc_store_prod",
                    "database": DatabaseTarget(
                        engine="oceanbase",
                        instance="10.126.106.14",
                        host="10.126.106.14",
                    ),
                }
            )
        }
    )


def _mysql_slow_context() -> InvestigationContext:
    context = _mysql_context()
    return context.model_copy(
        update={
            "alert": context.alert.model_copy(
                update={
                    "title": "mysql_slow_query_300",
                    "reason": "database_latency",
                    "alert_type": "mysql_slow_query_300",
                    "metric_name": "mysql_slow_query_300",
                    "cluster": "mysql-prod-pcm",
                    "database": DatabaseTarget(
                        engine="mysql",
                        instance="100.84.97.117:3306",
                        host="100.84.97.117",
                    ),
                }
            )
        }
    )


def test_prometheus_target_uses_canonical_database_endpoint_only() -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "database": context.alert.database.model_copy(update={"port": 3306}),
            "labels": {
                "instance": "label-instance",
                "alarm_host": "wrong-host",
                "alarm_port": "3307",
            },
        }
    )

    target = PrometheusMCPClient.monitoring_target_context(alert)

    assert target["host"] == "mysql-17"
    assert target["port"] == 3306
    assert target["endpoint"] == "mysql-17:3306"
    assert target["instance_candidates"] == ["mysql-17:3306", "mysql-17"]


def test_prometheus_mcp_settings_resolve_header_placeholder_without_persisting_secret(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    prompts = _write_prompt_files(tmp_path, "prometheus")
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "readOnly": True,
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "optionalHeaders": {
                            "${PROMETHEUS_MCP_API_KEY_HEADER}": (
                                "${PROMETHEUS_MCP_API_KEY}"
                            )
                        },
                        "prompts": prompts,
                        "toolPolicies": {
                            "get_targets": {
                                "capability": "target_discovery",
                                "fixedArguments": {},
                            },
                            "query_range": {
                                "capability": "range_query",
                                "startArgument": "start",
                                "endArgument": "end",
                                "timestampEncoding": "rfc3339",
                                "fixedArguments": {"operation": "query"},
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = load_prometheus_mcp_server_settings(
        settings_path,
        environment={
            "PROMETHEUS_MCP_SSE_URL": "https://prometheus.example.test/sse",
            "PROMETHEUS_MCP_API_KEY_HEADER": "X-API-Key",
            "PROMETHEUS_MCP_API_KEY": "test-prometheus-secret",
        },
    )

    assert resolved.url == "https://prometheus.example.test/sse"
    assert resolved.headers == {"X-API-Key": "test-prometheus-secret"}
    assert resolved.prompts == PROMETHEUS_PROMPTS
    assert resolved.tool_policies == (
        PrometheusMCPToolPolicy(
            name="get_targets",
            capability="target_discovery",
            fixed_arguments={},
        ),
        PrometheusMCPToolPolicy(
            name="query_range",
            capability="range_query",
            start_argument_path=("start",),
            end_argument_path=("end",),
            timestamp_encoding="rfc3339",
            fixed_arguments={"operation": "query"},
        ),
    )
    assert "test-prometheus-secret" not in settings_path.read_text(encoding="utf-8")


def test_prometheus_mcp_settings_reject_half_configured_optional_auth_header(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    prompts = _write_prompt_files(tmp_path, "prometheus")
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "readOnly": True,
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "optionalHeaders": {
                            "${PROMETHEUS_MCP_API_KEY_HEADER}": (
                                "${PROMETHEUS_MCP_API_KEY}"
                            )
                        },
                        "prompts": prompts,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        PrometheusMCPConfigurationError,
        match=r"optional header name and value .*must both be configured",
    ):
        load_prometheus_mcp_server_settings(
            settings_path,
            environment={
                "PROMETHEUS_MCP_SSE_URL": "https://prometheus.example.test/sse",
                "PROMETHEUS_MCP_API_KEY_HEADER": "Authorization",
                "PROMETHEUS_MCP_API_KEY": "",
            },
        )


@pytest.mark.asyncio
async def test_prometheus_prompt_file_update_changes_actual_model_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = tmp_path / "settings.json"
    first_prompts = MCPPromptBundle(
        role="prometheus-role-from-file",
        purpose="prometheus-purpose-from-file",
        workflow="prometheus-workflow-v1-from-file",
        safety="read_only: true\nprometheus-safety-from-file",
    )
    prompt_references = _write_prompt_files(
        tmp_path,
        "prometheus",
        first_prompts,
    )
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "readOnly": True,
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "headers": {},
                        "prompts": prompt_references,
                        "toolPolicies": {
                            "arbitrary_monitoring_tool": {
                                "capability": "range_query",
                                "startArgument": "start",
                                "endArgument": "end",
                                "timestampEncoding": "rfc3339",
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)

    async def capture_system_message() -> str:
        _FakeSession.calls = []
        model = _SequenceModel(
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"],
            arguments=[{"query": "up"}, {}],
        )
        client = PrometheusMCPClient.from_settings(
            settings_path,
            model,
            environment={
                "PROMETHEUS_MCP_SSE_URL": "https://prometheus.example.test/sse"
            },
            max_agent_steps=1,
        )
        await client.collect_alert_window(_context())
        return str(model.messages[0][0]["content"])

    first_message = await capture_system_message()
    workflow_path = tmp_path / prompt_references["workflow"]
    workflow_path.write_text("prometheus-workflow-v2-from-file", encoding="utf-8")
    second_message = await capture_system_message()

    assert "[role]\nprometheus-role-from-file" in second_message
    assert "[purpose]\nprometheus-purpose-from-file" in second_message
    assert "[safety]\nread_only: true\nprometheus-safety-from-file" in second_message
    assert "prometheus-workflow-v1-from-file" in first_message
    assert "prometheus-workflow-v1-from-file" not in second_message
    assert "[workflow]\nprometheus-workflow-v2-from-file" in second_message


def test_prometheus_settings_are_deployment_only_but_call_budget_is_runtime_editable() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
        prometheus_mcp_api_key="test-secret",
        prometheus_mcp_api_key_header="X-API-Key",
        prometheus_mcp_max_agent_steps=11,
    )

    assert settings.prometheus_mcp_enabled is True
    assert settings.prometheus_mcp_max_agent_steps == 11
    assert "prometheus_mcp_max_agent_steps" in RUNTIME_SETTINGS_KEYS
    assert "prometheus_mcp_sse_url" not in RUNTIME_SETTINGS_KEYS
    assert "prometheus_mcp_api_key" not in RUNTIME_SETTINGS_KEYS
    assert "prometheus_mcp_api_key_header" not in RUNTIME_SETTINGS_KEYS


def test_prometheus_mcp_is_enabled_without_an_api_key() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
        prometheus_mcp_api_key="",
    )

    assert settings.prometheus_mcp_enabled is True
    assert not any(
        "Prometheus MCP configuration is incomplete" in issue
        for issue in settings.readiness_issues()
    )


@pytest.mark.parametrize(
    ("header", "api_key", "missing_setting"),
    [
        ("Authorization", "", "PROMETHEUS_MCP_API_KEY"),
        ("", "secret", "PROMETHEUS_MCP_API_KEY_HEADER"),
    ],
)
def test_prometheus_mcp_readiness_rejects_half_configured_authentication(
    header: str,
    api_key: str,
    missing_setting: str,
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
        prometheus_mcp_api_key_header=header,
        prometheus_mcp_api_key=api_key,
    )

    issue = next(
        item
        for item in settings.readiness_issues()
        if "Prometheus MCP authentication is incomplete" in item
    )
    assert "PROMETHEUS_MCP_API_KEY_HEADER" in issue
    assert "PROMETHEUS_MCP_API_KEY" in issue
    assert missing_setting in issue
    assert "both be configured or both be empty" in issue


def test_prometheus_mcp_readiness_reports_header_only_configuration() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        prometheus_mcp_api_key_header="Authorization",
    )

    issues = settings.readiness_issues()

    assert any("Prometheus MCP authentication is incomplete" in item for item in issues)
    assert any("PROMETHEUS_MCP_SSE_URL" in item for item in issues)


def test_prometheus_mcp_rejects_business_error_with_successful_protocol_envelope() -> None:
    raw_result = type(
        "ToolResult",
        (),
        {
            "model_dump": lambda _self, **_: {
                "isError": False,
                "structuredContent": {
                    "status": "failed",
                    "message": "invalid PromQL range",
                },
            }
        },
    )()

    with pytest.raises(PrometheusMCPToolError, match="invalid PromQL range"):
        PrometheusMCPClient.result_payload(raw_result)


def test_prometheus_mcp_rejects_json_business_error_in_text_content() -> None:
    raw_result = type(
        "ToolResult",
        (),
        {
            "model_dump": lambda _self, **_: {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "error",
                                "message": "temporary backend failure",
                            }
                        ),
                    }
                ],
            }
        },
    )()

    with pytest.raises(PrometheusMCPToolError, match="temporary backend failure"):
        PrometheusMCPClient.result_payload(raw_result)


def test_prometheus_mcp_decodes_json_observation_from_text_content() -> None:
    observation = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"job": "mysql"},
                    "values": [[1786067700, "1"], [1786068000, "2"]],
                }
            ],
        },
    }
    raw_result = type(
        "ToolResult",
        (),
        {
            "model_dump": lambda _self, **_: {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": "```json\n"
                        + json.dumps(observation, ensure_ascii=False)
                        + "\n```",
                    }
                ],
            }
        },
    )()

    payload = PrometheusMCPClient.result_payload(raw_result)

    assert payload == observation
    assert has_monitoring_observation(payload) is True


def test_prometheus_call_result_keeps_complete_envelope_with_structured_payload() -> None:
    raw_result = type(
        "ToolResult",
        (),
        {
            "model_dump": lambda _self, **kwargs: {
                "_meta": {
                    "trace_id": "trace-1",
                    "api_key": "must-not-survive",
                    "by_alias": kwargs.get("by_alias"),
                },
                "content": [
                    {"type": "text", "text": "human-readable monitoring result"}
                ],
                "structuredContent": {"series": [{"value": 42}]},
                "isError": False,
            }
        },
    )()

    result = PrometheusMCPClient.call_result(raw_result)

    assert result.payload == {"series": [{"value": 42}]}
    assert result.raw_call_result == {
        "_meta": {
            "trace_id": "trace-1",
            "api_key": "***REDACTED***",
            "by_alias": True,
        },
        "content": [
            {"type": "text", "text": "human-readable monitoring result"}
        ],
        "structuredContent": {"series": [{"value": 42}]},
        "isError": False,
    }


def test_prometheus_mcp_range_contract_uses_timestamps_only_to_reject_mismatch() -> None:
    in_window = {
        "data": {
            "result": [
                {
                    "metric": {"job": "mysql"},
                    "values": [[1786067700, "1"], [1786068000, "2"]],
                }
            ]
        }
    }
    out_of_window = {
        "data": {
            "result": [
                {
                    "metric": {"job": "mysql"},
                    "values": [[1786067640, "1"], [1786068000, "2"]],
                }
            ]
        }
    }

    assert (
        PrometheusMCPClient.window_verification(
            policy=_FAKE_RANGE_POLICY,
            payload=in_window,
            window_start=datetime(2026, 8, 7, 1, 55, tzinfo=UTC),
            window_end=ALERT_TIME,
        )
        == "exact"
    )
    assert (
        PrometheusMCPClient.window_verification(
            policy=_FAKE_RANGE_POLICY,
            payload=out_of_window,
            window_start=datetime(2026, 8, 7, 1, 55, tzinfo=UTC),
            window_end=ALERT_TIME,
        )
        == "mismatch"
    )
    assert (
        PrometheusMCPClient.window_verification(
            policy=PrometheusMCPToolPolicy(
                name="instant_query",
                capability="catalog",
            ),
            payload=in_window,
            window_start=datetime(2026, 8, 7, 1, 55, tzinfo=UTC),
            window_end=ALERT_TIME,
        )
        == "unknown"
    )


class _AsyncContext:
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, *args: Any) -> None:
        return None


class _FakeTool:
    def model_dump(self, *, mode: str) -> dict[str, Any]:
        assert mode == "json"
        return {
            "name": "arbitrary_monitoring_tool",
            "description": "Server-defined monitoring query",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "start": {"type": "string"},
                    "end": {"type": "string"},
                },
            },
        }


class _FakeSession:
    calls: list[tuple[str, dict[str, Any]]] = []
    result: dict[str, Any] = {"structuredContent": {"series": [{"value": 42}]}}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def initialize(self) -> None:
        return None

    async def list_tools(self, cursor: str | None = None) -> Any:
        assert cursor is None
        return type("ToolList", (), {"tools": [_FakeTool()], "nextCursor": None})()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((name, arguments))
        return type("ToolResult", (), {"model_dump": lambda _self, **_: self.result})()


class _SequencedSession(_FakeSession):
    results: list[dict[str, Any] | Exception] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        index = len(self.calls)
        self.calls.append((name, arguments))
        result = self.results[index]
        if isinstance(result, Exception):
            raise result
        return type("ToolResult", (), {"model_dump": lambda _self, **_: result})()


class _SequenceModel:
    def __init__(
        self,
        names: list[str],
        arguments: list[dict[str, Any]] | None = None,
    ) -> None:
        self.names = names
        self.arguments = arguments
        self.messages: list[list[dict[str, Any]]] = []
        self.available_tools: list[set[str]] = []
        self.tool_definitions: list[list[dict[str, Any]]] = []

    async def request_mcp_tool_call(
        self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> MCPModelToolCall:
        self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
        index = len(self.messages) - 1
        available = {item["function"]["name"] for item in tools}
        self.available_tools.append(available)
        self.tool_definitions.append(json.loads(json.dumps(tools, ensure_ascii=False)))
        name = self.names[index]
        assert name in available
        return MCPModelToolCall(
            call_id=f"call-{index}",
            name=name,
            arguments=(
                self.arguments[index]
                if self.arguments is not None
                else {
                    "query": "up",
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                }
            ),
            request_id=f"request-{index}",
        )


class _TargetAwareTool:
    def __init__(self, name: str, schema: dict[str, Any]) -> None:
        self.name = name
        self.schema = schema

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        assert mode == "json"
        return {
            "name": self.name,
            "description": f"Fixture tool {self.name}",
            "inputSchema": self.schema,
            "annotations": {"readOnlyHint": True},
        }


class _TargetAwareSession(_FakeSession):
    calls: list[tuple[str, dict[str, Any]]] = []
    results: list[dict[str, Any]] = []

    async def list_tools(self, cursor: str | None = None) -> Any:
        assert cursor is None
        tools = [
            _TargetAwareTool(
                "get_targets",
                {
                    "type": "object",
                    "properties": {
                        "state": {"type": "string"},
                        "scrape_pool": {"type": "string"},
                        "limit": {"type": "integer"},
                        "offset": {"type": "integer"},
                    },
                    "additionalProperties": False,
                },
            ),
            _TargetAwareTool(
                "execute_range_query",
                {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "start": {"type": "string"},
                        "end": {"type": "string"},
                    },
                    "required": ["query", "start", "end"],
                    "additionalProperties": False,
                },
            ),
            _TargetAwareTool(
                "list_metrics",
                {
                    "type": "object",
                    "properties": {"filter_pattern": {"type": "string"}},
                    "additionalProperties": False,
                },
            ),
            _TargetAwareTool(
                "get_metric_metadata",
                {
                    "type": "object",
                    "properties": {"metric": {"type": "string"}},
                    "required": ["metric"],
                    "additionalProperties": False,
                },
            ),
        ]
        return type("ToolList", (), {"tools": tools, "nextCursor": None})()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        index = len(type(self).calls)
        type(self).calls.append((name, arguments))
        result = type(self).results[index]
        return type("ToolResult", (), {"model_dump": lambda _self, **_: result})()


def _target_aware_settings() -> PrometheusMCPServerSettings:
    return _server_settings(
        tool_policies=(
            PrometheusMCPToolPolicy(
                name="get_targets",
                capability="target_discovery",
            ),
            PrometheusMCPToolPolicy(
                name="execute_range_query",
                capability="range_query",
                start_argument_path=("start",),
                end_argument_path=("end",),
                timestamp_encoding="rfc3339",
            ),
            PrometheusMCPToolPolicy(
                name="list_metrics",
                capability="catalog",
            ),
            PrometheusMCPToolPolicy(
                name="get_metric_metadata",
                capability="catalog",
            ),
        )
    )


def _oceanbase_target_result() -> dict[str, Any]:
    return {
        "structuredContent": {
            "status": "success",
            "data": {
                "activeTargets": [
                    {
                        "labels": {
                            "job": "ocp-agent:62889/metrics/ob/basic",
                            "instance": "10.126.106.15:62889",
                        },
                        "discoveredLabels": {
                            "__meta_url": (
                                "http://ocp-prod.mcdchina.net:8080/api/v2/monitor/"
                                "prometheus_sd"
                            )
                        },
                        "scrapePool": "ocp_sd",
                        "scrapeUrl": "http://10.126.106.15:62889/metrics/ob/basic",
                        "health": "up",
                    },
                    {
                        "labels": {
                            "job": "ocp-agent:62889/metrics/obproxy",
                            "instance": "10.126.106.166:62889",
                        },
                        "scrapePool": "ocp_sd",
                        "scrapeUrl": "http://10.126.106.166:62889/metrics/obproxy",
                        "health": "up",
                    },
                ]
            },
        }
    }


def test_prometheus_local_policy_rejects_unknown_and_destructive_tools() -> None:
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "start": {"type": "string"},
            "end": {"type": "string"},
        },
    }
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(["arbitrary_monitoring_tool"]),
    )

    with pytest.raises(PrometheusMCPConfigurationError, match="at least one"):
        PrometheusMCPClient(
            _server_settings(tool_policies=()),
            _SequenceModel(["arbitrary_monitoring_tool"]),
        )

    with pytest.raises(PrometheusMCPConfigurationError, match="no tool authorized"):
        client.authorized_model_tools(
            [
                {
                    "name": "arbitrary_monitoring_tool",
                    "inputSchema": schema,
                    "annotations": {"destructiveHint": True, "readOnlyHint": True},
                }
            ]
        )

    for tool_annotations in ({}, {"readOnlyHint": False}):
        with pytest.raises(PrometheusMCPConfigurationError, match="no tool authorized"):
            client.authorized_model_tools(
                [
                    {
                        "name": "arbitrary_monitoring_tool",
                        "inputSchema": schema,
                        "annotations": tool_annotations,
                    }
                ]
            )

    second_policy = PrometheusMCPToolPolicy(
        name="second_monitoring_tool",
        capability="range_query",
        start_argument_path=("start",),
        end_argument_path=("end",),
        timestamp_encoding="rfc3339",
    )
    mixed_client = PrometheusMCPClient(
        _server_settings(tool_policies=(_FAKE_RANGE_POLICY, second_policy)),
        _SequenceModel(["arbitrary_monitoring_tool"]),
    )
    for unsafe_annotations in (
        {},
        {"readOnlyHint": True, "destructiveHint": True},
    ):
        with pytest.raises(
            PrometheusMCPConfigurationError,
            match="read-only contract failed for: second_monitoring_tool",
        ):
            mixed_client.authorized_model_tools(
                [
                    {
                        "name": "arbitrary_monitoring_tool",
                        "inputSchema": schema,
                        "annotations": {"readOnlyHint": True},
                    },
                    {
                        "name": "second_monitoring_tool",
                        "inputSchema": schema,
                        "annotations": unsafe_annotations,
                    },
                ]
            )

    converted, _ = client.authorized_model_tools(
        [
            {
                "name": "arbitrary_monitoring_tool",
                "inputSchema": schema,
                "annotations": {"readOnlyHint": True},
            }
        ]
    )
    description = converted[0]["function"]["description"]
    assert "capability=range_query" in description
    assert "root-cause-eligible" in description


@pytest.mark.asyncio
async def test_prometheus_stops_after_target_discovery_for_unmonitored_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _TargetAwareSession.calls = []
    _TargetAwareSession.results = [_oceanbase_target_result()]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _TargetAwareSession)
    model = _SequenceModel(
        ["get_targets", "finish_prometheus_investigation"],
        arguments=[
            {},
            {
                "monitoring_scope_status": "out_of_scope",
                "reason": "目标清单仅包含 OceanBase，告警数据库为 MySQL。",
                "monitored_database_engines": ["oceanbase"],
            },
        ],
    )
    client = PrometheusMCPClient(
        _target_aware_settings(),
        model,
        max_agent_steps=4,
    )

    result = await client.collect_alert_window(_mysql_context())

    assert _TargetAwareSession.calls == [("get_targets", {})]
    assert model.available_tools[0] == {"get_targets"}
    assert "finish_prometheus_investigation" in model.available_tools[1]
    assert result.monitoring_scope_status == "out_of_scope"
    assert result.monitored_database_engines == ("oceanbase",)
    assert result.termination_reason == "database_not_monitored"
    assert result.has_monitoring_data is False


@pytest.mark.asyncio
async def test_prometheus_queries_metrics_only_after_target_discovery_matches_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _TargetAwareSession.calls = []
    _TargetAwareSession.results = [
        {
            "structuredContent": {
                "status": "success",
                "data": {"activeTargets": []},
            }
        },
        _oceanbase_target_result(),
        {
            "structuredContent": {
                "status": "success",
                "data": {
                    "metrics": [
                        "ob_data_disk_usage_percent",
                        "obproxy_request_count",
                    ]
                },
            }
        },
        {
            "structuredContent": {
                "status": "success",
                "data": {
                    "ob_data_disk_usage_percent": {
                        "help": "OceanBase server data disk usage percent",
                        "type": "gauge",
                    }
                },
            }
        },
        {
            "structuredContent": {
                "status": "success",
                "data": {
                    "resultType": "matrix",
                    "result": [
                        {
                            "metric": {
                                "__name__": "ob_data_disk_usage_percent",
                                "job": "ocp-agent:62889/metrics/ob/basic",
                                "cluster": "sc_store_prod",
                            },
                            "values": [[1786067700, "91"]],
                        }
                    ],
                },
            }
        },
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _TargetAwareSession)
    model = _SequenceModel(
        [
            "get_targets",
            "get_targets",
            "list_metrics",
            "get_metric_metadata",
            "execute_range_query",
            "finish_prometheus_investigation",
        ],
        arguments=[
            {
                "state": "active",
                "scrape_pool": "oceanbase",
                "limit": 100,
                "offset": 0,
            },
            {"state": "active", "limit": 100, "offset": 0},
            {"filter_pattern": "ob|ocp"},
            {"metric": "ob_data_disk_usage_percent"},
            {
                "query": 'ob_data_disk_usage_percent{cluster="sc_store_prod"}',
                "monitoring_scope_reason": (
                    "ocp_sd 来自 OCP Prometheus 服务发现，目标同时包含 /metrics/ob/basic、"
                    "/metrics/obproxy 和 OceanBase 数据盘指标，支持 OceanBase 归属。"
                ),
                "monitored_database_engines": ["oceanbase"],
                "monitoring_target_identifiers": ["ocp_sd", "/metrics/ob/basic", "obproxy"],
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _target_aware_settings(),
        model,
        max_agent_steps=7,
    )

    result = await client.collect_alert_window(_oceanbase_context())

    assert [name for name, _arguments in _TargetAwareSession.calls] == [
        "get_targets",
        "get_targets",
        "list_metrics",
        "get_metric_metadata",
        "execute_range_query",
    ]
    assert _TargetAwareSession.calls[0] == (
        "get_targets",
        {"state": "active", "scrape_pool": "oceanbase", "limit": 100, "offset": 0},
    )
    assert model.available_tools[0] == {"get_targets"}
    assert model.available_tools[1] == {
        "execute_range_query",
        "finish_prometheus_investigation",
        "get_metric_metadata",
        "get_targets",
        "list_metrics",
    }
    assert model.available_tools[4] == {
        "execute_range_query",
        "finish_prometheus_investigation",
    }
    range_definition = next(
        item
        for item in model.tool_definitions[4]
        if item["function"]["name"] == "execute_range_query"
    )
    scope_finish_definition = next(
        item
        for item in model.tool_definitions[4]
        if item["function"]["name"] == "finish_prometheus_investigation"
    )
    assert {
        "monitoring_scope_reason",
        "monitored_database_engines",
        "monitoring_target_identifiers",
    } <= set(range_definition["function"]["parameters"]["required"])
    assert scope_finish_definition["function"]["parameters"]["properties"][
        "monitoring_scope_status"
    ]["enum"] == ["out_of_scope", "unknown"]
    assert _TargetAwareSession.calls[-1][1] == {
        "query": 'ob_data_disk_usage_percent{cluster="sc_store_prod"}',
        "start": "2026-08-07T01:55:00+00:00",
        "end": "2026-08-07T02:00:00+00:00",
    }
    assert result.monitoring_scope_status == "in_scope"
    assert result.monitoring_scope_reason and "obproxy" in result.monitoring_scope_reason
    assert result.monitored_database_engines == ("oceanbase",)
    assert result.monitoring_target_identifiers == (
        "ocp_sd",
        "/metrics/ob/basic",
        "obproxy",
    )
    assert result.has_monitoring_data is True
    assert result.finished_by_model is True


def test_prometheus_policy_reserves_range_budget_and_hides_finish_without_data() -> None:
    catalog_policy = PrometheusMCPToolPolicy(
        name="list_metrics",
        capability="catalog",
    )
    client = PrometheusMCPClient(
        _server_settings(tool_policies=(catalog_policy, _FAKE_RANGE_POLICY)),
        _SequenceModel([]),
        max_agent_steps=4,
    )
    tools = [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": name,
                "parameters": {"type": "object"},
            },
        }
        for name in (catalog_policy.name, _FAKE_RANGE_POLICY.name)
    ]
    calls = [
        MCPModelToolCall(call_id=f"call-{index}", name="list_metrics", arguments={})
        for index in range(2)
    ]

    reserved = client.model_tools_for_state(
        model_tool_list=tools,
        authorized_policies={
            catalog_policy.name: catalog_policy,
            _FAKE_RANGE_POLICY.name: _FAKE_RANGE_POLICY,
        },
        calls=calls,
        responses=[],
    )

    assert [item["function"]["name"] for item in reserved] == [
        _FAKE_RANGE_POLICY.name
    ]

    finishable = client.model_tools_for_state(
        model_tool_list=tools,
        authorized_policies={
            catalog_policy.name: catalog_policy,
            _FAKE_RANGE_POLICY.name: _FAKE_RANGE_POLICY,
        },
        calls=calls,
        responses=[
            {
                "has_monitoring_observation": True,
                "window_verification": "exact",
            }
        ],
    )

    assert "finish_prometheus_investigation" in {
        item["function"]["name"] for item in finishable
    }

    direct_range = client.model_tools_for_state(
        model_tool_list=tools,
        authorized_policies={
            catalog_policy.name: catalog_policy,
            _FAKE_RANGE_POLICY.name: _FAKE_RANGE_POLICY,
        },
        calls=[],
        responses=[],
        alert=_mysql_context().alert,
    )

    assert [item["function"]["name"] for item in direct_range] == [
        _FAKE_RANGE_POLICY.name
    ]


def test_prometheus_catalog_relevance_requires_alert_signal_semantics() -> None:
    alert = _mysql_slow_context().alert
    unrelated = [
        {
            "capability": "catalog",
            "result": {
                "metrics": [
                    "mysql_output_process_metrics_count",
                    "mysql_output_write_sql_count",
                    "mysql_sls_output_discard_count",
                ]
            },
        }
    ]
    relevant = [
        {
            "capability": "catalog",
            "result": {"metrics": {"mysql_global_status_slow_queries": {"type": "counter"}}},
        }
    ]
    incomplete = [
        {
            "capability": "catalog",
            "result": {
                "metrics": ["mysql_output_write_sql_count"],
                "total_count": 20,
                "returned_count": 10,
                "offset": 0,
                "has_more": True,
            },
        }
    ]

    assert PrometheusMCPClient.catalog_metric_relevance(alert, unrelated) == "irrelevant"
    assert PrometheusMCPClient.catalog_metric_relevance(alert, relevant) == "relevant"
    assert PrometheusMCPClient.catalog_metric_relevance(alert, incomplete) == "unknown"
    assert PrometheusMCPClient.catalog_metric_relevance(alert, []) == "unknown"


@pytest.mark.asyncio
async def test_prometheus_model_cannot_call_tool_outside_local_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnauthorizedModel:
        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            del messages, tools
            return MCPModelToolCall(
                call_id=f"unauthorized-{uuid4()}",
                name="delete_prometheus_data",
                arguments={"confirm": True},
            )

    _FakeSession.calls = []
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        UnauthorizedModel(),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert _FakeSession.calls == []
    assert result.has_monitoring_data is False
    assert result.termination_reason == "decision_limit_reached"
    assert len(result.tool_attempts) == 4
    assert {item["outcome"] for item in result.tool_attempts} == {
        "host_rejected_unauthorized"
    }
    assert all(
        item["tool_name"] == "delete_prometheus_data"
        for item in result.tool_attempts
    )


@pytest.mark.asyncio
async def test_prometheus_client_deduplicates_successful_calls_without_remote_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"series": [{"value": 42}]}}
    captured_sse: dict[str, Any] = {}

    def fake_sse_client(url: str, **kwargs: Any) -> _AsyncContext:
        captured_sse.update({"url": url, **kwargs})
        return _AsyncContext((object(), object()))

    monkeypatch.setattr(prometheus_harness_module, "sse_client", fake_sse_client)
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ],
        arguments=[
            {"query": "up"},
            {"query": "up"},
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(headers={"X-API-Key": "test-secret"}),
        model,
        max_agent_steps=2,
        sse_read_timeout_seconds=654,
    )

    result = await client.collect_alert_window(_context())

    assert captured_sse["headers"] == {"X-API-Key": "test-secret"}
    assert captured_sse["sse_read_timeout"] == 654
    assert _FakeSession.calls == [
        (
            "arbitrary_monitoring_tool",
            {
                "query": "up",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
        ),
    ]
    assert result.model_tool_calls == ("arbitrary_monitoring_tool",)
    assert len(result.responses) == 1
    assert result.call_limit_reached is False
    assert result.finished_by_model is True
    assert result.has_monitoring_data is True
    assert result.window_end == ALERT_TIME
    assert result.window_start.isoformat() == "2026-08-07T01:55:00+00:00"
    first_request = json.loads(model.messages[0][1]["content"])
    assert first_request["required_window"]["duration_seconds"] == 300


@pytest.mark.asyncio
async def test_prometheus_rejects_oceanbase_series_for_mysql_then_accepts_mysql_series(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {
            "structuredContent": {
                "series": [
                    {
                        "metric": {
                            "__name__": "ob_sysstat_cpu_usage",
                            "cluster": "oceanbase-prod",
                            "job": "oceanbase",
                        },
                        "values": [[1786067700, "95"]],
                    }
                ]
            }
        },
        {
            "structuredContent": {
                "series": [
                    {
                        "metric": {
                            "__name__": "mysql_cpu_usage",
                            "instance": "mysql-17:3306",
                            "job": "mysql",
                        },
                        "values": [[1786067700, "91"]],
                    }
                ]
            }
        },
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ],
        arguments=[
            {"query": "ob_sysstat_cpu_usage"},
            {"query": 'mysql_cpu_usage{instance="mysql-17:3306"}'},
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=3,
    )

    result = await client.collect_alert_window(_mysql_context())

    assert result.has_monitoring_data is True
    assert [item["target_verification"] for item in result.responses] == [
        "mismatch",
        "compatible",
    ]
    assert [item["root_cause_eligible"] for item in result.responses] == [False, True]
    assert [item["outcome"] for item in result.tool_attempts] == [
        "target_mismatch",
        "observation",
    ]
    assert "finish_prometheus_investigation" not in model.available_tools[1]
    first_feedback = next(
        payload
        for message in model.messages[1]
        if isinstance(message.get("content"), str)
        and message["content"].lstrip().startswith("{")
        for payload in [json.loads(message["content"])]
        if payload.get("host_control", {}).get("outcome") == "target_mismatch"
    )
    assert first_feedback["monitoring_result"]["host_target_verification"] == "mismatch"
    assert "重新执行range_query" in first_feedback["monitoring_result"]["instruction"]


@pytest.mark.asyncio
async def test_prometheus_stops_after_two_target_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oceanbase_result = {
        "structuredContent": {
            "series": [
                {
                    "metric": {
                        "__name__": "ob_sysstat_cpu_usage",
                        "cluster": "oceanbase-prod",
                        "job": "oceanbase",
                    },
                    "values": [[1786067700, "95"]],
                }
            ]
        }
    }
    _SequencedSession.calls = []
    _SequencedSession.results = [oceanbase_result, oceanbase_result]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
        ],
        arguments=[
            {"query": "ob_sysstat_cpu_usage"},
            {"query": 'ob_sysstat_cpu_usage{cluster="oceanbase-prod"}'},
            {"query": "mysql_cpu_usage"},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=8,
    )

    result = await client.collect_alert_window(_mysql_context())

    assert len(_SequencedSession.calls) == 2
    assert len(model.messages) == 2
    assert result.has_monitoring_data is False
    assert result.call_limit_reached is False
    assert result.termination_reason == "no_discriminating_evidence"
    assert result.inconclusive_reason is not None
    assert "仍与告警目标不一致" in result.inconclusive_reason


@pytest.mark.asyncio
async def test_prometheus_stops_when_catalog_has_no_slow_query_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CatalogAndRangeTool:
        def __init__(self, name: str, input_schema: dict[str, Any]) -> None:
            self.name = name
            self.input_schema = input_schema

        def model_dump(self, *, mode: str) -> dict[str, Any]:
            assert mode == "json"
            return {
                "name": self.name,
                "description": f"Fixture tool {self.name}",
                "inputSchema": self.input_schema,
                "annotations": {"readOnlyHint": True},
            }

    class CatalogAndRangeSession(_FakeSession):
        calls: list[tuple[str, dict[str, Any]]] = []
        results = [
            {
                "status": "success",
                "data": {"resultType": "matrix", "result": []},
            },
            {
                "metrics": [],
                "total_count": 0,
                "returned_count": 0,
                "has_more": False,
            },
            {
                "metrics": [
                    "mysql_output_process_metrics_count",
                    "mysql_output_write_sql_count",
                    "mysql_output_write_sql_milliseconds_summary_sum",
                    "mysql_sls_output_discard_count",
                ],
                "total_count": 4,
                "returned_count": 4,
                "has_more": False,
            },
        ]

        async def list_tools(self, cursor: str | None = None) -> Any:
            assert cursor is None
            tools = [
                CatalogAndRangeTool(
                    "execute_range_query",
                    {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                            "step": {"type": "string"},
                        },
                        "required": ["query", "start", "end"],
                        "additionalProperties": False,
                    },
                ),
                CatalogAndRangeTool(
                    "list_metrics",
                    {
                        "type": "object",
                        "properties": {"filter_pattern": {"type": "string"}},
                        "required": ["filter_pattern"],
                        "additionalProperties": False,
                    },
                ),
            ]
            return type("ToolList", (), {"tools": tools, "nextCursor": None})()

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            type(self).calls.append((name, arguments))
            payload = type(self).results[len(type(self).calls) - 1]
            raw = {"structuredContent": payload}
            return type(
                "ToolResult",
                (),
                {"model_dump": lambda _self, **_: raw},
            )()

    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(
        prometheus_harness_module,
        "ClientSession",
        CatalogAndRangeSession,
    )
    model = _SequenceModel(
        [
            "execute_range_query",
            "list_metrics",
            "list_metrics",
            "execute_range_query",
        ],
        arguments=[
            {
                "query": (
                    "rate(mysql_global_status_slow_queries"
                    '{cluster="mysql-prod-pcm",instance="100.84.97.117:3306"}[5m])'
                ),
                "step": "30s",
            },
            {"filter_pattern": "mysql.*slow"},
            {"filter_pattern": "mysql"},
            {"query": "mysql_up", "step": "30s"},
        ],
    )
    client = PrometheusMCPClient(
        PrometheusMCPServerSettings(
            url="https://prometheus.example.test/sse",
            headers={},
            prompts=PROMETHEUS_PROMPTS,
            tool_policies=(
                PrometheusMCPToolPolicy(
                    name="execute_range_query",
                    capability="range_query",
                    start_argument_path=("start",),
                    end_argument_path=("end",),
                    timestamp_encoding="rfc3339",
                ),
                PrometheusMCPToolPolicy(
                    name="list_metrics",
                    capability="catalog",
                ),
            ),
        ),
        model,
        max_agent_steps=8,
    )

    result = await client.collect_alert_window(_mysql_slow_context())

    assert [name for name, _arguments in CatalogAndRangeSession.calls] == [
        "execute_range_query",
        "list_metrics",
        "list_metrics",
    ]
    assert len(model.messages) == 3
    assert result.has_monitoring_data is False
    assert result.call_limit_reached is False
    assert result.termination_reason == "no_discriminating_evidence"
    assert result.inconclusive_reason is not None
    assert "未发现与当前告警信号语义相关的指标" in result.inconclusive_reason


@pytest.mark.asyncio
async def test_prometheus_client_deduplicates_empty_calls_without_spending_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {"isError": False},
        {"isError": False},
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
        ],
        arguments=[
            {"query": "up"},
            {"query": "up"},
            {"query": "mysql_up"},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert [arguments["query"] for _, arguments in _SequencedSession.calls] == [
        "up",
        "mysql_up",
    ]
    assert result.model_tool_calls == (
        "arbitrary_monitoring_tool",
        "arbitrary_monitoring_tool",
    )
    assert [item["outcome"] for item in result.tool_attempts] == [
        "no_data",
        "host_rejected_duplicate",
        "no_data",
    ]
    first_feedback = next(
        payload
        for message in model.messages[1]
        if isinstance(message.get("content"), str)
        and message["content"].lstrip().startswith("{")
        for payload in [json.loads(message["content"])]
        if "host_control" in payload
    )
    assert first_feedback["host_control"]["remote_calls_used"] == 1
    assert first_feedback["host_control"]["remote_calls_remaining"] == 1


@pytest.mark.asyncio
async def test_prometheus_stops_after_three_distinct_empty_range_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {"isError": False},
        {"isError": False},
        {"isError": False},
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
        ],
        arguments=[
            {"query": "mysql_up"},
            {"query": "mysql_threads_running"},
            {"query": "mysql_global_status_questions"},
            {"query": "mysql_global_status_slow_queries"},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=8,
    )

    result = await client.collect_alert_window(_mysql_context())

    assert len(_SequencedSession.calls) == 3
    assert len(model.messages) == 3
    assert result.call_limit_reached is False
    assert result.termination_reason == "no_discriminating_evidence"
    assert result.inconclusive_reason is not None
    assert "3 次不同的告警窗口范围查询且均无样本" in result.inconclusive_reason


@pytest.mark.asyncio
async def test_prometheus_client_binds_policy_window_before_remote_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {"structuredContent": {"series": [{"value": 41}]}},
        {"structuredContent": {"series": [{"value": 42}]}},
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ],
        arguments=[
            {"query": "up"},
            {
                "query": "up",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=3,
    )

    result = await client.collect_alert_window(_context())

    assert _SequencedSession.calls == [
        (
            "arbitrary_monitoring_tool",
            {
                "query": "up",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
        )
    ]
    assert result.responses[0]["model_arguments"] == {"query": "up"}
    assert result.responses[0]["window_verification"] == "exact"
    assert result.has_monitoring_data is True
    assert result.tool_attempts[1]["outcome"] == "host_rejected_duplicate"


def test_prometheus_factory_uses_outer_tool_timeout_for_sse_idle_timeout(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    prompts = _write_prompt_files(tmp_path, "prometheus")
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "readOnly": True,
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "headers": {},
                        "prompts": prompts,
                        "toolPolicies": {
                            "arbitrary_monitoring_tool": {
                                "capability": "range_query",
                                "startArgument": "start",
                                "endArgument": "end",
                                "timestampEncoding": "rfc3339",
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        _env_file=None,
        ai_provider="openai_compatible",
        ai_api_key="test-key",
        ai_model="test-model",
        mcp_settings_path=settings_path,
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
        prometheus_mcp_tool_timeout_seconds=777,
    )

    tool = factory_module._build_prometheus_mcp_tool(
        settings,
        _SequenceModel(["arbitrary_monitoring_tool"]),  # type: ignore[arg-type]
    )

    assert tool is not None
    assert tool.client.sse_read_timeout_seconds == 777


@pytest.mark.asyncio
async def test_prometheus_client_preserves_both_model_selection_errors_as_no_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AlwaysFailingModel:
        def __init__(self) -> None:
            self.attempts = 0

        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            del messages, tools
            self.attempts += 1
            raise RuntimeError(
                f"provider returned no tool call request-{self.attempts}"
            )

    _FakeSession.calls = []
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    model = AlwaysFailingModel()
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())
    evidence = await PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(result)
    ).execute(ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME), _context())

    assert model.attempts == 2
    assert _FakeSession.calls == []
    assert result.termination_reason == "model_error_no_result"
    assert result.termination_error_type == "PrometheusMCPModelError"
    assert "request-1" in (result.termination_error_detail or "")
    assert "request-2" in (result.termination_error_detail or "")
    diagnostics = result.tool_attempts[-1]["diagnostics"]
    assert diagnostics["first_error"].endswith("request-1")
    assert diagnostics["second_error"].endswith("request-2")
    assert diagnostics["remote_calls_remaining"] == 2
    assert evidence.status == ToolStatus.NO_DATA
    assert "连续两次未能选择有效工具" in evidence.summary


@pytest.mark.asyncio
async def test_prometheus_client_records_repeated_premature_finish_as_model_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(
            [
                "finish_prometheus_investigation",
                "finish_prometheus_investigation",
                "finish_prometheus_investigation",
                "finish_prometheus_investigation",
            ]
        ),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert _FakeSession.calls == []
    assert result.has_monitoring_data is False
    assert result.finished_by_model is False
    assert result.call_limit_reached is False
    assert result.termination_reason == "model_error_no_result"
    assert result.termination_error_type == "PrometheusMCPModelError"
    assert result.tool_attempts[-1]["outcome"] == "model_selection_error"
    assert result.tool_attempts[-1]["remote_calls_used"] == 0


@pytest.mark.asyncio
async def test_prometheus_client_returns_standard_mcp_error_text_to_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {
            "isError": True,
            "content": [{"type": "text", "text": "invalid range selector"}],
        },
        {"structuredContent": {"series": [{"value": 7}]}},
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ],
        arguments=[
            {"query": "up"},
            {"query": "mysql_up"},
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=3,
    )

    result = await client.collect_alert_window(_context())

    assert len(_SequencedSession.calls) == 2
    assert len(result.responses) == 1
    assert result.raw_call_results == (
        {
            "isError": True,
            "content": [{"type": "text", "text": "invalid range selector"}],
        },
        {"structuredContent": {"series": [{"value": 7}]}},
    )
    assert [item["outcome"] for item in result.tool_attempts] == [
        "tool_error",
        "observation",
    ]
    error_feedback = next(
        payload
        for message in model.messages[1]
        if isinstance(message.get("content"), str)
        and message["content"].lstrip().startswith("{")
        for payload in [json.loads(message["content"])]
        if "monitoring_result" in payload
    )
    assert error_feedback["monitoring_result"]["tool_error"] == "PrometheusMCPToolError"
    assert "invalid range selector" in error_feedback["monitoring_result"]["detail"]


@pytest.mark.asyncio
async def test_prometheus_evidence_reconnects_after_first_session_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        ConnectionError("stream closed"),
        {"structuredContent": {"series": [{"value": 7}]}},
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ]
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=3,
    )

    evidence = await PrometheusMCPEvidenceTool(client).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _context(),
    )

    assert len(_SequencedSession.calls) == 2
    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["mcp_session_attempts"] == 2
    assert (
        evidence.structured_data["reconnect_error_type"]
        == PrometheusMCPProtocolError.__name__
    )


@pytest.mark.asyncio
async def test_prometheus_reconnects_when_only_catalog_precedes_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {"structuredContent": {"metrics": ["mysql_up"]}},
        ConnectionError("stream closed"),
        {"structuredContent": {"series": [{"value": 7}]}},
    ]
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _SequencedSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ],
        arguments=[
            {"operation": "list"},
            {"query": "up", "attempt": 1},
            {
                "query": "up",
                "attempt": 2,
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=3,
    )

    evidence = await PrometheusMCPEvidenceTool(client).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _context(),
    )

    assert len(_SequencedSession.calls) == 3
    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["mcp_session_attempts"] == 2
    monitoring_results = evidence.structured_data["monitoring_results"]
    assert len(monitoring_results) == 2
    assert sum(
        item["has_monitoring_observation"] is True for item in monitoring_results
    ) == 1


@pytest.mark.asyncio
async def test_prometheus_evidence_does_not_reconnect_for_model_failure() -> None:
    class ModelFailingClient:
        def __init__(self) -> None:
            self.calls = 0

        async def collect_alert_window(
            self, context: InvestigationContext
        ) -> PrometheusMCPQueryResult:
            del context
            self.calls += 1
            raise PrometheusMCPModelError("model unavailable")

    client = ModelFailingClient()
    tool = PrometheusMCPEvidenceTool(client)  # type: ignore[arg-type]

    with pytest.raises(PrometheusMCPModelError, match="model unavailable"):
        await tool.execute(
            ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
            _context(),
        )

    assert client.calls == 1


@pytest.mark.asyncio
async def test_prometheus_client_preserves_response_after_later_model_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"series": [{"value": 42}]}}
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(["arbitrary_monitoring_tool"]),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())
    evidence = await PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(result)
    ).execute(ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME), _context())

    assert len(result.responses) == 1
    assert result.partial is True
    assert result.termination_reason == "model_error_after_partial_result"
    assert result.termination_error_type == "PrometheusMCPModelError"
    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["partial"] is True
    assert (
        evidence.structured_data["termination_reason"]
        == "model_error_after_partial_result"
    )


@pytest.mark.asyncio
async def test_prometheus_client_keeps_completed_response_when_sse_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingSSEContext(_AsyncContext):
        async def __aexit__(self, *args: Any) -> None:
            raise ExceptionGroup("SSE reader failed", [ConnectionError("stream closed")])

    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"series": [{"value": 42}]}}
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: FailingSSEContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"]
        ),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert len(result.responses) == 1
    assert result.partial is False
    assert result.finished_by_model is True
    assert result.termination_reason == "finished_by_model"
    assert result.termination_error_type is None




@pytest.mark.asyncio
async def test_prometheus_large_observation_is_preserved_and_remains_finishable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    _FakeSession.result = {
        "structuredContent": {
            "series": [
                {
                    "values": [
                        [1786067700, "1"],
                        [1786068000, "x" * 30_000],
                    ]
                }
            ]
        }
    }
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"]
        ),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert result.finished_by_model is True
    assert result.has_monitoring_data is True
    assert result.responses[0]["window_verification"] == "exact"
    values = result.responses[0]["result"]["series"][0]["values"]
    assert values[1][1] == "x" * 30_000


@pytest.mark.asyncio
async def test_prometheus_evidence_record_keeps_untruncated_raw_call_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    large_content = "raw-prometheus-content:" + ("x" * 250_000)
    raw_call_result = {
        "_meta": {"trace_id": "trace-large-result"},
        "content": [{"type": "text", "text": large_content}],
        "structuredContent": {
            "series": [
                {
                    "metric": {"job": "mysql"},
                    "values": [[1786067700, "1"], [1786068000, "2"]],
                }
            ]
        },
        "isError": False,
    }
    _FakeSession.calls = []
    _FakeSession.result = raw_call_result
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"]
        ),
        max_agent_steps=2,
    )
    executor = ToolExecutor(
        InvestigationToolRegistry([PrometheusMCPEvidenceTool(client)])
    )

    record = await executor.execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _context(),
    )

    assert record.status == ToolStatus.SUCCESS
    assert record.truncated is False
    assert record.structured_data["raw_call_results"] == [raw_call_result]
    preserved = record.structured_data["raw_call_results"][0]["content"][0]["text"]
    assert preserved == large_content
    assert len(preserved) == len(large_content)


class _RecordingPrometheusClient:
    def __init__(self, result: PrometheusMCPQueryResult) -> None:
        self.result = result

    async def collect_alert_window(self, context: InvestigationContext) -> PrometheusMCPQueryResult:
        assert context.alert.occurred_at == ALERT_TIME
        return self.result


def test_prometheus_outer_tool_declares_strict_empty_input_schema() -> None:
    assert PrometheusMCPEvidenceTool.input_schema == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }


@pytest.mark.asyncio
async def test_prometheus_evidence_marks_unmonitored_database_as_skipped() -> None:
    result = PrometheusMCPQueryResult(
        responses=(
            {
                "tool_name": "get_targets",
                "capability": "target_discovery",
                "has_monitoring_observation": False,
                "monitoring_scope_status": "out_of_scope",
                "root_cause_eligible": False,
                "result": {"data": {"activeTargets": []}},
            },
        ),
        window_start=ALERT_TIME.replace(minute=55),
        window_end=ALERT_TIME,
        model_tool_calls=("get_targets",),
        model_request_ids=(),
        call_limit_reached=False,
        finished_by_model=False,
        termination_reason="database_not_monitored",
        inconclusive_reason="当前仅发现 OceanBase 监控目标。",
        monitoring_scope_status="out_of_scope",
        monitoring_scope_reason=(
            "Prometheus 目标清单仅识别到 oceanbase，不包含告警数据库类型 mysql。"
        ),
        monitored_database_engines=("oceanbase",),
    )

    evidence = await PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert evidence.status == ToolStatus.SKIPPED
    assert "已跳过后续指标查询" in evidence.summary
    assert evidence.structured_data["reason_code"] == "database_not_monitored"
    assert evidence.structured_data["root_cause_eligible"] is False
    assert (
        evidence.structured_data["root_cause_ineligible_reason"]
        == "database_not_monitored"
    )


@pytest.mark.asyncio
async def test_prometheus_outer_tool_rejects_caller_parameters() -> None:
    result = PrometheusMCPQueryResult(
        responses=(),
        window_start=ALERT_TIME.replace(minute=55),
        window_end=ALERT_TIME,
        model_tool_calls=(),
        model_request_ids=(),
        call_limit_reached=False,
        finished_by_model=False,
    )
    client = _RecordingPrometheusClient(result)

    with pytest.raises(PrometheusMCPReadOnlyViolation, match="alert context"):
        await PrometheusMCPEvidenceTool(client).execute(  # type: ignore[arg-type]
            ToolExecutionRequest(
                tool_name=PROMETHEUS_METRICS_TOOL_NAME,
                parameters={"start": "caller-controlled"},
            ),
            _context(),
        )


@pytest.mark.asyncio
async def test_prometheus_evidence_at_budget_is_success_only_when_monitoring_result_exists(
) -> (
    None
):
    base = {
        "window_start": ALERT_TIME.replace(minute=55),
        "window_end": ALERT_TIME,
        "model_tool_calls": ("query", "query"),
        "model_request_ids": (),
        "call_limit_reached": True,
        "finished_by_model": False,
    }
    context = _context()
    request = ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME)
    usable_tool = PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(
                PrometheusMCPQueryResult(
                    responses=(
                        {
                            "tool_name": "query",
                            "has_monitoring_observation": True,
                            "window_verification": "exact",
                            "result": {"value": 1},
                        },
                    ),
                **base,
            )
        )  # type: ignore[arg-type]
    )
    empty_tool = PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(PrometheusMCPQueryResult(responses=(), **base))  # type: ignore[arg-type]
    )

    usable = await usable_tool.execute(request, context)
    empty = await empty_tool.execute(request, context)

    assert usable.status == ToolStatus.SUCCESS
    assert usable.structured_data["root_cause_eligible"] is True
    assert usable.structured_data["call_limit_reached"] is True
    assert "已达到 MCP 调用上限" in usable.summary
    assert empty.status == ToolStatus.NO_DATA
    assert empty.structured_data["root_cause_eligible"] is False
    assert empty.summary == "Prometheus MCP 调用次数达到上限，实时证据不足。"


@pytest.mark.asyncio
async def test_prometheus_no_data_trace_preserves_complete_results() -> None:
    tool_attempts: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    for index in range(8):
        catalog = index in {1, 2}
        arguments = (
            {"filter_pattern": "mysql.*slow" if index == 1 else "mysql"}
            if catalog
            else {
                "query": (
                    "rate(mysql_global_status_slow_queries"
                    '{cluster="mysql-prod-pcm",instance="100.84.97.117:3306"}[5m])'
                ),
                "start": "2026-08-11T08:22:42+00:00",
                "end": "2026-08-11T08:27:42+00:00",
                "step": "30s",
            }
        )
        capability = "catalog" if catalog else "range_query"
        outcome = "auxiliary_result" if catalog else "no_data"
        tool_attempts.append(
            {
                "tool_name": "list_metrics" if catalog else "execute_range_query",
                "model_arguments": arguments,
                "arguments": arguments,
                "capability": capability,
                "outcome": outcome,
                "window_verification": "unknown" if catalog else "exact",
                "target_verification": "not_applicable" if catalog else "unknown",
                "target_mismatch_reasons": [],
            }
        )
        result_payload: dict[str, Any]
        if index == 1:
            result_payload = {"metrics": [], "total_count": 0}
        elif index == 2:
            result_payload = {
                "metrics": [
                    "mysql_output_process_metrics_count",
                    "mysql_output_write_sql_count",
                    "mysql_sls_output_discard_count",
                ],
                "total_count": 3,
            }
        else:
            result_payload = {
                "resultType": "matrix",
                "result": [],
                "links": [{"href": "http://prometheus.invalid/" + "x" * 4_000}],
            }
        responses.append(
            {
                "tool_name": "list_metrics" if catalog else "execute_range_query",
                "model_arguments": arguments,
                "arguments": arguments,
                "capability": capability,
                "has_monitoring_observation": False,
                "window_verification": "unknown" if catalog else "exact",
                "target_verification": "not_applicable" if catalog else "unknown",
                "target_mismatch_reasons": [],
                "root_cause_eligible": False,
                "root_cause_ineligible_reason": (
                    "auxiliary_result" if catalog else "no_observation"
                ),
                "result": result_payload,
            }
        )
    result = PrometheusMCPQueryResult(
        responses=tuple(responses),
        window_start=datetime(2026, 8, 11, 8, 22, 42, tzinfo=UTC),
        window_end=datetime(2026, 8, 11, 8, 27, 42, tzinfo=UTC),
        model_tool_calls=tuple(item["tool_name"] for item in tool_attempts),
        model_request_ids=tuple(f"request-{index}" for index in range(8)),
        call_limit_reached=True,
        finished_by_model=False,
        tool_attempts=tuple(tool_attempts),
        termination_reason="call_limit_reached",
    )
    tool = PrometheusMCPEvidenceTool(_RecordingPrometheusClient(result))  # type: ignore[arg-type]
    executor = ToolExecutor(InvestigationToolRegistry([tool]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_slow_context(),
    )

    serialized = json.dumps(record.structured_data, ensure_ascii=False, default=str)
    assert record.status == ToolStatus.NO_DATA
    assert record.truncated is False
    assert len(serialized) > 12_000
    assert record.structured_data["schema_version"] == "prometheus-evidence-v2"
    assert record.structured_data["root_cause_eligible"] is False
    assert record.structured_data["root_cause_ineligible_reason"] != ("evidence_payload_truncated")
    assert record.structured_data["catalog_inventory"]["metric_count"] == 3
    assert len(record.structured_data["tool_attempts"]) == 8
    assert len(record.structured_data["monitoring_results"]) == 8
    assert "prometheus.invalid" in serialized


@pytest.mark.asyncio
async def test_prometheus_target_mismatch_is_preserved_but_is_no_data() -> None:
    result = PrometheusMCPQueryResult(
        responses=(
            {
                "tool_name": "query_range",
                "has_monitoring_observation": True,
                "window_verification": "exact",
                "target_verification": "mismatch",
                "target_mismatch_reasons": ["监控序列标识为 oceanbase"],
                "result": {"series": [{"metric": {"job": "oceanbase"}, "value": 95}]},
            },
        ),
        window_start=ALERT_TIME.replace(minute=55),
        window_end=ALERT_TIME,
        model_tool_calls=("query_range",),
        model_request_ids=(),
        call_limit_reached=True,
        finished_by_model=False,
    )

    evidence = await PrometheusMCPEvidenceTool(  # type: ignore[arg-type]
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert result.has_monitoring_data is False
    assert evidence.status == ToolStatus.NO_DATA
    assert evidence.structured_data["target_mismatch_count"] == 1
    assert evidence.structured_data["required_target"]["database_engine"] == "mysql"
    assert evidence.structured_data["root_cause_ineligible_reason"] == "target_mismatch"
    assert "与告警目标不一致" in evidence.summary


@pytest.mark.asyncio
async def test_prometheus_partial_result_is_not_root_cause_eligible() -> None:
    result = PrometheusMCPQueryResult(
        responses=(
            {
                "tool_name": "query",
                "has_monitoring_observation": True,
                "window_verification": "exact",
                "result": {"value": 1},
            },
        ),
        window_start=ALERT_TIME.replace(minute=55),
        window_end=ALERT_TIME,
        model_tool_calls=("query",),
        model_request_ids=(),
        call_limit_reached=False,
        finished_by_model=False,
        partial=True,
        termination_reason="sse_error_after_partial_result",
    )

    evidence = await PrometheusMCPEvidenceTool(  # type: ignore[arg-type]
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _context(),
    )

    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["partial"] is True
    assert evidence.structured_data["root_cause_eligible"] is False
    assert (
        evidence.structured_data["root_cause_ineligible_reason"]
        == "partial_evidence"
    )


@pytest.mark.asyncio
async def test_prometheus_catalog_and_empty_series_are_not_root_cause_evidence() -> None:
    base = {
        "window_start": ALERT_TIME.replace(minute=55),
        "window_end": ALERT_TIME,
        "model_tool_calls": ("list_metrics", "query_range"),
        "model_request_ids": (),
        "call_limit_reached": False,
        "finished_by_model": False,
        "termination_reason": "decision_limit_reached",
    }
    result = PrometheusMCPQueryResult(
        responses=(
            {"tool_name": "list_metrics", "result": {"metrics": ["mysql_up"]}},
            {
                "tool_name": "list_metrics_alternate",
                "result": {"data": ["mysql_up", "mysql_threads_running"]},
            },
            {
                "tool_name": "query_range",
                "result": {"series": [{"metric": {"job": "mysql"}, "values": []}]},
            },
        ),
        **base,
    )

    evidence = await PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _context(),
    )

    assert result.has_monitoring_data is False
    assert evidence.status == ToolStatus.NO_DATA
    assert evidence.structured_data["root_cause_eligible"] is False


@pytest.mark.asyncio
async def test_strategy_does_not_add_prometheus_without_agent_selection() -> None:
    strategy = await DefaultInvestigationStrategyProvider(
        available_tools=["alert_context", PROMETHEUS_METRICS_TOOL_NAME],
        prometheus_tool_timeout_seconds=321,
    ).select(_context().alert)

    assert strategy.tool_plan == []
