from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import app.adapters.prometheus_harness as prometheus_harness_module
from app.adapters.investigation import (
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
    PrometheusMCPServerSettings,
    has_monitoring_observation,
    load_prometheus_mcp_server_settings,
)
from app.config import RUNTIME_SETTINGS_KEYS, Settings
from app.domain.models import (
    DatabaseTarget,
    InvestigationContext,
    NormalizedAlert,
    Severity,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import MCPPromptBundle

ALERT_TIME = datetime(2026, 8, 7, 2, 0, tzinfo=UTC)
ALERT_WINDOW_START = ALERT_TIME - timedelta(minutes=5)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS_PROMPTS = MCPPromptBundle(
    role="Prometheus metrics investigator",
    purpose="Collect relevant Prometheus evidence.",
    workflow="Choose discovered tools from their descriptions and schemas.",
    safety="All investigation calls must have read-only intent.",
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
) -> PrometheusMCPServerSettings:
    return PrometheusMCPServerSettings(
        url="https://prometheus.example.test/sse",
        headers=headers or {},
        prompts=PROMETHEUS_PROMPTS,
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
    assert target["host_source"] == "canonical_alert.database.host"
    assert target["port_source"] == "canonical_alert.database.port"
    assert target["endpoint"] == "mysql-17:3306"
    assert target["instance_candidates"] == ["mysql-17:3306", "mysql-17"]


def test_prometheus_target_marks_flashduty_detail_endpoint_as_authoritative() -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "source": "flashduty",
            "database": context.alert.database.model_copy(update={"port": 3306}),
        }
    )

    target = PrometheusMCPClient.monitoring_target_context(alert)

    assert target["host"] == "mysql-17"
    assert target["port"] == 3306
    assert target["host_source"] == "flashduty_alert_detail.alarm_host"
    assert target["port_source"] == "flashduty_alert_detail.alarm_port"


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
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "headers": {},
                        "prompts": prompt_references,
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


def test_prometheus_settings_are_deployment_only_without_provider_call_budget() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
        prometheus_mcp_api_key="test-secret",
        prometheus_mcp_api_key_header="X-API-Key",
    )

    assert settings.prometheus_mcp_enabled is True
    assert "prometheus_mcp_max_agent_steps" not in RUNTIME_SETTINGS_KEYS
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


def test_prometheus_mcp_preserves_business_error_with_successful_protocol_envelope() -> None:
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

    assert PrometheusMCPClient.result_payload(raw_result) == {
        "status": "failed",
        "message": "invalid PromQL range",
    }


def test_prometheus_mcp_preserves_json_business_error_in_text_content() -> None:
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

    assert PrometheusMCPClient.result_payload(raw_result) == {
        "status": "error",
        "message": "temporary backend failure",
    }


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
    opaque = "x" * 50_000
    raw_result = type(
        "ToolResult",
        (),
        {
            "model_dump": lambda _self, **kwargs: {
                "_meta": {
                    "trace_id": "trace-1",
                    "api_key": "mcp-owned-secret",
                    "opaque": opaque,
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
            "api_key": "mcp-owned-secret",
            "opaque": opaque,
            "by_alias": True,
        },
        "content": [
            {"type": "text", "text": "human-readable monitoring result"}
        ],
        "structuredContent": {"series": [{"value": 42}]},
        "isError": False,
    }


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
    return _server_settings()


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


def test_prometheus_exposes_discovered_tools_regardless_of_annotations() -> None:
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

    converted = client.discovered_model_tools(
        [
            {
                "name": "arbitrary_monitoring_tool",
                "inputSchema": schema,
                "annotations": {"destructiveHint": True, "readOnlyHint": False},
            },
            {
                "name": "second_monitoring_tool",
                "inputSchema": schema,
            }
        ]
    )

    assert [item["function"]["name"] for item in converted] == [
        "arbitrary_monitoring_tool",
        "second_monitoring_tool",
    ]


def test_prometheus_finish_tool_records_monitoring_scope_contract() -> None:
    client = PrometheusMCPClient(_server_settings(), _SequenceModel([]))

    finish = client.model_tools_for_state(model_tool_list=[])[0]["function"]

    assert finish["name"] == "finish_prometheus_investigation"
    schema = finish["parameters"]
    assert schema["properties"]["monitoring_scope_status"]["enum"] == [
        "in_scope",
        "out_of_scope",
        "unknown",
    ]
    assert schema["required"] == ["monitoring_scope_status", "reason"]


def test_prometheus_model_observation_is_bounded_deterministic_projection() -> None:
    payload = {
        "data": {
            "api_key": "mcp-owned-secret",
            "activeTargets": [
                {
                    "labels": {
                        "job": "oceanbase",
                        "instance": "ob-prod-1:2882",
                    },
                    "scrapeUrl": "http://ob-prod-1:8088/metrics",
                }
            ],
            "result": [
                {
                    "metric": {"__name__": "ob_cpu_usage", "job": "oceanbase"},
                    "values": [[2, "90"], [1, "80"]],
                }
            ],
            "opaque_log": "x" * 1_000,
        }
    }

    projection = PrometheusMCPClient.project_model_observation(
        payload,
        alert=_mysql_context().alert,
    )

    assert projection["series_count"] == 1
    assert projection["sample_count"] == 2
    assert projection["series"][0]["avg"] == 85
    assert projection["series"][0]["latest"] == 90
    assert projection["series"][0]["delta"] == 10
    assert projection["series"][0]["metric"] == {"__name__": "ob_cpu_usage"}
    serialized = json.dumps(projection, ensure_ascii=False)
    assert "activeTargets" not in serialized
    assert "mcp-owned-secret" not in serialized
    assert "ob-prod-1" not in serialized
    assert "x" * 1_000 not in serialized
    assert len(serialized) < 10_000


def test_prometheus_query_target_text_does_not_attribute_unlabelled_series() -> None:
    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": {"__name__": "mysql_threads_running"},
                        "values": [[1786067700, "8"], [1786068000, "15"]],
                    }
                ]
            }
        },
        arguments={
            "query": 'mysql_threads_running{instance="mysql-17:3306"}',
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=_mysql_context().alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is None


def test_prometheus_range_projection_prefers_database_target_over_collector_instance() -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "cluster": "mysql-prod-devops",
            "database": context.alert.database.model_copy(
                update={
                    "host": "100.84.97.124",
                    "instance": "100.84.97.124:3311",
                    "port": 3311,
                }
            ),
        }
    )
    raw_result = {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    {
                        "resultType": "matrix",
                        "result": [
                            {
                                "metric": {
                                    "__name__": "mysql:cpu:usage",
                                    "group": "mysql-prod-devops",
                                    "instance": "100.84.97.124:5706",
                                    "port": "3311",
                                    "server": "server-mysql_124",
                                    "service": "mysql",
                                    "target": "100.84.97.124:3311",
                                },
                                "values": [
                                    [1786067700, "10191762286"],
                                    [1786068000, "10191964447"],
                                ],
                            }
                        ],
                    }
                ),
            }
        ],
        "isError": False,
        "structuredContent": None,
    }

    payload = PrometheusMCPClient.call_result(raw_result).payload
    projection = PrometheusMCPClient.project_alert_window_range(
        payload,
        arguments={
            "query": 'mysql:cpu:usage{target="100.84.97.124:3311"}',
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
            "step": "30s",
        },
        alert=alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is not None
    assert projection["target_match"]["authoritative_fields"] == [
        "database.endpoint",
        "database.host",
    ]
    assert projection["timeseries"]["series_count"] == 1
    assert projection["timeseries"]["sample_count"] == 2
    assert projection["timeseries"]["series"][0] == {
        "metric": {"__name__": "mysql:cpu:usage"},
        "sample_count": 2,
        "min": 10191762286,
        "max": 10191964447,
        "avg": 10191863366.5,
        "latest": 10191964447,
        "delta": 202161,
    }


def test_prometheus_range_projection_rejects_wrong_database_target_over_instance() -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "database": context.alert.database.model_copy(
                update={
                    "host": "100.84.97.124",
                    "instance": "100.84.97.124:3311",
                    "port": 3311,
                }
            ),
        }
    )

    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {
                        "__name__": "mysql:cpu:usage",
                        "instance": "100.84.97.124:3311",
                        "port": "3311",
                        "target": "100.84.97.125:3311",
                    },
                    "values": [[1786067700, "8"], [1786068000, "15"]],
                }
            ],
        },
        arguments={
            "query": 'mysql:cpu:usage{target="100.84.97.124:3311"}',
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is None


def test_prometheus_range_projection_keeps_only_series_matching_alert_labels() -> None:
    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": {
                            "__name__": "mysql_threads_running",
                            "instance": "mysql-17:3306",
                        },
                        "values": [[1786067700, "8"], [1786068000, "15"]],
                    },
                    {
                        "metric": {
                            "__name__": "mysql_threads_running",
                            "instance": "other-db:3306",
                            "api_key": "other-series-secret",
                        },
                        "values": [[1786067700, "800"], [1786068000, "1500"]],
                    },
                ]
            }
        },
        arguments={
            "query": "mysql_threads_running",
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=_mysql_context().alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is not None
    assert projection["excluded_series_count"] == 1
    assert projection["timeseries"]["series_count"] == 1
    assert projection["timeseries"]["sample_count"] == 2
    assert projection["timeseries"]["series"][0]["max"] == 15
    assert "other-series-secret" not in json.dumps(projection, ensure_ascii=False)


@pytest.mark.parametrize(
    "metric",
    [
        {
            "__name__": "mysql_threads_running",
            "instance": "mysql-17:3307",
        },
        {
            "__name__": "mysql_threads_running",
            "instance": "mysql-17:3306",
            "database": "billing",
        },
    ],
    ids=["wrong_port", "same_host_wrong_database"],
)
def test_prometheus_range_projection_rejects_conflicting_target_labels(
    metric: dict[str, str],
) -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "database": context.alert.database.model_copy(
                update={"database": "orders", "port": 3306}
            )
        }
    )

    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": metric,
                        "values": [[1786067700, "8"], [1786068000, "15"]],
                    }
                ]
            }
        },
        arguments={
            "query": "mysql_threads_running",
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is None


@pytest.mark.parametrize(
    "metric",
    [
        {
            "__name__": "mysql_threads_running",
            "cluster": "mysql-prod",
        },
        {
            "__name__": "mysql_threads_running",
            "database": "orders",
        },
    ],
    ids=["cluster_only", "database_only"],
)
def test_prometheus_range_projection_requires_host_label_when_alert_has_host(
    metric: dict[str, str],
) -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "cluster": "mysql-prod",
            "database": context.alert.database.model_copy(
                update={"database": "orders", "port": 3306}
            ),
        }
    )

    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": metric,
                        "values": [[1786067700, "8"], [1786068000, "15"]],
                    }
                ]
            }
        },
        arguments={
            "query": "mysql_threads_running",
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is None


def test_prometheus_range_projection_uses_other_identity_when_alert_has_no_host() -> None:
    context = _mysql_context()
    alert = context.alert.model_copy(
        update={
            "cluster": "mysql-prod",
            "database": context.alert.database.model_copy(
                update={
                    "host": None,
                    "port": None,
                    "instance": None,
                    "database": "orders",
                }
            ),
        }
    )

    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": {
                            "__name__": "mysql_threads_running",
                            "cluster": "mysql-prod",
                            "database": "orders",
                        },
                        "values": [[1786067700, "8"], [1786068000, "15"]],
                    }
                ]
            }
        },
        arguments={
            "query": "mysql_threads_running",
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is not None
    assert projection["target_match"]["authoritative_fields"] == [
        "cluster",
        "database.database",
    ]


def test_prometheus_instant_value_is_not_a_range_projection() -> None:
    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": {
                            "__name__": "mysql_threads_running",
                            "instance": "mysql-17:3306",
                        },
                        "value": [1786068000, "15"],
                    }
                ]
            }
        },
        arguments={
            "query": 'mysql_threads_running{instance="mysql-17:3306"}',
            "start": "2026-08-07T01:55:00+00:00",
            "end": "2026-08-07T02:00:00+00:00",
        },
        alert=_mysql_context().alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is None


@pytest.mark.parametrize(
    ("arguments", "values"),
    [
        (
            {
                "start": "2026-08-07T01:54:59+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            [[1786067700, "8"], [1786068000, "15"]],
        ),
        (
            {
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            [[1786067699, "8"], [1786068000, "15"]],
        ),
    ],
    ids=["non_exact_argument_window", "sample_outside_window"],
)
def test_prometheus_range_projection_requires_exact_window_and_in_window_samples(
    arguments: dict[str, Any],
    values: list[list[Any]],
) -> None:
    projection = PrometheusMCPClient.project_alert_window_range(
        {
            "data": {
                "result": [
                    {
                        "metric": {
                            "__name__": "mysql_threads_running",
                            "instance": "mysql-17:3306",
                        },
                        "values": values,
                    }
                ]
            }
        },
        arguments=arguments,
        alert=_mysql_context().alert,
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
    )

    assert projection is None


@pytest.mark.asyncio
async def test_prometheus_exposes_all_tools_during_target_discovery(
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
    )

    result = await client.collect_alert_window(_mysql_context())

    assert _TargetAwareSession.calls == [("get_targets", {})]
    expected_tools = {
        "execute_range_query",
        "finish_prometheus_investigation",
        "get_metric_metadata",
        "get_targets",
        "list_metrics",
    }
    assert model.available_tools == [expected_tools, expected_tools]
    assert result.monitoring_scope_status == "out_of_scope"
    assert result.monitoring_scope_reason == "目标清单仅包含 OceanBase，告警数据库为 MySQL。"
    assert result.termination_reason == "database_not_monitored"
    assert result.has_monitoring_data is False


@pytest.mark.asyncio
async def test_prometheus_model_can_choose_discovery_and_range_tools_in_any_order(
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
                                "svr_ip": "10.126.106.14",
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
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _target_aware_settings(),
        model,
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
    expected_tools = {
        "execute_range_query",
        "finish_prometheus_investigation",
        "get_metric_metadata",
        "get_targets",
        "list_metrics",
    }
    assert all(available == expected_tools for available in model.available_tools)
    range_definition = next(
        item
        for item in model.tool_definitions[4]
        if item["function"]["name"] == "execute_range_query"
    )
    assert range_definition["function"]["parameters"]["required"] == [
        "query",
        "start",
        "end",
    ]
    assert _TargetAwareSession.calls[-1][1] == {
        "query": 'ob_data_disk_usage_percent{cluster="sc_store_prod"}',
        "start": "2026-08-07T01:55:00+00:00",
        "end": "2026-08-07T02:00:00+00:00",
    }
    assert result.monitoring_scope_status == "not_checked"
    assert result.has_monitoring_data is True
    assert result.finished_by_model is True


def test_prometheus_always_exposes_all_discovered_tools_and_finish() -> None:
    client = PrometheusMCPClient(_server_settings(), _SequenceModel([]))
    tool_names = ("list_metrics", "arbitrary_monitoring_tool")
    tools = [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": name,
                "parameters": {"type": "object"},
            },
        }
        for name in tool_names
    ]
    reserved = client.model_tools_for_state(
        model_tool_list=tools,
    )

    expected = [
        "list_metrics",
        "arbitrary_monitoring_tool",
        "finish_prometheus_investigation",
    ]
    assert [item["function"]["name"] for item in reserved] == expected

    finishable = client.model_tools_for_state(
        model_tool_list=tools,
    )

    assert [item["function"]["name"] for item in finishable] == expected

    direct_range = client.model_tools_for_state(
        model_tool_list=tools,
    )

    assert [item["function"]["name"] for item in direct_range] == expected


@pytest.mark.asyncio
async def test_prometheus_host_forwards_model_tool_name_without_local_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnauthorizedModel:
        def __init__(self) -> None:
            self.calls = 0

        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            del messages, tools
            self.calls += 1
            if self.calls > 1:
                return MCPModelToolCall(
                    call_id=f"finish-{uuid4()}",
                    name="finish_prometheus_investigation",
                    arguments={},
                )
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
    )

    result = await client.collect_alert_window(_context())

    assert _FakeSession.calls == [("delete_prometheus_data", {"confirm": True})]
    assert result.has_monitoring_data is False
    assert result.responses[0]["projection_kind"] == "auxiliary"
    assert result.termination_reason == "finished_by_model"
    assert [item["outcome"] for item in result.tool_attempts] == ["result"]
    assert result.tool_attempts[0]["tool_name"] == "delete_prometheus_data"
    assert result.tool_attempts[0]["arguments"] == {"confirm": True}


@pytest.mark.asyncio
async def test_prometheus_client_keeps_calling_until_model_finishes(
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
            {"query": "mysql_up"},
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(headers={"X-API-Key": "test-secret"}),
        model,
        sse_read_timeout_seconds=654,
    )

    result = await client.collect_alert_window(_context())

    assert captured_sse["headers"] == {"X-API-Key": "test-secret"}
    assert captured_sse["sse_read_timeout"] == 654
    assert _FakeSession.calls == [
        ("arbitrary_monitoring_tool", {"query": "up"}),
        ("arbitrary_monitoring_tool", {"query": "mysql_up"}),
    ]
    assert result.model_tool_calls == (
        "arbitrary_monitoring_tool",
        "arbitrary_monitoring_tool",
    )
    assert len(result.responses) == 2
    assert result.finished_by_model is True
    assert result.has_monitoring_data is False
    assert all(
        item["projection_kind"] == "auxiliary" for item in result.responses
    )
    assert result.window_end == ALERT_TIME
    assert result.window_start.isoformat() == "2026-08-07T01:55:00+00:00"
    first_request = json.loads(model.messages[0][1]["content"])
    assert first_request["required_window"]["duration_seconds"] == 300


@pytest.mark.asyncio
async def test_prometheus_only_qualifies_target_matched_cross_engine_series(
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
            {
                "query": "ob_sysstat_cpu_usage",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            {
                "query": 'mysql_cpu_usage{instance="mysql-17:3306"}',
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
    )

    result = await client.collect_alert_window(_mysql_context())

    assert result.has_monitoring_data is True
    assert all("target_verification" not in item for item in result.responses)
    assert [item["root_cause_eligible"] for item in result.responses] == [False, True]
    assert [item["projection_kind"] for item in result.responses] == [
        "auxiliary",
        "alert_window_range",
    ]
    assert [item["outcome"] for item in result.tool_attempts] == [
        "result",
        "result",
    ]
    assert all(
        "finish_prometheus_investigation" in available
        for available in model.available_tools
    )


@pytest.mark.asyncio
async def test_prometheus_client_recovers_after_multiple_model_selection_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RecoveringModel:
        def __init__(self) -> None:
            self.attempts = 0

        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            del messages, tools
            self.attempts += 1
            if self.attempts <= 3:
                raise RuntimeError(
                    f"provider returned no tool call request-{self.attempts}"
                )
            return MCPModelToolCall(
                call_id="finish-after-model-repairs",
                name="finish_prometheus_investigation",
                arguments={},
            )

    _FakeSession.calls = []
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _FakeSession)
    model = RecoveringModel()
    client = PrometheusMCPClient(
        _server_settings(),
        model,
    )

    result = await client.collect_alert_window(_context())
    evidence = await PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(result)
    ).execute(ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME), _context())

    assert model.attempts == 4
    assert _FakeSession.calls == []
    assert result.finished_by_model is True
    assert result.termination_reason == "finished_by_model"
    assert result.termination_error_type is None
    assert result.tool_attempts == ()
    assert evidence.status == ToolStatus.NO_DATA
    assert "未返回可用监控结果" in evidence.summary


@pytest.mark.asyncio
async def test_prometheus_client_accepts_model_finish_without_monitoring_data(
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
            ["finish_prometheus_investigation"]
        ),
    )

    result = await client.collect_alert_window(_context())

    assert _FakeSession.calls == []
    assert result.has_monitoring_data is False
    assert result.finished_by_model is True
    assert result.termination_reason == "finished_by_model"
    assert result.termination_error_type is None
    assert result.tool_attempts == ()


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
    )

    result = await client.collect_alert_window(_context())

    assert len(_SequencedSession.calls) == 2
    assert len(result.responses) == 1
    assert [item["outcome"] for item in result.tool_attempts] == [
        "tool_error",
        "result",
    ]
    error_feedback = next(
        payload
        for message in model.messages[1]
        if isinstance(message.get("content"), str)
        and message["content"].lstrip().startswith("{")
        for payload in [json.loads(message["content"])]
        if payload.get("isError") is True
    )
    assert error_feedback == {
        "isError": True,
        "content": [{"type": "text", "text": "invalid range selector"}],
    }


@pytest.mark.asyncio
async def test_prometheus_evidence_reconnects_after_first_session_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        ConnectionError("stream closed"),
        {
            "structuredContent": {
                "series": [
                    {
                        "metric": {
                            "__name__": "mysql_up",
                            "instance": "mysql-17:3306",
                        },
                        "values": [[1786067700, "7"]],
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
            "finish_prometheus_investigation",
        ],
        arguments=[
            {
                "query": 'mysql_up{instance="mysql-17:3306"}',
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
    )

    evidence = await PrometheusMCPEvidenceTool(client).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
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
        {
            "structuredContent": {
                "series": [
                    {
                        "metric": {
                            "__name__": "mysql_up",
                            "instance": "mysql-17:3306",
                        },
                        "values": [[1786067700, "7"]],
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
            {"operation": "list"},
            {
                "query": 'mysql_up{instance="mysql-17:3306"}',
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
                "attempt": 1,
            },
            {},
        ],
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
    )

    evidence = await PrometheusMCPEvidenceTool(client).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert len(_SequencedSession.calls) == 3
    assert _SequencedSession.calls[1] == _SequencedSession.calls[2]
    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["mcp_session_attempts"] == 2
    monitoring_results = evidence.structured_data["monitoring_results"]
    assert len(monitoring_results) == 1
    assert monitoring_results[0]["projection_kind"] == "alert_window_range"


@pytest.mark.asyncio
async def test_prometheus_evidence_does_not_reconnect_for_model_failure() -> None:
    class ModelFailingClient:
        def __init__(self) -> None:
            self.calls = 0
            self.prompts = PROMETHEUS_PROMPTS

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
async def test_prometheus_client_preserves_response_while_repairing_model_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    _FakeSession.result = {
        "structuredContent": {
            "series": [
                {
                    "metric": {
                        "__name__": "mysql_up",
                        "instance": "mysql-17:3306",
                    },
                    "values": [[1786067700, "42"]],
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
    class ModelFailureThenFinish:
        def __init__(self) -> None:
            self.attempts = 0

        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            del messages, tools
            self.attempts += 1
            if self.attempts == 1:
                return MCPModelToolCall(
                    call_id="monitoring-result",
                    name="arbitrary_monitoring_tool",
                    arguments={
                        "query": 'mysql_up{instance="mysql-17:3306"}',
                        "start": "2026-08-07T01:55:00+00:00",
                        "end": "2026-08-07T02:00:00+00:00",
                    },
                )
            if self.attempts == 2:
                raise RuntimeError("temporary model selection failure")
            return MCPModelToolCall(
                call_id="finish-after-repair",
                name="finish_prometheus_investigation",
                arguments={},
            )

    model = ModelFailureThenFinish()
    client = PrometheusMCPClient(_server_settings(), model)

    result = await client.collect_alert_window(_mysql_context())
    evidence = await PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert len(result.responses) == 1
    assert model.attempts == 3
    assert result.partial is False
    assert result.finished_by_model is True
    assert result.termination_reason == "finished_by_model"
    assert result.termination_error_type is None
    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["partial"] is False
    assert evidence.structured_data["termination_reason"] == "finished_by_model"


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
                    "metric": {
                        "__name__": "mysql_up",
                        "instance": "mysql-17:3306",
                    },
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
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"],
            arguments=[
                {
                    "query": 'mysql_up{instance="mysql-17:3306"}',
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                },
                {},
            ],
        ),
    )

    result = await client.collect_alert_window(_mysql_context())

    assert result.finished_by_model is True
    assert result.has_monitoring_data is False
    assert result.responses[0]["projection_kind"] == "auxiliary"
    assert "window_verification" not in result.responses[0]
    assert "target_verification" not in result.responses[0]
    values = result.responses[0]["result"]["series"][0]["values"]
    assert values[1][1] == "x" * 30_000


@pytest.mark.asyncio
async def test_prometheus_evidence_record_does_not_expose_raw_call_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    large_content = "raw-prometheus-content:" + ("x" * 250_000)
    raw_call_result = {
        "_meta": {"trace_id": "trace-large-result"},
        "content": [{"type": "text", "text": large_content}],
        "structuredContent": {
            "series": [
                {
                    "metric": {
                        "__name__": "mysql_up",
                        "job": "mysql",
                        "instance": "mysql-17:3306",
                    },
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
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"],
            arguments=[
                {
                    "query": 'mysql_up{instance="mysql-17:3306"}',
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                },
                {},
            ],
        ),
    )
    executor = ToolExecutor(
        InvestigationToolRegistry([PrometheusMCPEvidenceTool(client)])
    )

    record = await executor.execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert record.status == ToolStatus.SUCCESS
    assert record.truncated is False
    assert "raw_call_results" not in record.structured_data
    assert large_content not in json.dumps(record.structured_data, ensure_ascii=False)


class _RecordingPrometheusClient:
    def __init__(self, result: PrometheusMCPQueryResult) -> None:
        self.result = result
        self.prompts = PROMETHEUS_PROMPTS

    async def collect_alert_window(self, context: InvestigationContext) -> PrometheusMCPQueryResult:
        assert context.alert.occurred_at == ALERT_TIME
        return self.result


def _qualified_projection_response(
    *,
    tool_name: str = "query_range",
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "projection_kind": "alert_window_range",
        "has_monitoring_observation": True,
        "root_cause_eligible": True,
        "projection": {
            "projection_kind": "alert_window_range",
            "window": {
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
            "target_match": {
                "matched": True,
                "authoritative_fields": ["database.instance"],
            },
            "timeseries": {
                "has_numeric_samples": True,
                "series_count": 1,
                "sample_count": 1,
                "series": [
                    {
                        "metric": {"__name__": "mysql_up"},
                        "sample_count": 1,
                        "min": 1,
                        "max": 1,
                        "avg": 1,
                        "latest": 1,
                        "delta": 0,
                    }
                ],
                "omitted_series_count": 0,
            },
        },
    }


@pytest.mark.asyncio
async def test_prometheus_outer_tool_does_not_reject_caller_parameters() -> None:
    result = PrometheusMCPQueryResult(
        responses=(),
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
        model_tool_calls=(),
        model_request_ids=(),
        finished_by_model=True,
        termination_reason="finished_by_model",
    )
    tool = PrometheusMCPEvidenceTool(_RecordingPrometheusClient(result))  # type: ignore[arg-type]

    evidence = await tool.execute(
        ToolExecutionRequest(
            tool_name=PROMETHEUS_METRICS_TOOL_NAME,
            parameters={"server_defined": {"opaque": True}},
        ),
        _context(),
    )

    assert evidence.status == ToolStatus.NO_DATA


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
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
        model_tool_calls=("get_targets",),
        model_request_ids=(),
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
async def test_prometheus_evidence_is_success_only_when_monitoring_result_exists() -> None:
    base = {
        "window_start": ALERT_WINDOW_START,
        "window_end": ALERT_TIME,
        "model_tool_calls": ("query", "query"),
        "model_request_ids": (),
        "finished_by_model": True,
        "termination_reason": "finished_by_model",
    }
    context = _context()
    request = ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME)
    usable_tool = PrometheusMCPEvidenceTool(
        _RecordingPrometheusClient(
                PrometheusMCPQueryResult(
                    responses=(_qualified_projection_response(tool_name="query"),),
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
    assert usable.structured_data["finished_by_model"] is True
    assert "已达到 MCP 调用上限" not in usable.summary
    assert empty.status == ToolStatus.NO_DATA
    assert empty.structured_data["root_cause_eligible"] is False
    assert empty.summary == "Prometheus MCP 未返回可用监控结果，实时证据不足。"


@pytest.mark.asyncio
async def test_prometheus_no_data_output_excludes_auxiliary_response_values() -> None:
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
        finished_by_model=True,
        tool_attempts=tuple(tool_attempts),
        termination_reason="finished_by_model",
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
    assert len(serialized) < 5_000
    assert record.structured_data["schema_version"] == "prometheus-evidence-v2"
    assert record.structured_data["root_cause_eligible"] is False
    assert record.structured_data["root_cause_ineligible_reason"] != ("evidence_payload_truncated")
    assert record.structured_data["model_tool_call_count"] == 8
    assert record.structured_data["tool_attempt_count"] == 8
    assert record.structured_data["monitoring_results"] == []
    assert "catalog_inventory" not in record.structured_data
    assert "tool_attempts" not in record.structured_data
    assert "prometheus.invalid" not in serialized
    assert "mysql_output_write_sql_count" not in serialized


@pytest.mark.asyncio
async def test_prometheus_target_mismatch_response_does_not_enter_main_agent() -> None:
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
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
        model_tool_calls=("query_range",),
        model_request_ids=(),
        finished_by_model=True,
        termination_reason="finished_by_model",
    )

    evidence = await PrometheusMCPEvidenceTool(  # type: ignore[arg-type]
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert result.has_monitoring_data is False
    assert evidence.status == ToolStatus.NO_DATA
    assert evidence.structured_data["monitoring_results"] == []
    assert "target_mismatch_count" not in evidence.structured_data
    assert evidence.structured_data["required_target"]["database_engine"] == "mysql"


@pytest.mark.asyncio
async def test_prometheus_partial_result_is_not_root_cause_eligible() -> None:
    result = PrometheusMCPQueryResult(
        responses=(_qualified_projection_response(tool_name="query"),),
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
        model_tool_calls=("query",),
        model_request_ids=(),
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
async def test_prometheus_out_of_scope_finish_wins_over_incidental_numeric_payload() -> None:
    result = PrometheusMCPQueryResult(
        responses=(
            {
                "tool_name": "get_targets",
                "has_monitoring_observation": True,
                "result": {"active_target_count": 1},
            },
        ),
        window_start=ALERT_WINDOW_START,
        window_end=ALERT_TIME,
        model_tool_calls=("get_targets",),
        model_request_ids=(),
        finished_by_model=True,
        termination_reason="database_not_monitored",
        monitoring_scope_status="out_of_scope",
        monitoring_scope_reason="仅配置 OceanBase 监控，告警数据库为 MySQL。",
    )

    evidence = await PrometheusMCPEvidenceTool(  # type: ignore[arg-type]
        _RecordingPrometheusClient(result)
    ).execute(
        ToolExecutionRequest(tool_name=PROMETHEUS_METRICS_TOOL_NAME),
        _mysql_context(),
    )

    assert evidence.status == ToolStatus.SKIPPED
    assert evidence.structured_data["reason_code"] == "database_not_monitored"
    assert (
        evidence.structured_data["root_cause_ineligible_reason"]
        == "database_not_monitored"
    )


@pytest.mark.asyncio
async def test_prometheus_catalog_and_empty_series_are_not_root_cause_evidence() -> None:
    base = {
        "window_start": ALERT_WINDOW_START,
        "window_end": ALERT_TIME,
        "model_tool_calls": ("list_metrics", "query_range"),
        "model_request_ids": (),
        "finished_by_model": False,
        "termination_reason": "finished_by_model",
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
