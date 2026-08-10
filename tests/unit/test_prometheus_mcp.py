from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import app.adapters.prometheus_mcp as prometheus_module
import app.application.factory as factory_module
from app.adapters.investigation import DefaultInvestigationStrategyProvider
from app.adapters.prometheus_mcp import (
    PROMETHEUS_MCP_EVIDENCE_RESULT_MAX_CHARS,
    PROMETHEUS_MCP_MODEL_RESULT_MAX_CHARS,
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
    load_prometheus_mcp_server_settings,
)
from app.config import RUNTIME_SETTINGS_KEYS, Settings
from app.domain.models import (
    InvestigationContext,
    InvestigationStrategy,
    NormalizedAlert,
    Severity,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall

ALERT_TIME = datetime(2026, 8, 7, 2, 0, tzinfo=UTC)
_FAKE_RANGE_POLICY = PrometheusMCPToolPolicy(
    name="arbitrary_monitoring_tool",
    capability="range_query",
    start_argument_path=("start",),
    end_argument_path=("end",),
    timestamp_encoding="rfc3339",
)


def _server_settings(
    *,
    headers: dict[str, str] | None = None,
    tool_policies: tuple[PrometheusMCPToolPolicy, ...] = (_FAKE_RANGE_POLICY,),
) -> PrometheusMCPServerSettings:
    return PrometheusMCPServerSettings(
        url="https://prometheus.example.test/sse",
        headers=headers or {},
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


def test_prometheus_mcp_settings_resolve_header_placeholder_without_persisting_secret(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "headers": {
                            "${PROMETHEUS_MCP_API_KEY_HEADER}": (
                                "${PROMETHEUS_MCP_API_KEY}"
                            )
                        },
                        "toolPolicies": {
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
    assert resolved.tool_policies == (
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


def test_prometheus_mcp_settings_omit_optional_auth_header_when_key_is_empty(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "headers": {
                            "${PROMETHEUS_MCP_API_KEY_HEADER}": (
                                "${PROMETHEUS_MCP_API_KEY}"
                            )
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
            "PROMETHEUS_MCP_API_KEY_HEADER": "Authorization",
            "PROMETHEUS_MCP_API_KEY": "",
        },
    )

    assert resolved.headers == {}


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
        PrometheusMCPClient._result_payload(raw_result)


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
        PrometheusMCPClient._result_payload(raw_result)


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

    payload = PrometheusMCPClient._result_payload(raw_result)

    assert payload == observation
    assert prometheus_module._has_monitoring_observation(payload) is True


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
        PrometheusMCPClient._window_verification(
            policy=_FAKE_RANGE_POLICY,
            payload=in_window,
            window_start=datetime(2026, 8, 7, 1, 55, tzinfo=UTC),
            window_end=ALERT_TIME,
        )
        == "exact"
    )
    assert (
        PrometheusMCPClient._window_verification(
            policy=_FAKE_RANGE_POLICY,
            payload=out_of_window,
            window_start=datetime(2026, 8, 7, 1, 55, tzinfo=UTC),
            window_end=ALERT_TIME,
        )
        == "mismatch"
    )
    assert (
        PrometheusMCPClient._window_verification(
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

    async def request_mcp_tool_call(
        self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> MCPModelToolCall:
        self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
        index = len(self.messages) - 1
        available = {item["function"]["name"] for item in tools}
        self.available_tools.append(available)
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
        client._authorized_model_tools(
            [
                {
                    "name": "arbitrary_monitoring_tool",
                    "inputSchema": schema,
                    "annotations": {"destructiveHint": True, "readOnlyHint": True},
                }
            ]
        )

    converted, _ = client._authorized_model_tools(
        [{"name": "arbitrary_monitoring_tool", "inputSchema": schema}]
    )
    description = converted[0]["function"]["description"]
    assert "capability=range_query" in description
    assert "root-cause-eligible" in description


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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        UnauthorizedModel(),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert _FakeSession.calls == []
    assert result.has_monitoring_data is False
    assert result.termination_reason == "decision_limit_reached"
    assert {item["outcome"] for item in result.tool_attempts} == {
        "host_rejected_unauthorized"
    }


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

    monkeypatch.setattr(prometheus_module, "sse_client", fake_sse_client)
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ]
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
async def test_prometheus_client_deduplicates_empty_calls_without_spending_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SequencedSession.calls = []
    _SequencedSession.results = [
        {"isError": False},
        {"isError": False},
    ]
    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _SequencedSession)
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
    first_feedback = json.loads(model.messages[1][-1]["content"])
    assert first_feedback["host_control"]["remote_calls_used"] == 1
    assert first_feedback["host_control"]["remote_calls_remaining"] == 1


@pytest.mark.asyncio
async def test_prometheus_client_reserves_a_range_call_after_catalog_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NamedTool:
        def __init__(self, name: str, properties: dict[str, Any]) -> None:
            self.name = name
            self.properties = properties

        def model_dump(self, *, mode: str) -> dict[str, Any]:
            assert mode == "json"
            return {
                "name": self.name,
                "description": f"Remote {self.name}",
                "inputSchema": {
                    "type": "object",
                    "properties": self.properties,
                },
            }

    class CatalogAndRangeSession(_FakeSession):
        calls: list[tuple[str, dict[str, Any]]] = []

        async def list_tools(self, cursor: str | None = None) -> Any:
            assert cursor is None
            return type(
                "ToolList",
                (),
                {
                    "tools": [
                        NamedTool("list_metrics", {"prefix": {"type": "string"}}),
                        NamedTool(
                            "query_range",
                            {
                                "query": {"type": "string"},
                                "start": {"type": "string"},
                                "end": {"type": "string"},
                            },
                        ),
                    ],
                    "nextCursor": None,
                },
            )()

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            self.calls.append((name, arguments))
            result = (
                {"structuredContent": {"metrics": ["mysql_up"]}}
                if name == "list_metrics"
                else {"structuredContent": {"series": [{"value": 1}]}}
            )
            return type("ToolResult", (), {"model_dump": lambda _self, **_: result})()

    class CatalogFirstModel:
        def __init__(self) -> None:
            self.messages: list[list[dict[str, Any]]] = []
            self.available_tools: list[set[str]] = []

        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
            available = {item["function"]["name"] for item in tools}
            self.available_tools.append(available)
            index = len(self.messages) - 1
            if "finish_prometheus_investigation" in available:
                name = "finish_prometheus_investigation"
                arguments = {}
            elif "list_metrics" in available:
                name = "list_metrics"
                arguments = {"prefix": f"mysql-{index}"}
            else:
                name = "query_range"
                arguments = {"query": "mysql_up"}
            return MCPModelToolCall(
                call_id=f"catalog-first-{index}",
                name=name,
                arguments=arguments,
            )

    policies = (
        PrometheusMCPToolPolicy(name="list_metrics", capability="catalog"),
        PrometheusMCPToolPolicy(
            name="query_range",
            capability="range_query",
            start_argument_path=("start",),
            end_argument_path=("end",),
            timestamp_encoding="rfc3339",
        ),
    )
    CatalogAndRangeSession.calls = []
    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", CatalogAndRangeSession)
    model = CatalogFirstModel()
    client = PrometheusMCPClient(
        _server_settings(tool_policies=policies),
        model,
        max_agent_steps=4,
    )

    result = await client.collect_alert_window(_context())

    assert [name for name, _ in CatalogAndRangeSession.calls] == [
        "list_metrics",
        "list_metrics",
        "query_range",
    ]
    assert model.available_tools[:2] == [
        {"list_metrics", "query_range"},
        {"list_metrics", "query_range"},
    ]
    assert model.available_tools[2] == {"query_range"}
    assert result.has_monitoring_data is True
    assert result.call_limit_reached is False
    assert result.finished_by_model is True
    initial_state = json.loads(model.messages[0][2]["content"])
    assert initial_state["authorized_tool_capabilities"] == {
        "list_metrics": "catalog",
        "query_range": "range_query",
    }
    second_round_feedback = json.loads(model.messages[1][-1]["content"])
    assert second_round_feedback["host_control"]["capability"] == "catalog"
    assert second_round_feedback["host_control"]["remote_calls_remaining"] == 3


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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _SequencedSession)
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
    settings_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prometheus": {
                        "url": "${PROMETHEUS_MCP_SSE_URL}",
                        "headers": {},
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
async def test_prometheus_client_hides_finish_until_a_usable_response_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"series": [{"value": 42}]}}
    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
    model = _SequenceModel(
        [
            "finish_prometheus_investigation",
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
        ]
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=3,
    )

    result = await client.collect_alert_window(_context())

    assert _FakeSession.calls == [
        (
            "arbitrary_monitoring_tool",
            {
                "query": "up",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
        )
    ]
    assert result.finished_by_model is True
    assert result.termination_reason == "finished_by_model"
    assert "finish_prometheus_investigation" not in model.available_tools[0]
    repair_feedback = json.loads(model.messages[1][-1]["content"])
    assert repair_feedback["host_event"] == "model_tool_selection_retry"
    assert repair_feedback["remote_calls_remaining"] == 3
    assert "finish_prometheus_investigation" in model.available_tools[-1]


@pytest.mark.asyncio
async def test_prometheus_client_retries_model_selection_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FlakyModel:
        def __init__(self) -> None:
            self.attempts = 0
            self.messages: list[list[dict[str, Any]]] = []

        async def request_mcp_tool_call(
            self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> MCPModelToolCall:
            self.attempts += 1
            self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
            if self.attempts == 1:
                raise RuntimeError("temporary model failure")
            return MCPModelToolCall(
                call_id="call-after-retry",
                name="arbitrary_monitoring_tool",
                arguments={
                    "query": "up",
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                },
            )

    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"series": [{"value": 42}]}}
    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
    model = FlakyModel()
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=1,
    )

    result = await client.collect_alert_window(_context())

    assert model.attempts == 2
    repair = json.loads(model.messages[1][-1]["content"])
    assert repair["host_event"] == "model_tool_selection_retry"
    assert repair["previous_error_type"] == "RuntimeError"
    assert repair["remote_calls_used"] == 0
    assert repair["remote_call_limit"] == 1
    assert repair["remote_calls_remaining"] == 1
    assert result.has_monitoring_data is True
    assert _FakeSession.calls == [
        (
            "arbitrary_monitoring_tool",
            {
                "query": "up",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
            },
        )
    ]


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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _SequencedSession)
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

    result = await client.collect_alert_window(_context())

    assert len(_SequencedSession.calls) == 2
    assert len(result.responses) == 1
    assert [item["outcome"] for item in result.tool_attempts] == [
        "tool_error",
        "observation",
    ]
    error_feedback = json.loads(model.messages[1][-1]["content"])
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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _SequencedSession)
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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _SequencedSession)
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
    assert len(evidence.structured_data["monitoring_results"]) == 1


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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
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
async def test_prometheus_client_preserves_response_when_sse_exit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingSSEContext(_AsyncContext):
        async def __aexit__(self, *args: Any) -> None:
            raise ExceptionGroup("SSE reader failed", [ConnectionError("stream closed")])

    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"series": [{"value": 42}]}}
    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: FailingSSEContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
    client = PrometheusMCPClient(
        _server_settings(),
        _SequenceModel(
            ["arbitrary_monitoring_tool", "finish_prometheus_investigation"]
        ),
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert len(result.responses) == 1
    assert result.partial is True
    assert result.termination_reason == "sse_error_after_partial_result"
    assert result.termination_error_type == "ConnectionError"


@pytest.mark.asyncio
async def test_prometheus_client_bounds_only_the_model_view_of_a_large_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeSession.calls = []
    _FakeSession.result = {"structuredContent": {"metrics": ["metric_name"] * 2_000}}

    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
    model = _SequenceModel(
        [
            "arbitrary_monitoring_tool",
            "finish_prometheus_investigation",
            "finish_prometheus_investigation",
            "finish_prometheus_investigation",
        ]
    )
    client = PrometheusMCPClient(
        _server_settings(),
        model,
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    # Both accumulated evidence and the smaller follow-up model view are bounded
    # independently before another large response can amplify memory use.
    evidence_result = result.responses[0]["result"]
    assert evidence_result["result_truncated_for_evidence"] is True
    assert len(evidence_result["preview"]) == PROMETHEUS_MCP_EVIDENCE_RESULT_MAX_CHARS
    model_result = json.loads(model.messages[1][-1]["content"])["monitoring_result"]
    assert model_result["result_truncated_for_model"] is True
    assert model_result["original_char_count"] > PROMETHEUS_MCP_MODEL_RESULT_MAX_CHARS
    assert len(model_result["preview"]) == PROMETHEUS_MCP_MODEL_RESULT_MAX_CHARS
    assert "不得重复同一工具" in model.messages[0][0]["content"]
    assert result.has_monitoring_data is False
    assert result.termination_reason == "model_error_no_result"


@pytest.mark.asyncio
async def test_prometheus_large_observation_remains_finishable_after_evidence_truncation(
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
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _FakeSession)
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
    assert result.responses[0]["result"]["result_truncated_for_evidence"] is True


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
) -> None:
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
async def test_strategy_adds_prometheus_to_every_alert_when_available() -> None:
    strategy = await DefaultInvestigationStrategyProvider(
        available_tools=["alert_context", PROMETHEUS_METRICS_TOOL_NAME],
        prometheus_tool_timeout_seconds=321,
    ).select(_context().alert)

    requests = {item.tool_name: item for item in strategy.tool_plan}
    assert requests[PROMETHEUS_METRICS_TOOL_NAME].required is True
    assert requests[PROMETHEUS_METRICS_TOOL_NAME].timeout_seconds == 321
