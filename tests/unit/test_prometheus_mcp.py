from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import app.adapters.prometheus_mcp as prometheus_module
from app.adapters.investigation import DefaultInvestigationStrategyProvider
from app.adapters.prometheus_mcp import (
    PROMETHEUS_MCP_MODEL_RESULT_MAX_CHARS,
    PROMETHEUS_METRICS_TOOL_NAME,
    PrometheusMCPClient,
    PrometheusMCPEvidenceTool,
    PrometheusMCPQueryResult,
    PrometheusMCPServerSettings,
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
            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
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


class _SequenceModel:
    def __init__(self, names: list[str]) -> None:
        self.names = names
        self.messages: list[list[dict[str, Any]]] = []

    async def request_mcp_tool_call(
        self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> MCPModelToolCall:
        self.messages.append(messages)
        index = len(self.messages) - 1
        available = {item["function"]["name"] for item in tools}
        name = self.names[index]
        assert name in available
        return MCPModelToolCall(
            call_id=f"call-{index}",
            name=name,
            arguments={"query": "up"},
            request_id=f"request-{index}",
        )


@pytest.mark.asyncio
async def test_prometheus_client_allows_server_defined_tools_and_preserves_data_at_budget(
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
    model = _SequenceModel(["arbitrary_monitoring_tool", "arbitrary_monitoring_tool"])
    client = PrometheusMCPClient(
        PrometheusMCPServerSettings(
            url="https://prometheus.example.test/sse", headers={"X-API-Key": "test-secret"}
        ),
        model,
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    assert captured_sse["headers"] == {"X-API-Key": "test-secret"}
    assert _FakeSession.calls == [
        ("arbitrary_monitoring_tool", {"query": "up"}),
        ("arbitrary_monitoring_tool", {"query": "up"}),
    ]
    assert result.call_limit_reached is True
    assert result.has_monitoring_data is True
    assert result.window_end == ALERT_TIME
    assert result.window_start.isoformat() == "2026-08-07T01:55:00+00:00"
    first_request = json.loads(model.messages[0][1]["content"])
    assert first_request["required_window"]["duration_seconds"] == 300


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
    model = _SequenceModel(["arbitrary_monitoring_tool", "finish_prometheus_investigation"])
    client = PrometheusMCPClient(
        PrometheusMCPServerSettings(url="https://prometheus.example.test/sse", headers={}),
        model,
        max_agent_steps=2,
    )

    result = await client.collect_alert_window(_context())

    # The evidence remains complete, while the follow-up model turn receives a
    # bounded generic preview rather than a server-specific filtered payload.
    assert len(result.responses[0]["result"]["metrics"]) == 2_000
    model_result = json.loads(model.messages[1][-1]["content"])["monitoring_result"]
    assert model_result["result_truncated_for_model"] is True
    assert model_result["original_char_count"] > PROMETHEUS_MCP_MODEL_RESULT_MAX_CHARS
    assert len(model_result["preview"]) == PROMETHEUS_MCP_MODEL_RESULT_MAX_CHARS
    assert "不得重复同一工具" in model.messages[0][0]["content"]


class _RecordingPrometheusClient:
    def __init__(self, result: PrometheusMCPQueryResult) -> None:
        self.result = result

    async def collect_alert_window(self, context: InvestigationContext) -> PrometheusMCPQueryResult:
        assert context.alert.occurred_at == ALERT_TIME
        return self.result


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
                responses=({"tool_name": "query", "result": {"value": 1}},),
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
async def test_strategy_adds_prometheus_to_every_alert_when_available() -> None:
    strategy = await DefaultInvestigationStrategyProvider(
        available_tools=["alert_context", PROMETHEUS_METRICS_TOOL_NAME],
        prometheus_tool_timeout_seconds=321,
    ).select(_context().alert)

    requests = {item.tool_name: item for item in strategy.tool_plan}
    assert requests[PROMETHEUS_METRICS_TOOL_NAME].required is True
    assert requests[PROMETHEUS_METRICS_TOOL_NAME].timeout_seconds == 321
