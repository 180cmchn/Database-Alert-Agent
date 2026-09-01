from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4, uuid5

import httpx
import pytest
from anyio import ClosedResourceError, EndOfStream
from sqlalchemy import select

import app.adapters.prometheus_harness as prometheus_harness_module
from app.adapters.persistence import (
    AgentArtifactRow,
    SQLAlchemyAlertRepository,
    ToolInvocationRow,
)
from app.adapters.prometheus_harness import (
    PrometheusHarnessRuntimeDependencies,
    PrometheusHarnessState,
)
from app.adapters.prometheus_mcp import (
    PROMETHEUS_MCP_SERVER_NAME,
    PrometheusMCPClient,
    PrometheusMCPServerSettings,
)
from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    RepositoryEventSink,
    RunManifest,
    ToolInvocationStatus,
)
from app.domain.models import (
    DatabaseTarget,
    InvestigationContext,
    InvestigationRun,
    NormalizedAlert,
    Severity,
)
from app.domain.ports import RunLeaseConflict
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import MCPPromptBundle, MCPTransport
from app.mcp_runtime import DiscoveredMCPTool, RepositoryMCPCheckpointStore

_ALERT_TIME = datetime(2026, 8, 7, 2, 0, tzinfo=UTC)
_ALERT_WINDOW_START = _ALERT_TIME - timedelta(minutes=5)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROMETHEUS_PROMPTS = MCPPromptBundle(
    role="Prometheus metrics investigator",
    purpose="Collect relevant Prometheus evidence.",
    workflow="Choose discovered tools from their descriptions and schemas.",
    safety="All investigation calls must have read-only intent.",
)


class _AsyncContext:
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _HarnessSession:
    calls: list[tuple[str, dict[str, Any]]] = []
    results: list[dict[str, Any] | Exception] = []
    session_count = 0
    exit_count = 0

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        type(self).session_count += 1

    async def __aenter__(self) -> _HarnessSession:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        type(self).exit_count += 1
        return None

    async def initialize(self) -> None:
        return None

    async def list_tools(self, cursor: str | None = None) -> Any:
        assert cursor is None
        tool = type(
            "PrometheusTool",
            (),
            {
                "model_dump": lambda _self, **_: {
                    "name": "query_range",
                    "description": "Run a read-only Prometheus range query",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                            "operation": {"type": "string"},
                        },
                        "required": ["query", "start", "end", "operation"],
                        "additionalProperties": False,
                    },
                    "annotations": {"readOnlyHint": True},
                }
            },
        )()
        return type("ToolList", (), {"tools": [tool], "nextCursor": None})()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        type(self).calls.append((name, arguments))
        result = type(self).results.pop(0)
        if isinstance(result, Exception):
            raise result
        return type("ToolResult", (), {"model_dump": lambda _self, **_: result})()


class _SequenceModel:
    def __init__(self, responses: list[MCPModelToolCall | Exception]) -> None:
        self.responses = responses
        self.messages: list[list[dict[str, Any]]] = []
        self.tools: list[list[dict[str, Any]]] = []

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        self.messages.append(messages)
        self.tools.append(tools)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _context(
    *,
    run_id: Any | None = None,
    lease_owner: str | None = None,
    fencing_token: int | None = None,
    external_id: str = "prometheus-harness-alert",
) -> InvestigationContext:
    return InvestigationContext(
        run_id=run_id or uuid4(),
        alert=NormalizedAlert(
            external_id=external_id,
            source="canonical",
            raw_severity="WARNING",
            severity=Severity.WARNING,
            title="Database latency elevated",
            reason="database_latency",
            occurred_at=_ALERT_TIME,
        ),
        lease_owner=lease_owner,
        fencing_token=fencing_token,
    )


def _client(
    model: _SequenceModel,
    *,
    repository: SQLAlchemyAlertRepository | None = None,
    timeout_seconds: float = 60,
    mcp_transport: MCPTransport = "sse",
) -> PrometheusMCPClient:
    return PrometheusMCPClient(
        PrometheusMCPServerSettings(
            url="https://prometheus.example.test/sse",
            headers={},
            prompts=PROMETHEUS_PROMPTS,
            transport=mcp_transport,
        ),
        model,
        timeout_seconds=timeout_seconds,
        harness_runtime_dependencies=(
            PrometheusHarnessRuntimeDependencies(repository) if repository is not None else None
        ),
    )


def test_prometheus_harness_exposes_all_discovered_tools_ignoring_annotations() -> None:
    client = _client(_SequenceModel([]))
    scenario = prometheus_harness_module.PrometheusHarnessScenario(
        client=client,
        context=_context(),
        window_start=_ALERT_WINDOW_START,
        window_end=_ALERT_TIME,
    )

    specs = scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name="missing_annotations",
                input_schema={"type": "object"},
            ),
            DiscoveredMCPTool(
                name="destructive_annotation",
                input_schema={"type": "object"},
                annotations={"destructiveHint": True, "readOnlyHint": False},
            ),
        ]
    )

    assert [spec.name for spec in specs] == [
        "destructive_annotation",
        "missing_annotations",
    ]
    assert all(spec.capability == "prometheus.remote_tool" for spec in specs)
    assert all("annotations" not in item["function"] for item in scenario.model_tools.values())


def test_prometheus_harness_forwards_model_arguments_unchanged() -> None:
    client = _client(_SequenceModel([]))
    scenario = prometheus_harness_module.PrometheusHarnessScenario(
        client=client,
        context=_context(),
        window_start=_ALERT_WINDOW_START,
        window_end=_ALERT_TIME,
    )
    scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name="query_range",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
            )
        ]
    )
    arguments = {
        "query": "up",
        "start": int(_ALERT_WINDOW_START.timestamp()),
        "end": int(_ALERT_TIME.timestamp()),
        "operation": "model-operation",
        "schema_extra": {"opaque": True},
    }
    action = type(
        "Action",
        (),
        {
            "tool_name": "query_range",
            "objective": "query",
            "hypothesis_ids": [],
            "arguments": arguments,
        },
    )()

    prepared = scenario.prepare_call(
        action,
        state=scenario.initial_state(),
    )

    assert prepared.effective_arguments == arguments
    assert prepared.local_result is None


def test_prometheus_harness_rejects_wrong_range_window_with_exact_correction() -> None:
    client = _client(_SequenceModel([]))
    scenario = prometheus_harness_module.PrometheusHarnessScenario(
        client=client,
        context=_context(),
        window_start=_ALERT_WINDOW_START,
        window_end=_ALERT_TIME,
    )
    scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name="query_range",
                description="Run a Prometheus range query",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "start": {"type": "number"},
                        "end": {"type": "number"},
                    },
                    "required": ["query", "start", "end"],
                    "additionalProperties": False,
                },
            )
        ]
    )
    arguments = {
        "query": "mysql_up",
        "start": int(datetime(2025, 8, 7, 1, 55, tzinfo=UTC).timestamp()),
        "end": int(datetime(2025, 8, 7, 2, 0, tzinfo=UTC).timestamp()),
    }
    action = type(
        "Action",
        (),
        {
            "tool_name": "query_range",
            "objective": "query",
            "hypothesis_ids": [],
            "arguments": arguments,
        },
    )()
    state = scenario.initial_state()

    prepared = scenario.prepare_call(action, state=state)
    transition = scenario.on_result(state, prepared, prepared.local_result)

    assert prepared.effective_arguments == arguments
    correction = prepared.local_result["host_validation"]
    assert correction["transport_sent"] is False
    assert correction["reason_code"] == "alert_window_mismatch"
    assert correction["expected_arguments"] == {
        "start": int(_ALERT_WINDOW_START.timestamp()),
        "end": int(_ALERT_TIME.timestamp()),
    }
    assert correction["expected_window"]["timezone"] == "Asia/Shanghai"
    assert correction["expected_window"]["start"] == "2026-08-07T09:55:00+08:00"
    assert correction["expected_window"]["end"] == "2026-08-07T10:00:00+08:00"
    assert transition.status == ToolInvocationStatus.SKIPPED
    assert transition.state.executed_calls == []
    assert transition.state.tool_attempts[0]["outcome"] == "rejected_locally"
    messages = transition.message
    assert isinstance(messages, list)
    tool_result = json.loads(messages[-2]["content"])
    assert tool_result == {"host_validation": correction}
    host_control = json.loads(messages[-1]["content"])["host_control"]
    assert host_control["remote_calls_used"] == 0
    assert host_control["capability"] == "host_window_validation"


def test_prometheus_harness_preserves_responses_output_items_in_prepared_call() -> None:
    client = _client(_SequenceModel([]))
    scenario = prometheus_harness_module.PrometheusHarnessScenario(
        client=client,
        context=_context(),
        window_start=_ALERT_WINDOW_START,
        window_end=_ALERT_TIME,
    )
    scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name="query_range",
                input_schema={"type": "object", "additionalProperties": True},
            )
        ]
    )
    arguments = {
        "query": "mysql_up",
        "start": "2026-08-07T09:55:00+08:00",
        "end": "2026-08-07T10:00:00+08:00",
    }
    native_items = (
        {
            "type": "reasoning",
            "id": "prom-reasoning",
            "encrypted_content": "encrypted-prom",
            "summary": [],
        },
        {
            "type": "function_call",
            "id": "prom-function-item",
            "call_id": "prom-function-call",
            "name": "query_range",
            "arguments": json.dumps(arguments),
            "status": "completed",
        },
    )
    scenario.register_model_call(
        MCPModelToolCall(
            call_id="prom-function-call",
            name="query_range",
            arguments=arguments,
            provider_output_items=native_items,
        )
    )
    action = type(
        "Action",
        (),
        {
            "tool_name": "query_range",
            "objective": "query",
            "hypothesis_ids": [],
            "arguments": arguments,
        },
    )()

    prepared = scenario.prepare_call(action, state=scenario.initial_state())
    restored = prometheus_harness_module.PrometheusHarnessScenario._model_call_from_prepared(
        prepared
    )
    messages = client.completed_tool_messages(
        restored,
        {"value": 1},
        host_control={"instruction": "continue"},
    )

    assert restored.provider_output_items == native_items
    assert messages[:2] == list(native_items)
    assert messages[-2]["type"] == "function_call_output"
    assert messages[-2]["call_id"] == "prom-function-call"
    assert json.loads(messages[-2]["output"]) == {"value": 1}
    assert json.loads(messages[-1]["content"]) == {"host_control": {"instruction": "continue"}}


def test_prometheus_protocol_failure_returns_complete_raw_response_to_model() -> None:
    client = _client(_SequenceModel([]))
    scenario = prometheus_harness_module.PrometheusHarnessScenario(
        client=client,
        context=_context(),
        window_start=_ALERT_WINDOW_START,
        window_end=_ALERT_TIME,
    )
    scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name="query_range",
                input_schema={"type": "object", "additionalProperties": True},
            )
        ]
    )
    arguments = {
        "query": "up",
        "start": "2026-08-07T09:55:00+08:00",
        "end": "2026-08-07T10:00:00+08:00",
    }
    scenario.register_model_call(
        MCPModelToolCall(
            call_id="protocol-error-call",
            name="query_range",
            arguments=arguments,
        )
    )
    state = scenario.initial_state()
    prepared = scenario.prepare_call(
        type(
            "Action",
            (),
            {
                "tool_name": "query_range",
                "objective": "query",
                "hypothesis_ids": [],
                "arguments": arguments,
            },
        )(),
        state=state,
    )
    raw_response = ["malformed-envelope", {"secret_key": "mcp-owned-secret"}]
    prepared.metadata["mcp_raw_response"] = raw_response

    transition = scenario.on_failure(
        state,
        prepared,
        SimpleNamespace(code="host_result_processing_error", message="invalid envelope"),
        ToolInvocationStatus.FAILED,
    )

    tool_message = next(item for item in transition.message if item.get("role") == "tool")
    assert json.loads(tool_message["content"]) == raw_response


async def _durable_context(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
) -> tuple[InvestigationContext, RunManifest, InvestigationRun]:
    run_id = uuid4()
    context = _context(run_id=run_id, external_id=external_id)
    stored, created = await repository.create_or_get(context.alert)
    assert created is True
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="prometheus-harness-test",
    )
    run = await repository.create_run(
        str(stored.alert.id),
        "prometheus-worker",
        300,
        manifest=manifest,
    )
    assert run is not None
    assert run.lease_owner is not None
    return (
        context.model_copy(
            update={
                "alert": stored.alert,
                "lease_owner": run.lease_owner,
                "fencing_token": run.fencing_token,
            }
        ),
        manifest,
        run,
    )


@pytest.fixture(autouse=True)
def _fake_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    _HarnessSession.calls = []
    _HarnessSession.results = []
    _HarnessSession.session_count = 0
    _HarnessSession.exit_count = 0
    monkeypatch.setattr(
        prometheus_harness_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_harness_module, "ClientSession", _HarnessSession)


@pytest.mark.asyncio
async def test_prometheus_sse_transport_disables_http_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def recording_sse_client(*_args: Any, **kwargs: Any) -> _AsyncContext:
        captured.update(kwargs)
        return _AsyncContext((object(), object()))

    monkeypatch.setattr(prometheus_harness_module, "sse_client", recording_sse_client)
    connector = prometheus_harness_module.PrometheusMCPConnector(_client(_SequenceModel([])))

    session = await connector.open_session()
    factory = captured["httpx_client_factory"]
    client = factory(
        headers={"X-API-Key": "secret"},
        timeout=httpx.Timeout(10),
    )
    try:
        assert client.follow_redirects is False
    finally:
        await client.aclose()
        await session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_transport", ("sse", "streamable_http"))
async def test_prometheus_connector_uses_configured_mcp_transport(
    monkeypatch: pytest.MonkeyPatch,
    mcp_transport: MCPTransport,
) -> None:
    calls: dict[str, Any] = {}
    read_stream = object()
    write_stream = object()
    client = _client(_SequenceModel([]), mcp_transport=mcp_transport)

    if mcp_transport == "sse":

        def sse_connector(url: str, **kwargs: Any) -> _AsyncContext:
            calls["sse"] = {"url": url, **kwargs}
            return _AsyncContext((read_stream, write_stream))

        def unexpected_streamable(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("streamable HTTP connector must not be used")

        monkeypatch.setattr(prometheus_harness_module, "sse_client", sse_connector)
        monkeypatch.setattr(
            prometheus_harness_module,
            "streamable_http_client",
            unexpected_streamable,
        )
    else:
        http_client = object()

        def async_http_client(**kwargs: Any) -> _AsyncContext:
            calls["http_client"] = kwargs
            return _AsyncContext(http_client)

        def streamable_connector(url: str, *, http_client: Any) -> _AsyncContext:
            calls["streamable"] = {"url": url, "http_client": http_client}
            return _AsyncContext((read_stream, write_stream, lambda: "streamable-session"))

        def unexpected_sse(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("SSE connector must not be used")

        monkeypatch.setattr(
            prometheus_harness_module.httpx,
            "AsyncClient",
            async_http_client,
        )
        monkeypatch.setattr(
            prometheus_harness_module,
            "streamable_http_client",
            streamable_connector,
        )
        monkeypatch.setattr(prometheus_harness_module, "sse_client", unexpected_sse)

    session = await prometheus_harness_module.PrometheusMCPConnector(client).open_session()
    try:
        if mcp_transport == "sse":
            assert calls["sse"] == {
                "url": "https://prometheus.example.test/sse",
                "headers": {},
                "timeout": 60,
                "sse_read_timeout": 60,
                "httpx_client_factory": prometheus_harness_module._no_redirect_http_client,
            }
            assert session.session_id.startswith("prometheus-mcp-")
        else:
            assert calls["streamable"] == {
                "url": "https://prometheus.example.test/sse",
                "http_client": http_client,
            }
            assert calls["http_client"]["headers"] == {}
            assert calls["http_client"]["auth"] is None
            assert calls["http_client"]["follow_redirects"] is False
            assert calls["http_client"]["timeout"].connect == 60
            assert session.session_id == "streamable-session"
    finally:
        await session.close()


@pytest.mark.asyncio
async def test_prometheus_connector_discovers_all_pages_until_cursor_is_exhausted() -> None:
    class PagedSession:
        def __init__(self) -> None:
            self.cursors: list[str | None] = []

        async def list_tools(self, *, cursor: str | None = None) -> Any:
            self.cursors.append(cursor)
            page = 0 if cursor is None else int(cursor.removeprefix("page-"))
            tool = type(
                "PagedTool",
                (),
                {
                    "model_dump": lambda _self, **_: {
                        "name": f"tool-{page}",
                        "description": f"page {page}",
                        "inputSchema": {"type": "object"},
                    }
                },
            )()
            next_cursor = f"page-{page + 1}" if page < 11 else None
            return type(
                "ToolPage",
                (),
                {"tools": [tool], "nextCursor": next_cursor},
            )()

    class Stack:
        async def aclose(self) -> None:
            return None

    raw_session = PagedSession()
    session = prometheus_harness_module.PrometheusMCPToolSession(
        client=_client(_SequenceModel([])),
        stack=Stack(),  # type: ignore[arg-type]
        session=raw_session,
        session_id="paged-session",
    )

    tools = await session.list_tools()

    assert [tool.name for tool in tools] == [f"tool-{page}" for page in range(12)]
    assert raw_session.cursors == [None, *[f"page-{page}" for page in range(1, 12)]]


@pytest.mark.asyncio
async def test_prometheus_whole_run_timeout_bounds_repeated_model_failures() -> None:
    class AlwaysFailingModel(_SequenceModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.messages.append(messages)
            self.tools.append(tools)
            raise RuntimeError("temporary model failure")

    result = await asyncio.wait_for(
        _client(AlwaysFailingModel([]), timeout_seconds=0.03).collect_alert_window(_context()),
        timeout=0.5,
    )

    assert result.finished_by_model is False
    assert result.termination_reason == "deadline_exceeded"


@pytest.mark.asyncio
async def test_prometheus_cancellation_propagates_and_closes_session() -> None:
    planning_started = asyncio.Event()

    class BlockingModel(_SequenceModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.messages.append(messages)
            self.tools.append(tools)
            planning_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    task = asyncio.create_task(_client(BlockingModel([])).collect_alert_window(_context()))
    await asyncio.wait_for(planning_started.wait(), timeout=0.5)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert _HarnessSession.exit_count == 1


@pytest.mark.asyncio
async def test_shared_harness_recovers_from_temporary_missing_model_tool_call() -> None:
    _HarnessSession.results = [{"structuredContent": {"series": [{"value": 1}]}}]
    model = _SequenceModel(
        [
            RuntimeError("provider returned zero tool calls"),
            MCPModelToolCall(
                call_id="query-1",
                name="query_range",
                arguments={
                    "query": "mysql_up",
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                    "operation": "query",
                },
                request_id="request-query-1",
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
                request_id="request-finish-1",
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert any("上一轮没有形成有效的单工具调用" in str(messages) for messages in model.messages)
    assert result.finished_by_model is True
    assert result.has_monitoring_data is False
    assert result.responses[0]["projection_kind"] == "auxiliary"
    assert result.model_request_ids == ("request-query-1",)
    assert result.termination_error_type is None


@pytest.mark.asyncio
async def test_shared_harness_forwards_window_and_operation_arguments_unchanged() -> None:
    _HarnessSession.results = [{"structuredContent": {"series": [{"value": 1}]}}]
    model = _SequenceModel(
        [
            MCPModelToolCall(
                call_id="query-1",
                name="query_range",
                arguments={
                    "query": "rate(mysql_global_status_slow_queries[5m])",
                    "start": "2026-08-07T09:55:00+08:00",
                    "end": "2026-08-07T10:00:00+08:00",
                    "operation": "model-defined-operation",
                    "schema_extra": {"opaque": True},
                },
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert _HarnessSession.calls == [
        (
            "query_range",
            {
                "query": "rate(mysql_global_status_slow_queries[5m])",
                "start": "2026-08-07T09:55:00+08:00",
                "end": "2026-08-07T10:00:00+08:00",
                "operation": "model-defined-operation",
                "schema_extra": {"opaque": True},
            },
        )
    ]
    assert result.responses[0]["model_arguments"] == _HarnessSession.calls[0][1]
    assert result.responses[0]["arguments"] == _HarnessSession.calls[0][1]
    assert "window_verification" not in result.responses[0]
    assert "target_verification" not in result.responses[0]


@pytest.mark.asyncio
async def test_shared_harness_rejects_wrong_window_before_transport() -> None:
    raw_response = {
        "_meta": {
            "trace_id": "raw-response-trace",
            "api_key": "mcp-owned-secret",
        },
        "structuredContent": {"data": {"result": [{"values": [[1_893_456_000, "1"]]}]}},
        "isError": False,
    }
    _HarnessSession.results = [raw_response]
    model = _SequenceModel(
        [
            MCPModelToolCall(
                call_id="query-outside-window",
                name="query_range",
                arguments={
                    "query": "mysql_up",
                    "start": "2099-01-01T00:00:00+00:00",
                    "end": "2099-01-01T00:05:00+00:00",
                    "operation": "query",
                },
            ),
            MCPModelToolCall(
                call_id="query-exact-window",
                name="query_range",
                arguments={
                    "query": "mysql_threads_running",
                    "start": "2026-08-07T09:55:00+08:00",
                    "end": "2026-08-07T10:00:00+08:00",
                    "operation": "query",
                },
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert _HarnessSession.calls == [
        (
            "query_range",
            {
                "query": "mysql_threads_running",
                "start": "2026-08-07T09:55:00+08:00",
                "end": "2026-08-07T10:00:00+08:00",
                "operation": "query",
            },
        )
    ]
    correction_message = next(
        message for message in reversed(model.messages[1]) if message["role"] == "tool"
    )
    correction = json.loads(correction_message["content"])["host_validation"]
    assert correction["transport_sent"] is False
    assert correction["reason_code"] == "alert_window_mismatch"
    assert correction["expected_arguments"] == {
        "start": "2026-08-07T09:55:00+08:00",
        "end": "2026-08-07T10:00:00+08:00",
    }
    host_control = next(
        payload["host_control"]
        for message in model.messages[1]
        if message.get("role") == "user" and isinstance(message.get("content"), str)
        for payload in [json.loads(message["content"])]
        if "host_control" in payload
    )
    assert host_control["remote_calls_used"] == 0
    assert host_control["capability"] == "host_window_validation"

    accepted_tool_message = next(
        message for message in reversed(model.messages[2]) if message["role"] == "tool"
    )
    accepted_feedback = json.loads(accepted_tool_message["content"])
    assert accepted_feedback == raw_response
    assert accepted_feedback["_meta"]["api_key"] == "mcp-owned-secret"
    assert "1893456000" in accepted_tool_message["content"]
    assert result.finished_by_model is True
    assert len(result.responses) == 1
    assert result.model_tool_calls == ("query_range",)
    assert [attempt["outcome"] for attempt in result.tool_attempts] == [
        "rejected_locally",
        "result",
    ]


@pytest.mark.asyncio
async def test_prometheus_planner_exposes_model_reasoning_content() -> None:
    client = _client(
        _SequenceModel(
            [
                MCPModelToolCall(
                    call_id="reasoning-call",
                    name="query_range",
                    arguments={"query": "up"},
                    reasoning_content="先确认目标监控范围，再查询窗口指标。",
                )
            ]
        )
    )
    scenario = prometheus_harness_module.PrometheusHarnessScenario(
        client=client,
        context=_context(),
        window_start=_ALERT_WINDOW_START,
        window_end=_ALERT_TIME,
    )
    specs = scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name="query_range",
                input_schema={"type": "object", "additionalProperties": True},
            )
        ]
    )
    planner = prometheus_harness_module.PrometheusHarnessPlanner(
        client=client,
        scenario=scenario,
    )

    action = await planner.plan(
        messages=scenario.initial_messages(scenario.initial_state()),
        tools=specs,
    )

    assert action["action"] == "call_tool"
    assert planner.last_reasoning_content == "先确认目标监控范围，再查询窗口指标。"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "transport_error",
    [
        ConnectionError("stream closed while awaiting response"),
        ExceptionGroup(
            "SSE task group failed",
            [
                RuntimeError("cancel-scope cleanup failed"),
                httpx.RemoteProtocolError("peer closed the response stream"),
            ],
        ),
        EndOfStream(),
        ClosedResourceError(),
    ],
    ids=["connection-error", "nested-httpx-error", "end-of-stream", "closed-resource"],
)
async def test_shared_harness_preserves_results_across_transport_interruption(
    transport_error: Exception,
) -> None:
    _HarnessSession.results = [
        {"structuredContent": {"series": [{"value": 1}]}},
        transport_error,
        {"structuredContent": {"series": [{"value": 2}]}},
    ]
    retried_arguments = {
        "query": "rate(mysql_global_status_slow_queries[5m])",
        "start": "2026-08-07T01:55:00+00:00",
        "end": "2026-08-07T02:00:00+00:00",
        "operation": "query",
    }
    retried_provider_items = (
        {
            "type": "reasoning",
            "id": "retry-reasoning-item",
            "encrypted_content": "encrypted-retry-reasoning",
            "summary": [],
        },
        {
            "type": "function_call",
            "id": "retry-function-item",
            "call_id": "query-2",
            "name": "query_range",
            "arguments": json.dumps(retried_arguments),
            "status": "completed",
        },
    )
    model = _SequenceModel(
        [
            MCPModelToolCall(
                call_id="query-1",
                name="query_range",
                arguments={
                    "query": "mysql_up",
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                    "operation": "query",
                },
                request_id="request-query-1",
            ),
            MCPModelToolCall(
                call_id="query-2",
                name="query_range",
                arguments=retried_arguments,
                request_id="request-query-2",
                provider_output_items=retried_provider_items,
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert _HarnessSession.calls[0][1]["query"] == "mysql_up"
    assert _HarnessSession.calls[-1][1]["query"] == ("rate(mysql_global_status_slow_queries[5m])")
    assert len(result.responses) == 2
    assert result.has_monitoring_data is False
    assert all(item["projection_kind"] == "auxiliary" for item in result.responses)
    assert result.finished_by_model is True
    assert [attempt["outcome"] for attempt in result.tool_attempts] == [
        "result",
        "transport_error",
        "result",
    ]
    assert result.tool_attempts[1]["error_type"] == "prometheus_mcp_transport_error"
    assert result.tool_attempts[1]["evidence_disposition"] == "MISSING"
    assert result.tool_attempts[1]["is_contradiction"] is False
    assert "request-query-1" in result.model_request_ids
    assert "request-query-2" in result.model_request_ids
    finish_messages = model.messages[2]
    assert sum(item.get("id") == "retry-reasoning-item" for item in finish_messages) == 1
    assert sum(item.get("id") == "retry-function-item" for item in finish_messages) == 1
    assert (
        sum(
            item.get("type") == "function_call_output" and item.get("call_id") == "query-2"
            for item in finish_messages
        )
        == 1
    )


@pytest.mark.asyncio
async def test_repeated_model_failures_continue_until_explicit_finish(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'prometheus-model-resume.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    context, manifest, _run = await _durable_context(
        repository,
        external_id="prometheus-model-resume",
    )
    assert context.lease_owner is not None
    assert context.fencing_token is not None

    model = _SequenceModel(
        [
            RuntimeError("provider returned zero tool calls"),
            RuntimeError("provider returned text instead of a tool call"),
            MCPModelToolCall(
                call_id="finish-after-repairs",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )
    try:
        result = await _client(model, repository=repository).collect_alert_window(context)

        assert len(model.messages) == 3
        assert result.finished_by_model is True
        assert result.termination_reason == "finished_by_model"
        assert result.has_monitoring_data is False
        assert result.tool_attempts == ()
        checkpoint_store = RepositoryMCPCheckpointStore[
            PrometheusHarnessState,
            dict[str, Any],
        ](
            repository,
            provider=PROMETHEUS_MCP_SERVER_NAME,
            manifest_hash=manifest.digest(),
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )
        checkpoint = await checkpoint_store.load(context.run_id)
        assert checkpoint is not None
        assert checkpoint.state.consecutive_model_errors == []
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_model_repair_checkpoint_resume_allows_further_selection(
    tmp_path: Path,
) -> None:
    class FailureThenInterruptModel(_SequenceModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.messages.append(messages)
            self.tools.append(tools)
            if len(self.messages) == 1:
                raise RuntimeError("first Prometheus selection failed before restart")
            raise asyncio.CancelledError

    database_url = f"sqlite+aiosqlite:///{tmp_path / 'prometheus-model-repair.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    context, _, _run = await _durable_context(
        repository,
        external_id="prometheus-model-repair",
    )
    outer_dispatch_id = uuid4()
    with pytest.raises(asyncio.CancelledError):
        await _client(
            FailureThenInterruptModel([]),
            repository=repository,
        ).collect_alert_window(
            context.model_copy(
                update={
                    "outer_dispatch_id": outer_dispatch_id,
                }
            )
        )
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resumed_model = _SequenceModel(
        [
            RuntimeError("second Prometheus selection failed after restart"),
            RuntimeError("third Prometheus selection failed after restart"),
            MCPModelToolCall(
                call_id="finish-after-resume-repairs",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )
    result = await _client(
        resumed_model,
        repository=restarted_repository,
    ).collect_alert_window(
        context.model_copy(
            update={
                "outer_dispatch_id": outer_dispatch_id,
            }
        )
    )

    assert len(resumed_model.messages) == 3
    assert result.finished_by_model is True
    assert result.termination_reason == "finished_by_model"
    assert result.termination_error_type is None
    assert result.tool_attempts == ()
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_prometheus_raw_response_store_ignores_legacy_sanitized_artifact() -> None:
    invocation_id = uuid4()
    run_id = uuid4()
    arguments = {"query": "legacy"}
    legacy_id = uuid5(invocation_id, "prometheus-mcp-remote-response/v1")
    legacy_artifact = SimpleNamespace(
        artifact_id=legacy_id,
        kind="prometheus_mcp_remote_response",
        media_type="application/json",
        uri=f"agent-artifact://{legacy_id}",
        metadata={
            "contract": "prometheus-mcp-remote-response/v1",
            "provider": PROMETHEUS_MCP_SERVER_NAME,
            "run_id": str(run_id),
            "tool_name": "legacy_tool",
            "invocation_id": str(invocation_id),
            "outer_dispatch_id": None,
            "internal_only": True,
        },
    )

    class LegacyOnlyRepository:
        def __init__(self) -> None:
            self.requested_ids: list[str] = []

        async def get_agent_artifact(self, artifact_id: str) -> Any:
            self.requested_ids.append(artifact_id)
            if artifact_id == str(legacy_id):
                return legacy_artifact, {
                    "contract": "prometheus-mcp-remote-response/v1",
                    "provider": PROMETHEUS_MCP_SERVER_NAME,
                    "run_id": str(run_id),
                    "tool_name": "legacy_tool",
                    "arguments": arguments,
                    "response": {"secret_key": "[REDACTED]"},
                }
            return None

    repository = LegacyOnlyRepository()
    store = prometheus_harness_module.RepositoryPrometheusRemoteResponseStore(repository)

    recovered = await store.load(
        run_id=run_id,
        invocation_id=invocation_id,
        tool_name="legacy_tool",
        arguments=arguments,
    )

    assert recovered is None
    assert repository.requested_ids == [str(store.artifact_id(invocation_id))]


@pytest.mark.asyncio
async def test_raw_response_is_artifacted_when_investigation_is_cancelled(
    tmp_path: Path,
) -> None:
    class InterruptAfterQueryModel(_SequenceModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.messages.append(messages)
            self.tools.append(tools)
            if len(self.messages) == 1:
                return MCPModelToolCall(
                    call_id="persist-before-interrupt",
                    name="query_range",
                    arguments={
                        "query": "mysql_up",
                        "start": "2026-08-07T09:55:00+08:00",
                        "end": "2026-08-07T10:00:00+08:00",
                    },
                )
            raise asyncio.CancelledError

    database_url = f"sqlite+aiosqlite:///{tmp_path / 'prometheus-response-audit.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    context, _, run = await _durable_context(
        repository,
        external_id="prometheus-response-audit",
    )
    outer_dispatch_id = uuid4()
    raw_response = {
        "_meta": {
            "trace_id": "complete-response",
            "api_key": "mcp-owned-secret",
        },
        "content": [{"type": "text", "text": "x" * 50_000}],
        "structuredContent": {"series": [{"value": 1}]},
        "isError": False,
    }
    _HarnessSession.results = [raw_response]
    model = InterruptAfterQueryModel([])

    with pytest.raises(asyncio.CancelledError):
        await _client(
            model,
            repository=repository,
        ).collect_alert_window(context.model_copy(update={"outer_dispatch_id": outer_dispatch_id}))

    followup_context = json.dumps(model.messages[1], ensure_ascii=False)
    assert "agent-artifact://" not in followup_context
    assert "prometheus_mcp_remote_response" not in followup_context
    assert "complete-response" in followup_context
    assert "mcp-owned-secret" in followup_context
    assert "x" * 50_000 in followup_context

    async with repository.session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    stored = await repository.get_agent_artifact(rows[0].id)
    assert stored is not None
    artifact, content = stored
    assert artifact.metadata["internal_only"] is True
    assert artifact.metadata["sanitized"] is False
    assert isinstance(content, bytes)
    decoded_artifact = json.loads(content)
    assert decoded_artifact["response"] == raw_response
    assert decoded_artifact["invocation_id"] == artifact.metadata["invocation_id"]
    assert decoded_artifact["outer_dispatch_id"] == artifact.metadata["outer_dispatch_id"]
    await repository.close()


@pytest.mark.asyncio
async def test_recovery_replays_checkpointed_response_without_remote_recall(
    tmp_path: Path,
) -> None:
    class InterruptAfterQueryModel(_SequenceModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.messages.append(messages)
            self.tools.append(tools)
            if len(self.messages) == 1:
                return MCPModelToolCall(
                    call_id="query-before-response-replay",
                    name="query_range",
                    arguments={
                        "query": 'mysql_up{instance="mysql-17:3306"}',
                        "start": "2026-08-07T01:55:00+00:00",
                        "end": "2026-08-07T02:00:00+00:00",
                    },
                )
            raise asyncio.CancelledError

    database_url = f"sqlite+aiosqlite:///{tmp_path / 'prometheus-response-replay.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    context, _, run = await _durable_context(
        repository,
        external_id="prometheus-response-replay",
    )
    outer_dispatch_id = uuid4()
    scoped_context = context.model_copy(
        update={
            "outer_dispatch_id": outer_dispatch_id,
            "alert": context.alert.model_copy(
                update={
                    "database": DatabaseTarget(
                        engine="mysql",
                        instance="mysql-17:3306",
                        host="mysql-17",
                        port=3306,
                    )
                }
            ),
        }
    )
    raw_response = {
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
    _HarnessSession.results = [raw_response]
    with pytest.raises(asyncio.CancelledError):
        await _client(
            InterruptAfterQueryModel([]),
            repository=repository,
        ).collect_alert_window(scoped_context)

    assert len(_HarnessSession.calls) == 1
    async with repository.session_factory() as session:
        artifacts_before_finish = (
            (
                await session.execute(
                    select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                )
            )
            .scalars()
            .all()
        )
    assert len(artifacts_before_finish) == 1
    stored_before_finish = await repository.get_agent_artifact(artifacts_before_finish[0].id)
    assert stored_before_finish is not None
    artifact_before_finish, content_before_finish = stored_before_finish
    assert artifact_before_finish.metadata["internal_only"] is True
    assert isinstance(content_before_finish, bytes)
    assert json.loads(content_before_finish)["response"] == raw_response
    resumed_model = _SequenceModel(
        [
            MCPModelToolCall(
                call_id="finish-after-response-replay",
                name="finish_prometheus_investigation",
                arguments={
                    "monitoring_scope_status": "in_scope",
                    "reason": "已从持久化响应恢复监控事实。",
                },
            )
        ]
    )
    result = await _client(
        resumed_model,
        repository=repository,
    ).collect_alert_window(scoped_context)

    assert len(_HarnessSession.calls) == 1
    assert result.finished_by_model is True
    assert result.has_monitoring_data is True
    assert result.responses[0]["result"] == raw_response["structuredContent"]
    followup_context = json.dumps(resumed_model.messages[0], ensure_ascii=False)
    assert "agent-artifact://" not in followup_context
    assert "prometheus_mcp_remote_response" not in followup_context
    async with repository.session_factory() as session:
        artifacts = (
            (
                await session.execute(
                    select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                )
            )
            .scalars()
            .all()
        )
        invocations = (
            (
                await session.execute(
                    select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
                )
            )
            .scalars()
            .all()
        )
    assert len(artifacts) == 1
    assert len(invocations) == 1
    assert invocations[0].status == ToolInvocationStatus.SUCCEEDED.value
    stored = await repository.get_agent_artifact(artifacts[0].id)
    assert stored is not None
    artifact, content = stored
    assert artifact.metadata["internal_only"] is True
    assert artifact.metadata["sanitized"] is False
    assert isinstance(content, bytes)
    assert json.loads(content)["response"] == raw_response
    await repository.close()


@pytest.mark.asyncio
async def test_is_error_response_is_persisted_after_investigation_completion(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-is-error-audit.db'}"
    )
    await repository.initialize()
    context, _, run = await _durable_context(
        repository,
        external_id="prometheus-is-error-audit",
    )
    raw_error = {
        "isError": True,
        "content": [{"type": "text", "text": "invalid range selector"}],
    }
    _HarnessSession.results = [raw_error]
    result = await _client(
        _SequenceModel(
            [
                MCPModelToolCall(
                    call_id="is-error-query",
                    name="query_range",
                    arguments={
                        "query": "invalid",
                        "start": "2026-08-07T09:55:00+08:00",
                        "end": "2026-08-07T10:00:00+08:00",
                    },
                ),
                MCPModelToolCall(
                    call_id="finish-after-is-error",
                    name="finish_prometheus_investigation",
                    arguments={
                        "monitoring_scope_status": "unknown",
                        "reason": "查询返回工具错误。",
                    },
                ),
            ]
        ),
        repository=repository,
    ).collect_alert_window(context)

    assert result.tool_attempts[0]["outcome"] == "tool_error"
    async with repository.session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    stored = await repository.get_agent_artifact(rows[0].id)
    assert stored is not None
    artifact, content = stored
    assert artifact.metadata["internal_only"] is True
    assert artifact.metadata["sanitized"] is False
    assert isinstance(content, bytes)
    assert json.loads(content)["response"] == raw_error
    await repository.close()


@pytest.mark.asyncio
async def test_transport_failure_without_response_creates_no_response_artifact(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-no-response-audit.db'}"
    )
    await repository.initialize()
    context, _, run = await _durable_context(
        repository,
        external_id="prometheus-no-response-audit",
    )
    _HarnessSession.results = [ConnectionError("connection closed before response")]
    await _client(
        _SequenceModel(
            [
                MCPModelToolCall(
                    call_id="transport-failure-query",
                    name="query_range",
                    arguments={
                        "query": "mysql_up",
                        "start": "2026-08-07T09:55:00+08:00",
                        "end": "2026-08-07T10:00:00+08:00",
                    },
                )
            ]
        ),
        repository=repository,
        timeout_seconds=0.05,
    ).collect_alert_window(context)

    async with repository.session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                )
            )
            .scalars()
            .all()
        )
    assert rows == []
    await repository.close()


@pytest.mark.asyncio
async def test_prometheus_planner_records_reasoning_once_without_delta_streams(
    tmp_path: Path,
) -> None:
    class ReasoningModel(_SequenceModel):
        def __init__(self, responses: list[MCPModelToolCall | Exception]) -> None:
            super().__init__(responses)
            self.received_callbacks: list[Any | None] = []

        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
            reasoning_callback: Any | None = None,
        ) -> MCPModelToolCall:
            self.messages.append(messages)
            self.tools.append(tools)
            self.received_callbacks.append(reasoning_callback)
            return MCPModelToolCall(
                call_id="finish-with-reasoning",
                name="finish_prometheus_investigation",
                arguments={
                    "monitoring_scope_status": "unknown",
                    "reason": "没有更多可用信息。",
                },
                reasoning_content="先确认监控范围，再决定是否查询指标。",
            )

    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-reasoning-once.db'}"
    )
    await repository.initialize()
    context, _, run = await _durable_context(
        repository,
        external_id="prometheus-reasoning-once",
    )
    model = ReasoningModel([])
    await _client(
        model,
        repository=repository,
    ).collect_alert_window(context)

    # Durable reasoning deltas dominated the bounded planner wall time, so the
    # Prometheus harness no longer forwards a reasoning callback at all.
    assert model.received_callbacks == [None]

    events = await repository.list_agent_events(str(run.id))
    reasoning = [
        event
        for event in events
        if event.kind == AgentEventKind.TRACE_REASONING
        and event.payload.get("provider") == PROMETHEUS_MCP_SERVER_NAME
    ]
    assert [event.payload["content"] for event in reasoning] == [
        "先确认监控范围，再决定是否查询指标。",
    ]
    assert all("delta_index" not in event.payload for event in reasoning)
    assert all("stream_id" not in event.payload for event in reasoning)
    finish_decisions = [
        event
        for event in events
        if event.kind == AgentEventKind.MODEL_DECISION and event.payload.get("action") == "finish"
    ]
    assert len(finish_decisions) == 1
    assert finish_decisions[0].payload["reasoning"] == "先确认监控范围，再决定是否查询指标。"
    await repository.close()


@pytest.mark.asyncio
async def test_only_target_matched_alert_window_projection_is_persisted_to_trace(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-public-trace.db'}"
    )
    await repository.initialize()
    try:
        context, _, run = await _durable_context(
            repository,
            external_id="prometheus-public-trace",
        )
        context = context.model_copy(
            update={
                "alert": context.alert.model_copy(
                    update={
                        "cluster": "mysql-prod",
                        "database": DatabaseTarget(
                            engine="mysql",
                            instance="mysql-17:3306",
                            host="mysql-17",
                            port=3306,
                        ),
                    }
                )
            }
        )
        discovery_response = {
            "_meta": {"api_key": "discovery-secret"},
            "structuredContent": {
                "activeTargets": [
                    {
                        "labels": {"instance": "mysql-17:3306"},
                        "scrapeUrl": "http://mysql-17:9104/metrics",
                    }
                ]
            },
            "isError": False,
        }
        range_response = {
            "_meta": {"api_key": "range-secret"},
            "structuredContent": {
                "data": {
                    "result": [
                        {
                            "metric": {
                                "__name__": "mysql_threads_running",
                                "instance": "mysql-17:3306",
                                "api_key": "metric-label-secret",
                            },
                            "values": [
                                [1_786_067_700, "8"],
                                [1_786_068_000, "15"],
                            ],
                        }
                    ]
                }
            },
            "isError": False,
        }
        _HarnessSession.results = [discovery_response, range_response]
        model = _SequenceModel(
            [
                MCPModelToolCall(
                    call_id="discover-targets",
                    name="query_range",
                    arguments={
                        "query": "up",
                        "start": "2026-08-07T09:55:00+08:00",
                        "end": "2026-08-07T10:00:00+08:00",
                        "operation": "targets",
                    },
                ),
                MCPModelToolCall(
                    call_id="qualified-range",
                    name="query_range",
                    arguments={
                        "query": 'mysql_threads_running{instance="mysql-17:3306"}',
                        "start": "2026-08-07T01:55:00+00:00",
                        "end": "2026-08-07T02:00:00+00:00",
                        "operation": "query_range",
                    },
                ),
                MCPModelToolCall(
                    call_id="finish-qualified-range",
                    name="finish_prometheus_investigation",
                    arguments={
                        "monitoring_scope_status": "in_scope",
                        "reason": "目标已匹配并完成范围查询。",
                    },
                ),
            ]
        )

        result = await _client(model, repository=repository).collect_alert_window(context)

        assert result.has_monitoring_data is True
        assert len(result.responses) == 2
        assert [item["projection_kind"] for item in result.responses] == [
            "auxiliary",
            "alert_window_range",
        ]
        internal_context = json.dumps(model.messages, ensure_ascii=False)
        assert "discovery-secret" in internal_context
        assert "range-secret" in internal_context
        assert "metric-label-secret" in internal_context

        events = await repository.list_agent_events(str(run.id))
        observations = [
            event
            for event in events
            if event.kind == AgentEventKind.TRACE_OBSERVATION
            and event.payload.get("provider") == PROMETHEUS_MCP_SERVER_NAME
        ]
        assert len(observations) == 1
        trace_content = observations[0].payload["content"]
        trace_observation = json.loads(trace_content)
        assert trace_observation["projection_kind"] == "alert_window_range"
        assert trace_observation["projection"]["timeseries"]["sample_count"] == 2
        assert "mysql_threads_running" in trace_content
        assert "activeTargets" not in trace_content
        assert "discovery-secret" not in trace_content
        assert "range-secret" not in trace_content
        assert "metric-label-secret" not in trace_content
        assert "mysql-17:3306" not in trace_content

        async with repository.session_factory() as session:
            artifacts = (
                (
                    await session.execute(
                        select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                    )
                )
                .scalars()
                .all()
            )
        assert len(artifacts) == 2
        stored_responses = []
        for row in artifacts:
            stored = await repository.get_agent_artifact(row.id)
            assert stored is not None
            artifact, content = stored
            assert artifact.metadata["internal_only"] is True
            assert artifact.metadata["sanitized"] is False
            assert isinstance(content, bytes)
            stored_responses.append(json.loads(content)["response"])
        assert discovery_response in stored_responses
        assert range_response in stored_responses
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_semantically_empty_range_result_is_preserved_until_model_finishes(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-no-data.db'}"
    )
    await repository.initialize()
    try:
        context, _, run = await _durable_context(
            repository,
            external_id="prometheus-semantic-no-data",
        )
        _HarnessSession.results = [
            {
                "structuredContent": {
                    "status": "success",
                    "data": {"resultType": "matrix", "result": []},
                }
            },
            {
                "structuredContent": {
                    "status": "success",
                    "data": {"resultType": "matrix", "result": []},
                }
            },
        ]
        result = await _client(
            _SequenceModel(
                [
                    MCPModelToolCall(
                        call_id="empty-query",
                        name="query_range",
                        arguments={
                            "query": "mysql_up",
                            "start": "2026-08-07T01:55:00+00:00",
                            "end": "2026-08-07T02:00:00+00:00",
                            "operation": "query",
                        },
                    ),
                    MCPModelToolCall(
                        call_id="second-query",
                        name="query_range",
                        arguments={
                            "query": "mysql_threads_running",
                            "start": "2026-08-07T01:55:00+00:00",
                            "end": "2026-08-07T02:00:00+00:00",
                            "operation": "query",
                        },
                    ),
                    MCPModelToolCall(
                        call_id="finish-1",
                        name="finish_prometheus_investigation",
                        arguments={},
                    ),
                ]
            ),
            repository=repository,
        ).collect_alert_window(context)

        assert result.has_monitoring_data is False
        assert result.finished_by_model is True
        assert len(result.responses) == 2
        assert result.responses[0]["has_monitoring_observation"] is False
        assert [attempt["outcome"] for attempt in result.tool_attempts] == [
            "result",
            "result",
        ]
        assert result.tool_attempts[0]["arguments"] == result.tool_attempts[0]["model_arguments"]
        events = await repository.list_agent_events(str(run.id))
        no_data_events = [
            event
            for event in events
            if event.kind == AgentEventKind.TOOL_INVOCATION_NO_DATA
            and event.payload.get("provider") == PROMETHEUS_MCP_SERVER_NAME
        ]
        assert no_data_events == []
        async with repository.session_factory() as session:
            invocations = (
                (
                    await session.execute(
                        select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
                    )
                )
                .scalars()
                .all()
            )
        assert len(invocations) == 2
        assert {invocation.status for invocation in invocations} == {
            ToolInvocationStatus.SUCCEEDED.value
        }
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_repository_harness_uses_context_fencing_and_ignores_foreign_events(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-harness.db'}"
    )
    await repository.initialize()
    try:
        context, manifest, run = await _durable_context(
            repository,
            external_id="prometheus-durable-run",
        )
        assert context.lease_owner is not None
        assert context.fencing_token is not None
        foreign_sink = RepositoryEventSink(
            repository,
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )
        await foreign_sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.TOOL_INVOCATION_FAILED,
                payload={
                    "provider": "archery_mcp",
                    "error_code": "ForeignToolError",
                    "message": "foreign-tool-failure",
                },
            )
        )
        await foreign_sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.MCP_SESSION_FAILED,
                payload={
                    "provider": "archery_mcp",
                    "error_code": "ForeignSessionError",
                    "message": "foreign-session-failure",
                },
            )
        )
        await foreign_sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.TOOL_INVOCATION_FAILED,
                payload={
                    "provider": PROMETHEUS_MCP_SERVER_NAME,
                    "dispatch_scope_id": str(uuid4()),
                    "error_code": "SiblingDispatchToolError",
                    "message": "sibling-dispatch-tool-failure",
                },
            )
        )
        _HarnessSession.results = [
            {"structuredContent": {"series": [{"value": 1}]}},
            {"structuredContent": {"series": [{"value": 2}]}},
        ]
        result = await _client(
            _SequenceModel(
                [
                    MCPModelToolCall(
                        call_id="query-1",
                        name="query_range",
                        arguments={
                            "query": "mysql_up",
                            "start": "2026-08-07T01:55:00+00:00",
                            "end": "2026-08-07T02:00:00+00:00",
                            "operation": "query",
                        },
                    ),
                    MCPModelToolCall(
                        call_id="query-2",
                        name="query_range",
                        arguments={
                            "query": "mysql_threads_running",
                            "start": "2026-08-07T01:55:00+00:00",
                            "end": "2026-08-07T02:00:00+00:00",
                            "operation": "query",
                        },
                    ),
                    MCPModelToolCall(
                        call_id="finish-1",
                        name="finish_prometheus_investigation",
                        arguments={},
                    ),
                ]
            ),
            repository=repository,
        ).collect_alert_window(context)

        assert result.finished_by_model is True
        assert [attempt["outcome"] for attempt in result.tool_attempts] == [
            "result",
            "result",
        ]
        assert result.termination_error_type is None
        assert result.termination_error_detail is None
        events = await repository.list_agent_events(str(run.id))
        assert {event.payload.get("provider") for event in events} == {
            "archery_mcp",
            PROMETHEUS_MCP_SERVER_NAME,
        }
        checkpoint = await repository.load_checkpoint(
            str(run.id),
            namespace=f"mcp:{PROMETHEUS_MCP_SERVER_NAME}",
        )
        assert checkpoint is not None
        assert checkpoint.manifest_hash == manifest.digest()
        async with repository.session_factory() as session:
            invocations = (
                (
                    await session.execute(
                        select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
                    )
                )
                .scalars()
                .all()
            )
        assert len(invocations) == 2
        assert {invocation.provider for invocation in invocations} == {PROMETHEUS_MCP_SERVER_NAME}

        stale_context, _, stale_run = await _durable_context(
            repository,
            external_id="prometheus-stale-run",
        )
        assert stale_context.fencing_token is not None
        sessions_before_stale_call = _HarnessSession.session_count
        with pytest.raises(RunLeaseConflict):
            await _client(
                _SequenceModel([]),
                repository=repository,
            ).collect_alert_window(
                stale_context.model_copy(update={"fencing_token": stale_context.fencing_token + 1})
            )

        assert _HarnessSession.session_count == sessions_before_stale_call
        assert await repository.list_agent_events(str(stale_run.id)) == []
        assert (
            await repository.load_checkpoint(
                str(stale_run.id),
                namespace=f"mcp:{PROMETHEUS_MCP_SERVER_NAME}",
            )
            is None
        )
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_outer_recovery_without_scoped_checkpoint_never_opens_prometheus_session(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-missing-outer-checkpoint.db'}"
    )
    await repository.initialize()
    try:
        context, _manifest, _run = await _durable_context(
            repository,
            external_id="prometheus-missing-outer-checkpoint",
        )
        recovery_context = context.model_copy(
            update={
                "outer_dispatch_id": uuid4(),
            }
        )

        result = await _client(
            _SequenceModel(
                [
                    MCPModelToolCall(
                        call_id="finish-recovery",
                        name="finish_prometheus_investigation",
                        arguments={
                            "monitoring_scope_status": "unknown",
                            "reason": "未找到可恢复检查点，重新发现后结束。",
                        },
                    )
                ]
            ),
            repository=repository,
        ).collect_alert_window(recovery_context)

        assert result.finished_by_model is True
        assert result.monitoring_scope_status == "unknown"
        assert _HarnessSession.session_count == 1
        assert _HarnessSession.calls == []
    finally:
        await repository.close()
