from __future__ import annotations

import json
from contextlib import AsyncExitStack
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

import app.adapters.generic_mcp as generic_mcp_module
from app.adapters.generic_mcp import (
    GenericMCPConfigurationError,
    GenericMCPReadOnlyViolation,
    GenericReadOnlyMCPEvidenceTool,
)
from app.domain.models import (
    InvestigationContext,
    InvestigationStrategy,
    NormalizedAlert,
    Severity,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import (
    MCPPromptBundle,
    MCPServerDescriptor,
    ResolvedMCPConnection,
)


class _RemoteTool:
    def __init__(
        self,
        name: str = "query_data",
        *,
        annotations: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.annotations = annotations

    def model_dump(self, *, mode: str, exclude_none: bool) -> dict[str, Any]:
        assert mode == "json"
        payload: dict[str, Any] = {
            "name": self.name,
            "description": "Read database observations.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        }
        if self.annotations is not None or not exclude_none:
            payload["annotations"] = self.annotations
        return payload


class _RemoteResult:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(
        self, *, mode: str, by_alias: bool, exclude_none: bool
    ) -> dict[str, Any]:
        assert mode == "json"
        assert by_alias is True
        assert exclude_none is False
        return self.payload


class _Session:
    def __init__(
        self,
        tools: list[_RemoteTool],
        results: list[dict[str, Any]] | None = None,
    ) -> None:
        self.tools = tools
        self.results = list(results or [])
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self, *, cursor: str | None = None) -> Any:
        assert cursor is None
        return type("ListedTools", (), {"tools": self.tools})()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> _RemoteResult:
        self.calls.append((name, arguments))
        if not self.results:
            raise AssertionError("unexpected remote tool call")
        return _RemoteResult(self.results.pop(0))


class _SequenceModel:
    def __init__(self, calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.calls = calls
        self.messages: list[list[dict[str, Any]]] = []
        self.tool_names: list[set[str]] = []

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        index = len(self.messages)
        if index >= len(self.calls):
            raise AssertionError("model was called more times than expected")
        self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
        available = {item["function"]["name"] for item in tools}
        self.tool_names.append(available)
        name, arguments = self.calls[index]
        assert name in available
        return MCPModelToolCall(
            call_id=f"call-{index}",
            name=name,
            arguments=arguments,
            request_id=f"request-{index}",
        )


class _FailingModel:
    async def request_mcp_tool_call(self, **_kwargs: Any) -> MCPModelToolCall:
        raise AssertionError("model must not be called")


def _descriptor(
    *,
    transport: str = "streamable_http",
    max_agent_steps: int = 8,
) -> MCPServerDescriptor:
    return MCPServerDescriptor(
        name="example",
        read_only=True,
        url_template="${EXAMPLE_MCP_URL}",
        header_templates={},
        optional_header_templates={},
        prompts=MCPPromptBundle(
            role="Read-only database observer.",
            purpose="Collect relevant database evidence.",
            workflow="Inspect one result before choosing the next query.",
            safety="Every operation must remain read_only: true.",
        ),
        provider_options={
            "transport": transport,
            "maxAgentSteps": max_agent_steps,
        },
        referenced_environment_variables=("EXAMPLE_MCP_URL",),
        optional_environment_variables=(),
    )


def _connection() -> ResolvedMCPConnection:
    return ResolvedMCPConnection(
        url="https://mcp.example.test/endpoint",
        headers={"Authorization": "test-token"},
    )


def _context() -> InvestigationContext:
    alert = NormalizedAlert(
        external_id="generic-mcp-alert",
        source="canonical",
        raw_severity="WARNING",
        severity=Severity.WARNING,
        title="Database latency elevated",
        reason="database_latency",
        occurred_at=datetime(2026, 8, 12, 4, 0, tzinfo=UTC),
    )
    return InvestigationContext(
        run_id=uuid4(),
        alert=alert,
        strategy=InvestigationStrategy(
            strategy_id="generic-mcp-test",
            title="Generic MCP test",
            description="Exercise the declarative MCP adapter.",
        ),
    )


def _request(tool: GenericReadOnlyMCPEvidenceTool) -> ToolExecutionRequest:
    return ToolExecutionRequest(tool_name=tool.name, objective="Collect live evidence.")


def _bind_session(
    monkeypatch: pytest.MonkeyPatch,
    tool: GenericReadOnlyMCPEvidenceTool,
    session: _Session,
) -> None:
    async def open_session(_stack: AsyncExitStack) -> _Session:
        return session

    monkeypatch.setattr(tool, "_open_session", open_session)


@pytest.mark.asyncio
async def test_no_remote_tools_returns_no_data_without_calling_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = GenericReadOnlyMCPEvidenceTool(
        _descriptor(), _connection(), _FailingModel()
    )
    session = _Session([])
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data == {
        "reason_code": "no_explicit_read_only_tools"
    }
    assert session.calls == []


@pytest.mark.asyncio
async def test_tool_without_read_only_annotations_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = GenericReadOnlyMCPEvidenceTool(
        _descriptor(), _connection(), _FailingModel()
    )
    session = _Session([_RemoteTool(annotations=None)])
    _bind_session(monkeypatch, tool, session)

    with pytest.raises(GenericMCPReadOnlyViolation, match="no explicit read-only"):
        await tool.execute(_request(tool), _context())

    assert session.calls == []


@pytest.mark.asyncio
async def test_destructive_tool_is_rejected_even_when_marked_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = GenericReadOnlyMCPEvidenceTool(
        _descriptor(), _connection(), _FailingModel()
    )
    session = _Session(
        [
            _RemoteTool(
                annotations={"readOnlyHint": True, "destructiveHint": True}
            )
        ]
    )
    _bind_session(monkeypatch, tool, session)

    with pytest.raises(GenericMCPReadOnlyViolation, match="not explicitly read-only"):
        await tool.execute(_request(tool), _context())

    assert session.calls == []


@pytest.mark.asyncio
async def test_agent_can_inspect_multiple_results_before_finishing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "first"}),
            ("query_data", {"query": "second"}),
            ("finish_investigation", {"reason": "enough evidence"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[{"rows": [{"value": 1}]}, {"rows": [{"value": 2}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [
        ("query_data", {"query": "first"}),
        ("query_data", {"query": "second"}),
    ]
    assert [item["result"] for item in outcome.structured_data["observations"]] == [
        {"rows": [{"value": 1}]},
        {"rows": [{"value": 2}]},
    ]
    assert all(
        item["has_data"] is True and item["is_error"] is False
        for item in outcome.structured_data["observations"]
    )
    assert outcome.structured_data["read_only"] is True
    assert outcome.structured_data["root_cause_eligible"] is True
    assert outcome.structured_data["successful_observation_count"] == 2
    assert [len(messages) for messages in model.messages] == [2, 3, 4]
    assert model.tool_names == [
        {"query_data", "finish_investigation"},
        {"query_data", "finish_investigation"},
        {"query_data", "finish_investigation"},
    ]


@pytest.mark.asyncio
async def test_complete_large_remote_result_is_not_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    large_text = "complete-row-data:" + ("x" * 250_000)
    model = _SequenceModel(
        [
            ("query_data", {"query": "large result"}),
            ("finish_investigation", {"reason": "complete"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True, "destructiveHint": False})],
        results=[{"content": [{"type": "text", "text": large_text}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    observation = outcome.structured_data["observations"][0]
    assert observation["result"]["content"][0]["text"] == large_text
    assert len(observation["result"]["content"][0]["text"]) == len(large_text)
    assert "truncated" not in observation
    assert large_text in model.messages[1][-1]["content"]


@pytest.mark.asyncio
async def test_generic_mcp_preserves_null_fields_and_aliases_in_raw_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "complete envelope"}),
            ("finish_investigation", {"reason": "complete"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[
            {
                "_meta": None,
                "content": [],
                "structuredContent": {"rows": [{"value": 1}]},
                "isError": False,
            }
        ],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.structured_data["observations"][0]["result"] == {
        "_meta": None,
        "content": [],
        "structuredContent": {"rows": [{"value": 1}]},
        "isError": False,
    }


@pytest.mark.asyncio
async def test_mcp_error_result_is_feedback_but_never_successful_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "bad query"}),
            ("finish_investigation", {"reason": "remote rejected it"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[
            {
                "isError": True,
                "content": [{"type": "text", "text": "query failed"}],
            }
        ],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data["reason_code"] == "remote_tool_errors"
    assert outcome.structured_data["root_cause_eligible"] is False
    assert outcome.structured_data["observations"][0]["is_error"] is True
    assert outcome.structured_data["observations"][0]["has_data"] is False
    assert "query failed" in model.messages[1][-1]["content"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "empty_result",
    [
        {"isError": False, "content": []},
        {"isError": False, "structuredContent": {}},
        {"rows": []},
    ],
)
async def test_empty_result_returns_no_data(
    monkeypatch: pytest.MonkeyPatch,
    empty_result: dict[str, Any],
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "empty"}),
            ("finish_investigation", {"reason": "no data"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[empty_result],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data["reason_code"] == "empty_remote_results"
    assert outcome.structured_data["root_cause_eligible"] is False


@pytest.mark.asyncio
async def test_agent_can_recover_from_remote_error_with_later_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "bad"}),
            ("query_data", {"query": "corrected"}),
            ("finish_investigation", {"reason": "usable data collected"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[
            {"isError": True, "content": [{"type": "text", "text": "invalid"}]},
            {"isError": False, "structuredContent": {"rows": [{"value": 1}]}},
        ],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert outcome.structured_data["successful_observation_count"] == 1
    assert outcome.structured_data["root_cause_eligible"] is True
    assert [item["is_error"] for item in outcome.structured_data["observations"]] == [
        True,
        False,
    ]


@pytest.mark.asyncio
async def test_agent_step_limit_preserves_results_but_marks_them_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel([("query_data", {"query": "last allowed call"})])
    tool = GenericReadOnlyMCPEvidenceTool(
        _descriptor(max_agent_steps=1), _connection(), model
    )
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[{"rows": [{"value": 1}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert outcome.structured_data["observations"] == [
        {
            "tool_name": "query_data",
            "arguments": {"query": "last allowed call"},
            "result": {"rows": [{"value": 1}]},
            "is_error": False,
            "has_data": True,
        }
    ]
    assert outcome.structured_data["finished_by_model"] is False
    assert outcome.structured_data["partial"] is True
    assert outcome.structured_data["termination_reason"] == "max_agent_steps_reached"
    assert outcome.structured_data["root_cause_eligible"] is False
    assert "调查结果不完整" in outcome.summary


class _PagedSession(_Session):
    def __init__(self) -> None:
        super().__init__(
            [],
            results=[{"structuredContent": {"rows": [{"value": 1}]}}],
        )
        self.cursors: list[str | None] = []

    async def list_tools(self, *, cursor: str | None = None) -> Any:
        self.cursors.append(cursor)
        if cursor is None:
            return type(
                "ListedTools",
                (),
                {
                    "tools": [
                        _RemoteTool(
                            "first_page_tool",
                            annotations={"readOnlyHint": True},
                        )
                    ],
                    "nextCursor": "second-page",
                },
            )()
        assert cursor == "second-page"
        return type(
            "ListedTools",
            (),
            {
                "tools": [
                    _RemoteTool(
                        "second_page_tool",
                        annotations={"readOnlyHint": True},
                    )
                ],
                "nextCursor": None,
            },
        )()


@pytest.mark.asyncio
async def test_agent_can_call_tool_discovered_on_later_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("second_page_tool", {"query": "page two"}),
            ("finish_investigation", {"reason": "done"}),
        ]
    )
    tool = GenericReadOnlyMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _PagedSession()
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.cursors == [None, "second-page"]
    assert session.calls == [("second_page_tool", {"query": "page two"})]
    assert model.tool_names[0] == {
        "first_page_tool",
        "second_page_tool",
        "finish_investigation",
    }


class _EndlessPagedSession:
    def __init__(self) -> None:
        self.cursors: list[str | None] = []

    async def list_tools(self, *, cursor: str | None = None) -> Any:
        self.cursors.append(cursor)
        return type(
            "ListedTools",
            (),
            {"tools": [], "nextCursor": f"page-{len(self.cursors)}"},
        )()


@pytest.mark.asyncio
async def test_tool_listing_stops_after_ten_pages() -> None:
    tool = GenericReadOnlyMCPEvidenceTool(
        _descriptor(), _connection(), _FailingModel()
    )
    session = _EndlessPagedSession()

    with pytest.raises(GenericMCPConfigurationError, match="exceeded 10 pages"):
        await tool._list_tools(session)  # type: ignore[arg-type]

    assert session.cursors == [None, *[f"page-{index}" for index in range(1, 10)]]


class _AsyncContext:
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _InitializedSession:
    def __init__(self) -> None:
        self.initialized = False

    async def initialize(self) -> None:
        self.initialized = True


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["sse", "streamable_http"])
async def test_open_session_uses_configured_transport(
    monkeypatch: pytest.MonkeyPatch,
    transport: str,
) -> None:
    tool = GenericReadOnlyMCPEvidenceTool(
        _descriptor(transport=transport),
        _connection(),
        _FailingModel(),
        timeout_seconds=12.5,
    )
    read_stream = object()
    write_stream = object()
    initialized_session = _InitializedSession()
    calls: dict[str, Any] = {}

    def client_session(
        read: Any,
        write: Any,
        *,
        read_timeout_seconds: timedelta,
        client_info: Any,
    ) -> _AsyncContext:
        calls["session"] = {
            "read": read,
            "write": write,
            "timeout": read_timeout_seconds,
            "client_name": client_info.name,
        }
        return _AsyncContext(initialized_session)

    monkeypatch.setattr(generic_mcp_module, "ClientSession", client_session)

    if transport == "sse":

        def sse_connector(url: str, **kwargs: Any) -> _AsyncContext:
            calls["sse"] = {"url": url, **kwargs}
            return _AsyncContext((read_stream, write_stream))

        def unexpected_streamable(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("streamable connector must not be used")

        def unexpected_http_client(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("standalone HTTP client must not be used")

        monkeypatch.setattr(generic_mcp_module, "sse_client", sse_connector)
        monkeypatch.setattr(
            generic_mcp_module, "streamable_http_client", unexpected_streamable
        )
        monkeypatch.setattr(
            generic_mcp_module.httpx, "AsyncClient", unexpected_http_client
        )
    else:
        http_client = object()

        def async_http_client(**kwargs: Any) -> _AsyncContext:
            calls["http_client"] = kwargs
            return _AsyncContext(http_client)

        def streamable_connector(
            url: str, *, http_client: Any
        ) -> _AsyncContext:
            calls["streamable"] = {"url": url, "http_client": http_client}
            return _AsyncContext((read_stream, write_stream, object()))

        def unexpected_sse(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("SSE connector must not be used")

        monkeypatch.setattr(generic_mcp_module.httpx, "AsyncClient", async_http_client)
        monkeypatch.setattr(
            generic_mcp_module, "streamable_http_client", streamable_connector
        )
        monkeypatch.setattr(generic_mcp_module, "sse_client", unexpected_sse)

    async with AsyncExitStack() as stack:
        session = await tool._open_session(stack)

    assert session is initialized_session
    assert initialized_session.initialized is True
    assert calls["session"] == {
        "read": read_stream,
        "write": write_stream,
        "timeout": timedelta(seconds=12.5),
        "client_name": "database-alert-agent",
    }
    if transport == "sse":
        assert calls["sse"] == {
            "url": "https://mcp.example.test/endpoint",
            "headers": {"Authorization": "test-token"},
            "timeout": 12.5,
            "sse_read_timeout": 12.5,
            "httpx_client_factory": generic_mcp_module._no_redirect_http_client,
        }
    else:
        assert calls["streamable"] == {
            "url": "https://mcp.example.test/endpoint",
            "http_client": calls["streamable"]["http_client"],
        }
        assert calls["http_client"]["headers"] == {
            "Authorization": "test-token"
        }
        assert calls["http_client"]["follow_redirects"] is False
        assert calls["http_client"]["timeout"].connect == 12.5


@pytest.mark.asyncio
async def test_sse_http_client_factory_disables_redirects() -> None:
    client = generic_mcp_module._no_redirect_http_client(
        headers={"Authorization": "secret"},
        timeout=httpx.Timeout(5),
    )
    try:
        assert client.follow_redirects is False
        assert client.headers["Authorization"] == "secret"
    finally:
        await client.aclose()
