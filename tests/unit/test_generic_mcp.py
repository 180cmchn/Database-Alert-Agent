from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4, uuid5

import httpx
import pytest

import app.adapters.generic_mcp as generic_mcp_module
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.generic_mcp import (
    GenericMCPConfigurationError,
    GenericMCPEvidenceTool,
)
from app.adapters.persistence import AgentArtifactRow, SQLAlchemyAlertRepository
from app.agent_runtime.contracts import ArtifactRef, RunManifest
from app.agent_runtime.events import InMemoryEventSink
from app.agent_runtime.trace import AgentTraceKind, AgentTraceScope, trace_entry_from_event
from app.domain.models import (
    InvestigationContext,
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


class _SimulatedProcessCrash(BaseException):
    pass


class _RemoteTool:
    def __init__(
        self,
        name: str = "query_data",
        *,
        annotations: dict[str, Any] | None = None,
        input_schema: Any = None,
    ) -> None:
        self.name = name
        self.annotations = annotations
        self.input_schema = (
            {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            }
            if input_schema is None
            else input_schema
        )

    def model_dump(self, *, mode: str, exclude_none: bool) -> dict[str, Any]:
        assert mode == "json"
        payload: dict[str, Any] = {
            "name": self.name,
            "description": "Read database observations.",
            "inputSchema": self.input_schema,
        }
        if self.annotations is not None or not exclude_none:
            payload["annotations"] = self.annotations
        return payload


class _RemoteResult:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, *, mode: str, by_alias: bool, exclude_none: bool) -> dict[str, Any]:
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
    def __init__(
        self,
        calls: list[tuple[str, dict[str, Any]]],
        *,
        require_discovered_name: bool = True,
        reasoning: list[str | None] | None = None,
    ) -> None:
        self.calls = calls
        self.require_discovered_name = require_discovered_name
        self.reasoning = reasoning or [None] * len(calls)
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
        if self.require_discovered_name:
            assert name in available
        return MCPModelToolCall(
            call_id=f"call-{index}",
            name=name,
            arguments=arguments,
            request_id=f"request-{index}",
            reasoning_content=self.reasoning[index],
        )


class _FailingModel:
    async def request_mcp_tool_call(self, **_kwargs: Any) -> MCPModelToolCall:
        raise AssertionError("model must not be called")


class _FailAfterFirstRemoteResultModel(_SequenceModel):
    def __init__(
        self,
        call: tuple[str, dict[str, Any]],
        *,
        before_failure: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__([call])
        self.failed_messages: list[dict[str, Any]] | None = None
        self.before_failure = before_failure

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        if self.messages:
            if self.before_failure is not None:
                await self.before_failure()
            self.failed_messages = json.loads(json.dumps(messages, ensure_ascii=False))
            raise RuntimeError("model failed after the first remote response")
        return await super().request_mcp_tool_call(messages=messages, tools=tools)


class _BlockAfterFirstRemoteResultModel(_SequenceModel):
    def __init__(self, call: tuple[str, dict[str, Any]]) -> None:
        super().__init__([call])
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        if self.messages:
            self.waiting.set()
            await self.release.wait()
            raise AssertionError("blocked model call must be cancelled")
        return await super().request_mcp_tool_call(messages=messages, tools=tools)


def _descriptor() -> MCPServerDescriptor:
    return MCPServerDescriptor(
        name="example",
        url_template="${EXAMPLE_MCP_URL}",
        header_templates={},
        optional_header_templates={},
        prompts=MCPPromptBundle(
            role="Database evidence observer.",
            purpose="Collect relevant database evidence.",
            workflow="Inspect one result before choosing the next query.",
            safety="Use this MCP according to its configured role.",
        ),
        provider_options={},
        referenced_environment_variables=("EXAMPLE_MCP_URL",),
        optional_environment_variables=(),
    )


def _connection(*, transport: str = "streamable_http") -> ResolvedMCPConnection:
    return ResolvedMCPConnection(
        url="https://mcp.example.test/endpoint",
        headers={"Authorization": "test-token"},
        transport=transport,  # type: ignore[arg-type]
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
    )


async def _durable_context(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
) -> InvestigationContext:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": external_id,
            "severity": "WARNING",
            "title": "Declarative MCP audit artifact",
            "reason": "audit_test",
        }
    )
    stored, _created = await repository.create_or_get(alert)
    run_id = uuid4()
    run = await repository.create_run(
        str(stored.alert.id),
        "generic-mcp-test-worker",
        300,
        manifest=RunManifest(
            run_id=run_id,
            agent_name="generic-mcp-test",
            code_version="test",
        ),
    )
    assert run is not None and run.lease_owner is not None
    return InvestigationContext(
        run_id=run.id,
        alert=alert,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
        outer_dispatch_id=uuid4(),
    )


def _request(
    tool: GenericMCPEvidenceTool,
    *,
    parameters: dict[str, Any] | None = None,
) -> ToolExecutionRequest:
    return ToolExecutionRequest(
        tool_name=tool.name,
        objective="Collect live evidence.",
        parameters=parameters or {},
    )


def _bind_session(
    monkeypatch: pytest.MonkeyPatch,
    tool: GenericMCPEvidenceTool,
    session: _Session,
) -> None:
    async def open_session(_stack: AsyncExitStack) -> _Session:
        return session

    monkeypatch.setattr(tool, "_open_session", open_session)


@pytest.mark.asyncio
async def test_no_remote_tools_returns_no_data_without_calling_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    session = _Session([])
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data == {"reason_code": "no_discovered_tools"}
    assert session.calls == []


@pytest.mark.asyncio
async def test_tool_without_annotations_is_discovered_and_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "current state"}),
            ("finish_investigation", {"reason": "done"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session([_RemoteTool(annotations=None)])
    session.results.append({"rows": [{"value": 1}]})
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [("query_data", {"query": "current state"})]
    assert model.tool_names[0] == {"query_data", "finish_investigation"}


@pytest.mark.asyncio
async def test_remote_annotations_do_not_filter_dynamically_discovered_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "declared by MCP"}),
            ("finish_investigation", {"reason": "done"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True, "destructiveHint": True})],
        results=[{"rows": [{"value": 1}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [("query_data", {"query": "declared by MCP"})]


@pytest.mark.asyncio
async def test_remote_finish_name_is_not_shadowed_by_local_finish_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("finish_investigation", {"remote": "argument"}),
            ("finish_investigation_2", {"reason": "done"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool("finish_investigation")],
        results=[{"rows": [{"value": 1}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [("finish_investigation", {"remote": "argument"})]
    assert model.tool_names == [
        {"finish_investigation", "finish_investigation_2"},
        {"finish_investigation", "finish_investigation_2"},
    ]


def test_remote_tool_name_and_schema_are_forwarded_without_host_validation() -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    remote_schema = {
        "type": "object",
        "properties": {"opaque": {"mcp_extension": [1, {"nested": True}]}},
        "mcp_extension": {"host_must_not_interpret": True},
    }

    definition = tool._tool_definition(
        _RemoteTool("server:owned/tool-name", input_schema=remote_schema)
    )

    assert tool.input_schema == {"type": "object", "additionalProperties": True}
    assert definition["function"]["name"] == "server:owned/tool-name"
    assert definition["function"]["parameters"] == remote_schema
    empty_definition = tool._tool_definition(_RemoteTool(input_schema={}))
    assert empty_definition["function"]["parameters"] == {}


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
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
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
    assert all("result" not in item for item in outcome.structured_data["observations"])
    assert [item["response_ordinal"] for item in outcome.structured_data["observations"]] == [1, 2]
    assert [item["decision_round"] for item in outcome.structured_data["observations"]] == [
        1,
        2,
    ]
    assert all(
        item["has_data"] is True and item["is_error"] is False
        for item in outcome.structured_data["observations"]
    )
    assert outcome.structured_data["root_cause_eligible"] is True
    assert outcome.structured_data["finished_by_model"] is True
    assert outcome.structured_data["partial"] is False
    assert outcome.structured_data["termination_reason"] == "model_finished"
    assert outcome.structured_data["successful_observation_count"] == 2
    assert [len(messages) for messages in model.messages] == [2, 4, 6]
    first_assistant_call, first_tool_result = model.messages[1][-2:]
    assert first_assistant_call == {
        "role": "assistant",
        "tool_calls": [
            {
                "id": "call-0",
                "type": "function",
                "function": {
                    "name": "query_data",
                    "arguments": '{"query":"first"}',
                },
            }
        ],
    }
    assert first_tool_result == {
        "role": "tool",
        "tool_call_id": "call-0",
        "content": '{"rows":[{"value":1}]}',
    }
    assert model.tool_names == [
        {"query_data", "finish_investigation"},
        {"query_data", "finish_investigation"},
        {"query_data", "finish_investigation"},
    ]


@pytest.mark.asyncio
async def test_each_declarative_mcp_round_emits_exact_react_trace_without_raw_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = InMemoryEventSink()
    model = _SequenceModel(
        [
            ("query_data", {"query": "current state"}),
            ("finish_investigation", {"reason": "enough facts"}),
        ],
        reasoning=["先查询当前状态。", "现有事实已经足够。"],
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        event_sink=sink,
    )
    raw_value = "critical-prefix:" + ("x" * 2_000) + ":raw-tail"
    session = _Session(
        [_RemoteTool()],
        results=[{"rows": [{"value": raw_value}]}],
    )
    _bind_session(monkeypatch, tool, session)
    context = _context()

    outcome = await tool.execute(_request(tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    entries = [
        entry
        for event in await sink.read(context.run_id)
        if (entry := trace_entry_from_event(event)) is not None
    ]
    assert [entry.kind for entry in entries] == [
        AgentTraceKind.REASONING,
        AgentTraceKind.ACTION,
        AgentTraceKind.OBSERVATION,
        AgentTraceKind.REASONING,
        AgentTraceKind.ACTION,
    ]
    assert all(entry.scope == AgentTraceScope.MCP_INTERNAL for entry in entries)
    assert entries[0].content == "先查询当前状态。"
    assert entries[3].content == "现有事实已经足够。"
    assert json.loads(entries[1].content) == {
        "action": "call_tool",
        "arguments": {"query": "current state"},
        "tool_name": "query_data",
    }
    observation = json.loads(entries[2].content)
    assert observation["observation_type"] == "program_fact_projection"
    assert "result" not in observation
    assert raw_value not in entries[2].content
    assert ":raw-tail" not in entries[2].content
    assert observation["projection"]["scalar_groups"][0]["samples"][0]["value"][
        "excerpt"
    ].startswith("critical-prefix:")
    assert json.loads(entries[4].content)["action"] == "finish"


@pytest.mark.asyncio
async def test_declarative_mcp_persists_reasoning_deltas_without_complete_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StreamingModel(_SequenceModel):
        async def request_mcp_tool_call(  # type: ignore[no-untyped-def]
            self,
            *,
            messages,
            tools,
            reasoning_callback,
        ):
            index = len(self.messages)
            await reasoning_callback(f"round-{index}-part-a", 0)
            await reasoning_callback(f"round-{index}-part-b", 1)
            call = await super().request_mcp_tool_call(messages=messages, tools=tools)
            return MCPModelToolCall(
                call_id=call.call_id,
                name=call.name,
                arguments=call.arguments,
                request_id=call.request_id,
                reasoning_content=f"round-{index}-part-around-{index}-part-b",
                usage=call.usage,
            )

    sink = InMemoryEventSink()
    model = StreamingModel(
        [
            ("query_data", {"query": "current state"}),
            ("finish_investigation", {"reason": "enough facts"}),
        ]
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        event_sink=sink,
    )
    session = _Session([_RemoteTool()], results=[{"rows": [{"value": 1}]}])
    _bind_session(monkeypatch, tool, session)
    context = _context()

    outcome = await tool.execute(_request(tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    reasoning_events = [
        event for event in await sink.read(context.run_id) if event.kind.value == "TRACE_REASONING"
    ]
    assert [event.payload["content"] for event in reasoning_events] == [
        "round-0-part-a",
        "round-0-part-b",
        "round-1-part-a",
        "round-1-part-b",
    ]
    assert [event.payload["delta_index"] for event in reasoning_events] == [0, 1, 0, 1]
    assert len({event.payload["stream_id"] for event in reasoning_events}) == 2
    assert all(":reasoning:request:0" in event.payload["stream_id"] for event in reasoning_events)


@pytest.mark.asyncio
async def test_declarative_mcp_replays_responses_items_across_two_tool_rounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResponsesSequenceModel:
        def __init__(self) -> None:
            self.messages: list[list[dict[str, Any]]] = []

        async def request_mcp_tool_call(  # type: ignore[no-untyped-def]
            self,
            *,
            messages,
            tools,
        ):
            del tools
            self.messages.append(json.loads(json.dumps(messages, ensure_ascii=False)))
            index = len(self.messages) - 1
            if index < 2:
                call_id = f"responses-call-{index}"
                return MCPModelToolCall(
                    call_id=call_id,
                    name="query_data",
                    arguments={"query": f"round-{index + 1}"},
                    provider_output_items=(
                        {
                            "type": "reasoning",
                            "id": f"reasoning-{index}",
                            "encrypted_content": f"encrypted-{index}",
                            "summary": [],
                        },
                        {
                            "type": "function_call",
                            "id": f"function-item-{index}",
                            "call_id": call_id,
                            "name": "query_data",
                            "arguments": json.dumps(
                                {"query": f"round-{index + 1}"},
                                ensure_ascii=False,
                            ),
                            "status": "completed",
                        },
                    ),
                )
            return MCPModelToolCall(
                call_id="responses-finish",
                name="finish_investigation",
                arguments={"reason": "two rounds completed"},
            )

    model = ResponsesSequenceModel()
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    raw_results = [
        {"structuredContent": {"value": 1}},
        {"structuredContent": {"value": 2}},
    ]
    session = _Session([_RemoteTool()], results=raw_results)
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [
        ("query_data", {"query": "round-1"}),
        ("query_data", {"query": "round-2"}),
    ]
    second_input = model.messages[1]
    assert second_input[-3]["type"] == "reasoning"
    assert second_input[-3]["encrypted_content"] == "encrypted-0"
    assert second_input[-2]["type"] == "function_call"
    assert second_input[-2]["call_id"] == "responses-call-0"
    assert second_input[-1]["type"] == "function_call_output"
    assert second_input[-1]["call_id"] == "responses-call-0"
    assert json.loads(second_input[-1]["output"]) == raw_results[0]
    third_input = model.messages[2]
    assert [item.get("call_id") for item in third_input if "call_id" in item] == [
        "responses-call-0",
        "responses-call-0",
        "responses-call-1",
        "responses-call-1",
    ]
    assert [
        json.loads(item["output"])
        for item in third_input
        if item.get("type") == "function_call_output"
    ] == raw_results


@pytest.mark.asyncio
async def test_responses_items_survive_process_crash_recovery_without_remote_recall(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ResponsesFirstCallModel:
        async def request_mcp_tool_call(  # type: ignore[no-untyped-def]
            self,
            *,
            messages,
            tools,
        ):
            del messages, tools
            call_id = "responses-checkpoint-call"
            return MCPModelToolCall(
                call_id=call_id,
                name="query_data",
                arguments={"query": "durable responses result"},
                provider_output_items=(
                    {
                        "type": "reasoning",
                        "id": "responses-checkpoint-reasoning",
                        "encrypted_content": "durable-encrypted-reasoning",
                        "summary": [],
                    },
                    {
                        "type": "function_call",
                        "id": "responses-checkpoint-function",
                        "call_id": call_id,
                        "name": "query_data",
                        "arguments": '{"query":"durable responses result"}',
                        "status": "completed",
                    },
                ),
            )

    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-responses-recovery.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="responses-recovery")
    first_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        ResponsesFirstCallModel(),
        repository=repository,
    )
    raw_envelope = {
        "structuredContent": {"rows": [{"instance_id": 917}]},
        "api_key": "responses-owned-secret",
        "isError": False,
    }
    first_session = _Session([_RemoteTool()], results=[raw_envelope])
    _bind_session(monkeypatch, first_tool, first_session)
    save_checkpoint = first_tool._save_execution_checkpoint

    async def interrupt_after_raw_staging(*args: Any, **kwargs: Any) -> None:
        await save_checkpoint(*args, **kwargs)
        if args[0].pending_response_index is not None:
            raise _SimulatedProcessCrash

    monkeypatch.setattr(
        first_tool,
        "_save_execution_checkpoint",
        interrupt_after_raw_staging,
    )
    with pytest.raises(_SimulatedProcessCrash):
        await first_tool.execute(_request(first_tool), context)

    resumed_model = _SequenceModel(
        [("finish_investigation", {"reason": "responses state recovered"})]
    )
    resumed_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        resumed_model,
        repository=repository,
    )
    resumed_session = _Session([_RemoteTool()])
    _bind_session(monkeypatch, resumed_tool, resumed_session)

    outcome = await resumed_tool.execute(_request(resumed_tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    assert resumed_session.calls == []
    reasoning_item, function_item, output_item = resumed_model.messages[0][-3:]
    assert reasoning_item["id"] == "responses-checkpoint-reasoning"
    assert reasoning_item["encrypted_content"] == "durable-encrypted-reasoning"
    assert function_item["id"] == "responses-checkpoint-function"
    assert function_item["call_id"] == "responses-checkpoint-call"
    assert output_item["type"] == "function_call_output"
    assert output_item["call_id"] == "responses-checkpoint-call"
    assert json.loads(output_item["output"]) == raw_envelope
    await repository.close()


@pytest.mark.asyncio
async def test_declarative_mcp_reasoning_retry_appends_new_request_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InterruptedModel:
        calls = 0

        async def request_mcp_tool_call(  # type: ignore[no-untyped-def]
            self,
            *,
            messages,
            tools,
            reasoning_callback,
        ):
            del messages, tools
            self.calls += 1
            await reasoning_callback(f"attempt-{self.calls}", 0)
            if self.calls == 1:
                raise asyncio.CancelledError
            return MCPModelToolCall(
                call_id="finish-after-recovery",
                name="finish_investigation",
                arguments={"reason": "recovered"},
                reasoning_content=f"attempt-{self.calls}",
            )

    sink = InMemoryEventSink()
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        InterruptedModel(),
        event_sink=sink,
    )
    session = _Session([_RemoteTool()])
    _bind_session(monkeypatch, tool, session)
    context = _context()

    with pytest.raises(asyncio.CancelledError):
        await tool.execute(_request(tool), context)
    outcome = await tool.execute(_request(tool), context)

    assert outcome.status == ToolStatus.NO_DATA
    reasoning_events = [
        event for event in await sink.read(context.run_id) if event.kind.value == "TRACE_REASONING"
    ]
    assert [event.payload["content"] for event in reasoning_events] == [
        "attempt-1",
        "attempt-2",
    ]
    assert reasoning_events[0].payload["stream_id"].endswith(":request:0")
    assert reasoning_events[1].payload["stream_id"].endswith(":request:1")


@pytest.mark.asyncio
async def test_complete_large_remote_result_is_raw_for_model_but_filtered_from_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    large_text = "complete-row-data:" + ("x" * 250_000)
    model = _SequenceModel(
        [
            ("query_data", {"query": "large result"}),
            ("finish_investigation", {"reason": "complete"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    raw_envelope = {
        "content": [{"type": "text", "text": large_text}],
        "token": "server-owned-secret-token",
    }
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True, "destructiveHint": False})],
        results=[raw_envelope],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    observation = outcome.structured_data["observations"][0]
    assert "result" not in observation
    assert large_text not in outcome.model_dump_json()
    assert "server-owned-secret-token" not in outcome.model_dump_json()
    assert "truncated" not in observation
    model_observation = json.loads(model.messages[1][-1]["content"])
    assert model_observation == raw_envelope
    assert model_observation["content"][0]["text"] == large_text
    assert model_observation["token"] == "server-owned-secret-token"
    projection = observation["projection"]
    assert projection["source_path"] == "/result"
    assert projection["source_json_chars"] > len(large_text)
    text_sample = projection["scalar_groups"][0]["samples"][0]["value"]
    assert text_sample["excerpt"] == large_text[:500]
    assert text_sample["total_chars"] == len(large_text)
    assert len(model.messages[1][-1]["content"]) > len(large_text)


@pytest.mark.asyncio
async def test_remote_response_is_persisted_after_a_later_model_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-deferred-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="deferred-artifact")
    assert context.outer_dispatch_id is not None
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )

    async def assert_artifact_not_persisted() -> None:
        assert await repository.get_agent_artifact(str(artifact_id)) is None

    model = _FailAfterFirstRemoteResultModel(
        ("query_data", {"query": "retain before next decision"}),
        before_failure=assert_artifact_not_persisted,
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        repository=repository,
    )
    raw_value = "raw-audit-value:" + ("z" * 20_000)
    session = _Session(
        [_RemoteTool()],
        results=[{"rows": [{"value": raw_value}], "token": "secret-token"}],
    )
    _bind_session(monkeypatch, tool, session)

    with pytest.raises(RuntimeError, match="model failed after the first remote response"):
        await tool.execute(_request(tool), context)

    assert model.failed_messages is not None
    failed_context = json.dumps(model.failed_messages, ensure_ascii=False)
    assert raw_value in failed_context
    assert "secret-token" in failed_context
    assert "agent-artifact://" not in failed_context
    stored = await repository.get_agent_artifact(str(artifact_id))
    assert stored is not None
    artifact, content = stored
    assert artifact.kind == "declarative_mcp_remote_response"
    assert artifact.metadata["internal_only"] is True
    assert artifact.metadata["sanitized"] is False
    assert artifact.metadata["raw_response_unmodified"] is True
    assert artifact.metadata["response_ordinal"] == 1
    assert isinstance(content, bytes)
    decoded_content = json.loads(content.decode("utf-8"))
    assert decoded_content["result"]["rows"][0]["value"] == raw_value
    assert decoded_content["result"]["token"] == "secret-token"
    async with repository.session_factory() as database_session:
        row = await database_session.get(AgentArtifactRow, str(artifact_id))
        assert row is not None
        assert row.invocation_id == str(invocation_id)
    await repository.close()


@pytest.mark.asyncio
async def test_process_crash_response_checkpoint_allows_chat_recovery_without_remote_recall(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-chat-recovery.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    context = await _durable_context(repository, external_id="chat-response-recovery")
    assert context.outer_dispatch_id is not None
    first_model = _SequenceModel([("query_data", {"query": "durable chat response"})])
    first_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        first_model,
        repository=repository,
    )
    raw_envelope = {
        "content": [{"type": "text", "text": "r" * 50_000}],
        "token": "checkpoint-owned-secret",
        "isError": False,
    }
    first_session = _Session([_RemoteTool()], results=[raw_envelope])
    _bind_session(monkeypatch, first_tool, first_session)
    save_checkpoint = first_tool._save_execution_checkpoint
    interrupted = False

    async def interrupt_after_raw_staging(*args: Any, **kwargs: Any) -> None:
        nonlocal interrupted
        await save_checkpoint(*args, **kwargs)
        state = args[0]
        if state.pending_response_index is not None and not interrupted:
            interrupted = True
            raise _SimulatedProcessCrash

    monkeypatch.setattr(
        first_tool,
        "_save_execution_checkpoint",
        interrupt_after_raw_staging,
    )

    with pytest.raises(_SimulatedProcessCrash):
        await first_tool.execute(_request(first_tool), context)

    assert first_session.calls == [("query_data", {"query": "durable chat response"})]
    namespace = f"mcp:example_mcp:{context.outer_dispatch_id}"
    staged = await repository.load_checkpoint(str(context.run_id), namespace=namespace)
    assert staged is not None
    assert staged.state["pending_response_index"] == 0
    assert staged.state["remote_responses"][0]["envelope"] == raw_envelope
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    assert await repository.get_agent_artifact(str(artifact_id)) is None
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()

    resumed_model = _SequenceModel([("finish_investigation", {"reason": "recovered raw response"})])
    resumed_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        resumed_model,
        repository=restarted_repository,
    )
    resumed_session = _Session([_RemoteTool()])
    _bind_session(monkeypatch, resumed_tool, resumed_session)

    outcome = await resumed_tool.execute(_request(resumed_tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    assert resumed_session.calls == []
    assistant_call, tool_result = resumed_model.messages[0][-2:]
    assert assistant_call["role"] == "assistant"
    assert assistant_call["tool_calls"][0]["id"] == "call-0"
    assert tool_result["role"] == "tool"
    assert tool_result["tool_call_id"] == "call-0"
    assert json.loads(tool_result["content"]) == raw_envelope
    stored = await restarted_repository.get_agent_artifact(str(artifact_id))
    assert stored is not None and isinstance(stored[1], bytes)
    assert json.loads(stored[1].decode("utf-8"))["result"] == raw_envelope
    completed = await restarted_repository.load_checkpoint(
        str(context.run_id),
        namespace=namespace,
    )
    assert completed is not None
    assert completed.state["completed"] is True
    assert completed.state["pending_response_index"] is None
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_recovered_raw_response_is_artifacted_when_server_now_lists_no_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-empty-catalog-recovery.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="empty-catalog-recovery")
    assert context.outer_dispatch_id is not None
    raw_envelope = {
        "structuredContent": {"rows": [{"value": "durable-before-empty-catalog"}]},
        "secret_key": "mcp-owned-empty-catalog-secret",
        "isError": False,
    }
    first_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        _SequenceModel([("query_data", {"query": "stage before catalog changes"})]),
        repository=repository,
    )
    first_session = _Session([_RemoteTool()], results=[raw_envelope])
    _bind_session(monkeypatch, first_tool, first_session)
    save_checkpoint = first_tool._save_execution_checkpoint
    interrupted = False

    async def interrupt_after_staging(*args: Any, **kwargs: Any) -> None:
        nonlocal interrupted
        await save_checkpoint(*args, **kwargs)
        if args[0].pending_response_index is not None and not interrupted:
            interrupted = True
            raise _SimulatedProcessCrash

    monkeypatch.setattr(first_tool, "_save_execution_checkpoint", interrupt_after_staging)
    with pytest.raises(_SimulatedProcessCrash):
        await first_tool.execute(_request(first_tool), context)

    resumed_model = _SequenceModel([])
    resumed_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        resumed_model,
        repository=repository,
    )
    empty_session = _Session([])
    _bind_session(monkeypatch, resumed_tool, empty_session)

    outcome = await resumed_tool.execute(_request(resumed_tool), context)

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data == {"reason_code": "no_discovered_tools"}
    assert resumed_model.messages == []
    assert empty_session.calls == []
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    stored = await repository.get_agent_artifact(str(artifact_id))
    assert stored is not None and isinstance(stored[1], bytes)
    assert json.loads(stored[1].decode("utf-8"))["result"] == raw_envelope
    await repository.close()


@pytest.mark.asyncio
async def test_chat_orphan_artifact_recovers_after_first_checkpoint_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-chat-orphan-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="chat-orphan-artifact")
    assert context.outer_dispatch_id is not None
    arguments = {"query": "recover chat orphan response", "opaque": "model-owned-value"}
    first_model = _SequenceModel(
        [("query_data", arguments)],
        reasoning=["inspect the complete chat response"],
    )
    first_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        first_model,
        repository=repository,
    )
    raw_envelope = {
        "structuredContent": {"rows": [{"instance_id": 481}]},
        "secret_key": "mcp-owned-chat-orphan-secret",
        "isError": False,
    }
    first_session = _Session([_RemoteTool()], results=[raw_envelope])
    _bind_session(monkeypatch, first_tool, first_session)
    save_checkpoint = repository.save_checkpoint
    failed_pending_write = False

    async def fail_first_pending_checkpoint(  # type: ignore[no-untyped-def]
        checkpoint,
        **kwargs,
    ):
        nonlocal failed_pending_write
        if checkpoint.state.get("pending_response_index") == 0 and not failed_pending_write:
            failed_pending_write = True
            raise RuntimeError("first pending checkpoint was not committed")
        return await save_checkpoint(checkpoint, **kwargs)

    monkeypatch.setattr(repository, "save_checkpoint", fail_first_pending_checkpoint)

    with pytest.raises(RuntimeError, match="first pending checkpoint was not committed"):
        await first_tool.execute(_request(first_tool), context)

    assert first_session.calls == [("query_data", arguments)]
    namespace = f"mcp:example_mcp:{context.outer_dispatch_id}"
    assert await repository.load_checkpoint(str(context.run_id), namespace=namespace) is None
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    stored_before = await repository.get_agent_artifact(str(artifact_id))
    assert stored_before is not None and isinstance(stored_before[1], bytes)
    artifact_before, content_before = stored_before
    payload_before = json.loads(content_before.decode("utf-8"))
    expected_identity = {
        "run_id": str(context.run_id),
        "invocation_id": str(invocation_id),
        "outer_dispatch_id": str(context.outer_dispatch_id),
    }
    assert artifact_before.uri == f"agent-artifact://{artifact_id}"
    assert {key: artifact_before.metadata[key] for key in expected_identity} == expected_identity
    assert {key: payload_before[key] for key in expected_identity} == expected_identity
    assert payload_before["contract"] == "declarative-mcp-remote-response/v2"
    assert payload_before["arguments"] == arguments
    assert payload_before["result"] == raw_envelope
    assert payload_before["model_call"] == {
        "protocol": "chat",
        "call_id": "call-0",
        "name": "query_data",
        "arguments": arguments,
        "request_id": "request-0",
        "reasoning_content": "inspect the complete chat response",
        "usage": None,
        "provider_output_items": [],
    }

    resumed_model = _SequenceModel([("finish_investigation", {"reason": "chat orphan recovered"})])
    resumed_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        resumed_model,
        repository=repository,
    )
    resumed_session = _Session([_RemoteTool()])
    _bind_session(monkeypatch, resumed_tool, resumed_session)

    outcome = await resumed_tool.execute(_request(resumed_tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    assert resumed_session.calls == []
    assistant_call, tool_result = resumed_model.messages[0][-2:]
    assert assistant_call["role"] == "assistant"
    assert assistant_call["tool_calls"][0]["id"] == "call-0"
    assert json.loads(assistant_call["tool_calls"][0]["function"]["arguments"]) == arguments
    assert tool_result["role"] == "tool"
    assert tool_result["tool_call_id"] == "call-0"
    assert json.loads(tool_result["content"]) == raw_envelope
    stored_after = await repository.get_agent_artifact(str(artifact_id))
    assert stored_after is not None and isinstance(stored_after[1], bytes)
    assert stored_after[0].sha256 == artifact_before.sha256
    assert stored_after[1] == content_before
    await repository.close()


@pytest.mark.asyncio
async def test_responses_orphan_artifact_recovers_after_first_checkpoint_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    call_id = "responses-orphan-call"
    arguments = {"query": "recover responses orphan result"}
    provider_output_items = (
        {
            "type": "reasoning",
            "id": "responses-orphan-reasoning",
            "encrypted_content": "durable-orphan-reasoning",
            "summary": [],
        },
        {
            "type": "function_call",
            "id": "responses-orphan-function",
            "call_id": call_id,
            "name": "query_data",
            "arguments": '{"query":"recover responses orphan result"}',
            "status": "completed",
        },
    )

    class ResponsesFirstCallModel:
        async def request_mcp_tool_call(  # type: ignore[no-untyped-def]
            self,
            *,
            messages,
            tools,
        ):
            del messages, tools
            return MCPModelToolCall(
                call_id=call_id,
                name="query_data",
                arguments=arguments,
                request_id="responses-orphan-request",
                reasoning_content="responses orphan reasoning",
                usage={"input_tokens": 17, "output_tokens": 9},
                provider_output_items=provider_output_items,
            )

    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-responses-orphan-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="responses-orphan-artifact")
    assert context.outer_dispatch_id is not None
    first_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        ResponsesFirstCallModel(),
        repository=repository,
    )
    raw_envelope = {
        "content": [{"type": "text", "text": "complete responses orphan result"}],
        "api_key": "mcp-owned-responses-orphan-secret",
        "isError": False,
    }
    first_session = _Session([_RemoteTool()], results=[raw_envelope])
    _bind_session(monkeypatch, first_tool, first_session)
    save_checkpoint = repository.save_checkpoint
    failed_pending_write = False

    async def fail_first_pending_checkpoint(  # type: ignore[no-untyped-def]
        checkpoint,
        **kwargs,
    ):
        nonlocal failed_pending_write
        if checkpoint.state.get("pending_response_index") == 0 and not failed_pending_write:
            failed_pending_write = True
            raise RuntimeError("responses pending checkpoint was not committed")
        return await save_checkpoint(checkpoint, **kwargs)

    monkeypatch.setattr(repository, "save_checkpoint", fail_first_pending_checkpoint)

    with pytest.raises(RuntimeError, match="responses pending checkpoint was not committed"):
        await first_tool.execute(_request(first_tool), context)

    assert first_session.calls == [("query_data", arguments)]
    namespace = f"mcp:example_mcp:{context.outer_dispatch_id}"
    assert await repository.load_checkpoint(str(context.run_id), namespace=namespace) is None
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    stored_before = await repository.get_agent_artifact(str(artifact_id))
    assert stored_before is not None and isinstance(stored_before[1], bytes)
    artifact_before, content_before = stored_before
    payload_before = json.loads(content_before.decode("utf-8"))
    assert payload_before["result"] == raw_envelope
    assert payload_before["model_call"]["call_id"] == call_id
    assert payload_before["model_call"]["request_id"] == "responses-orphan-request"
    assert payload_before["model_call"]["reasoning_content"] == "responses orphan reasoning"
    assert payload_before["model_call"]["usage"] == {
        "input_tokens": 17,
        "output_tokens": 9,
    }
    assert payload_before["model_call"]["provider_output_items"] == list(provider_output_items)

    resumed_model = _SequenceModel(
        [("finish_investigation", {"reason": "responses orphan recovered"})]
    )
    resumed_tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        resumed_model,
        repository=repository,
    )
    resumed_session = _Session([_RemoteTool()])
    _bind_session(monkeypatch, resumed_tool, resumed_session)

    outcome = await resumed_tool.execute(_request(resumed_tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    assert resumed_session.calls == []
    reasoning_item, function_item, output_item = resumed_model.messages[0][-3:]
    assert reasoning_item == provider_output_items[0]
    assert function_item == provider_output_items[1]
    assert output_item["type"] == "function_call_output"
    assert output_item["call_id"] == call_id
    assert json.loads(output_item["output"]) == raw_envelope
    stored_after = await repository.get_agent_artifact(str(artifact_id))
    assert stored_after is not None and isinstance(stored_after[1], bytes)
    assert stored_after[0].sha256 == artifact_before.sha256
    assert stored_after[1] == content_before
    await repository.close()


@pytest.mark.asyncio
async def test_cancellation_closes_transport_before_persisting_raw_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-cancellation-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="cancellation-artifact")
    assert context.outer_dispatch_id is not None
    model = _BlockAfterFirstRemoteResultModel(
        ("query_data", {"query": "persist before cancellation propagates"})
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        repository=repository,
    )
    raw_envelope = {
        "structuredContent": {"rows": [{"instance_id": 731}]},
        "secret_key": "mcp-owned-cancellation-secret",
        "isError": False,
    }
    session = _Session([_RemoteTool()], results=[raw_envelope])
    transport_closed = False

    async def open_session(stack: AsyncExitStack) -> _Session:
        def mark_transport_closed() -> None:
            nonlocal transport_closed
            transport_closed = True

        stack.callback(mark_transport_closed)
        return session

    monkeypatch.setattr(tool, "_open_session", open_session)
    persist_artifacts = tool._persist_remote_response_artifacts
    persistence_saw_closed_transport: list[bool] = []

    async def persist_after_transport_close(**kwargs: Any) -> None:
        persistence_saw_closed_transport.append(transport_closed)
        await persist_artifacts(**kwargs)

    monkeypatch.setattr(
        tool,
        "_persist_remote_response_artifacts",
        persist_after_transport_close,
    )

    execution = asyncio.create_task(tool.execute(_request(tool), context))
    await model.waiting.wait()
    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    assert persistence_saw_closed_transport == [True]
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    stored = await repository.get_agent_artifact(str(artifact_id))
    assert stored is not None and isinstance(stored[1], bytes)
    assert json.loads(stored[1].decode("utf-8"))["result"] == raw_envelope
    await repository.close()


@pytest.mark.asyncio
async def test_outer_asyncio_timeout_closes_transport_before_persisting_raw_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-outer-timeout-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="outer-timeout-artifact")
    assert context.outer_dispatch_id is not None
    model = _BlockAfterFirstRemoteResultModel(
        ("query_data", {"query": "persist before timeout propagates"})
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        repository=repository,
    )
    raw_envelope = {
        "content": [{"type": "text", "text": "complete timeout response"}],
        "api_key": "mcp-owned-timeout-secret",
        "isError": False,
    }
    session = _Session([_RemoteTool()], results=[raw_envelope])
    transport_closed = False

    async def open_session(stack: AsyncExitStack) -> _Session:
        def mark_transport_closed() -> None:
            nonlocal transport_closed
            transport_closed = True

        stack.callback(mark_transport_closed)
        return session

    monkeypatch.setattr(tool, "_open_session", open_session)
    persist_artifacts = tool._persist_remote_response_artifacts
    persistence_saw_closed_transport: list[bool] = []

    async def persist_after_transport_close(**kwargs: Any) -> None:
        persistence_saw_closed_transport.append(transport_closed)
        await persist_artifacts(**kwargs)

    monkeypatch.setattr(
        tool,
        "_persist_remote_response_artifacts",
        persist_after_transport_close,
    )

    execution = asyncio.create_task(tool.execute(_request(tool), context))
    await model.waiting.wait()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await execution

    assert persistence_saw_closed_transport == [True]
    assert execution.cancelled()
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    stored = await repository.get_agent_artifact(str(artifact_id))
    assert stored is not None and isinstance(stored[1], bytes)
    assert json.loads(stored[1].decode("utf-8"))["result"] == raw_envelope
    await repository.close()


@pytest.mark.asyncio
async def test_completed_response_is_persisted_after_a_later_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FailingSecondCallSession(_Session):
        async def call_tool(self, name: str, arguments: dict[str, Any]) -> _RemoteResult:
            if self.calls:
                self.calls.append((name, arguments))
                raise httpx.ConnectError("MCP connection dropped")
            return await super().call_tool(name, arguments)

    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-connection-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="connection-artifact")
    model = _SequenceModel(
        [
            ("query_data", {"query": "first response"}),
            ("query_data", {"query": "connection fails"}),
        ]
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        repository=repository,
    )
    raw_envelope = {
        "rows": [{"value": "complete-before-connection-failure"}],
        "api_key": "server-owned-secret",
    }
    session = FailingSecondCallSession([_RemoteTool()], results=[raw_envelope])
    _bind_session(monkeypatch, tool, session)

    with pytest.raises(httpx.ConnectError, match="MCP connection dropped"):
        await tool.execute(_request(tool), context)

    assert context.outer_dispatch_id is not None
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v2:example:response:1",
    )
    stored = await repository.get_agent_artifact(str(artifact_id))
    assert stored is not None
    artifact, content = stored
    assert artifact.metadata["internal_only"] is True
    assert isinstance(content, bytes)
    assert json.loads(content.decode("utf-8"))["result"] == raw_envelope
    await repository.close()


@pytest.mark.asyncio
async def test_each_remote_response_uses_a_stable_independent_artifact_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-artifact-ids.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="artifact-identities")
    model = _SequenceModel(
        [
            ("query_data", {"query": "first"}),
            ("query_data", {"query": "second"}),
            ("finish_investigation", {"reason": "done"}),
        ]
    )
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(),
        model,
        repository=repository,
    )
    raw_values = [
        "first-audit-prefix:" + ("a" * 2_000) + ":first-private-tail",
        "second-audit-prefix:" + ("b" * 2_000) + ":second-private-tail",
    ]
    session = _Session(
        [_RemoteTool()],
        results=[{"rows": [{"value": value}]} for value in raw_values],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), context)

    assert outcome.status == ToolStatus.SUCCESS
    assert all("result" not in item for item in outcome.structured_data["observations"])
    serialized_outcome = outcome.model_dump_json()
    assert "first-private-tail" not in serialized_outcome
    assert "second-private-tail" not in serialized_outcome
    assert context.outer_dispatch_id is not None
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_ids = [
        uuid5(
            invocation_id,
            f"declarative-mcp-remote-response/v2:example:response:{ordinal}",
        )
        for ordinal in (1, 2)
    ]
    assert artifact_ids[0] != artifact_ids[1]
    stored = [await repository.get_agent_artifact(str(item)) for item in artifact_ids]
    assert all(item is not None for item in stored)
    raw_contents = [item[1] for item in stored if item is not None]
    assert all(isinstance(item, bytes) for item in raw_contents)
    contents = [json.loads(item.decode("utf-8")) for item in raw_contents]
    assert [item["result"]["rows"][0]["value"] for item in contents] == raw_values
    assert all(
        "internal_audit_artifact" not in item for item in outcome.structured_data["observations"]
    )
    replayed = await tool._persist_remote_response_artifact(
        request=_request(tool),
        context=context,
        tool_name="query_data",
        arguments={"query": "first"},
        result={"rows": [{"value": raw_values[0]}]},
        model_call=MCPModelToolCall(
            call_id="call-0",
            name="query_data",
            arguments={"query": "first"},
            request_id="request-0",
        ),
        response_index=0,
        decision_round=1,
    )
    assert replayed is not None and replayed.artifact_id == artifact_ids[0]
    await repository.close()


@pytest.mark.parametrize(
    "provider_output_items",
    [
        [],
        [{"type": "message", "content": "unexpected"}],
        [{"type": "reasoning", "id": "reasoning-only"}],
        [
            {
                "type": "function_call",
                "call_id": "responses-call",
                "name": "query_data",
                "arguments": '{"query":"expected"}',
            },
            {
                "type": "function_call",
                "call_id": "responses-call",
                "name": "query_data",
                "arguments": '{"query":"expected"}',
            },
        ],
        [
            {
                "type": "function_call",
                "call_id": "responses-call",
                "name": "query_data",
                "arguments": "{bad-json",
            }
        ],
        [
            {
                "type": "function_call",
                "call_id": "other-call",
                "name": "query_data",
                "arguments": '{"query":"expected"}',
            }
        ],
        [
            {
                "type": "function_call",
                "call_id": "responses-call",
                "name": "other_tool",
                "arguments": '{"query":"expected"}',
            }
        ],
        [
            {
                "type": "function_call",
                "call_id": "responses-call",
                "name": "query_data",
                "arguments": '{"query":"different"}',
            }
        ],
        [
            {
                "type": "function_call",
                "call_id": "responses-call",
                "name": "query_data",
                "arguments": "[]",
            }
        ],
    ],
    ids=[
        "empty-responses-lineage",
        "other-item-type",
        "missing-function-call",
        "multiple-function-calls",
        "invalid-json-arguments",
        "mismatched-call-id",
        "mismatched-name",
        "mismatched-arguments",
        "non-object-arguments",
    ],
)
def test_decode_model_call_rejects_tampered_responses_lineage(
    provider_output_items: list[dict[str, Any]],
) -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    arguments = {"query": "expected"}
    payload = {
        "protocol": "responses",
        "call_id": "responses-call",
        "name": "query_data",
        "arguments": arguments,
        "request_id": "responses-request",
        "reasoning_content": None,
        "usage": None,
        "provider_output_items": provider_output_items,
    }

    with pytest.raises(GenericMCPConfigurationError):
        tool._decode_model_call(
            payload,
            tool_name="query_data",
            arguments=arguments,
        )


def test_decode_model_call_rejects_provider_items_marked_as_chat() -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    arguments = {"query": "expected"}
    payload = {
        "protocol": "chat",
        "call_id": "chat-call",
        "name": "query_data",
        "arguments": arguments,
        "request_id": "chat-request",
        "reasoning_content": None,
        "usage": None,
        "provider_output_items": [
            {
                "type": "function_call",
                "call_id": "chat-call",
                "name": "query_data",
                "arguments": '{"query":"expected"}',
            }
        ],
    }

    with pytest.raises(GenericMCPConfigurationError):
        tool._decode_model_call(
            payload,
            tool_name="query_data",
            arguments=arguments,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "bool-response-index",
        "float-response-index",
        "wrong-response-round",
        "wrong-active-decision-round",
        "wrong-completed-decision-round",
    ],
)
def test_checkpoint_decoder_rejects_tampered_response_state(mutation: str) -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    invocation_id = uuid4()
    initial_messages = [{"role": "system", "content": "checkpoint identity"}]
    arguments = {"query": "checkpoint response"}
    response = {
        "tool_name": "query_data",
        "arguments": arguments,
        "envelope": {"rows": [{"value": 1}]},
        "model_call": {
            "protocol": "chat",
            "call_id": "checkpoint-call",
            "name": "query_data",
            "arguments": arguments,
            "request_id": "checkpoint-request",
            "reasoning_content": None,
            "usage": None,
            "provider_output_items": [],
        },
        "response_index": 0,
        "decision_round": 1,
    }
    payload = {
        "contract": "declarative-mcp-investigation-checkpoint/v1",
        "server": "example",
        "source_system": "example_mcp",
        "invocation_id": str(invocation_id),
        "messages": deepcopy(initial_messages),
        "observations": [{"response_ordinal": 1}],
        "remote_responses": [response],
        "decision_round": 1,
        "pending_response_index": None,
        "finished_by_model": False,
        "completed": False,
    }
    if mutation == "bool-response-index":
        response["response_index"] = False
    elif mutation == "float-response-index":
        response["response_index"] = 0.0
    elif mutation == "wrong-response-round":
        response["decision_round"] = 2
    elif mutation == "wrong-active-decision-round":
        payload["decision_round"] = 2
    else:
        payload["finished_by_model"] = True
        payload["completed"] = True

    with pytest.raises(GenericMCPConfigurationError):
        tool._decode_execution_state(
            payload,
            initial_messages=initial_messages,
            invocation_id=invocation_id,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "uri",
        "metadata-run-id",
        "metadata-invocation-id",
        "metadata-outer-dispatch-id",
        "content-run-id",
        "content-invocation-id",
        "content-outer-dispatch-id",
        "metadata-bool-ordinal",
        "metadata-bool-decision-round",
        "content-bool-ordinal",
        "content-bool-index",
        "content-bool-decision-round",
    ],
)
def test_orphan_artifact_decoder_rejects_identity_and_ordinal_tampering(
    mutation: str,
) -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    context = _context().model_copy(update={"outer_dispatch_id": uuid4()})
    invocation_id = tool._audit_invocation_id(request=_request(tool), context=context)
    artifact_id = tool._remote_response_artifact_id(invocation_id, response_index=0)
    identity = {
        "run_id": str(context.run_id),
        "invocation_id": str(invocation_id),
        "outer_dispatch_id": str(context.outer_dispatch_id),
    }
    metadata = {
        "contract": "declarative-mcp-remote-response/v2",
        "server": "example",
        "source_system": "example_mcp",
        **identity,
        "tool_name": "query_data",
        "response_ordinal": 1,
        "decision_round": 1,
        "sanitized": False,
        "raw_response_unmodified": True,
        "internal_only": True,
    }
    arguments = {"query": "artifact response"}
    payload = {
        "contract": "declarative-mcp-remote-response/v2",
        "server": "example",
        "source_system": "example_mcp",
        **identity,
        "tool_name": "query_data",
        "arguments": arguments,
        "model_call": {
            "protocol": "chat",
            "call_id": "artifact-call",
            "name": "query_data",
            "arguments": arguments,
            "request_id": "artifact-request",
            "reasoning_content": None,
            "usage": None,
            "provider_output_items": [],
        },
        "response_ordinal": 1,
        "response_index": 0,
        "decision_round": 1,
        "result": {"rows": [{"value": 1}]},
    }
    uri = f"agent-artifact://{artifact_id}"
    if mutation == "uri":
        uri = "agent-artifact://tampered"
    elif mutation.startswith("metadata-"):
        field = mutation.removeprefix("metadata-").replace("-", "_")
        if field == "bool_ordinal":
            metadata["response_ordinal"] = True
        elif field == "bool_decision_round":
            metadata["decision_round"] = True
        else:
            metadata[field] = "tampered"
    elif mutation.startswith("content-"):
        field = mutation.removeprefix("content-").replace("-", "_")
        if field == "bool_ordinal":
            payload["response_ordinal"] = True
        elif field == "bool_index":
            payload["response_index"] = True
        elif field == "bool_decision_round":
            payload["decision_round"] = True
        else:
            payload[field] = "tampered"
    artifact = ArtifactRef(
        artifact_id=artifact_id,
        kind="declarative_mcp_remote_response",
        media_type="application/json",
        uri=uri,
        metadata=metadata,
    )
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    with pytest.raises(GenericMCPConfigurationError):
        tool._decode_remote_response_artifact(
            artifact,
            content,
            expected_artifact_id=artifact_id,
            expected_index=0,
            expected_context=context,
            expected_invocation_id=invocation_id,
        )


@pytest.mark.asyncio
async def test_program_projection_groups_aggregates_and_sorts_result_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "aggregate"}),
            ("finish_investigation", {"reason": "complete"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool()],
        results=[
            {
                "_meta": {"token": "internal-noise"},
                "rows": [
                    {"latency": 7, "state": "slow"},
                    {"latency": 1, "state": "ok"},
                    {"latency": 4, "state": "slow"},
                ],
                "single": 99,
            }
        ],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    projected_observation = outcome.structured_data["observations"][0]
    assert "result" not in projected_observation
    projection = projected_observation["projection"]
    assert "source_sha256" not in projection
    assert '"sha256"' not in json.dumps(projection, ensure_ascii=False)
    assert projection["ignored_metadata_field_count"] == 1
    assert [item["path_pattern"] for item in projection["numeric_aggregates"]] == [
        "/result/rows/*/latency",
        "/result/single",
    ]
    latency = projection["numeric_aggregates"][0]
    assert latency == {
        "path_pattern": "/result/rows/*/latency",
        "count": 3,
        "min": 1,
        "max": 7,
        "avg": 4,
        "first": 7,
        "latest": 4,
        "delta": -3,
        "source_paths": [
            "/result/rows/0/latency",
            "/result/rows/1/latency",
            "/result/rows/2/latency",
        ],
        "omitted_source_path_count": 0,
    }
    assert projection["scalar_groups"][0]["path_pattern"].endswith("/rows/*/state")
    assert projection["scalar_groups"][0]["value_count"] == 3
    assert [sample["value"] for sample in projection["scalar_groups"][0]["samples"]] == [
        "ok",
        "slow",
    ]
    assert "internal-noise" in model.messages[1][-1]["content"]
    assert "internal-noise" not in outcome.model_dump_json()


def test_program_projection_recursively_omits_infrastructure_provenance() -> None:
    projection = generic_mcp_module._project_result_for_model(
        {
            "structuredContent": {
                "rows": [
                    {
                        "status": "slow",
                        "latency_ms": 17,
                        "checksum": "business-checksum-42",
                        "raw_payload": {"private": "raw-envelope-secret"},
                        "artifact": {
                            "artifact_id": "artifact-id-secret",
                            "uri": "agent-artifact://nested-secret",
                        },
                        "sourceArtifact": {
                            "artifactUri": "agent-artifact://source-secret",
                        },
                        "artifactId": "camel-artifact-id-secret",
                        "artifact_uri": "agent-artifact://field-secret",
                        "uri": "https://internal.example/artifact-secret",
                        "source_sha256": "source-sha-secret",
                        "sha256": "sha-secret",
                        "hash": "hash-secret",
                        "digest": "digest-secret",
                        "reference": "agent-artifact://value-secret",
                    }
                ]
            }
        },
        source_path="/result",
        is_error=False,
    )

    serialized = json.dumps(projection, ensure_ascii=False)
    for hidden in (
        "raw_payload",
        "raw-envelope-secret",
        "artifact-id-secret",
        "nested-secret",
        "source-secret",
        "camel-artifact-id-secret",
        "field-secret",
        "internal.example",
        "source-sha-secret",
        "sha-secret",
        "hash-secret",
        "digest-secret",
        "value-secret",
        "agent-artifact://",
    ):
        assert hidden not in serialized
    assert projection["ignored_metadata_field_count"] == 11
    assert [item["path_pattern"] for item in projection["numeric_aggregates"]] == [
        "/result/structuredContent/rows/*/latency_ms"
    ]
    retained_scalars = {
        item["path_pattern"]: [sample["value"] for sample in item["samples"]]
        for item in projection["scalar_groups"]
    }
    assert retained_scalars == {
        "/result/structuredContent/rows/*/checksum": ["business-checksum-42"],
        "/result/structuredContent/rows/*/status": ["slow"],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "metadata_only_result",
    [
        {
            "isError": False,
            "_meta": {"request_id": "internal-request"},
            "raw_payload": {"rows": [{"value": 99}]},
            "artifact": {"uri": "agent-artifact://internal"},
            "source_sha256": "a" * 64,
            "usage": {"tokens": 42},
        },
        {"isError": False, "content": [{"type": "text"}]},
    ],
)
async def test_metadata_or_raw_only_result_is_no_data_after_projection(
    monkeypatch: pytest.MonkeyPatch,
    metadata_only_result: dict[str, Any],
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "metadata only"}),
            ("finish_investigation", {"reason": "no visible facts"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session([_RemoteTool()], results=[metadata_only_result])
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data["reason_code"] == "empty_remote_results"
    observation = outcome.structured_data["observations"][0]
    assert observation["has_data"] is False
    assert observation["projection"]["has_data"] is False
    assert observation["projection"]["numeric_aggregates"] == []
    assert observation["projection"]["scalar_groups"] == []


@pytest.mark.asyncio
async def test_generic_mcp_projects_null_fields_and_aliases_without_returning_raw_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _SequenceModel(
        [
            ("query_data", {"query": "complete envelope"}),
            ("finish_investigation", {"reason": "complete"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
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

    observation = outcome.structured_data["observations"][0]
    assert "result" not in observation
    assert observation["projection"]["source_path"] == "/result"
    assert observation["projection"]["ignored_metadata_field_count"] == 2
    assert observation["projection"]["has_data"] is True


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
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    error_envelope = {
        "isError": True,
        "content": [{"type": "text", "text": "query failed"}],
        "secret": "remote-error-secret",
    }
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True})],
        results=[error_envelope],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.NO_DATA
    assert outcome.structured_data["reason_code"] == "remote_tool_errors"
    assert outcome.structured_data["root_cause_eligible"] is False
    assert outcome.structured_data["observations"][0]["is_error"] is True
    assert outcome.structured_data["observations"][0]["has_data"] is False
    assert json.loads(model.messages[1][-1]["content"]) == error_envelope
    assert "remote-error-secret" not in outcome.model_dump_json()


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
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
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
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
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
async def test_arguments_and_caller_parameters_are_forwarded_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_arguments = {
        "query": {"unexpected": ["nested", {"shape": True}]},
        "extra": None,
    }
    second_arguments = {"another": {"schema": "is not checked by the host"}}
    caller_parameters = {"scope": {"cluster": "orders", "replicas": [1, 2]}}
    model = _SequenceModel(
        [
            ("query_data", first_arguments),
            ("query_data", second_arguments),
            ("finish_investigation", {"reason": "explicitly complete"}),
        ]
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool()],
        results=[{"rows": [{"value": 1}]}, {"rows": [{"value": 2}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(
        _request(tool, parameters=caller_parameters),
        _context(),
    )

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [
        ("query_data", first_arguments),
        ("query_data", second_arguments),
    ]
    initial_payload = json.loads(model.messages[0][1]["content"])
    assert initial_payload["read_only"] is True
    assert initial_payload["caller_parameters"] == caller_parameters
    assert [item["arguments"] for item in outcome.structured_data["observations"]] == [
        first_arguments,
        second_arguments,
    ]
    assert outcome.structured_data["finished_by_model"] is True
    assert outcome.structured_data["partial"] is False
    assert outcome.structured_data["termination_reason"] == "model_finished"
    assert outcome.structured_data["root_cause_eligible"] is True
    assert len(model.messages) == 3


@pytest.mark.asyncio
async def test_model_tool_name_is_forwarded_without_host_allowlist_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = {"server_decides": {"whether": "this call is valid"}}
    model = _SequenceModel(
        [
            ("tool_not_returned_by_list_tools", arguments),
            ("finish_investigation", {"reason": "done"}),
        ],
        require_discovered_name=False,
    )
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
    session = _Session(
        [_RemoteTool("advertised_tool")],
        results=[{"rows": [{"value": 1}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    assert outcome.status == ToolStatus.SUCCESS
    assert session.calls == [("tool_not_returned_by_list_tools", arguments)]


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
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), model)
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


class _ManyPagedSession:
    def __init__(self, page_count: int) -> None:
        self.page_count = page_count
        self.cursors: list[str | None] = []

    async def list_tools(self, *, cursor: str | None = None) -> Any:
        self.cursors.append(cursor)
        page_number = len(self.cursors)
        return type(
            "ListedTools",
            (),
            {
                "tools": [_RemoteTool(f"tool-{page_number}")],
                "nextCursor": (f"page-{page_number}" if page_number < self.page_count else None),
            },
        )()


@pytest.mark.asyncio
async def test_tool_listing_continues_beyond_ten_pages() -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())
    session = _ManyPagedSession(page_count=15)

    tools = await tool._list_tools(session)  # type: ignore[arg-type]

    assert len(tools) == 15
    assert session.cursors == [None, *[f"page-{index}" for index in range(1, 15)]]


class _RepeatedCursorSession:
    async def list_tools(self, *, cursor: str | None = None) -> Any:
        return type(
            "ListedTools",
            (),
            {"tools": [], "nextCursor": "same-cursor"},
        )()


@pytest.mark.asyncio
async def test_tool_listing_rejects_only_repeated_cursor_loop() -> None:
    tool = GenericMCPEvidenceTool(_descriptor(), _connection(), _FailingModel())

    with pytest.raises(GenericMCPConfigurationError, match="repeated tool-list cursor"):
        await tool._list_tools(_RepeatedCursorSession())  # type: ignore[arg-type]


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
    tool = GenericMCPEvidenceTool(
        _descriptor(),
        _connection(transport=transport),
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
        monkeypatch.setattr(generic_mcp_module, "streamable_http_client", unexpected_streamable)
        monkeypatch.setattr(generic_mcp_module.httpx, "AsyncClient", unexpected_http_client)
    else:
        http_client = object()

        def async_http_client(**kwargs: Any) -> _AsyncContext:
            calls["http_client"] = kwargs
            return _AsyncContext(http_client)

        def streamable_connector(url: str, *, http_client: Any) -> _AsyncContext:
            calls["streamable"] = {"url": url, "http_client": http_client}
            return _AsyncContext((read_stream, write_stream, object()))

        def unexpected_sse(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("SSE connector must not be used")

        monkeypatch.setattr(generic_mcp_module.httpx, "AsyncClient", async_http_client)
        monkeypatch.setattr(generic_mcp_module, "streamable_http_client", streamable_connector)
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
        assert calls["http_client"]["headers"] == {"Authorization": "test-token"}
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
