from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack
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
from app.agent_runtime.contracts import RunManifest
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
    def __init__(self, call: tuple[str, dict[str, Any]]) -> None:
        super().__init__([call])
        self.failed_messages: list[dict[str, Any]] | None = None

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        if self.messages:
            self.failed_messages = json.loads(json.dumps(messages, ensure_ascii=False))
            raise RuntimeError("model failed after the first remote response")
        return await super().request_mcp_tool_call(messages=messages, tools=tools)


def _descriptor(*, transport: str = "streamable_http") -> MCPServerDescriptor:
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
        provider_options={"transport": transport},
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
    assert [len(messages) for messages in model.messages] == [2, 3, 4]
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
async def test_complete_large_remote_result_is_projected_without_leaking_into_tool_outcome(
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
    session = _Session(
        [_RemoteTool(annotations={"readOnlyHint": True, "destructiveHint": False})],
        results=[{"content": [{"type": "text", "text": large_text}]}],
    )
    _bind_session(monkeypatch, tool, session)

    outcome = await tool.execute(_request(tool), _context())

    observation = outcome.structured_data["observations"][0]
    assert "result" not in observation
    assert large_text not in outcome.model_dump_json()
    assert "truncated" not in observation
    model_observation = json.loads(model.messages[1][-1]["content"])
    assert large_text not in model.messages[1][-1]["content"]
    assert "result" not in model_observation
    assert model_observation["observation_type"] == "program_fact_projection"
    projection = model_observation["projection"]
    assert projection == observation["projection"]
    assert projection["source_path"] == "/result"
    assert projection["source_json_chars"] > len(large_text)
    text_sample = projection["scalar_groups"][0]["samples"][0]["value"]
    assert text_sample["excerpt"] == large_text[:500]
    assert text_sample["total_chars"] == len(large_text)
    assert len(model.messages[1][-1]["content"]) < 5_000


@pytest.mark.asyncio
async def test_remote_response_is_persisted_before_a_later_model_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'generic-mcp-immediate-artifact.db'}"
    )
    await repository.initialize()
    context = await _durable_context(repository, external_id="immediate-artifact")
    model = _FailAfterFirstRemoteResultModel(
        ("query_data", {"query": "retain before next decision"})
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
    assert raw_value not in failed_context
    assert "agent-artifact://" not in failed_context
    assert context.outer_dispatch_id is not None
    invocation_id = uuid5(context.outer_dispatch_id, "attempt:1")
    artifact_id = uuid5(
        invocation_id,
        "declarative-mcp-remote-response/v1:example:response:1",
    )
    stored = await repository.get_agent_artifact(str(artifact_id))
    assert stored is not None
    artifact, content = stored
    assert artifact.kind == "declarative_mcp_remote_response"
    assert artifact.metadata["internal_only"] is True
    assert artifact.metadata["response_ordinal"] == 1
    assert isinstance(content, dict)
    assert content["result"]["rows"][0]["value"] == raw_value
    assert content["result"]["token"] == "***REDACTED***"
    async with repository.session_factory() as database_session:
        row = await database_session.get(AgentArtifactRow, str(artifact_id))
        assert row is not None
        assert row.invocation_id == str(invocation_id)
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
            f"declarative-mcp-remote-response/v1:example:response:{ordinal}",
        )
        for ordinal in (1, 2)
    ]
    assert artifact_ids[0] != artifact_ids[1]
    stored = [await repository.get_agent_artifact(str(item)) for item in artifact_ids]
    assert all(item is not None for item in stored)
    contents = [item[1] for item in stored if item is not None]
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
        response_index=0,
        decision_round=1,
    )
    assert replayed is not None and replayed.artifact_id == artifact_ids[0]
    await repository.close()


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
    assert "internal-noise" not in model.messages[1][-1]["content"]


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
