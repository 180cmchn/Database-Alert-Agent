from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import app.adapters.archery_harness as archery_harness_module
from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ArcheryMCPClient,
)
from app.adapters.persistence import (
    SQLAlchemyAlertRepository,
)
from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    BudgetLedger,
    BudgetLimits,
    InMemoryEventSink,
    ToolInvocationStatus,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    DiscoveredMCPTool,
    MCPAgentHarnessRuntime,
    ReplayCallFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)
from tests.unit.archery_harness_support import (
    ALERT_CONTEXT,
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    FINAL_SQL,
    FINISH_TOOL_NAME,
    INSTANCE_SQL,
    MEMBER_SQL,
    OCCURRED_AT,
    RESULT_ASSESSMENT_TOOL_NAME,
    TARGET_ARGUMENTS,
    _call,
    _client,
    _create_durable_run,
    _finish,
    _lineage_actions,
    _lineage_replay_calls,
    _named_call,
    _response_result_success,
    _result_assessment,
    _scenario,
    _ScriptedModel,
    _success,
    _target_call,
    _tools,
)


def _terminal_auth_failure() -> ReplayCallFixture:
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
        expected_arguments={},
        result={
            "structuredContent": {
                "status": "failed",
                "message": "authentication rejected",
            }
        },
    )


def test_archery_harness_does_not_require_or_hide_a_fixed_login_tool() -> None:
    specs_without_login = _scenario().build_tool_specs(_tools()[1:])
    assert [spec.name for spec in specs_without_login[:-2]] == [ARCHERY_MCP_QUERY_TOOL_NAME]
    assert [spec.name for spec in specs_without_login[-2:]] == [
        RESULT_ASSESSMENT_TOOL_NAME,
        FINISH_TOOL_NAME,
    ]

    specs = _scenario().build_tool_specs(
        [
            DiscoveredMCPTool(
                name="new_archery_tool",
                input_schema={"type": "object"},
            ),
        ]
    )

    assert [spec.name for spec in specs[:-2]] == ["new_archery_tool"]
    assert [spec.name for spec in specs[-2:]] == [
        RESULT_ASSESSMENT_TOOL_NAME,
        FINISH_TOOL_NAME,
    ]


@pytest.mark.asyncio
async def test_archery_planner_exposes_model_reasoning_content() -> None:
    class ReasoningModel(_ScriptedModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.requests.append({"messages": messages, "tools": tools})
            return MCPModelToolCall(
                call_id="finish-with-reasoning",
                name=FINISH_TOOL_NAME,
                arguments={"reason": "No additional evidence is needed"},
                request_id="request-finish-with-reasoning",
                reasoning_content="Inspect the returned slow-log facts.",
            )

    client = _client(
        ReasoningModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
    )
    registry = archery_harness_module._PlannerCallRegistry()
    scenario = archery_harness_module.ArcheryHarnessScenario(
        client,
        archery_harness_module.ArcheryHarnessState(
            window_start=OCCURRED_AT,
            window_end=OCCURRED_AT,
            occurred_at=OCCURRED_AT,
            alert_context=dict(ALERT_CONTEXT),
            alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
        ),
        registry,
    )
    planner = archery_harness_module.ArcheryHarnessPlanner(
        client,
        scenario,
        registry,
    )

    await planner.plan(messages=[], tools=[])

    assert planner.last_reasoning_content == "Inspect the returned slow-log facts."


@pytest.mark.asyncio
async def test_archery_planner_forwards_provider_reasoning_deltas() -> None:
    class StreamingReasoningModel(_ScriptedModel):
        async def request_mcp_tool_call(  # type: ignore[no-untyped-def]
            self,
            *,
            messages,
            tools,
            reasoning_callback,
        ):
            self.requests.append({"messages": messages, "tools": tools})
            await reasoning_callback("Inspect ", 0)
            await reasoning_callback("slow-log facts.", 1)
            return MCPModelToolCall(
                call_id="finish-streaming-reasoning",
                name=FINISH_TOOL_NAME,
                arguments={"reason": "No additional evidence is needed"},
                request_id="request-finish-streaming-reasoning",
                reasoning_content="Inspect slow-log facts.",
            )

    client = _client(
        StreamingReasoningModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
    )
    registry = archery_harness_module._PlannerCallRegistry()
    scenario = archery_harness_module.ArcheryHarnessScenario(
        client,
        archery_harness_module.ArcheryHarnessState(
            window_start=OCCURRED_AT,
            window_end=OCCURRED_AT,
            occurred_at=OCCURRED_AT,
            alert_context=dict(ALERT_CONTEXT),
            alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
        ),
        registry,
    )
    planner = archery_harness_module.ArcheryHarnessPlanner(
        client,
        scenario,
        registry,
    )
    deltas: list[tuple[int, str]] = []

    async def capture(content: str, delta_index: int) -> None:
        deltas.append((delta_index, content))

    await planner.plan(messages=[], tools=[], reasoning_callback=capture)

    assert deltas == [(0, "Inspect "), (1, "slow-log facts.")]
    assert planner.last_reasoning_content == "Inspect slow-log facts."


@pytest.mark.asyncio
async def test_shared_harness_preserves_schema_valid_window_character_limit() -> None:
    final_arguments = {
        **TARGET_ARGUMENTS,
        "sql_content": FINAL_SQL,
        "max_result_chars": 123_456,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            MCPModelToolCall(
                call_id="final-with-limit",
                name=ARCHERY_MCP_QUERY_TOOL_NAME,
                arguments=final_arguments,
                request_id="request-final-with-limit",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-no-character-limit",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "sql_text": "SELECT 1",
                            }
                        ],
                        max_result_chars=123_456,
                    ),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    query_tool = next(
        item
        for item in model.requests[0]["tools"]
        if item["function"]["name"] == ARCHERY_MCP_QUERY_TOOL_NAME
    )
    assert "max_result_chars" in query_tool["function"]["parameters"]["properties"]
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert len(model.requests) == 5
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert all(
        entry.get("reason_code") != "max_result_chars_forbidden"
        for entry in result.diagnostics["query_trace"]
    )
    assert connector.opened_session_ids == ["archery-no-character-limit"]


@pytest.mark.asyncio
async def test_auxiliary_raw_payload_is_replayed_to_internal_model() -> None:
    auxiliary_secret = "authentication-and-metadata-raw-response"
    raw_member_result = {
        "structuredContent": {
            "status": "success",
            "full_sql": MEMBER_SQL,
            "rows": [{"f_instance_id": 53}],
            "authentication_token": auxiliary_secret,
            "raw_metadata": {"secret": auxiliary_secret},
        }
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("final", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-auxiliary-projection",
                tools=_tools(),
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
                        result=raw_member_result,
                    ),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "sample": "SELECT 1",
                                "query_time_max": 2.5,
                            }
                        ],
                    ),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    feedback_messages = model.requests[1]["messages"]
    assistant_message = next(
        message
        for message in reversed(feedback_messages)
        if message.get("role") == "assistant"
        and any(call.get("id") == "member" for call in message.get("tool_calls", []))
    )
    tool_message = next(
        message
        for message in reversed(feedback_messages)
        if message.get("role") == "tool" and message.get("tool_call_id") == "member"
    )
    assert assistant_message["role"] == "assistant"
    assert assistant_message["tool_calls"] == [
        {
            "id": "member",
            "type": "function",
            "function": {
                "name": ARCHERY_MCP_QUERY_TOOL_NAME,
                "arguments": json.dumps(
                    {**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            },
        }
    ]
    assert tool_message["role"] == "tool"
    assert tool_message["tool_call_id"] == "member"
    raw_feedback = tool_message["content"]
    assert isinstance(raw_feedback, str)
    assert json.loads(raw_feedback) == raw_member_result
    assert auxiliary_secret in raw_feedback


@pytest.mark.asyncio
async def test_persisted_trace_exposes_only_final_history_projection(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'archery-trace-boundary.db'}"
    )
    await repository.initialize()
    _, run = await _create_durable_run(
        repository,
        external_id="archery-trace-boundary",
    )
    auxiliary_secret = "archery-auxiliary-response-secret"
    auxiliary_column = "internal_member_lookup_column"
    final_sample = "SELECT final_trace_projection"
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-trace-boundary",
                tools=_tools(),
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": MEMBER_SQL,
                                "columns": ["f_instance_id", auxiliary_column],
                                "rows": [
                                    {
                                        "f_instance_id": 53,
                                        auxiliary_column: auxiliary_secret,
                                    }
                                ],
                                "secret_key": auxiliary_secret,
                            }
                        },
                    ),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "sample": final_sample,
                                "query_time_max": 4.25,
                            }
                        ],
                    ),
                ],
            )
        ],
    )
    assert run.lease_owner is not None

    result = await _client(
        _ScriptedModel(_lineage_actions()),
        connector,
        repository=repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=uuid4(),
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert result.query_completed is True
    events = await repository.list_agent_events(str(run.id))
    observation_events = [
        event for event in events if event.kind == AgentEventKind.TRACE_OBSERVATION
    ]
    assert len(observation_events) == 1
    trace_content = observation_events[0].payload["content"]
    assert isinstance(trace_content, str)
    projection = json.loads(trace_content)
    assert projection["projection_kind"] == "mysql_slow_query_review_history"
    assert projection["rows"][0]["sample_snippet"] == final_sample
    assert projection["rows"][0]["query_time_max"] == 4.25
    persisted_trace = json.dumps(
        [event.payload for event in observation_events],
        ensure_ascii=False,
    )
    assert auxiliary_secret not in persisted_trace
    assert auxiliary_column not in persisted_trace
    assert "f_instance_id" not in persisted_trace
    await repository.close()


@pytest.mark.asyncio
async def test_shared_harness_records_reasoning_once_without_delta_streams(
    tmp_path: Path,
) -> None:
    class StreamingCapableModel(_ScriptedModel):
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
            self.received_callbacks.append(reasoning_callback)
            return await super().request_mcp_tool_call(
                messages=messages,
                tools=tools,
            )

    finish_with_reasoning = MCPModelToolCall(
        call_id="finish-with-reasoning",
        name=FINISH_TOOL_NAME,
        arguments={"reason": "Archery evidence collection is complete"},
        request_id="request-finish-with-reasoning",
        reasoning_content="Inspect the returned slow-log facts before finishing.",
    )
    model = StreamingCapableModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("final", FINAL_SQL),
            finish_with_reasoning,
        ]
    )
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'archery-reasoning-once.db'}"
    )
    await repository.initialize()
    _, run = await _create_durable_run(
        repository,
        external_id="archery-reasoning-once",
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reasoning-once",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )
    assert run.lease_owner is not None

    result = await _client(
        model,
        connector,
        repository=repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=uuid4(),
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert result.query_completed is True
    # Durable reasoning deltas dominated the bounded planner wall time, so the
    # Archery harness no longer forwards a reasoning callback at all.
    assert model.received_callbacks == [None, None, None, None, None]

    events = await repository.list_agent_events(str(run.id))
    reasoning_events = [
        event
        for event in events
        if event.kind == AgentEventKind.TRACE_REASONING
        and event.payload.get("provider") == ARCHERY_HARNESS_PROVIDER
    ]
    assert [event.payload["content"] for event in reasoning_events] == [
        "Inspect the returned slow-log facts before finishing.",
    ]
    assert all("delta_index" not in event.payload for event in reasoning_events)
    assert all("stream_id" not in event.payload for event in reasoning_events)
    finish_decisions = [
        event
        for event in events
        if event.kind == AgentEventKind.MODEL_DECISION
        and event.payload.get("action") == "call_tool"
        and event.payload.get("tool_name") == FINISH_TOOL_NAME
    ]
    assert len(finish_decisions) == 1
    assert (
        finish_decisions[0].payload["reasoning"]
        == "Inspect the returned slow-log facts before finishing."
    )
    await repository.close()


@pytest.mark.asyncio
async def test_business_error_raw_payload_is_replayed_to_internal_model() -> None:
    error_secret = "archery-error-secret-key"
    raw_error = {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": "Archery rejected the query",
                "secret_key": error_secret,
            }
        ],
    }
    model = _ScriptedModel([_call("member-error", MEMBER_SQL), _finish()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-raw-business-error",
                tools=_tools(),
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
                        result=raw_error,
                    )
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    tool_message = next(
        message
        for message in reversed(model.requests[1]["messages"])
        if message.get("role") == "tool" and message.get("tool_call_id") == "member-error"
    )
    raw_feedback = tool_message["content"]
    assert isinstance(raw_feedback, str)
    assert json.loads(raw_feedback) == raw_error
    assert error_secret in raw_feedback


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("row_key", "response_result_wrapped"),
    [("results", False), ("data", False), ("instances", True)],
    ids=["results", "data", "response-result"],
)
async def test_instance_discovery_raw_response_drives_followup_queries(
    row_key: str,
    response_result_wrapped: bool,
) -> None:
    class RawResponseDrivenModel:
        def __init__(self) -> None:
            self.requests: list[dict[str, Any]] = []
            self.discovered_instance_id: int | None = None
            self.discovered_member_id: int | None = None
            self.discovered_endpoint: str | None = None
            self.discovery_feedback = ""

        @staticmethod
        def raw_response(messages: list[dict[str, Any]]) -> dict[str, Any]:
            for message in reversed(messages):
                content = message.get("content", message.get("output"))
                if not isinstance(content, str):
                    continue
                try:
                    payload = json.loads(content)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and "structuredContent" in payload:
                    return payload
            raise AssertionError("No structured Archery response was replayed")

        @staticmethod
        def structured_payload(raw_response: dict[str, Any]) -> dict[str, Any]:
            structured = raw_response["structuredContent"]
            response = structured.get("response")
            if not isinstance(response, dict) or not isinstance(response.get("result"), str):
                return structured
            text = response["result"]
            marker = "结果：\n"
            payload = json.loads(text.split(marker, 1)[1] if marker in text else text)
            columns = payload.get("column_list")
            rows = payload.get("rows")
            if (
                isinstance(columns, list)
                and all(isinstance(column, str) for column in columns)
                and isinstance(rows, list)
            ):
                payload["rows"] = [
                    dict(zip(columns, row, strict=True))
                    if isinstance(row, list) and len(row) == len(columns)
                    else row
                    for row in rows
                ]
            return payload

        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.requests.append(
                {
                    "messages": deepcopy(messages),
                    "tools": deepcopy(tools),
                }
            )
            available_names = {item["function"]["name"] for item in tools}
            if available_names == {RESULT_ASSESSMENT_TOOL_NAME}:
                pending = json.loads(str(messages[-1]["content"]))
                return _result_assessment(
                    str(pending["source_invocation_id"]),
                    scope=str(pending["scope"]),
                    stage=str(pending["stage"]),
                    history_id=pending.get("history_id"),
                    content_state="complete",
                    basis="appears_complete",
                )
            turn = sum(
                {item["function"]["name"] for item in request["tools"]}
                != {RESULT_ASSESSMENT_TOOL_NAME}
                for request in self.requests
            )
            if turn == 1:
                return MCPModelToolCall(
                    call_id="discover-instance",
                    name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
                    arguments=discovery_arguments,
                    request_id="request-discover-instance",
                )
            if turn > 4:
                return _finish(reason="Raw-response-driven Archery investigation completed")

            raw_response = self.raw_response(messages)
            structured = self.structured_payload(raw_response)
            if turn == 2:
                self.discovery_feedback = json.dumps(raw_response, ensure_ascii=False)
                self.discovered_instance_id = int(structured[row_key][0]["id"])
                return MCPModelToolCall(
                    call_id="query-member",
                    name=ARCHERY_MCP_QUERY_TOOL_NAME,
                    arguments={
                        **TARGET_ARGUMENTS,
                        "instance_id": self.discovered_instance_id,
                        "sql_content": MEMBER_SQL,
                    },
                    request_id="request-query-member",
                )
            if turn == 3:
                self.discovered_member_id = int(structured["rows"][0]["f_instance_id"])
                return MCPModelToolCall(
                    call_id="query-instance",
                    name=ARCHERY_MCP_QUERY_TOOL_NAME,
                    arguments={
                        **TARGET_ARGUMENTS,
                        "instance_id": self.discovered_instance_id,
                        "sql_content": (
                            "SELECT host, port FROM sql_instance "
                            f"WHERE id = {self.discovered_member_id} LIMIT 1"
                        ),
                    },
                    request_id="request-query-instance",
                )
            if turn == 4:
                endpoint_row = structured["rows"][0]
                self.discovered_endpoint = f"{endpoint_row['host']}:{endpoint_row['port']}"
                return MCPModelToolCall(
                    call_id="query-history",
                    name=ARCHERY_MCP_QUERY_TOOL_NAME,
                    arguments={
                        **TARGET_ARGUMENTS,
                        "instance_id": self.discovered_instance_id,
                        "sql_content": FINAL_SQL.replace(
                            "db-1.example:3306",
                            self.discovered_endpoint,
                        ),
                    },
                    request_id="request-query-history",
                )
            return _finish(reason="Raw-response-driven Archery investigation completed")

    discovery_arguments = {
        "resource_group_id": 9,
        "instance_ref": "archery-production",
        "page": 1,
        "size": 200,
    }
    discovery_secret = "v-7Qx9P3mN-opaque"
    model = RawResponseDrivenModel()
    tools = [
        *_tools(),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            description="List Archery database instances",
            input_schema={
                "type": "object",
                "properties": {
                    "resource_group_id": {"type": "integer"},
                    "instance_ref": {"type": "string"},
                    "page": {"type": "integer"},
                    "size": {"type": "integer"},
                },
                "required": ["resource_group_id"],
            },
        ),
    ]
    discovery_rows = [
        {
            "id": 17,
            "name": "archery-production",
            "access_token": discovery_secret,
        }
    ]
    discovery_result = (
        {
            "structuredContent": {
                "response": {
                    "result": json.dumps({row_key: discovery_rows}, ensure_ascii=False),
                }
            }
        }
        if response_result_wrapped
        else {
            "structuredContent": {
                "status": "ok",
                row_key: discovery_rows,
            }
        }
    )
    query_calls = (
        [
            _response_result_success(
                MEMBER_SQL,
                columns=["f_instance_id"],
                rows=[[53]],
            ),
            _response_result_success(
                INSTANCE_SQL,
                columns=["host", "port"],
                rows=[["db-1.example", 3306]],
            ),
            _response_result_success(
                FINAL_SQL,
                columns=["hostname_max", "sample", "query_time_max"],
                rows=[["db-1.example:3306", "SELECT projection_driven", 3.5]],
            ),
        ]
        if response_result_wrapped
        else [
            _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
            _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
            _success(
                FINAL_SQL,
                rows=[
                    {
                        "hostname_max": "db-1.example:3306",
                        "sample": "SELECT projection_driven",
                        "query_time_max": 3.5,
                    }
                ],
            ),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id=f"archery-instance-discovery-{row_key}",
                tools=tools,
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
                        expected_arguments=discovery_arguments,
                        result=discovery_result,
                    ),
                    *query_calls,
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert len(model.requests) == 6
    assert model.discovered_instance_id == 17
    assert model.discovered_member_id == 53
    assert model.discovered_endpoint == "db-1.example:3306"
    assert result.instance_id == 17
    assert result.metadata_resolution_tables == ("t_instance_member", "sql_instance")
    assert '"structuredContent"' in model.discovery_feedback
    discovery_payload = model.structured_payload(json.loads(model.discovery_feedback))
    assert discovery_payload[row_key][0]["id"] == 17
    assert discovery_payload[row_key][0]["name"] == "archery-production"
    assert discovery_secret in model.discovery_feedback
    assert "***REDACTED***" not in model.discovery_feedback
    assert "internal_audit_artifact_only" not in model.discovery_feedback
    assert ArcheryMCPClient.payload_row_count(result.payload) == 1
    assert discovery_secret not in json.dumps(result.payload, ensure_ascii=False)


@pytest.mark.asyncio
async def test_shared_archery_harness_replays_responses_items_for_next_tool_call() -> None:
    base_call = _call("responses-member", MEMBER_SQL)
    first = MCPModelToolCall(
        call_id=base_call.call_id,
        name=base_call.name,
        arguments=base_call.arguments,
        request_id=base_call.request_id,
        provider_output_items=(
            {
                "type": "reasoning",
                "id": "responses-reasoning-member",
                "encrypted_content": "encrypted-member",
                "summary": [],
            },
            {
                "type": "function_call",
                "id": "responses-item-member",
                "call_id": base_call.call_id,
                "name": base_call.name,
                "arguments": json.dumps(base_call.arguments, ensure_ascii=False),
                "status": "completed",
            },
        ),
    )
    model = _ScriptedModel(
        [
            first,
            _named_call("terminal-login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-responses-replay",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _terminal_auth_failure(),
                ],
            )
        ],
    )

    await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    second_input = model.requests[1]["messages"]
    reasoning_item = next(
        item for item in second_input if item.get("id") == "responses-reasoning-member"
    )
    function_item = next(item for item in second_input if item.get("id") == "responses-item-member")
    output_item = next(
        item
        for item in reversed(second_input)
        if item.get("type") == "function_call_output" and item.get("call_id") == base_call.call_id
    )
    assert reasoning_item["type"] == "reasoning"
    assert reasoning_item["encrypted_content"] == "encrypted-member"
    assert function_item["type"] == "function_call"
    assert function_item["call_id"] == base_call.call_id
    assert output_item["call_id"] == base_call.call_id
    assert json.loads(output_item["output"]) == {
        "structuredContent": {
            "status": "success",
            "full_sql": MEMBER_SQL,
            "rows": [{"f_instance_id": 53}],
        }
    }


@pytest.mark.asyncio
async def test_archery_resume_replays_prepared_state_and_responses_items() -> None:
    class InterruptAfterDecisionSink(InMemoryEventSink):
        def __init__(self) -> None:
            super().__init__()
            self.should_interrupt = True

        async def append(
            self,
            event: AgentEvent,
            *,
            expected_version: int | None = None,
        ) -> AgentEvent:
            committed = await super().append(event, expected_version=expected_version)
            if self.should_interrupt and event.kind == AgentEventKind.MODEL_DECISION:
                self.should_interrupt = False
                raise asyncio.CancelledError
            return committed

    base_call = _call("durable-responses-member", MEMBER_SQL)
    provider_output_items = (
        {
            "type": "reasoning",
            "id": "durable-archery-reasoning",
            "encrypted_content": "encrypted-durable-archery",
            "summary": [],
        },
        {
            "type": "function_call",
            "id": "durable-archery-function",
            "call_id": base_call.call_id,
            "name": base_call.name,
            "arguments": json.dumps(base_call.arguments, ensure_ascii=False),
            "status": "completed",
        },
    )
    durable_call = MCPModelToolCall(
        call_id=base_call.call_id,
        name=base_call.name,
        arguments=base_call.arguments,
        request_id=base_call.request_id,
        provider_output_items=provider_output_items,
    )
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [ReplaySessionFixture(session_id="archery-before-decision-crash", tools=_tools())],
    )
    first_client = _client(_ScriptedModel([durable_call]), first_connector)
    window_start, window_end = archery_harness_module.client_window(
        first_client,
        OCCURRED_AT,
    )
    first_state = archery_harness_module.ArcheryHarnessState(
        window_start=window_start,
        window_end=window_end,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
    )
    first_registry = archery_harness_module._PlannerCallRegistry()
    first_scenario = archery_harness_module.ArcheryHarnessScenario(
        first_client,
        first_state,
        first_registry,
    )
    checkpoints: list[Any] = []

    async def capture_checkpoint(snapshot: Any) -> None:
        checkpoints.append(snapshot)

    sink = InterruptAfterDecisionSink()
    first_runtime = MCPAgentHarnessRuntime(
        connector=first_connector,
        planner=archery_harness_module.ArcheryHarnessPlanner(
            first_client,
            first_scenario,
            first_registry,
        ),
        scenario=first_scenario,
        event_sink=sink,
        budget=BudgetLedger(BudgetLimits()),
        checkpoint_hook=capture_checkpoint,
    )
    with pytest.raises(asyncio.CancelledError):
        await first_runtime.run(run_id=uuid4(), initial_state=first_state)

    stale_checkpoint = checkpoints[-1]
    assert stale_checkpoint.state.query_trace == []
    second_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-after-decision-crash",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _terminal_auth_failure(),
                ],
            )
        ],
    )
    resumed_model = _ScriptedModel(
        [
            _named_call("terminal-login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
            _finish("finish-after-durable-call"),
        ]
    )
    resumed_client = _client(resumed_model, second_connector)
    resumed_registry = archery_harness_module._PlannerCallRegistry()
    resumed_scenario = archery_harness_module.ArcheryHarnessScenario(
        resumed_client,
        deepcopy(stale_checkpoint.state),
        resumed_registry,
    )
    result = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=archery_harness_module.ArcheryHarnessPlanner(
            resumed_client,
            resumed_scenario,
            resumed_registry,
        ),
        scenario=resumed_scenario,
        event_sink=sink,
        budget=BudgetLedger(BudgetLimits()),
    ).resume(
        stale_checkpoint,
        restored_budget=BudgetLedger.from_snapshot(stale_checkpoint.budget),
    )

    assert len(result.state.query_trace) == 1
    assert result.state.query_trace[0]["referenced_tables"] == ["t_instance_member"]
    assert result.state.query_trace[0]["sent_to_mcp"] is True
    assert result.state.query_trace[0]["outcome"] == "ok"
    assert result.state.last_query_target == (17, "archery")
    resumed_messages = resumed_model.requests[0]["messages"]
    assert sum(item.get("id") == "durable-archery-reasoning" for item in resumed_messages) == 1
    assert sum(item.get("id") == "durable-archery-function" for item in resumed_messages) == 1
    assert (
        sum(
            item.get("type") == "function_call_output" and item.get("call_id") == base_call.call_id
            for item in resumed_messages
        )
        == 1
    )


@pytest.mark.parametrize(
    ("unsafe_sql", "reason_code"),
    [
        ("DELETE FROM orders WHERE id = 1", "sample_execution_forbidden"),
        (
            "EXPLAIN ANALYZE DELETE FROM orders WHERE id = 1",
            "explain_analyze_forbidden",
        ),
    ],
)
@pytest.mark.asyncio
async def test_archery_pending_checkpoint_reapplies_current_sql_policy_before_transport(
    unsafe_sql: str,
    reason_code: str,
) -> None:
    sample = "DELETE FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 104,
            "checksum": "delete-orders-resume",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]

    class LegacyPermissiveScenario(archery_harness_module.ArcheryHarnessScenario):
        def prepare_call(self, action: Any, *, state: Any) -> Any:
            prepared = super().prepare_call(action, state=state)
            if action.arguments.get("sql_content") != unsafe_sql:
                return prepared
            metadata = deepcopy(prepared.metadata)
            metadata.pop("local_rejection", None)
            return prepared.model_copy(
                update={"metadata": metadata, "local_result": None},
                deep=True,
            )

    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-before-pending-policy-upgrade",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )
    first_model = _ScriptedModel(
        [
            _call("member-before-upgrade", MEMBER_SQL),
            _call("instance-before-upgrade", INSTANCE_SQL),
            _call("history-before-upgrade", FINAL_SQL),
            _target_call(
                "unsafe-before-upgrade",
                unsafe_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
        ]
    )
    first_client = _client(first_model, first_connector)
    window_start, window_end = archery_harness_module.client_window(
        first_client,
        OCCURRED_AT,
    )
    first_state = archery_harness_module.ArcheryHarnessState(
        window_start=window_start,
        window_end=window_end,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
    )
    first_registry = archery_harness_module._PlannerCallRegistry()
    first_scenario = LegacyPermissiveScenario(
        first_client,
        first_state,
        first_registry,
    )
    checkpoints: list[Any] = []

    async def interrupt_unsafe_pending(snapshot: Any) -> None:
        if (
            snapshot.active_call is not None
            and snapshot.active_call.tool_name == ARCHERY_MCP_QUERY_TOOL_NAME
            and snapshot.active_call.effective_arguments.get("sql_content") == unsafe_sql
            and snapshot.invocations
            and snapshot.invocations[-1].status == ToolInvocationStatus.PENDING
        ):
            checkpoints.append(snapshot)
            raise asyncio.CancelledError

    sink = InMemoryEventSink()
    with pytest.raises(asyncio.CancelledError):
        await MCPAgentHarnessRuntime(
            connector=first_connector,
            planner=archery_harness_module.ArcheryHarnessPlanner(
                first_client,
                first_scenario,
                first_registry,
            ),
            scenario=first_scenario,
            event_sink=sink,
            budget=BudgetLedger(BudgetLimits()),
            checkpoint_hook=interrupt_unsafe_pending,
        ).run(run_id=uuid4(), initial_state=first_state)

    stale_checkpoint = checkpoints[-1]
    assert stale_checkpoint.active_call is not None
    assert stale_checkpoint.active_call.local_result is None
    second_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-after-pending-policy-upgrade",
                tools=_tools(),
                calls=[],
            )
        ],
    )
    resumed_model = _ScriptedModel([_finish("finish-after-local-policy-refresh")])
    resumed_client = _client(resumed_model, second_connector)
    resumed_registry = archery_harness_module._PlannerCallRegistry()
    resumed_scenario = archery_harness_module.ArcheryHarnessScenario(
        resumed_client,
        deepcopy(stale_checkpoint.state),
        resumed_registry,
    )
    result = await MCPAgentHarnessRuntime(
        connector=second_connector,
        planner=archery_harness_module.ArcheryHarnessPlanner(
            resumed_client,
            resumed_scenario,
            resumed_registry,
        ),
        scenario=resumed_scenario,
        event_sink=sink,
        budget=BudgetLedger(BudgetLimits()),
    ).resume(
        stale_checkpoint,
        restored_budget=BudgetLedger.from_snapshot(stale_checkpoint.budget),
    )

    assert result.budget.consumed.remote_tool_calls == 3
    assert result.state.executed_model_calls == [ARCHERY_MCP_QUERY_TOOL_NAME] * 3
    assert len(result.state.query_trace) == len(stale_checkpoint.state.query_trace) == 4
    assert result.state.query_trace[-1]["sql_summary"] == unsafe_sql
    assert result.state.query_trace[-1]["outcome"] == "rejected_locally"
    assert result.state.query_trace[-1]["reason_code"] == reason_code
    local_record = next(
        record
        for record in result.remote_responses
        if record.invocation_id == result.invocations[-1].invocation_id
    )
    assert local_record.is_remote is False
