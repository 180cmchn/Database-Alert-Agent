from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select

import app.adapters.archery_harness as archery_harness_module
from app.adapters.ai import OpenAICompatibleAdvisor
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
    ArcheryHarnessRuntimeDependencies,
    ArcheryMCPConnector,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPClient,
    ArcheryMCPProtocolError,
    MCPServerSettings,
)
from app.adapters.persistence import (
    AgentArtifactRow,
    SQLAlchemyAlertRepository,
    ToolInvocationRow,
)
from app.agent_runtime import AgentEventKind, RunManifest, ToolInvocationStatus
from app.domain.models import InvestigationRun
from app.domain.ports import RunLeaseConflict
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import load_mcp_catalog
from app.mcp_runtime import (
    DiscoveredMCPTool,
    ReplayCallFixture,
    ReplayCallOutcome,
    ReplayErrorFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
)

OCCURRED_AT = datetime.fromisoformat("2026-07-23T16:00:00+08:00")
ARCHERY_MCP_LOGIN_TOOL_NAME = "ensure_login_gymJPA"
ARCHERY_MCP_QUERY_TOOL_NAME = "sql_query_gymJPA"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARCHERY_PROMPTS = load_mcp_catalog(
    PROJECT_ROOT / "config/mcp/settings.json"
).require("archery").prompts
ALERT_CONTEXT = {"alert_endpoint": "db-1.example:3306"}
FINISH_TOOL_NAME = "finish_archery_investigation"
TARGET_ARGUMENTS = {
    "instance_id": 17,
    "db_name": "archery",
    "limit_num": 20,
}
FINAL_SQL = (
    "SELECT hostname_max, ts_min, ts_max, sql_text "
    f"FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784793300) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "ORDER BY ts_min DESC LIMIT 20"
)
MEMBER_SQL = (
    "SELECT f_instance_id FROM t_instance_member "
    "WHERE f_ip = 'db-1.example' AND f_port = 3306 LIMIT 1"
)
INSTANCE_SQL = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"


def _lineage_actions(final_sql: str = FINAL_SQL) -> list[MCPModelToolCall]:
    return [
        _call("member", MEMBER_SQL),
        _call("instance", INSTANCE_SQL),
        _call("final", final_sql),
        _finish(),
    ]


def _lineage_replay_calls(
    final_sql: str = FINAL_SQL,
    *,
    rows: list[dict[str, Any]] | None = None,
) -> list[ReplayCallFixture]:
    return [
        _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
        _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
        _success(final_sql, rows=rows),
    ]


class _ScriptedModel:
    def __init__(self, responses: list[MCPModelToolCall | Exception]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

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
                "tool_names": [item["function"]["name"] for item in tools],
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _call(call_id: str, sql: str) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        request_id=f"request-{call_id}",
    )


def _finish(
    call_id: str = "finish",
    *,
    reason: str = "Archery evidence collection is complete",
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=FINISH_TOOL_NAME,
        arguments={"reason": reason},
        request_id=f"request-{call_id}",
    )


def _tools() -> list[DiscoveredMCPTool]:
    return [
        DiscoveredMCPTool(
            name=ARCHERY_MCP_LOGIN_TOOL_NAME,
            description="Confirm the configured Archery identity",
            input_schema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_QUERY_TOOL_NAME,
            description="Execute one read-only SELECT",
            input_schema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "integer"},
                    "db_name": {"type": "string"},
                    "sql_content": {"type": "string"},
                    "limit_num": {"type": "integer"},
                    "max_result_chars": {"type": "integer"},
                },
                "required": ["instance_id", "db_name", "sql_content"],
            },
            annotations={"readOnlyHint": True},
        ),
    ]


def _success(sql: str, *, rows: list[dict[str, Any]] | None = None) -> ReplayCallFixture:
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        result={
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": rows or [],
            }
        },
    )


def _client(
    model: _ScriptedModel,
    connector: ReplayMCPConnector,
    *,
    repository: SQLAlchemyAlertRepository | None = None,
) -> ArcheryMCPClient:
    return ArcheryMCPClient(
        MCPServerSettings(
            url="https://archery.example.test/mcp",
            headers={"X-Archery-Token": "fixture-token"},
            prompts=ARCHERY_PROMPTS,
        ),
        model,
        harness_connector=connector,
        harness_runtime_dependencies=(
            ArcheryHarnessRuntimeDependencies(repository)
            if repository is not None
            else None
        ),
    )


def _scenario() -> archery_harness_module.ArcheryHarnessScenario:
    client = _client(
        _ScriptedModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
    )
    state = archery_harness_module.ArcheryHarnessState(
        window_start=OCCURRED_AT,
        window_end=OCCURRED_AT,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
    )
    return archery_harness_module.ArcheryHarnessScenario(
        client,
        state,
        archery_harness_module._PlannerCallRegistry(),
    )


async def _create_durable_run(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
) -> tuple[RunManifest, InvestigationRun]:
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="archery-harness-test",
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": external_id,
            "severity": "WARNING",
            "title": "MySQL/mysql_slow_query_400/db-1.example:3306",
            "reason": "database_latency",
            "occurred_at": OCCURRED_AT.isoformat(),
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    run = await repository.create_run(
        str(stored.alert.id),
        "archery-worker",
        300,
        manifest=manifest,
    )
    assert run is not None
    assert run.id == run_id
    assert run.lease_owner == "archery-worker"
    return manifest, run


@pytest.mark.asyncio
async def test_connector_closes_entered_contexts_when_initialize_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    class _TrackedContext:
        def __init__(self, name: str, value: Any) -> None:
            self.name = name
            self.value = value

        async def __aenter__(self) -> Any:
            return self.value

        async def __aexit__(self, *_args: Any) -> None:
            closed.append(self.name)

    class _CancelledSession:
        async def __aenter__(self) -> _CancelledSession:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            closed.append("session")

        async def initialize(self) -> None:
            raise asyncio.CancelledError

    http_context = _TrackedContext("http", object())
    stream_context = _TrackedContext(
        "stream",
        (object(), object(), lambda: "cancelled-session"),
    )
    monkeypatch.setattr(
        archery_harness_module.httpx,
        "AsyncClient",
        lambda **_kwargs: http_context,
    )
    monkeypatch.setattr(
        archery_harness_module,
        "streamable_http_client",
        lambda *_args, **_kwargs: stream_context,
    )
    monkeypatch.setattr(
        archery_harness_module,
        "ClientSession",
        lambda *_args, **_kwargs: _CancelledSession(),
    )
    client = _client(
        _ScriptedModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
    )

    with pytest.raises(asyncio.CancelledError):
        await ArcheryMCPConnector(client).open_session()

    assert closed == ["session", "stream", "http"]


@pytest.mark.asyncio
async def test_archery_sdk_session_preserves_null_fields_and_aliases() -> None:
    class _RawSession:
        async def call_tool(self, *args: Any, **kwargs: Any) -> Any:
            del args, kwargs

            class _Result:
                def model_dump(self, **options: Any) -> dict[str, Any]:
                    assert options == {
                        "by_alias": True,
                        "mode": "json",
                        "exclude_none": False,
                    }
                    return {
                        "_meta": None,
                        "content": [],
                        "structuredContent": None,
                        "isError": False,
                    }

            return _Result()

    sdk_session = archery_harness_module._ArcherySDKSession(
        owner=_client(_ScriptedModel([]), ReplayMCPConnector("archery", [])),
        stack=archery_harness_module.AsyncExitStack(),
        session=_RawSession(),  # type: ignore[arg-type]
        session_id="complete-envelope",
    )

    result = await sdk_session.call_tool("query", {})

    assert result == {
        "_meta": None,
        "content": [],
        "structuredContent": None,
        "isError": False,
    }


@pytest.mark.asyncio
async def test_archery_sdk_session_lists_more_than_ten_tool_pages() -> None:
    requested_cursors: list[str | None] = []

    class _RawTool:
        def __init__(self, name: str) -> None:
            self.name = name

        def model_dump(self, **options: Any) -> dict[str, Any]:
            assert options == {
                "by_alias": True,
                "mode": "json",
                "exclude_none": True,
            }
            return {
                "name": self.name,
                "description": f"Capability for {self.name}",
                "inputSchema": {"type": "object"},
            }

    class _PagedSession:
        async def list_tools(self, *, params: Any = None) -> Any:
            requested_cursors.append(getattr(params, "cursor", None))
            page = len(requested_cursors)
            return SimpleNamespace(
                tools=[_RawTool(f"archery_tool_{page}")],
                nextCursor=f"cursor-{page}" if page < 12 else None,
            )

    sdk_session = archery_harness_module._ArcherySDKSession(
        owner=_client(_ScriptedModel([]), ReplayMCPConnector("archery", [])),
        stack=archery_harness_module.AsyncExitStack(),
        session=_PagedSession(),  # type: ignore[arg-type]
        session_id="multi-page-tools",
    )

    tools = await sdk_session.list_tools()

    assert len(tools) == 12
    assert [tool.name for tool in tools] == [
        f"archery_tool_{page}" for page in range(1, 13)
    ]
    assert requested_cursors == [None, *(f"cursor-{page}" for page in range(1, 12))]


@pytest.mark.asyncio
async def test_archery_sdk_session_rejects_repeated_tool_list_cursor() -> None:
    class _RawTool:
        name = "archery_tool"

        @staticmethod
        def model_dump(**_options: Any) -> dict[str, Any]:
            return {"name": "archery_tool", "inputSchema": {"type": "object"}}

    class _RepeatingCursorSession:
        async def list_tools(self, *, params: Any = None) -> Any:
            del params
            return SimpleNamespace(tools=[_RawTool()], nextCursor="repeated-cursor")

    sdk_session = archery_harness_module._ArcherySDKSession(
        owner=_client(_ScriptedModel([]), ReplayMCPConnector("archery", [])),
        stack=archery_harness_module.AsyncExitStack(),
        session=_RepeatingCursorSession(),  # type: ignore[arg-type]
        session_id="repeated-cursor",
    )

    with pytest.raises(ArcheryMCPProtocolError, match="repeated tools/list cursor"):
        await sdk_session.list_tools()


@pytest.mark.asyncio
async def test_bootstrap_records_session_without_calling_a_fixed_login_tool() -> None:
    class _SessionWithoutBootstrapCalls:
        session_id = "archery-dynamic-session"

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            raise AssertionError(f"unexpected bootstrap call: {name} {arguments}")

    client = _client(
        _ScriptedModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
    )
    state = archery_harness_module.ArcheryHarnessState(
        window_start=OCCURRED_AT,
        window_end=OCCURRED_AT,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
    )
    scenario = archery_harness_module.ArcheryHarnessScenario(
        client,
        state,
        archery_harness_module._PlannerCallRegistry(),
    )

    restored = await scenario.bootstrap(_SessionWithoutBootstrapCalls(), state)  # type: ignore[arg-type]

    assert restored.session_id == "archery-dynamic-session"
    assert restored.mcp_roundtrip_count == 0
    assert not hasattr(restored, "raw_mcp_call_results")


@pytest.mark.asyncio
async def test_shared_harness_repairs_model_response_without_local_step_limit() -> None:
    model = _ScriptedModel(
        [RuntimeError("model returned zero tool calls"), *_lineage_actions()]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=_lineage_replay_calls(
                    rows=[{"hostname_max": "db-1.example:3306", "sql_text": "SELECT 1"}]
                ),
            )
        ],
    )
    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert len(model.requests) == 5
    assert "Return exactly one valid Agent action" in str(model.requests[1]["messages"])
    assert connector.opened_session_ids == ["archery-1"]


@pytest.mark.asyncio
async def test_shared_harness_ignores_annotations_and_exposes_all_discovered_tools() -> None:
    tools = _tools()
    for tool in tools:
        tool.annotations = {
            "readOnlyHint": False,
            "destructiveHint": True,
            "provider_extension": "ignored",
        }
    tools.extend(
        DiscoveredMCPTool(
            name=name,
            description=f"Dynamic capability for {name}",
            input_schema={"type": "object"},
            annotations={"readOnlyHint": "not-a-boolean"},
        )
        for name in (
            ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
            ARCHERY_MCP_INSTANCES_TOOL_NAME,
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            ARCHERY_MCP_TABLES_TOOL_NAME,
            ARCHERY_MCP_COLUMNS_TOOL_NAME,
        )
    )
    model = _ScriptedModel(_lineage_actions())
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-without-annotations",
                tools=tools,
                calls=_lineage_replay_calls(
                    rows=[{"hostname_max": "db-1.example:3306", "sql_text": "SELECT 1"}]
                ),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert connector.opened_session_ids == ["archery-without-annotations"]
    assert set(model.requests[0]["tool_names"]) == {
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_DATABASES_TOOL_NAME,
        ARCHERY_MCP_TABLES_TOOL_NAME,
        ARCHERY_MCP_COLUMNS_TOOL_NAME,
        FINISH_TOOL_NAME,
    }


@pytest.mark.parametrize(
    "annotations",
    [
        {},
        {"readOnlyHint": None},
        {"destructiveHint": False},
        {"readOnlyHint": True},
        {"readOnlyHint": True, "destructiveHint": False},
        {"readOnlyHint": False},
        {"readOnlyHint": True, "destructiveHint": True},
        {"readOnlyHint": "true"},
        {"readOnlyHint": True, "read_only_hint": False},
    ],
)
def test_archery_harness_ignores_all_remote_annotations(
    annotations: dict[str, Any],
) -> None:
    tools = _tools()
    tools[-1].annotations = annotations

    specs = _scenario().build_tool_specs(tools)

    assert [spec.name for spec in specs] == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    ]
    assert specs[-1].input_schema == tools[-1].input_schema


def test_archery_harness_exposes_unknown_dynamic_tool_with_original_contract() -> None:
    schema = {
        "type": "object",
        "properties": {"scope": {"type": "string"}},
        "required": ["scope"],
        "additionalProperties": False,
    }
    tools = [
        *_tools(),
        DiscoveredMCPTool(
            name="request_query_permission_gymJPA",
            description="Dynamically discovered Archery capability",
            input_schema=schema,
        ),
    ]

    specs = _scenario().build_tool_specs(tools)

    assert [spec.name for spec in specs] == [
        ARCHERY_MCP_LOGIN_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        "request_query_permission_gymJPA",
    ]
    assert specs[-1].capability == "Dynamically discovered Archery capability"
    assert specs[-1].input_schema == schema


@pytest.mark.asyncio
async def test_unknown_dynamic_tool_can_return_final_history_by_actual_sql() -> None:
    dynamic_tool_name = "deployment_specific_query"
    dynamic_arguments = {"deployment_scope": "primary"}
    model = _ScriptedModel(
        [
            MCPModelToolCall(
                call_id="dynamic-history",
                name=dynamic_tool_name,
                arguments=dynamic_arguments,
                request_id="request-dynamic-history",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-dynamic-history",
                tools=[
                    DiscoveredMCPTool(
                        name=dynamic_tool_name,
                        description="Deployment-specific query capability",
                        input_schema={"type": "object", "additionalProperties": True},
                    )
                ],
                calls=[
                    ReplayCallFixture(
                        tool_name=dynamic_tool_name,
                        expected_arguments=dynamic_arguments,
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": FINAL_SQL,
                                "rows": [
                                    {
                                        "hostname_max": "db-1.example:3306",
                                        "sample": "SELECT dynamic history",
                                    }
                                ],
                            }
                        },
                    )
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == FINAL_SQL
    assert result.executed_sql == FINAL_SQL
    assert result.model_tool_calls == (dynamic_tool_name,)


@pytest.mark.asyncio
async def test_actual_response_sql_overrides_requested_history_for_classification() -> None:
    actual_sql = "SELECT index_name FROM information_schema.statistics"
    model = _ScriptedModel([_call("mismatched-sql", FINAL_SQL), _finish()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-actual-sql-wins",
                tools=_tools(),
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": actual_sql,
                                "rows": [{"index_name": "idx_hostname"}],
                            }
                        },
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
    assert result.requested_sql == ""
    assert not hasattr(result, "raw_mcp_call_results")


def test_archery_harness_does_not_require_or_hide_a_fixed_login_tool() -> None:
    specs_without_login = _scenario().build_tool_specs(_tools()[1:])
    assert [spec.name for spec in specs_without_login] == [ARCHERY_MCP_QUERY_TOOL_NAME]

    specs = _scenario().build_tool_specs(
        [
            DiscoveredMCPTool(
                name="new_archery_tool",
                input_schema={"type": "object"},
            ),
        ]
    )

    assert [spec.name for spec in specs] == ["new_archery_tool"]


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
async def test_shared_harness_preserves_schema_and_sends_remote_character_limit() -> None:
    final_arguments = {
        **TARGET_ARGUMENTS,
        "sql_content": FINAL_SQL,
        "max_result_chars": 123_456,
    }
    model = _ScriptedModel(
        [
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
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments=final_arguments,
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": FINAL_SQL,
                                "rows": [
                                    {
                                        "hostname_max": "db-1.example:3306",
                                        "sql_text": "SELECT 1",
                                    }
                                ],
                            }
                        },
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
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert len(model.requests) == 2
    assert connector.opened_session_ids == ["archery-no-character-limit"]


@pytest.mark.asyncio
async def test_auxiliary_raw_payload_stays_out_of_model_messages() -> None:
    auxiliary_secret = "authentication-and-metadata-raw-response"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
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
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": MEMBER_SQL,
                                "rows": [{"f_instance_id": 53}],
                                "authentication_token": auxiliary_secret,
                                "raw_metadata": {"secret": auxiliary_secret},
                            }
                        },
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
    final_request_messages = json.dumps(
        model.requests[1]["messages"], ensure_ascii=False, default=str
    )
    assert auxiliary_secret not in final_request_messages
    assert "f_instance_id" in final_request_messages
    assert "internal_audit_artifact_only" in final_request_messages
    assert "authentication_token" not in final_request_messages
    assert "raw_metadata" not in final_request_messages


@pytest.mark.asyncio
async def test_shared_archery_harness_executes_text_agent_action_history_query() -> None:
    action = {
        "action": "call_tool",
        "tool_name": ARCHERY_MCP_QUERY_TOOL_NAME,
        "objective": "Collect read-only Archery evidence for the fixed alert window",
        "hypothesis_ids": [],
        "arguments": {**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
    }

    class TextActionCompletions:
        def __init__(self) -> None:
            self.request_count = 0

        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            self.request_count += 1
            if self.request_count == 2:
                return SimpleNamespace(
                    id="archery-text-finish-request",
                    choices=[
                        SimpleNamespace(
                            finish_reason="tool_calls",
                            message=SimpleNamespace(
                                content=None,
                                tool_calls=[
                                    SimpleNamespace(
                                        id="archery-text-finish-call",
                                        function=SimpleNamespace(
                                            name=FINISH_TOOL_NAME,
                                            arguments=json.dumps(
                                                {"reason": "Text action evidence is complete"}
                                            ),
                                        ),
                                    )
                                ],
                            ),
                        )
                    ],
                )
            return SimpleNamespace(
                id="archery-text-action-request",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(
                            content=json.dumps(action),
                            tool_calls=[],
                        ),
                    )
                ],
            )

    advisor = object.__new__(OpenAICompatibleAdvisor)
    advisor._api_key = "test-key"
    advisor._model = "tool-model"
    advisor._max_tokens = 16_384
    completions = TextActionCompletions()
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-text-action",
                tools=_tools(),
                calls=[
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "sql_text": "SELECT from text action",
                            }
                        ],
                    ),
                ],
            )
        ],
    )

    result = await _client(advisor, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == FINAL_SQL
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert result.model_request_ids == ("archery-text-action-request",)
    assert completions.request_count == 2
    assert connector.opened_session_ids == ["archery-text-action"]


@pytest.mark.asyncio
async def test_shared_harness_keeps_repairing_until_model_explicitly_finishes() -> None:
    model = _ScriptedModel(
        [
            RuntimeError("provider returned zero tool calls request-1"),
            RuntimeError("provider returned zero tool calls request-2"),
            RuntimeError("provider returned zero tool calls request-3"),
            _finish(reason="No useful Archery call remains"),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert len(model.requests) == 4
    assert result.diagnostics is not None
    assert result.diagnostics["model_selection_errors"] == []
    assert result.diagnostics["mcp_tool_call_count"] == 0
    assert result.diagnostics["harness_stop_reason"] == "COMPLETED"


@pytest.mark.asyncio
async def test_shared_harness_resume_keeps_repairing_until_explicit_finish(
    tmp_path: Path,
) -> None:
    class FailureThenInterruptModel(_ScriptedModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            self.requests.append(
                {
                    "messages": deepcopy(messages),
                    "tool_names": [item["function"]["name"] for item in tools],
                }
            )
            if len(self.requests) == 1:
                raise RuntimeError("first selection failed before restart")
            raise asyncio.CancelledError

    database_url = f"sqlite+aiosqlite:///{tmp_path / 'archery-model-repair.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    _, run = await _create_durable_run(repository, external_id="archery-model-repair")
    assert run.lease_owner is not None
    outer_dispatch_id = uuid4()
    with pytest.raises(asyncio.CancelledError):
        await _client(
            FailureThenInterruptModel([]),
            ReplayMCPConnector(
                ARCHERY_HARNESS_PROVIDER,
                [
                    ReplaySessionFixture(
                        session_id="archery-model-before-restart",
                        tools=_tools(),
                        calls=[],
                    )
                ],
            ),
            repository=repository,
        ).execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            outer_dispatch_id=outer_dispatch_id,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resumed_model = _ScriptedModel(
        [
            RuntimeError("second selection failed after restart"),
            RuntimeError("third selection failed after restart"),
            _finish(reason="No useful Archery call remains after restart"),
        ]
    )
    result = await _client(
        resumed_model,
        ReplayMCPConnector(
            ARCHERY_HARNESS_PROVIDER,
            [
                ReplaySessionFixture(
                    session_id="archery-model-after-restart",
                    tools=_tools(),
                    calls=[],
                )
            ],
        ),
        repository=restarted_repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=outer_dispatch_id,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert len(resumed_model.requests) == 3
    assert result.query_completed is False
    assert result.diagnostics is not None
    assert result.diagnostics["model_selection_errors"] == []
    assert result.diagnostics["harness_stop_reason"] == "COMPLETED"
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_shared_harness_reconnects_without_losing_prior_observations() -> None:
    auxiliary_sql = (
        "SELECT index_name, column_name FROM information_schema.statistics "
        "WHERE table_schema = 'archery' LIMIT 20"
    )
    interrupted_sql = FINAL_SQL.replace("ORDER BY", "AND ts_max >= ts_min ORDER BY")
    model = _ScriptedModel(
        [
            _call("auxiliary", auxiliary_sql),
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("interrupted", interrupted_sql),
            _call("final", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[
                    _success(auxiliary_sql, rows=[{"index_name": "idx_host_ts"}]),
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            **TARGET_ARGUMENTS,
                            "sql_content": interrupted_sql,
                        },
                        outcome=ReplayCallOutcome.DISCONNECT,
                        error=ReplayErrorFixture(
                            code="connection_lost",
                            message="Connection closed before a terminal response",
                            retryable=True,
                            unknown_outcome=True,
                        ),
                    ),
                ],
            ),
            ReplaySessionFixture(
                session_id="archery-2",
                tools=_tools(),
                calls=[
                    _success(
                        FINAL_SQL,
                        rows=[{"hostname_max": "db-1.example:3306", "sql_text": "SELECT 2"}],
                    ),
                ],
            ),
        ],
    )
    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert connector.opened_session_ids == ["archery-1", "archery-2"]
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 5
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_session_attempts"] == 2
    assert "idx_host_ts" in str(model.requests[4]["messages"])
    assert "MISSING" in str(model.requests[4]["messages"])


@pytest.mark.asyncio
async def test_shared_harness_allows_more_than_two_session_attempts() -> None:
    connection_error = ReplayErrorFixture(
        code="temporary_connection_error",
        message="Archery MCP transport temporarily unavailable",
        retryable=True,
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-session-attempt-1",
                open_error=connection_error,
            ),
            ReplaySessionFixture(
                session_id="archery-session-attempt-2",
                open_error=connection_error.model_copy(deep=True),
            ),
            ReplaySessionFixture(
                session_id="archery-session-attempt-3",
                tools=_tools(),
                calls=_lineage_replay_calls(
                    rows=[{"hostname_max": "db-1.example:3306", "sql_text": "SELECT 3"}]
                ),
            ),
        ],
    )

    result = await _client(
        _ScriptedModel(_lineage_actions()),
        connector,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert connector.opened_session_ids == [
        "archery-session-attempt-1",
        "archery-session-attempt-2",
        "archery-session-attempt-3",
    ]
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_session_attempts"] == 3


@pytest.mark.asyncio
async def test_shared_harness_reconnects_and_continues_after_tool_timeout() -> None:
    broad_sql = FINAL_SQL.replace(
        "AND ts_min >= FROM_UNIXTIME(1784793300) ",
        "AND ts_max >= FROM_UNIXTIME(1784793300) ",
    )
    model = _ScriptedModel(
        [
            *_lineage_actions()[:2],
            _call("broad", broad_sql),
            _call("final", FINAL_SQL),
            _finish(),
        ]
    )
    timeout = ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={**TARGET_ARGUMENTS, "sql_content": broad_sql},
        outcome=ReplayCallOutcome.ERROR,
        error=ReplayErrorFixture(
            code="TimeoutError",
            message="Archery query timed out",
            retryable=True,
        ),
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                    timeout,
                ],
            ),
            ReplaySessionFixture(
                session_id="archery-after-timeout",
                tools=_tools(),
                calls=[
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "sql_text": "SELECT after timeout",
                            }
                        ],
                    ),
                ],
            ),
        ],
    )
    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert connector.opened_session_ids == ["archery-1", "archery-after-timeout"]
    timeout_feedback = str(model.requests[3]["messages"])
    assert "Archery query timed out" in timeout_feedback
    assert "MISSING" in timeout_feedback
    assert result.diagnostics is not None
    assert result.diagnostics["query_trace"][2]["outcome"] == "tool_error"
    assert not hasattr(result, "raw_mcp_call_results")


@pytest.mark.asyncio
async def test_shared_harness_persists_and_resumes_completed_run_without_reconnect(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(f"sqlite+aiosqlite:///{tmp_path / 'archery.db'}")
    await repository.initialize()
    manifest, run = await _create_durable_run(
        repository,
        external_id="archery-durable-run",
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-durable-1",
                tools=_tools(),
                calls=_lineage_replay_calls(
                    rows=[
                        {
                            "hostname_max": "db-1.example:3306",
                            "sql_text": "SELECT durable",
                        }
                    ]
                ),
            )
        ],
    )
    client = _client(
        _ScriptedModel(_lineage_actions()),
        connector,
        repository=repository,
    )
    assert run.lease_owner is not None
    outer_dispatch_id = uuid4()

    first = await client.execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=outer_dispatch_id,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert first.query_completed is True
    assert connector.opened_session_ids == ["archery-durable-1"]
    events = await repository.list_agent_events(str(run.id))
    assert events[-1].kind == AgentEventKind.RUN_COMPLETED
    checkpoint = await repository.load_checkpoint(
        str(run.id),
        namespace=f"mcp:{ARCHERY_HARNESS_PROVIDER}:{outer_dispatch_id}",
    )
    assert checkpoint is not None
    assert checkpoint.manifest_hash == manifest.digest()
    assert checkpoint.sequence == events[-1].sequence
    assert checkpoint.stop_reason is not None
    async with repository.session_factory() as session:
        invocations = (
            await session.execute(
                select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
            )
        ).scalars().all()
        artifacts = (
            await session.execute(
                select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
            )
        ).scalars().all()
    assert len(invocations) == 3
    assert all(item.status == ToolInvocationStatus.SUCCEEDED.value for item in invocations)
    assert len(artifacts) == 3
    persisted_counts = (len(events), len(invocations), len(artifacts))

    resume_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    resumed = await _client(
        _ScriptedModel([]),
        resume_connector,
        repository=repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=outer_dispatch_id,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert resumed == first
    assert resume_connector.opened_session_ids == []
    resumed_events = await repository.list_agent_events(str(run.id))
    resumed_checkpoint = await repository.load_checkpoint(
        str(run.id),
        namespace=f"mcp:{ARCHERY_HARNESS_PROVIDER}:{outer_dispatch_id}",
    )
    assert resumed_checkpoint is not None
    async with repository.session_factory() as session:
        resumed_invocation_count = len(
            (
                await session.execute(
                    select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
                )
            ).scalars().all()
        )
        resumed_artifact_count = len(
            (
                await session.execute(
                    select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
                )
            ).scalars().all()
        )
    assert (
        len(resumed_events),
        resumed_invocation_count,
        resumed_artifact_count,
    ) == persisted_counts
    assert resumed_checkpoint.version == checkpoint.version + 1
    assert resumed_checkpoint.sequence == checkpoint.sequence
    await repository.close()


@pytest.mark.asyncio
async def test_shared_harness_mid_run_resume_plans_from_restored_runtime_state(
    tmp_path: Path,
) -> None:
    class InterruptingModel(_ScriptedModel):
        async def request_mcp_tool_call(
            self,
            *,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]],
        ) -> MCPModelToolCall:
            if self.responses:
                return await super().request_mcp_tool_call(messages=messages, tools=tools)
            self.requests.append({"messages": deepcopy(messages), "tool_names": []})
            raise asyncio.CancelledError

    database_url = f"sqlite+aiosqlite:///{tmp_path / 'archery-mid-run-resume.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    _, run = await _create_durable_run(repository, external_id="archery-mid-run-resume")
    assert run.lease_owner is not None
    outer_dispatch_id = uuid4()
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-before-restart",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                ],
            )
        ],
    )
    with pytest.raises(asyncio.CancelledError):
        await _client(
            InterruptingModel(_lineage_actions()[:2]),
            first_connector,
            repository=repository,
        ).execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            outer_dispatch_id=outer_dispatch_id,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resume_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-after-restart",
                tools=_tools(),
                calls=[_success(FINAL_SQL)],
            )
        ],
    )
    resumed_model = _ScriptedModel(
        [_call("final-after-restart", FINAL_SQL), _finish("finish-after-restart")]
    )
    resumed = await _client(
        resumed_model,
        resume_connector,
        repository=restarted_repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=outer_dispatch_id,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert resumed.query_completed is True
    assert resumed.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert resumed.diagnostics is not None
    assert resumed.diagnostics["model_decision_count"] == 3
    assert "resumed-fixture" not in str(resumed_model.requests[0]["messages"])
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_new_scoped_dispatch_without_checkpoint_starts_archery_session(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'archery-missing-outer-checkpoint.db'}"
    )
    await repository.initialize()
    _, run = await _create_durable_run(
        repository,
        external_id="archery-missing-outer-checkpoint",
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-new-dispatch",
                tools=_tools(),
                calls=[],
            )
        ],
    )
    client = _client(
        _ScriptedModel([_finish("No Archery call is required")]),
        connector,
        repository=repository,
    )
    assert run.lease_owner is not None

    result = await client.execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=uuid4(),
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert result.query_completed is False
    assert connector.opened_session_ids == ["archery-new-dispatch"]
    await repository.close()


@pytest.mark.asyncio
async def test_shared_harness_recovers_artifact_from_checkpoint_after_process_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'artifact-recovery.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    _, run = await _create_durable_run(
        repository,
        external_id="archery-artifact-recovery",
    )
    rows = [
        {
            "hostname_max": "db-1.example:3306",
            "sql_text": "SELECT recovered",
        }
    ]
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-artifact-first-process",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                ],
            )
        ],
    )

    original_save = archery_harness_module.RepositoryArcheryRemoteResponseStore.save
    interrupted = False

    async def interrupt_after_response_save(store: Any, **kwargs: Any) -> None:
        nonlocal interrupted
        await original_save(store, **kwargs)
        if not interrupted:
            interrupted = True
            raise asyncio.CancelledError

    monkeypatch.setattr(
        archery_harness_module.RepositoryArcheryRemoteResponseStore,
        "save",
        interrupt_after_response_save,
    )
    assert run.lease_owner is not None
    with pytest.raises(asyncio.CancelledError):
        await _client(
            _ScriptedModel([_call("artifact-recovery-member", MEMBER_SQL)]),
            first_connector,
            repository=repository,
        ).execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )

    async with repository.session_factory() as session:
        invocations = (
            await session.execute(
                select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
            )
        ).scalars().all()
        artifacts = (
            await session.execute(
                select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
            )
        ).scalars().all()
    assert len(invocations) == 1
    assert invocations[0].status == ToolInvocationStatus.STARTED.value
    assert len(artifacts) == 1
    stored_before_restart = await repository.get_agent_artifact(artifacts[0].id)
    assert stored_before_restart is not None
    first_artifact, first_content = stored_before_restart
    assert first_artifact.kind == "archery_mcp_remote_response"
    assert first_artifact.metadata["internal_only"] is True
    assert first_artifact.metadata["invocation_id"] == invocations[0].id
    assert isinstance(first_content, dict)
    assert first_content["response"] == {
        "structuredContent": {
            "status": "success",
            "full_sql": MEMBER_SQL,
            "rows": [{"f_instance_id": 53}],
        }
    }
    await repository.close()

    monkeypatch.setattr(
        archery_harness_module.RepositoryArcheryRemoteResponseStore,
        "save",
        original_save,
    )
    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resume_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-artifact-recovery-resume",
                tools=_tools(),
                calls=[
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                    _success(FINAL_SQL, rows=rows),
                ],
            )
        ],
    )
    resumed = await _client(
        _ScriptedModel(_lineage_actions()[1:]),
        resume_connector,
        repository=restarted_repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert resumed.query_completed is True
    assert resume_connector.opened_session_ids == ["archery-artifact-recovery-resume"]
    async with restarted_repository.session_factory() as session:
        recovered_invocations = (
            await session.execute(
                select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
            )
        ).scalars().all()
        recovered_artifacts = (
            await session.execute(
                select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
            )
        ).scalars().all()
    assert len(recovered_invocations) == 3
    assert all(
        item.status == ToolInvocationStatus.SUCCEEDED.value
        for item in recovered_invocations
    )
    assert len(recovered_artifacts) == 3
    artifact_id = recovered_artifacts[-1].id
    persisted_artifact = await restarted_repository.get_agent_artifact(artifact_id)
    assert persisted_artifact is not None
    assert isinstance(persisted_artifact[1], dict)
    assert persisted_artifact[1]["response"] == {
        "structuredContent": {
            "status": "success",
            "full_sql": FINAL_SQL,
            "rows": rows,
        }
    }
    assert not hasattr(resumed, "raw_mcp_call_results")
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_shared_harness_persists_tool_error_response_before_processing(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'archery-tool-error-audit.db'}"
    )
    await repository.initialize()
    _, run = await _create_durable_run(
        repository,
        external_id="archery-tool-error-audit",
    )
    raw_error = {
        "isError": True,
        "content": [{"type": "text", "text": "Archery rejected the query"}],
    }
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-tool-error-audit",
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
    assert run.lease_owner is not None

    result = await _client(
        _ScriptedModel([_call("tool-error", MEMBER_SQL), _finish()]),
        connector,
        repository=repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert result.query_completed is False
    async with repository.session_factory() as session:
        artifacts = (
            await session.execute(
                select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
            )
        ).scalars().all()
    assert len(artifacts) == 1
    stored = await repository.get_agent_artifact(artifacts[0].id)
    assert stored is not None
    artifact, content = stored
    assert artifact.metadata["internal_only"] is True
    assert isinstance(content, dict)
    assert content["response"] == raw_error
    await repository.close()


@pytest.mark.asyncio
async def test_shared_harness_rejects_stale_fencing_before_opening_mcp_session(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(f"sqlite+aiosqlite:///{tmp_path / 'stale.db'}")
    await repository.initialize()
    _, run = await _create_durable_run(repository, external_id="archery-stale-run")
    connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    client = _client(_ScriptedModel([]), connector, repository=repository)
    assert run.lease_owner is not None

    with pytest.raises(RunLeaseConflict):
        await client.execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token + 1,
        )

    assert connector.opened_session_ids == []
    assert await repository.list_agent_events(str(run.id)) == []
    assert await repository.load_checkpoint(
        str(run.id),
        namespace=f"mcp:{ARCHERY_HARNESS_PROVIDER}",
    ) is None
    async with repository.session_factory() as session:
        assert (
            await session.execute(
                select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run.id))
            )
        ).scalars().all() == []
        assert (
            await session.execute(
                select(AgentArtifactRow).where(AgentArtifactRow.run_id == str(run.id))
            )
        ).scalars().all() == []
    await repository.close()
