from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4, uuid5

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
from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    BudgetLedger,
    BudgetLimits,
    InMemoryEventSink,
    RunManifest,
    ToolInvocationStatus,
)
from app.domain.models import InvestigationRun
from app.domain.ports import RunLeaseConflict
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import load_mcp_catalog
from app.mcp_runtime import (
    DiscoveredMCPTool,
    MCPAgentHarnessRuntime,
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
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
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


def _named_call(
    call_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=tool_name,
        arguments=arguments,
        request_id=f"request-{call_id}",
    )


def _target_call(
    call_id: str,
    sql: str,
    *,
    instance_id: int,
    db_name: str,
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            "instance_id": instance_id,
            "db_name": db_name,
            "limit_num": 20,
            "sql_content": sql,
        },
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


def _analysis_tools() -> list[DiscoveredMCPTool]:
    return [
        *_tools(),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            description="List allowlisted database instances",
            input_schema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            description="List databases for one allowlisted instance",
            input_schema={
                "type": "object",
                "properties": {"instance_id": {"type": "integer"}},
                "required": ["instance_id"],
            },
            annotations={"readOnlyHint": True},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_COLUMNS_TOOL_NAME,
            description="List real columns for one table",
            input_schema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "integer"},
                    "db_name": {"type": "string"},
                    "tb_name": {"type": "string"},
                },
                "required": ["instance_id", "db_name", "tb_name"],
            },
            annotations={"readOnlyHint": True},
        ),
    ]


def _analysis_discovery_actions(
    *,
    instance_id: int = 3,
) -> list[MCPModelToolCall]:
    return [
        _named_call("allowlist", ARCHERY_MCP_INSTANCES_TOOL_NAME, {}),
        _named_call(
            "databases",
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            {"instance_id": instance_id},
        ),
    ]


def _analysis_discovery_calls(
    *,
    instance_id: int = 3,
    endpoint: str = "orders-db.example:3306",
    db_name: str = "orders_prod",
) -> list[ReplayCallFixture]:
    host, port_text = endpoint.rsplit(":", 1)
    return [
        ReplayCallFixture(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            expected_arguments={},
            result={
                "structuredContent": {
                    "status": "success",
                    "rows": [{"id": instance_id, "host": host, "port": int(port_text)}],
                }
            },
        ),
        ReplayCallFixture(
            tool_name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            expected_arguments={"instance_id": instance_id},
            result={
                "structuredContent": {
                    "status": "success",
                    "rows": [{"name": db_name}],
                }
            },
        ),
    ]


def _success(
    sql: str,
    *,
    rows: list[dict[str, Any]] | None = None,
    max_result_chars: int | None = None,
) -> ReplayCallFixture:
    expected_arguments = {**TARGET_ARGUMENTS, "sql_content": sql}
    if max_result_chars is not None:
        expected_arguments["max_result_chars"] = max_result_chars
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments=expected_arguments,
        result={
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": rows or [],
            }
        },
    )


def _response_result_success(
    sql: str,
    *,
    columns: list[str],
    rows: list[list[Any]],
) -> ReplayCallFixture:
    payload = {
        "full_sql": sql,
        "rows": rows,
        "column_list": columns,
        "affected_rows": len(rows),
    }
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        result={
            "structuredContent": {
                "response": {
                    "result": (
                        f"SQL 查询已执行。\n执行的SQL：{sql}\n\n"
                        f"返回 {len(rows)} 行。\n结果：\n"
                        + json.dumps(payload, ensure_ascii=False)
                    )
                }
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


def _bound_history_scenario(
    rows: list[dict[str, Any]],
    *,
    instance_id: int = 3,
    endpoint: str = "orders-db.example:3306",
    db_name: str = "orders_prod",
) -> tuple[
    archery_harness_module.ArcheryHarnessScenario,
    archery_harness_module.ArcheryHarnessState,
]:
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={"rows": rows},
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.history_result_target = (
        TARGET_ARGUMENTS["instance_id"],
        TARGET_ARGUMENTS["db_name"],
    )
    state.analysis_instance_endpoints = {instance_id: {endpoint}}
    state.analysis_database_names = {instance_id: {db_name}}
    return scenario, state


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


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("deployment_specific_query", {"deployment_scope": "primary"}),
        (ARCHERY_MCP_QUERY_TOOL_NAME, dict(TARGET_ARGUMENTS)),
        (
            ARCHERY_MCP_QUERY_TOOL_NAME,
            {**TARGET_ARGUMENTS, "sql_content": {"statement": FINAL_SQL}},
        ),
    ],
)
@pytest.mark.asyncio
async def test_pre_history_tool_without_authorized_contract_is_rejected_before_mcp(
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    model = _ScriptedModel(
        [
            MCPModelToolCall(
                call_id="unauthorized-pre-history",
                name=tool_name,
                arguments=arguments,
                request_id="request-unauthorized-pre-history",
            ),
            _finish(),
        ]
    )
    tools = _tools()
    if tool_name != ARCHERY_MCP_QUERY_TOOL_NAME:
        tools.append(
            DiscoveredMCPTool(
                name=tool_name,
                description="Deployment-specific capability",
                input_schema={"type": "object", "additionalProperties": True},
            )
        )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-unauthorized-pre-history",
                tools=tools,
                calls=[],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert result.requested_sql == ""
    assert result.payload["status"] == "evidence_insufficient"
    assert result.model_tool_calls == ()
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 0
    assert connector.opened_session_ids == ["archery-reject-unauthorized-pre-history"]


@pytest.mark.parametrize(
    "annotations",
    [
        {"readOnlyHint": True},
        {"readOnlyHint": True, "destructiveHint": False},
    ],
)
def test_pre_history_read_only_auth_tool_remains_allowed(
    annotations: dict[str, Any],
) -> None:
    scenario = _scenario()
    scenario.build_tool_specs(
        [
            DiscoveredMCPTool(
                name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                description="Confirm the configured Archery identity",
                input_schema={"type": "object", "properties": {}},
                annotations=annotations,
            )
        ]
    )
    state = scenario.initial_state()

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
            objective="Confirm the configured identity",
            hypothesis_ids=[],
            arguments={},
        ),
        state=state,
    )

    assert prepared.local_result is None


@pytest.mark.parametrize(
    "annotations",
    [
        {},
        {"readOnlyHint": False},
        {"readOnlyHint": True, "destructiveHint": True},
    ],
)
@pytest.mark.asyncio
async def test_pre_history_dynamic_auth_tool_requires_nondestructive_read_only_contract(
    annotations: dict[str, Any],
) -> None:
    tool_name = "refresh_session_credentials_gymJPA"
    model = _ScriptedModel(
        [
            _named_call("unsafe-dynamic-auth", tool_name, {}),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-unsafe-dynamic-auth",
                tools=[
                    *_tools(),
                    DiscoveredMCPTool(
                        name=tool_name,
                        description="Refresh the current authentication session",
                        input_schema={"type": "object", "properties": {}},
                        annotations=annotations,
                    ),
                ],
                calls=[],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.model_tool_calls == ()
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 0
    assert result.diagnostics["model_attempted_tool_calls"] == [
        tool_name,
        FINISH_TOOL_NAME,
    ]


def test_dynamic_auth_allowlist_is_rebuilt_after_annotation_change() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    tool_name = "refresh_session_credentials_gymJPA"

    def discovered(annotations: dict[str, Any]) -> DiscoveredMCPTool:
        return DiscoveredMCPTool(
            name=tool_name,
            input_schema={"type": "object", "properties": {}},
            annotations=annotations,
        )

    scenario.build_tool_specs([discovered({"readOnlyHint": True})])
    allowed = scenario.prepare_call(
        SimpleNamespace(
            tool_name=tool_name,
            objective="Refresh authentication",
            hypothesis_ids=[],
            arguments={},
        ),
        state=state,
    )
    scenario.build_tool_specs(
        [
            discovered(
                {"readOnlyHint": True, "destructiveHint": True},
            )
        ]
    )
    rejected = scenario.prepare_call(
        SimpleNamespace(
            tool_name=tool_name,
            objective="Refresh authentication",
            hypothesis_ids=[],
            arguments={},
        ),
        state=state,
    )

    assert allowed.local_result is None
    assert rejected.metadata["local_rejection"]["reason_code"] == (
        "pre_history_tool_forbidden"
    )


@pytest.mark.asyncio
async def test_harness_parses_structured_response_result_history_rows() -> None:
    rows = [
        ["db-1.example:3306", "2026-07-23T15:59:10", "SELECT fixture one"],
        ["db-1.example:3306", "2026-07-23T15:59:20", "SELECT fixture two"],
    ]
    wrapped_result = (
        f"SQL 查询已执行。\n执行的SQL：{FINAL_SQL}\n\n返回 2 行。\n结果：\n"
        + json.dumps(
            {
                "full_sql": FINAL_SQL,
                "rows": rows,
                "column_list": ["hostname_max", "ts_min", "sql_text"],
                "affected_rows": 2,
            },
            ensure_ascii=False,
        )
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("wrapped-history", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-response-result-history",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
                        result={
                            "structuredContent": {
                                "response": {"result": wrapped_result},
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
    assert result.executed_sql == FINAL_SQL
    assert result.actual_sql_verified is True
    assert ArcheryMCPClient.payload_row_count(result.payload) == 2
    assert ArcheryMCPClient._tabular_rows(result.payload) == [
        {
            "hostname_max": "db-1.example:3306",
            "ts_min": "2026-07-23T15:59:10",
            "sql_text": "SELECT fixture one",
        },
        {
            "hostname_max": "db-1.example:3306",
            "ts_min": "2026-07-23T15:59:20",
            "sql_text": "SELECT fixture two",
        },
    ]
    assert len(model.requests) == 4


_MERGE_WINDOW_SQL = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784789700) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "AND ts_max >= FROM_UNIXTIME(1784793300) "
    "ORDER BY id DESC"
)
_MERGE_IDS_SQL = (
    f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784789700) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "AND ts_max >= FROM_UNIXTIME(1784793300) "
    "ORDER BY id DESC"
)
_MERGE_ID_SQL_60 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413460"
)
_MERGE_ID_SQL_54 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413454"
)
_MERGE_ID_SQL_44 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413644"
)
_MERGE_RECOVERED_ROW = {
    "id": 24413458,
    "hostname_max": "db-1.example:3306",
    "db_max": "dpm",
    "user_max": "dpm_rw",
    "checksum": "a" * 32,
    "sample": "UPDATE t_dpm_task_warning SET del_flag = 1",
    "ts_min": "2026-08-17T09:41:30",
    "ts_max": "2026-08-17T09:42:49",
    "ts_cnt": 6,
    "Query_time_sum": 0.340724,
    "Query_time_max": 0.058781,
    "Query_time_pct_95": 0.0585588,
}


def _merge_truncated_window_fixture() -> ReplayCallFixture:
    truncated_result = (
        '{"rows":['
        + json.dumps(_MERGE_RECOVERED_ROW, ensure_ascii=False)
        + ',{"id":24413460,"hostname_max":"db-1.example:3306'
    )
    wrapped_window_result = (
        f"SQL 查询已执行。\n执行的SQL：{_MERGE_WINDOW_SQL}\n\n返回 6 行。\n结果：\n"
        + truncated_result
    )
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _MERGE_WINDOW_SQL,
        },
        result={
            "structuredContent": {
                "response": {"result": wrapped_window_result},
            }
        },
    )


def _truncated_window_positional_fixture() -> ReplayCallFixture:
    """Mirror of run 2c18cb74: Archery's JSON puts ``rows`` before
    ``column_list``, so a mid-rows truncation recovers positional rows whose
    column names are lost with the tail of the payload.
    """
    recovered = json.dumps(
        [
            list({**_MERGE_RECOVERED_ROW, "id": row_id}.values())
            for row_id in (24413648, 24413647, 24413646, 24413645)
        ]
    )
    truncated_result = (
        '{"full_sql": '
        + json.dumps(_MERGE_WINDOW_SQL, ensure_ascii=False)
        + ', "rows": '
        + recovered[:-1]
        + ',\n      [24413644, "db-1.example:3306", "d'
    )
    wrapped_window_result = (
        f"SQL 查询已执行。\n执行的SQL：{_MERGE_WINDOW_SQL}\n\n返回 6 行。\n结果：\n"
        + truncated_result
    )
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _MERGE_WINDOW_SQL,
        },
        result={
            "structuredContent": {
                "response": {"result": wrapped_window_result},
            }
        },
    )


@pytest.mark.asyncio
async def test_truncated_window_merges_per_id_retrieval_rows_into_final_result() -> None:
    """Replay of run 2970f801: truncation -> id listing -> per-id retrieval.

    Before this fix every history SELECT overwrote state.final_result, so the
    evidence reaching the main Agent held only the last single-id row (1 of 6).
    """
    row_60 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413460,
        "checksum": "b" * 32,
        "ts_cnt": 40,
        "Query_time_sum": 12.5,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-merge",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _merge_truncated_window_fixture(),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413458}, {"id": 24413454}],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == _MERGE_WINDOW_SQL
    assert result.executed_sql == _MERGE_WINDOW_SQL
    payload = result.payload
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 2
    assert payload["merged_full_sqls"] == [_MERGE_ID_SQL_60, _MERGE_ID_SQL_54]
    assert "rows_recovered_from_truncated_json" not in payload
    assert [row["id"] for row in payload["rows"]] == [
        24413458,
        24413460,
        24413454,
    ]
    assert payload["rows"][0] == _MERGE_RECOVERED_ROW
    assert payload["rows"][1] == row_60
    assert payload["rows"][2] == row_54


@pytest.mark.asyncio
async def test_truncated_history_blocks_supplemental_calls_before_transport() -> None:
    explain_sql = f"EXPLAIN {_MERGE_RECOVERED_ROW['sample']}"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _named_call("early-allowlist", ARCHERY_MCP_INSTANCES_TOOL_NAME, {}),
            _target_call(
                "early-explain",
                explain_sql,
                instance_id=3,
                db_name="dpm",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-blocks-supplemental",
                tools=_analysis_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _merge_truncated_window_fixture(),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.payload["rows_recovered_from_truncated_json"] is True
    assert result.payload["history_recovery_id_listing_complete"] is False
    assert result.slow_query_analysis is not None
    reason_codes = [
        failure["reason_code"]
        for failure in result.slow_query_analysis["failures"]
    ]
    assert reason_codes.count("history_recovery_pending") == 2
    assert "history_recovery_incomplete" in reason_codes


@pytest.mark.asyncio
async def test_incomplete_per_id_recovery_keeps_merged_history_partial() -> None:
    row_60 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413460,
        "checksum": "b" * 32,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-incomplete-per-id-recovery",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _merge_truncated_window_fixture(),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[
                            {"id": 24413460},
                            {"id": 24413458},
                            {"id": 24413454},
                        ],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows_merged_from_per_id_queries"] is True
    assert result.payload["rows_recovered_from_truncated_json"] is True
    assert result.payload["history_recovery_complete"] is False
    assert result.payload["history_recovery_missing_ids"] == [24413454]
    assert [row["id"] for row in result.payload["rows"]] == [24413458, 24413460]
    assert result.diagnostics is not None
    assert result.diagnostics["history_recovery_complete"] is False
    assert result.diagnostics["history_recovery_missing_ids"] == [24413454]
    assert result.slow_query_analysis is not None
    assert any(
        failure["reason_code"] == "history_recovery_incomplete"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.asyncio
async def test_id_listing_after_truncation_never_becomes_final_result() -> None:
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-id-listing-only",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _merge_truncated_window_fixture(),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413458}, {"id": 24413454}],
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
    assert result.requested_sql == _MERGE_WINDOW_SQL
    assert result.payload["rows_recovered_from_truncated_json"] is True
    assert result.payload["rows"] == [_MERGE_RECOVERED_ROW]
    assert "rows_merged_from_per_id_queries" not in result.payload


@pytest.mark.asyncio
async def test_per_id_retrieval_without_window_query_still_merges() -> None:
    """Replay of the 2026-08-17 alert run: the model jumped straight from the
    id listing to per-id retrievals without any full-column window query, so
    state.final_result stayed empty and the main Agent saw "no passthrough
    result" although every per-id row had been recovered.
    """
    row_60 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413460,
        "checksum": "b" * 32,
        "ts_cnt": 40,
        "Query_time_sum": 12.5,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-per-id-without-window",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413460}, {"id": 24413454}],
                    ),
                    _success(_MERGE_ID_SQL_60, rows=[row_60]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == _MERGE_ID_SQL_60
    payload = result.payload
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 2
    assert payload["merged_full_sqls"] == [_MERGE_ID_SQL_60, _MERGE_ID_SQL_54]
    assert "rows_recovered_from_truncated_json" not in payload
    assert [row["id"] for row in payload["rows"]] == [24413460, 24413454]
    assert payload["rows"][0] == row_60
    assert payload["rows"][1] == row_54
    assert result.diagnostics["final_result_source"] == (
        "merged_per_id_queries_without_window_query"
    )


_TRUNCATED_ID_SQL_40 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413640"
)


def _truncated_id_retrieval_fixture(
    sql: str,
    *,
    max_result_chars: int | None = None,
) -> ReplayCallFixture:
    truncated_result = (
        '{"rows":[{"id":24413640,"hostname_max":"db-1.example:3306",'
        '"sample":"SELECT count(0) FROM t_device WHERE store_code IN ('
    )
    wrapped = (
        f"SQL 查询已执行。\n执行的SQL：{sql}\n\n返回 1 行。\n结果：\n"
        + truncated_result
    )
    expected = {**TARGET_ARGUMENTS, "sql_content": sql}
    if max_result_chars is not None:
        expected["max_result_chars"] = max_result_chars
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments=expected,
        result={
            "structuredContent": {
                "response": {"result": wrapped},
            }
        },
    )


@pytest.mark.asyncio
async def test_truncated_id_retrieval_gets_one_time_retry_hint() -> None:
    """Replay of run 92c9a017 (attempt=15): id=24413640's single-row retrieval
    was MCP-truncated with zero recoverable rows and the model silently moved
    on. The program now appends a one-time retry hint to the model-visible
    tool message, and never repeats the hint for the same SQL after the
    retry, so a hopeless SQL cannot loop until the budget expires.
    """
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    retry_call = MCPModelToolCall(
        call_id="id-40-retry",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40-retry",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-40", _TRUNCATED_ID_SQL_40),
            retry_call,
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-id-hint",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413640}, {"id": 24413454}],
                    ),
                    _truncated_id_retrieval_fixture(_TRUNCATED_ID_SQL_40),
                    _truncated_id_retrieval_fixture(
                        _TRUNCATED_ID_SQL_40,
                        max_result_chars=24000,
                    ),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    hint_request = model.requests[4]["messages"]
    hinted = [
        message
        for message in hint_request
        if message.get("role") == "tool"
        and "程序截断检测" in str(message.get("content"))
        and "max_result_chars=24000" in str(message.get("content"))
    ]
    assert hinted, "retry hint missing from the model-visible tool message"

    # After the retry (still truncated) the first-level hint must not repeat,
    # and the one-time field-level projection hint appears exactly once.
    after_retry = model.requests[5]["messages"]
    first_level_after_retry = [
        message
        for message in after_retry
        if message.get("role") == "tool"
        and "【程序截断检测】" in str(message.get("content"))
    ]
    field_level_after_retry = [
        message
        for message in after_retry
        if message.get("role") == "tool"
        and "字段级" in str(message.get("content"))
    ]
    assert len(first_level_after_retry) == 1
    assert len(field_level_after_retry) == 1

    assert result.query_completed is True
    assert [row["id"] for row in result.payload["rows"]] == [24413454]
    assert result.payload["merged_query_count"] == 3


_PROJECTION_SAMPLE_PREFIX = (
    "SELECT count(0) FROM t_device WHERE store_code IN "
    "('1000042256', '1000042257')"
)
_PROJECTION_ID_SQL_40 = ArcheryMCPClient.history_sample_projection_sql(24413640)


@pytest.mark.asyncio
async def test_truncated_id_retrieval_retry_then_projection_hint_recovers_row() -> None:
    """Replay of run be8080ac (attempt=16): the retry hint worked (the model
    retried with max_result_chars=24000) but the row was still truncated
    because its sample column alone is 321,237 bytes. The second-level hint
    now directs the model to a column-projection query that clips sample via
    LEFT(sample, 4000) and records the full length via
    LENGTH(sample) AS sample_full_length, so the recovered row (prefix +
    full length) reaches the main Agent as evidence.
    """
    row_40 = {
        "id": 24413640,
        "hostname_max": "db-1.example:3306",
        "sample": _PROJECTION_SAMPLE_PREFIX,
        "sample_full_length": 321237,
        "ts_cnt": 1,
        "Query_time_max": 0.806,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    retry_call = MCPModelToolCall(
        call_id="id-40-retry",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40-retry",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-40", _TRUNCATED_ID_SQL_40),
            retry_call,
            _call("id-40-projection", _PROJECTION_ID_SQL_40),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-id-projection",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413640}, {"id": 24413454}],
                    ),
                    _truncated_id_retrieval_fixture(_TRUNCATED_ID_SQL_40),
                    _truncated_id_retrieval_fixture(
                        _TRUNCATED_ID_SQL_40,
                        max_result_chars=24000,
                    ),
                    _success(_PROJECTION_ID_SQL_40, rows=[row_40]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    # First truncation still gets the retry hint.
    first_hint_request = model.requests[4]["messages"]
    assert any(
        "max_result_chars=24000" in str(message.get("content"))
        for message in first_hint_request
        if message.get("role") == "tool"
    )

    # The still-truncated retry gets the one-time projection hint with the
    # LEFT/LENGTH recipe including the concrete row id.
    projection_hint_request = model.requests[5]["messages"]
    projection_hinted = [
        message
        for message in projection_hint_request
        if message.get("role") == "tool"
        and "字段级" in str(message.get("content"))
        and "LEFT(sample, '4000') AS sample" in str(message.get("content"))
        and "LENGTH(sample) AS sample_full_length" in str(message.get("content"))
        and "WHERE id = 24413640" in str(message.get("content"))
    ]
    assert projection_hinted, "projection hint missing from the tool message"

    # After the successful projection query the hint is not repeated.
    after_projection = model.requests[6]["messages"]
    field_level_hints = [
        message
        for message in after_projection
        if message.get("role") == "tool"
        and "字段级" in str(message.get("content"))
    ]
    assert len(field_level_hints) == 1, "projection hint must not repeat"

    # The recovered row carries both the clipped prefix and the full length.
    assert result.query_completed is True
    payload_rows = result.payload["rows"]
    assert [row["id"] for row in payload_rows] == [24413640, 24413454]
    assert payload_rows[0]["sample"] == _PROJECTION_SAMPLE_PREFIX
    assert payload_rows[0]["sample_full_length"] == 321237
    assert result.payload["merged_query_count"] == 4


@pytest.mark.asyncio
async def test_history_followup_collects_dml_explain_structure_and_indexes() -> None:
    sample = "UPDATE orders SET status = 'done' WHERE id = 1"
    history_rows = [
        {
            "id": 101,
            "checksum": "update-orders",
            "sample": sample,
            "Query_time_max": 12.5,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-history-analysis",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": columns_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [
                                    {"COLUMN_NAME": "id", "COLUMN_TYPE": "bigint"},
                                    {"COLUMN_NAME": "status", "COLUMN_TYPE": "varchar(20)"},
                                ],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": explain_sql,
                                "rows": [{"table": "orders", "type": "range", "key": "PRIMARY"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": indexes_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": indexes_sql,
                                "rows": [{"INDEX_NAME": "PRIMARY", "COLUMN_NAME": "id"}],
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

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "succeeded"
    assert analysis["source_history_row"]["id"] == 101
    assert analysis["source_history_row"]["sample"] == sample
    assert analysis["target"]["instance_id"] == 3
    assert analysis["target"]["db_name"] == "orders_prod"
    assert analysis["explain_results"][0]["statement_type"] == "update"
    assert analysis["explain_results"][0]["result"]["rows"][0]["key"] == "PRIMARY"
    assert analysis["table_structure_results"][0]["result"]["row_count"] == 2
    assert analysis["index_results"][0]["result"]["row_count"] == 1
    assert analysis["missing_stages"] == []
    assert analysis["failures"] == []


@pytest.mark.asyncio
async def test_list_table_columns_can_supply_bound_structure_before_explain() -> None:
    sample = "SELECT * FROM orders WHERE customer_id = 1"
    explain_sql = f"EXPLAIN {sample}"
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 1011,
            "checksum": "list-columns-orders",
            "sample": sample,
            "Query_time_max": 12.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    column_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "tb_name": "orders",
    }
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _named_call("columns", ARCHERY_MCP_COLUMNS_TOOL_NAME, column_arguments),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-list-columns-analysis",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_COLUMNS_TOOL_NAME,
                        expected_arguments=column_arguments,
                        result={
                            "structuredContent": {
                                "status": "success",
                                "rows": [{"name": "id"}, {"name": "customer_id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": explain_sql,
                                "rows": [{"table": "orders", "key": "idx_customer"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": indexes_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": indexes_sql,
                                "rows": [
                                    {
                                        "INDEX_NAME": "idx_customer",
                                        "COLUMN_NAME": "customer_id",
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

    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "succeeded"
    assert analysis["table_structure_results"][0]["source"] == "list_table_columns"
    assert analysis["table_structure_results"][0]["result"]["columns"] == [
        "customer_id",
        "id",
    ]


@pytest.mark.parametrize(
    ("unsafe_sql", "arguments", "reason_code"),
    [
        (
            "SELECT 1; DELETE FROM orders",
            TARGET_ARGUMENTS,
            "multi_statement_forbidden",
        ),
        ("DELETE FROM orders", TARGET_ARGUMENTS, "direct_statement_forbidden"),
        (
            "WITH selected AS (SELECT id FROM orders) DELETE FROM orders",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        ("EXPLAIN DELETE FROM orders", TARGET_ARGUMENTS, "unbound_explain_forbidden"),
        (
            "EXPLAIN ANALYZE DELETE FROM orders",
            TARGET_ARGUMENTS,
            "explain_analyze_forbidden",
        ),
        ("SELECT SLEEP(1) FROM sql_instance", TARGET_ARGUMENTS, "direct_statement_forbidden"),
        (
            "SELECT * FROM sql_instance FOR UPDATE",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        ("SELECT @row_id := id FROM sql_instance", TARGET_ARGUMENTS, "direct_statement_forbidden"),
        (
            "SELECT f_instance_id FROM t_instance_member LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT f_instance_id FROM t_instance_member "
            "WHERE f_ip = 'db-1.example' OR f_port = 3306 LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT f_instance_id FROM t_instance_member "
            "WHERE f_ip = 'attacker.example' AND f_port = 9999 "
            "AND 'db-1.example' = 'db-1.example' AND 3306 = 3306 LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT f_id AS f_instance_id FROM t_instance_member "
            "WHERE f_ip = 'db-1.example' AND f_port = 3306 LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT host, port FROM sql_instance LIMIT 1",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = 'archery'",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT id FROM sql_instance WHERE id = custom_lookup(53)",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT s.id FROM sql_instance s "
            "JOIN t_instance_member m ON m.f_instance_id = s.id",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT id FROM sql_instance UNION "
            "SELECT f_instance_id FROM t_instance_member",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT id FROM sql_instance WHERE id IN "
            "(SELECT f_instance_id FROM t_instance_member)",
            TARGET_ARGUMENTS,
            "direct_statement_forbidden",
        ),
        (
            "SELECT * FROM {OJ sql_instance LEFT JOIN t_instance_member ON 1 = 1}",
            TARGET_ARGUMENTS,
            "multi_statement_forbidden",
        ),
        (
            r"SELECT id FROM sql_instance WHERE note = 'prefix\' OR id = 53'",
            TARGET_ARGUMENTS,
            "multi_statement_forbidden",
        ),
        (
            "SELECT h.* FROM mysql_slow_query_review_history h "
            "JOIN sql_instance s ON s.id = h.id",
            TARGET_ARGUMENTS,
            "history_recovery_query_forbidden",
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history "
            "UNION SELECT * FROM sql_instance",
            TARGET_ARGUMENTS,
            "history_recovery_query_forbidden",
        ),
        (
            "WITH history_rows AS ("
            "SELECT * FROM mysql_slow_query_review_history"
            ") SELECT * FROM history_rows JOIN sql_instance ON 1 = 1",
            TARGET_ARGUMENTS,
            "history_recovery_query_forbidden",
        ),
        (
            "SELECT * FROM orders",
            {"instance_id": 3, "db_name": "orders_prod", "limit_num": 20},
            "direct_statement_forbidden",
        ),
    ],
)
@pytest.mark.asyncio
async def test_unsafe_pre_history_sql_is_rejected_before_mcp(
    unsafe_sql: str,
    arguments: dict[str, Any],
    reason_code: str,
) -> None:
    unsafe_call = MCPModelToolCall(
        call_id="unsafe-pre-history",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**arguments, "sql_content": unsafe_sql},
        request_id="request-unsafe-pre-history",
    )
    model = _ScriptedModel([unsafe_call, *_lineage_actions()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-unsafe-pre-history",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.diagnostics is not None
    assert result.diagnostics["model_attempted_tool_calls"] == [
        ARCHERY_MCP_QUERY_TOOL_NAME
    ] * 4
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert any(
        entry.get("reason_code") == reason_code
        and entry.get("sent_to_mcp") is False
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.parametrize(
    "unsafe_lookup",
    [
        "SELECT host, port FROM sql_instance WHERE id = 53 + 946 LIMIT 1",
        "SELECT id AS host, id AS port FROM sql_instance WHERE id = 53 LIMIT 1",
    ],
)
@pytest.mark.asyncio
async def test_sql_instance_lookup_requires_exact_returned_member_id_predicate(
    unsafe_lookup: str,
) -> None:
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("unsafe-instance", unsafe_lookup),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-arithmetic-instance-id",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 3
    assert any(
        entry.get("reason_code") == "direct_statement_forbidden"
        and entry.get("sent_to_mcp") is False
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.parametrize(
    ("unsafe_lookup", "columns", "member_ids"),
    [
        (
            "SELECT f_instance_id FROM t_instance_member "
            "WHERE attacker_host = 'db-1.example' AND attacker_port = 3306 LIMIT 1",
            {
                "attacker_host",
                "attacker_port",
                "f_instance_id",
                "f_ip",
                "f_port",
            },
            set(),
        ),
        (
            "SELECT backup_host, backup_port FROM sql_instance "
            "WHERE id = 53 LIMIT 1",
            {"backup_host", "backup_port", "host", "id", "port"},
            {53},
        ),
    ],
)
def test_discovered_lookalike_endpoint_columns_are_rejected_before_transport(
    unsafe_lookup: str,
    columns: set[str],
    member_ids: set[int],
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    target = (17, "archery")
    table_name = (
        "t_instance_member" if "t_instance_member" in unsafe_lookup else "sql_instance"
    )
    state.table_columns = {target: {table_name: columns}}
    if member_ids:
        state.member_instance_ids = {target: member_ids}

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Reject lookalike endpoint columns",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": unsafe_lookup},
        ),
        state=state,
    )

    assert prepared.local_result is not None
    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "direct_statement_forbidden"
    )


@pytest.mark.asyncio
async def test_explain_analyze_is_rejected_before_mcp_and_history_is_preserved() -> None:
    sample = "DELETE FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 102,
            "checksum": "delete-orders",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    unsafe_sql = f"EXPLAIN ANALYZE {sample}"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("unsafe", unsafe_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-explain-analyze",
                tools=_tools(),
                # There is deliberately no fixture for the rejected call.
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "failed"
    assert analysis["failures"][0]["reason_code"] == "explain_analyze_forbidden"
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )


@pytest.mark.parametrize(
    "sample",
    [
        "SELECT * FROM {OJ orders LEFT JOIN customers ON orders.customer_id = customers.id}",
        r"SELECT * FROM orders WHERE note = 'prefix\' OR admin = 1'",
    ],
)
@pytest.mark.asyncio
async def test_lexically_ambiguous_explain_is_rejected_before_transport(
    sample: str,
) -> None:
    history_rows = [
        {
            "id": 110,
            "checksum": "ambiguous-explain",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 109,
            "checksum": "valid-control-for-ambiguous",
            "sample": "SELECT * FROM safe_orders",
            "Query_time_max": 1.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    explain_sql = f"EXPLAIN {sample}"
    model = _ScriptedModel(
        [
            *_lineage_actions()[:-1],
            _target_call(
                "ambiguous-explain",
                explain_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-ambiguous-explain",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.payload["rows"] == history_rows
    assert len(model.requests) == 5
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure.get("reason_code") == "multi_statement_forbidden"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.parametrize(
    "length_marker",
    [None, 0, -1, "invalid", 44, 46],
)
@pytest.mark.asyncio
async def test_invalid_sample_full_length_cannot_authorize_explain_transport(
    length_marker: Any,
) -> None:
    sample = "SELECT * FROM orders WHERE note = '慢查询'"
    assert len(sample.encode("utf-8")) == 45
    history_rows = [
        {
            "id": 111,
            "checksum": "invalid-sample-length",
            "sample": sample,
            "sample_full_length": length_marker,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 109,
            "checksum": "valid-control-for-length",
            "sample": "SELECT * FROM safe_orders",
            "Query_time_max": 1.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    explain_sql = f"EXPLAIN {sample}"
    model = _ScriptedModel(
        [
            *_lineage_actions()[:-1],
            _target_call(
                "invalid-length-explain",
                explain_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-invalid-sample-length",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.payload["rows"] == history_rows
    assert len(model.requests) == 5
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure.get("reason_code") == "explain_sample_not_in_history"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.asyncio
async def test_post_history_information_schema_union_udf_is_rejected_before_transport() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 112,
            "checksum": "orders-metadata-guard",
            "sample": sample,
            "Query_time_max": 9.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    unsafe_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "UNION SELECT mutate_state() FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    model = _ScriptedModel(
        [
            *_lineage_actions()[:-1],
            _target_call(
                "unsafe-information-schema",
                unsafe_sql,
                instance_id=3,
                db_name="orders_prod",
            ),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-information-schema-union-udf",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert len(model.requests) == 5
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure.get("reason_code") == "direct_statement_forbidden"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.asyncio
async def test_direct_dml_sample_is_rejected_before_mcp_and_history_is_preserved() -> None:
    sample = "INSERT INTO order_archive SELECT * FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 103,
            "checksum": "insert-archive",
            "sample": sample,
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("unsafe-dml", sample, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-direct-dml",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "failed"
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "sample_execution_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_direct_select_sample_formatting_variant_is_rejected_before_mcp() -> None:
    sample = "SELECT * FROM orders WHERE id=1 AND note = 'A  B'"
    direct_sql = " select * from orders where id = 1 and note='A  B'; "
    history_rows = [
        {
            "id": 1031,
            "checksum": "select-orders",
            "sample": sample,
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("direct-select", direct_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-direct-select",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["explain_results"] == []
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "sample_execution_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_arbitrary_post_history_business_select_is_rejected_before_mcp() -> None:
    history_rows = [
        {
            "id": 1032,
            "checksum": "select-orders",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    arbitrary_sql = "SELECT * FROM customers WHERE id = 1"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _target_call("arbitrary", arbitrary_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-arbitrary-select",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "direct_statement_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_multi_id_history_recovery_is_rejected_before_mcp() -> None:
    history_rows = [
        {
            "id": 1033,
            "checksum": "history-in",
            "sample": "SELECT 1",
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    in_sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
        "WHERE id IN (1033, 1034)"
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _call("multi-id", in_sql),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-multi-id",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "history_recovery_query_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_unscoped_history_id_listing_is_rejected_before_mcp() -> None:
    history_rows = [
        {
            "id": 10331,
            "checksum": "history-unscoped-ids",
            "sample": "SELECT 1",
            "Query_time_max": 8.0,
            "hostname_max": "db-1.example:3306",
            "db_max": "orders_prod",
        }
    ]
    unscoped_sql = f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _call("unscoped-ids", unscoped_sql),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-unscoped-ids",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "history_recovery_query_forbidden"
    )


@pytest.mark.parametrize(
    "unsafe_sql",
    [
        (
            f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} h "
            f"JOIN {ARCHERY_SLOW_QUERY_REVIEW_TABLE} h2 ON h2.id = h.id "
            "WHERE h.hostname_max = 'db-1.example:3306' "
            "AND h.ts_min >= FROM_UNIXTIME(1784793300) "
            "AND h.ts_min < FROM_UNIXTIME(1784793600)"
        ),
        (
            f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} h, "
            f"{ARCHERY_SLOW_QUERY_REVIEW_TABLE} h2 "
            "WHERE h.hostname_max = 'db-1.example:3306' "
            "AND h.ts_min >= FROM_UNIXTIME(1784793300) "
            "AND h.ts_min < FROM_UNIXTIME(1784793600)"
        ),
        (
            f"WITH history_rows AS (SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}) "
            "SELECT * FROM history_rows "
            "WHERE hostname_max = 'db-1.example:3306' "
            "AND ts_min >= FROM_UNIXTIME(1784793300) "
            "AND ts_min < FROM_UNIXTIME(1784793600)"
        ),
        (
            f"SELECT * FROM (SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}) h "
            "WHERE hostname_max = 'db-1.example:3306' "
            "AND ts_min >= FROM_UNIXTIME(1784793300) "
            "AND ts_min < FROM_UNIXTIME(1784793600)"
        ),
        FINAL_SQL.replace("SELECT *", "SELECT id, sample"),
    ],
)
@pytest.mark.asyncio
async def test_complex_or_partial_history_window_is_rejected_before_mcp(
    unsafe_sql: str,
) -> None:
    model = _ScriptedModel([_call("unsafe-history-shape", unsafe_sql), *_lineage_actions()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-history-source-shape",
                tools=_tools(),
                calls=_lineage_replay_calls(),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.diagnostics is not None
    assert any(
        entry.get("reason_code") == "history_recovery_query_forbidden"
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.parametrize(
    "wrong_target",
    [
        {"instance_id": 3, "db_name": "archery", "limit_num": 20},
        {"instance_id": 17, "db_name": "orders_prod", "limit_num": 20},
    ],
)
@pytest.mark.asyncio
async def test_history_recovery_wrong_target_is_rejected_before_mcp(
    wrong_target: dict[str, Any],
) -> None:
    history_rows = [
        {
            "id": 24413454,
            "hostname_max": "db-1.example:3306",
            "sample": "SELECT * FROM orders",
        }
    ]
    wrong_target_call = MCPModelToolCall(
        call_id="wrong-history-target",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**wrong_target, "sql_content": _MERGE_IDS_SQL},
        request_id="request-wrong-history-target",
    )
    model = _ScriptedModel(
        [*_lineage_actions()[:-1], wrong_target_call, _finish()]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-wrong-history-target",
                tools=_tools(),
                calls=_lineage_replay_calls(rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.slow_query_analysis is not None
    assert any(
        failure["reason_code"] == "history_recovery_query_forbidden"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.parametrize(
    "wrong_target",
    [
        {"instance_id": 3, "db_name": "archery", "limit_num": 20},
        {"instance_id": 17, "db_name": "orders_prod", "limit_num": 20},
    ],
)
@pytest.mark.asyncio
async def test_initial_history_wrong_target_is_rejected_before_mcp(
    wrong_target: dict[str, Any],
) -> None:
    history_call = MCPModelToolCall(
        call_id="wrong-initial-history-target",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**wrong_target, "sql_content": FINAL_SQL},
        request_id="request-wrong-initial-history-target",
    )
    model = _ScriptedModel(
        [_call("member", MEMBER_SQL), _call("instance", INSTANCE_SQL), history_call, _finish()]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-wrong-initial-history-target",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 2
    assert result.slow_query_analysis is None
    assert result.diagnostics is not None
    assert any(
        entry.get("reason_code") == "history_target_mismatch"
        for entry in result.diagnostics["query_trace"]
    )


@pytest.mark.asyncio
async def test_unknown_non_sql_tool_is_rejected_after_history() -> None:
    history_rows = [
        {
            "id": 1034,
            "checksum": "unknown-tool",
            "sample": "SELECT 1",
            "Query_time_max": 8.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    tool_name = "run_custom_probe_gymJPA"
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _named_call("custom-probe", tool_name, {"target": "orders"}),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-reject-custom-tool",
                tools=[
                    *_tools(),
                    DiscoveredMCPTool(
                        name=tool_name,
                        input_schema={"type": "object", "additionalProperties": True},
                    ),
                ],
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "followup_tool_forbidden"
    )
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3


@pytest.mark.asyncio
async def test_dml_plain_explain_target_syntax_failure_does_not_replace_history() -> None:
    sample = "DELETE FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 104,
            "checksum": "delete-orders-unsupported",
            "sample": sample,
            "Query_time_max": 7.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-explain-not-supported",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            "instance_id": 3,
                            "db_name": "orders_prod",
                            "limit_num": 20,
                            "sql_content": columns_sql,
                        },
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [{"COLUMN_NAME": "id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={
                            "instance_id": 3,
                            "db_name": "orders_prod",
                            "limit_num": 20,
                            "sql_content": explain_sql,
                        },
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": (
                                    "You have an error in your SQL syntax; target does not support "
                                    "EXPLAIN DELETE"
                                ),
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
    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "partial"
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "explain_not_supported_by_target"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("instance_id", "db_name", "reason_code"),
    [
        (4, "orders_prod", "instance_target_mismatch"),
        (3, "other_prod", "database_target_mismatch"),
        (3, "ORDERS_PROD", "database_target_mismatch"),
    ],
)
async def test_supplemental_metadata_requires_bound_instance_and_database(
    instance_id: int,
    db_name: str,
    reason_code: str,
) -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    history_rows = [
        {
            "id": 1041,
            "checksum": "target-orders",
            "sample": sample,
            "Query_time_max": 7.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("wrong-target", columns_sql, instance_id=instance_id, db_name=db_name),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id=f"archery-target-mismatch-{reason_code}",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["table_structure_results"] == []
    assert result.slow_query_analysis["failures"][0]["reason_code"] == reason_code


@pytest.mark.asyncio
async def test_plain_explain_requires_prior_structure_result_or_failure() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    history_rows = [
        {
            "id": 1045,
            "checksum": "structure-first",
            "sample": sample,
            "Query_time_max": 7.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("early-explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-structure-first",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "table_structure_required"
    )


@pytest.mark.asyncio
async def test_supplemental_actual_sql_mismatch_is_not_projected_as_explain() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    actual_sql = "EXPLAIN SELECT * FROM unrelated WHERE id = 1"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 1042,
            "checksum": "actual-sql-orders",
            "sample": sample,
            "Query_time_max": 7.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-actual-explain-mismatch",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": columns_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [{"COLUMN_NAME": "id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": actual_sql,
                                "rows": [{"table": "unrelated", "type": "ALL"}],
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

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["explain_results"] == []
    assert any(
        failure["reason_code"] == "actual_sql_mismatch"
        for failure in result.slow_query_analysis["failures"]
    )


@pytest.mark.parametrize(
    ("result", "reason_code"),
    [
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": INSTANCE_SQL,
                    "rows": [{"f_instance_id": 53}],
                }
            },
            "actual_sql_mismatch",
        ),
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": MEMBER_SQL,
                    "instance_id": 99,
                    "db_name": "archery",
                    "rows": [{"f_instance_id": 53}],
                }
            },
            "actual_target_mismatch",
        ),
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": MEMBER_SQL,
                    "instance_id": 17,
                    "db_name": "Archery",
                    "rows": [{"f_instance_id": 53}],
                }
            },
            "actual_target_mismatch",
        ),
        (
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": MEMBER_SQL,
                    "instance_id": 17,
                    "db_name": "archery",
                    "rows": [{"f_instance_id": 53}],
                },
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "full_sql": MEMBER_SQL,
                                "instance_id": 99,
                                "db_name": "archery",
                            }
                        ),
                    }
                ],
            },
            "actual_target_mismatch",
        ),
    ],
)
def test_pre_history_response_mismatch_does_not_authorize_metadata_lineage(
    result: dict[str, Any],
    reason_code: str,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Resolve the alert instance",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
        ),
        state=state,
    )

    scenario.on_result(state, prepared, result)

    assert state.member_instance_ids == {}
    assert state.resolved_endpoints == {}
    assert state.history_result_target is None
    assert state.slow_query_analysis_failures == []
    assert state.query_trace[-1]["outcome"] == "result_mismatch"
    assert state.query_trace[-1]["reason_code"] == reason_code


def test_explicit_actual_target_mismatch_is_not_collected() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1043,
                    "checksum": "actual-target-orders",
                    "sample": sample,
                    "Query_time_max": 7.0,
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Collect bound columns",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": columns_sql,
            },
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": columns_sql,
                "instance_id": 99,
                "db_name": "orders_prod",
                "rows": [{"COLUMN_NAME": "id"}],
            }
        },
    )

    assert state.slow_query_table_structure_results == []
    assert state.slow_query_analysis_failures[0]["reason_code"] == (
        "actual_target_mismatch"
    )


@pytest.mark.parametrize(
    ("metadata_table", "result_row", "result_attribute", "mismatched_field"),
    [
        (
            "COLUMNS",
            {
                "TABLE_SCHEMA": "other_prod",
                "TABLE_NAME": "orders",
                "COLUMN_NAME": "id",
            },
            "slow_query_table_structure_results",
            "db_name",
        ),
        (
            "STATISTICS",
            {
                "TABLE_SCHEMA": "orders_prod",
                "TABLE_NAME": "Orders",
                "INDEX_NAME": "PRIMARY",
            },
            "slow_query_index_results",
            "table_name",
        ),
    ],
)
def test_information_schema_row_target_mismatch_is_not_collected(
    metadata_table: str,
    result_row: dict[str, Any],
    result_attribute: str,
    mismatched_field: str,
) -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    selected_columns = (
        "TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME"
        if metadata_table == "COLUMNS"
        else "TABLE_SCHEMA, TABLE_NAME, INDEX_NAME"
    )
    metadata_sql = (
        f"SELECT {selected_columns} FROM information_schema.{metadata_table} "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1044,
                    "checksum": "row-target-orders",
                    "sample": sample,
                    "Query_time_max": 7.0,
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Collect bound metadata",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": metadata_sql,
            },
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": metadata_sql,
                "rows": [result_row],
            }
        },
    )

    assert getattr(state, result_attribute) == []
    failure = state.slow_query_analysis_failures[0]
    assert failure["reason_code"] == "actual_target_mismatch"
    assert mismatched_field in failure["detail"]


def test_incomplete_supplemental_results_are_recorded_only_as_evidence_gaps() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    columns_sql = (
        "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME "
        "FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    explain_sql = f"EXPLAIN {sample}"
    indexes_sql = (
        "SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME "
        "FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1045,
                "checksum": "incomplete-supplemental-orders",
                "sample": sample,
                "Query_time_max": 7.0,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    calls = (
        (
            columns_sql,
            {
                "TABLE_SCHEMA": "orders_prod",
                "TABLE_NAME": "orders",
                "COLUMN_NAME": "id",
            },
        ),
        (explain_sql, {"id": 1, "table": "orders", "type": "const"}),
        (
            indexes_sql,
            {
                "TABLE_SCHEMA": "orders_prod",
                "TABLE_NAME": "orders",
                "INDEX_NAME": "PRIMARY",
            },
        ),
    )

    for sql, row in calls:
        prepared = scenario.prepare_call(
            SimpleNamespace(
                tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                objective="Collect bound supplemental evidence",
                hypothesis_ids=(),
                arguments={
                    "instance_id": 3,
                    "db_name": "orders_prod",
                    "sql_content": sql,
                },
            ),
            state=state,
        )
        assert "local_rejection" not in prepared.metadata
        scenario.on_result(
            state,
            prepared,
            {
                "structuredContent": {
                    "status": "success",
                    "full_sql": sql,
                    "mcp_reported_row_count": 2,
                    "rows": [row],
                }
            },
        )

    assert state.slow_query_table_structure_results == []
    assert state.slow_query_explain_results == []
    assert state.slow_query_index_results == []
    incomplete_failures = [
        failure
        for failure in state.slow_query_analysis_failures
        if failure["reason_code"] == "supplemental_result_incomplete"
    ]
    assert [failure["stage"] for failure in incomplete_failures] == [
        "table_structure",
        "explain",
        "indexes",
    ]
    assert all(failure["error_type"] == "incomplete_result" for failure in incomplete_failures)


def test_database_discovery_actual_instance_mismatch_does_not_authorize_database() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={
            "rows": [
                {
                    "id": 1046,
                    "checksum": "database-target",
                    "sample": "SELECT * FROM orders",
                    "Query_time_max": 7.0,
                    "hostname_max": "orders-db.example:3306",
                    "db_max": "orders_prod",
                }
            ]
        },
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            objective="Discover bound databases",
            hypothesis_ids=(),
            arguments={"instance_id": 3},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "instance_id": 99,
                "rows": [{"name": "orders_prod"}],
            }
        },
    )

    assert state.analysis_database_names == {}
    assert state.slow_query_analysis_failures[0]["reason_code"] == (
        "actual_target_mismatch"
    )


@pytest.mark.parametrize(
    ("sql", "authorized_ids"),
    [
        (
            "SELECT SLEEP(10), * FROM mysql_slow_query_review_history "
            "WHERE id = 24413454",
            {24413454},
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 999",
            {24413454},
        ),
        (
            "SELECT * FROM mysql_slow_query_review_history WHERE id = 24413454",
            set(),
        ),
    ],
)
def test_id_listing_context_rejects_unsafe_or_unauthorized_per_id_queries(
    sql: str,
    authorized_ids: set[int],
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_ids = authorized_ids

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one listed history row",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "history_recovery_query_forbidden"
    )


def test_malformed_nonempty_id_listing_does_not_complete_recovery() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.window_start, state.window_end = archery_harness_module.client_window(
        scenario.client,
        OCCURRED_AT,
    )
    state.resolved_endpoints = {(17, "archery"): {"db-1.example:3306"}}
    listing = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="List history ids",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": _MERGE_IDS_SQL},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        listing,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": _MERGE_IDS_SQL,
                "rows": [{"id": "not-an-integer"}],
            }
        },
    )
    followup = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Discover supplemental target",
            hypothesis_ids=(),
            arguments={},
        ),
        state=state,
    )

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert state.history_recovery_ids == set()
    assert followup.metadata["local_rejection"]["reason_code"] == (
        "history_recovery_pending"
    )


def test_pending_recovery_diagnostic_distinguishes_unlisted_rows() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {24413458}
    state.history_id_rows = {
        24413458: dict(_MERGE_RECOVERED_ROW),
        24413454: {**_MERGE_RECOVERED_ROW, "id": 24413454},
    }
    state.history_full_row_ids = {24413458, 24413454}

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            objective="Discover supplemental target",
            hypothesis_ids=(),
            arguments={},
        ),
        state=state,
    )

    rejection = prepared.metadata["local_rejection"]
    assert rejection["reason_code"] == "history_recovery_pending"
    assert "未出现在完整 id 清单" in rejection["detail"]
    assert "24413454" in rejection["detail"]


def test_unverified_full_per_id_result_cannot_decode_positional_rows() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {24413454, 24413458}
    state.history_positional_rows = [
        [24413458, "db-1.example:3306", "dpm"]
    ]
    sql = f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413454"
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one listed history row",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                # Deliberately omit full_sql: the returned field order is not
                # trustworthy enough to decode another query's positional rows.
                "rows": [
                    {
                        "id": 24413454,
                        "hostname_max": "db-1.example:3306",
                        "db_max": "dpm",
                        "sample": "SELECT 1",
                    }
                ],
            }
        },
    )

    assert state.history_positional_reference_columns == []
    assert state.history_positional_rows == [
        [24413458, "db-1.example:3306", "dpm"]
    ]
    assert set(state.history_id_rows) == {24413454}


@pytest.mark.parametrize(
    ("include_marker", "marker"),
    [(False, None), (True, 0), (True, "invalid"), (True, "exact")],
)
def test_sample_prefix_provenance_blocks_explain_even_without_valid_length_marker(
    include_marker: bool,
    marker: Any,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413640
    sample = "SELECT * FROM orders WHERE id = 1"
    sql = scenario.client.history_sample_projection_sql(row_id)
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    row: dict[str, Any] = {
        "id": row_id,
        "hostname_max": "orders-db.example:3306",
        "db_max": "orders_prod",
        "checksum": "prefix-provenance",
        "sample": sample,
        "Query_time_max": 9,
    }
    if include_marker:
        row["sample_full_length"] = (
            len(sample.encode("utf-8")) if marker == "exact" else marker
        )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover sample prefix",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [row],
            }
        },
    )
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    explain = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain recovered sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert state.history_id_rows[row_id]["sample"] == sample
    assert row_id in state.history_sample_prefix_ids
    assert explain.metadata["local_rejection"]["reason_code"] == (
        "explain_sample_not_in_history"
    )


def test_only_verified_complete_full_per_id_sample_clears_prefix_provenance() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413454
    prefix = "SELECT * FROM orders WHERE note = 'prefix"
    complete = "SELECT * FROM orders WHERE note = 'complete'"
    sql = f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    state.history_sample_prefix_ids = {row_id}
    state.history_id_rows = {
        row_id: {
            "id": row_id,
            "sample": prefix,
            "sample_full_length": len(complete.encode("utf-8")),
        }
    }
    state.history_merge_sources = [
        {"full_sql": scenario.client.history_sample_projection_sql(row_id), "row_count": 1}
    ]

    missing_sample = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover full row without sample",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        missing_sample,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [{"id": row_id, "hostname_max": "db-1.example:3306"}],
            }
        },
    )

    assert state.history_id_rows[row_id]["sample"] == prefix
    assert state.history_id_rows[row_id]["sample_full_length"] == len(
        complete.encode("utf-8")
    )
    assert state.history_sample_prefix_ids == {row_id}
    assert state.history_full_row_ids == set()

    shortfall = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Reject incomplete full sample provenance",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        shortfall,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rowCount": 2,
                "rows": [{"id": row_id, "sample": complete}],
            }
        },
    )

    assert state.history_id_rows[row_id]["sample"] == prefix
    assert state.history_sample_prefix_ids == {row_id}
    assert state.history_full_row_ids == set()

    complete_sample = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover verified full sample",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        complete_sample,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [
                    {
                        "id": row_id,
                        "hostname_max": "db-1.example:3306",
                        "sample": complete,
                    }
                ],
            }
        },
    )

    assert state.history_id_rows[row_id]["sample"] == complete
    assert "sample_full_length" not in state.history_id_rows[row_id]
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == {row_id}


@pytest.mark.parametrize("projection", ["full", "sample_prefix"])
def test_per_id_row_without_sample_does_not_complete_history_recovery(
    projection: str,
) -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413454
    sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = {row_id}"
        if projection == "full"
        else scenario.client.history_sample_projection_sql(row_id)
    )
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover one history row",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [{"id": row_id}],
            }
        },
    )

    assert state.history_id_rows == {row_id: {"id": row_id}}
    assert state.history_full_row_ids == set()
    assert state.history_sample_prefix_ids == set()
    assert archery_harness_module._history_recovery_missing_ids(state) == {row_id}
    assert archery_harness_module._history_recovery_complete(state) is False


def test_complete_json_row_shortfall_starts_history_recovery() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.window_start, state.window_end = archery_harness_module.client_window(
        scenario.client,
        OCCURRED_AT,
    )
    state.resolved_endpoints = {(17, "archery"): {"db-1.example:3306"}}
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Read alert-window history",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": FINAL_SQL,
                "rows": [{**_MERGE_RECOVERED_ROW, "id": 24413458}],
                "mcp_reported_row_count": 2,
            }
        },
    )

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert state.final_result is not None
    assert state.final_result.payload["result_incomplete"] is True
    assert "row_count_shortfall" in state.final_result.payload[
        "result_incomplete_reasons"
    ]


def test_decoded_full_positional_sample_survives_later_prefix_projection() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    row_id = 24413640
    full_sample = "SELECT * FROM orders WHERE id = 4001"
    prefix_sample = "SELECT * FROM orders WHERE id = 4"
    state.history_result_target = (17, "archery")
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {row_id}
    state.history_sample_prefix_ids = {row_id}
    state.history_id_rows = {
        row_id: {
            "id": row_id,
            "sample": prefix_sample,
            "sample_full_length": len(full_sample.encode("utf-8")),
        }
    }
    state.history_positional_reference_columns = ["id", "sample", "ts_cnt"]
    state.history_positional_rows = [[row_id, full_sample, 7]]

    scenario._resolve_deferred_positional_rows(state)

    assert state.history_positional_rows == []
    assert state.history_id_rows[row_id]["sample"] == full_sample
    assert "sample_full_length" not in state.history_id_rows[row_id]
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == {row_id}

    sql = scenario.client.history_sample_projection_sql(row_id)
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Recover redundant sample prefix",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )
    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": [
                    {
                        "id": row_id,
                        "sample": prefix_sample,
                        "sample_full_length": len(full_sample.encode("utf-8")),
                    }
                ],
            }
        },
    )

    assert state.history_id_rows[row_id]["sample"] == full_sample
    assert "sample_full_length" not in state.history_id_rows[row_id]
    assert state.history_sample_prefix_ids == set()
    assert state.history_full_row_ids == {row_id}


def test_unresolved_positional_rows_keep_recovery_incomplete_until_same_id_full() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_recovery_required = True
    state.history_recovery_listing_completed = True
    state.history_recovery_ids = {1, 2}
    state.history_positional_reference_columns = ["id", "sample"]
    state.history_positional_rows = [
        [1],
        [2, "SELECT 2"],
        [3, "SELECT 3"],
        ["invalid", "SELECT invalid"],
    ]

    scenario._resolve_deferred_positional_rows(state)

    assert state.history_id_rows == {2: {"id": 2, "sample": "SELECT 2"}}
    assert state.history_positional_rows == [
        [1],
        [3, "SELECT 3"],
        ["invalid", "SELECT invalid"],
    ]
    assert archery_harness_module._history_recovery_complete(state) is False

    state.history_full_row_ids.add(1)
    state.history_id_rows[1] = {"id": 1, "sample": "SELECT 1"}
    scenario._resolve_deferred_positional_rows(state)

    assert state.history_positional_rows == [
        [3, "SELECT 3"],
        ["invalid", "SELECT invalid"],
    ]
    assert archery_harness_module._history_recovery_complete(state) is False


def test_unscoped_id_listing_is_rejected_before_any_history_result() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.resolved_endpoints = {(17, "archery"): {"db-1.example:3306"}}
    sql = f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE}"

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="List history ids",
            hypothesis_ids=(),
            arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "history_recovery_query_forbidden"
    )


def test_unknown_dynamic_sql_tool_is_rejected_even_for_valid_explain_shape() -> None:
    sample = "SELECT * FROM orders WHERE id = 1"
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1050,
                "checksum": "unknown-sql-tool",
                "sample": sample,
                "Query_time_max": 1,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name="custom_sql_probe_gymJPA",
            objective="Explain the selected sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == "sql_tool_forbidden"


@pytest.mark.parametrize(
    "sample",
    [
        "SELECT * FROM other_prod.orders",
        "UPDATE LOW_PRIORITY other_prod.orders SET status = 1",
        "UPDATE /*+ NO_MERGE(orders) */ other_prod.orders SET status = 1",
        "INSERT /*+ SET_VAR(foreign_key_checks=OFF) */ "
        "INTO other_prod.archive VALUES (1)",
        "DELETE FROM orders USING other_prod.orders WHERE orders.id = 1",
        "INSERT INTO archive TABLE other_prod.source_rows",
        "REPLACE INTO archive TABLE other_prod.source_rows",
        "WITH recent AS (SELECT * FROM other_prod.orders) SELECT * FROM recent",
        "WITH recent AS (TABLE other_prod.orders) SELECT * FROM recent",
        "SELECT * FROM (TABLE other_prod.orders) recent",
        "SELECT * FROM orders UNION ALL TABLE other_prod.archive",
        'SELECT * FROM "other_prod"."orders"',
        "SELECT * FROM (other_prod.secret)",
        "SELECT * FROM (other_prod.a JOIN orders b ON a.id = b.id)",
        "SELECT * FROM (orders a, other_prod.secret s)",
        "DELETE other_prod.orders FROM orders JOIN audit a ON orders.id = a.id",
        "DELETE /*+ NO_MERGE(orders) */ other_prod.orders.* "
        "FROM orders JOIN audit a ON orders.id = a.id",
    ],
)
def test_explicit_sample_schema_mismatch_is_rejected_for_supported_statements(
    sample: str,
) -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1051,
                "checksum": "schema-mismatch",
                "sample": sample,
                "Query_time_max": 2,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain the selected sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "sample_schema_mismatch"
    )


@pytest.mark.parametrize(
    "sample",
    [
        "SELECT 'FROM other_prod.decoy' FROM orders",
        "SELECT * FROM orders_prod.Orders",
    ],
)
def test_table_parser_does_not_invent_schema_mismatch(sample: str) -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1052,
                "checksum": "schema-match",
                "sample": sample,
                "Query_time_max": 2,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain the selected sample",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {sample}",
            },
        ),
        state=state,
    )

    assert prepared.metadata["local_rejection"]["reason_code"] == (
        "table_structure_required"
    )


def test_list_tables_actual_target_mismatch_does_not_mutate_discovery_state() -> None:
    scenario, state = _bound_history_scenario(
        [
            {
                "id": 1053,
                "checksum": "table-discovery-target",
                "sample": "SELECT * FROM orders",
                "Query_time_max": 2,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    )
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_TABLES_TOOL_NAME,
            objective="List bound tables",
            hypothesis_ids=(),
            arguments={"instance_id": 3, "db_name": "orders_prod"},
        ),
        state=state,
    )

    scenario.on_result(
        state,
        prepared,
        {
            "structuredContent": {
                "status": "success",
                "instance_id": 99,
                "db_name": "orders_prod",
                "rows": [{"name": "mysql_slow_query_log"}],
            }
        },
    )

    assert state.slow_log_tables == {}
    assert state.slow_query_analysis_failures[0]["reason_code"] == (
        "actual_target_mismatch"
    )


def test_structure_and_indexes_are_reused_for_same_physical_table() -> None:
    rows = [
        {
            "id": 1061,
            "checksum": "orders-a",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 3,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
        {
            "id": 1062,
            "checksum": "orders-b",
            "sample": "SELECT * FROM orders WHERE id = 2",
            "Query_time_max": 2,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        },
    ]
    scenario, state = _bound_history_scenario(rows)
    source_a = scenario.client.slow_query_source_row(rows[0])
    source_b = scenario.client.slow_query_source_row(rows[1])
    target = {"instance_id": 3, "db_name": "orders_prod", "table_name": "orders"}
    shared_structure = {
        "stage": "table_structure",
        "source_history_row": source_a,
        "target": target,
        "result": {"rows": [{"COLUMN_NAME": "id"}], "row_count": 1},
    }
    state.slow_query_table_structure_results = [shared_structure]
    state.slow_query_index_results = [
        {
            "stage": "indexes",
            "source_history_row": source_a,
            "target": target,
            "result": {"rows": [{"INDEX_NAME": "PRIMARY"}], "row_count": 1},
        }
    ]
    explain_results = [
        {
            "stage": "explain",
            "source_history_row": source,
            "target": {"instance_id": 3, "db_name": "orders_prod"},
            "result": {"rows": [{"table": "orders"}], "row_count": 1},
        }
        for source in (source_a, source_b)
    ]
    state.slow_query_explain_results = explain_results[:1]

    incomplete = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        state.final_result.payload,
    )
    state.slow_query_explain_results.append(explain_results[1])

    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
            objective="Explain the second checksum",
            hypothesis_ids=(),
            arguments={
                "instance_id": 3,
                "db_name": "orders_prod",
                "sql_content": f"EXPLAIN {rows[1]['sample']}",
            },
        ),
        state=state,
    )
    analysis = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        state.final_result.payload,
    )

    assert incomplete["status"] == "partial"
    assert incomplete["missing_stages"] == ["explain"]
    assert "local_rejection" not in prepared.metadata
    assert analysis["status"] == "succeeded"
    assert analysis["missing_stages"] == []


def test_all_truncated_samples_record_no_safe_explainable_sample() -> None:
    sample = "SELECT * FROM orders"
    rows = [
        {
            "id": 1070,
            "checksum": "truncated-only",
            "sample": sample,
            "sample_full_length": len(sample.encode("utf-8")) + 1,
            "Query_time_max": 5,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    scenario, state = _bound_history_scenario(rows)

    analysis = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        state.final_result.payload,
    )

    assert analysis["status"] == "not_applicable"
    assert analysis["failures"][0]["reason_code"] == "no_safe_explainable_sample"


def test_archery_restore_state_backfills_slow_query_fields_from_old_checkpoint() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    new_fields = (
        "slow_query_explain_results",
        "slow_query_table_structure_results",
        "slow_query_index_results",
        "slow_query_analysis_failures",
    )
    for field_name in new_fields:
        delattr(state, field_name)
    for field_name in ("analysis_instance_endpoints", "analysis_database_names"):
        delattr(state, field_name)
    delattr(state, "history_result_target")
    delattr(state, "history_recovery_ids")
    delattr(state, "supplemental_analysis_started")

    scenario.restore_state(state)

    assert all(getattr(state, field_name) == [] for field_name in new_fields)
    assert state.analysis_instance_endpoints == {}
    assert state.analysis_database_names == {}
    assert state.history_result_target is None
    assert state.history_recovery_ids == set()
    assert state.history_recovery_required is False
    assert state.history_recovery_listing_completed is False
    assert state.supplemental_analysis_started is False


def test_legacy_checkpoint_accumulator_restores_conservative_recovery_provenance() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_id_rows = {
        41: {"id": 41, "sample": "SELECT * FROM legacy_orders"}
    }
    state.history_merge_sources = [
        {
            "full_sql": (
                "SELECT * FROM mysql_slow_query_review_history WHERE id = 41"
            ),
            "row_count": 1,
        }
    ]
    for field_name in (
        "history_recovery_ids",
        "history_recovery_required",
        "history_recovery_listing_completed",
        "history_sample_prefix_ids",
        "history_full_row_ids",
    ):
        delattr(state, field_name)

    scenario.restore_state(state)

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert state.history_sample_prefix_ids == {41}
    assert state.history_full_row_ids == set()
    assert archery_harness_module._history_recovery_complete(state) is False


def test_restore_state_fails_closed_for_inconsistent_current_accumulator() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    state.history_id_rows = {42: {"id": 42, "sample": "SELECT 42"}}
    state.history_merge_sources = [
        {
            "full_sql": (
                "SELECT * FROM mysql_slow_query_review_history WHERE id = 42"
            ),
            "row_count": 1,
        }
    ]
    state.history_recovery_required = False
    state.history_recovery_ids = {42}
    state.history_recovery_listing_completed = True

    scenario.restore_state(state)

    assert state.history_recovery_required is True
    assert state.history_recovery_listing_completed is False
    assert archery_harness_module._history_recovery_complete(state) is False


def test_analysis_success_requires_same_source_target_and_table() -> None:
    scenario = _scenario()
    state = scenario.initial_state()
    history_payload = {
        "rows": [
            {
                "id": 1044,
                "checksum": "coherent-orders",
                "sample": "SELECT * FROM orders WHERE id = 1",
                "Query_time_max": 7.0,
                "hostname_max": "orders-db.example:3306",
                "db_max": "orders_prod",
            }
        ]
    }
    source = scenario.client.slow_query_source_row(history_payload["rows"][0])
    correct_target = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "endpoint": "orders-db.example:3306",
        "table_name": "orders",
    }
    state.analysis_instance_endpoints = {3: {"orders-db.example:3306"}}
    state.analysis_database_names = {3: {"orders_prod"}}
    state.slow_query_explain_results = [
        {
            "source_history_row": source,
            "target": correct_target,
            "result": {"row_count": 1, "rows": [{"table": "orders"}]},
        }
    ]
    state.slow_query_table_structure_results = [
        {
            "source_history_row": source,
            "target": {**correct_target, "instance_id": 99},
            "result": {"row_count": 1, "rows": [{"COLUMN_NAME": "id"}]},
        }
    ]
    state.slow_query_index_results = [
        {
            "source_history_row": source,
            "target": correct_target,
            "result": {"row_count": 1, "rows": [{"INDEX_NAME": "PRIMARY"}]},
        }
    ]

    analysis = archery_harness_module._build_slow_query_analysis(
        scenario.client,
        state,
        history_payload,
    )

    assert analysis["status"] == "partial"
    assert analysis["missing_stages"] == ["table_structure"]


@pytest.mark.asyncio
async def test_history_without_explainable_sample_marks_analysis_not_applicable() -> None:
    history_rows = [
        {
            "id": 105,
            "checksum": "ddl-only",
            "sample": "ALTER TABLE orders ADD COLUMN unsafe int",
            "Query_time_max": 20.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-no-explainable-sample",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "not_applicable"
    assert result.slow_query_analysis["source_history_row"] is None
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "no_safe_explainable_sample"
    )


@pytest.mark.asyncio
async def test_history_direct_finish_records_supplemental_analysis_not_attempted() -> None:
    history_rows = [
        {
            "id": 1051,
            "checksum": "finish-orders",
            "sample": "SELECT * FROM orders WHERE id = 1",
            "Query_time_max": 20.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel([*_lineage_actions(FINAL_SQL)[:-1], _finish()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-analysis-not-attempted",
                tools=_tools(),
                calls=_lineage_replay_calls(FINAL_SQL, rows=history_rows),
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.payload["rows"] == history_rows
    assert result.slow_query_analysis is not None
    assert result.slow_query_analysis["status"] == "failed"
    assert result.slow_query_analysis["failures"][0]["reason_code"] == (
        "slow_query_analysis_not_attempted"
    )


@pytest.mark.asyncio
async def test_followup_allowlist_failure_preserves_history_and_remaining_facts() -> None:
    sample = "SELECT * FROM orders WHERE customer_id = 1"
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    indexes_sql = (
        "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_rows = [
        {
            "id": 106,
            "checksum": "orders-customer",
            "sample": sample,
            "Query_time_max": 11.0,
            "hostname_max": "orders-db.example:3306",
            "db_max": "orders_prod",
        }
    ]
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("history", FINAL_SQL),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _target_call("indexes", indexes_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-followup-allowlist-failure",
                tools=_analysis_tools(),
                calls=[
                    *_lineage_replay_calls(FINAL_SQL, rows=history_rows),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": columns_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [
                                    {"COLUMN_NAME": "customer_id", "COLUMN_TYPE": "bigint"}
                                ],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "实例不在白名单中，已拒绝执行（allowlist）",
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": indexes_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": indexes_sql,
                                "rows": [
                                    {"INDEX_NAME": "idx_customer", "COLUMN_NAME": "customer_id"}
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
    assert result.payload["rows"] == history_rows
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_INSTANCES_TOOL_NAME,
        ARCHERY_MCP_DATABASES_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "partial"
    assert analysis["explain_results"] == []
    assert analysis["table_structure_results"][0]["result"]["row_count"] == 1
    assert analysis["index_results"][0]["result"]["rows"][0]["INDEX_NAME"] == (
        "idx_customer"
    )
    assert analysis["failures"][0]["reason_code"] == "instance_not_allowlisted"


@pytest.mark.asyncio
async def test_complete_window_query_resets_per_id_accumulation() -> None:
    row_a = dict(_MERGE_RECOVERED_ROW)
    row_c = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413462,
        "checksum": "d" * 32,
        "ts_cnt": 25,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window-truncated", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-60", _MERGE_ID_SQL_60),
            _call("window-requery", _MERGE_WINDOW_SQL),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-window-requery-resets",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _merge_truncated_window_fixture(),
                    _success(_MERGE_IDS_SQL, rows=[{"id": 24413460}]),
                    _success(_MERGE_ID_SQL_60, rows=[dict(_MERGE_RECOVERED_ROW)]),
                    _success(_MERGE_WINDOW_SQL, rows=[row_a, row_c]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert "rows_merged_from_per_id_queries" not in result.payload
    assert result.payload["rows"] == [row_a, row_c]
    assert "rows_recovered_from_truncated_json" not in result.payload


@pytest.mark.asyncio
async def test_per_id_only_history_keeps_supplemental_success_and_failure() -> None:
    per_id_sql = (
        f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413454"
    )
    sample = "DELETE FROM orders WHERE id = 1"
    explain_sql = f"EXPLAIN {sample}"
    columns_sql = (
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'orders_prod' AND TABLE_NAME = 'orders'"
    )
    history_row = {
        "id": 24413454,
        "checksum": "per-id-orders",
        "sample": sample,
        "Query_time_max": 6.0,
        "hostname_max": "orders-db.example:3306",
        "db_max": "orders_prod",
    }
    analysis_arguments = {
        "instance_id": 3,
        "db_name": "orders_prod",
        "limit_num": 20,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("per-id", per_id_sql),
            *_analysis_discovery_actions(),
            _target_call("columns", columns_sql, instance_id=3, db_name="orders_prod"),
            _target_call("explain", explain_sql, instance_id=3, db_name="orders_prod"),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-per-id-analysis",
                tools=_analysis_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL,
                        rows=[{"host": "db-1.example", "port": 3306}],
                    ),
                    _success(_MERGE_IDS_SQL, rows=[{"id": 24413454}]),
                    _success(per_id_sql, rows=[history_row]),
                    *_analysis_discovery_calls(),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": columns_sql},
                        result={
                            "structuredContent": {
                                "status": "success",
                                "full_sql": columns_sql,
                                "rows": [{"COLUMN_NAME": "id"}],
                            }
                        },
                    ),
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**analysis_arguments, "sql_content": explain_sql},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "permission denied for EXPLAIN",
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

    assert result.payload["rows"] == [history_row]
    assert result.instance_id == TARGET_ARGUMENTS["instance_id"]
    assert result.db_name == TARGET_ARGUMENTS["db_name"]
    assert result.slow_query_analysis is not None
    analysis = result.slow_query_analysis
    assert analysis["status"] == "partial"
    assert analysis["table_structure_results"][0]["result"]["row_count"] == 1
    assert any(
        failure["reason_code"] == "permission_denied"
        for failure in analysis["failures"]
    )


@pytest.mark.asyncio
async def test_truncated_id_retrieval_with_high_limit_skips_to_projection_hint() -> None:
    """Replay of run 2c18cb74 (attempt=18): the model already sent
    max_result_chars=24000 on the very first per-id query, so the level-1
    "retry with 24000" hint was a dead end the model correctly skipped --
    and the projection hint never fired because it required a second
    truncation of the same SQL. A first truncation under a high
    max_result_chars now goes straight to the field-level projection hint.
    """
    row_40 = {
        "id": 24413640,
        "hostname_max": "db-1.example:3306",
        "sample": _PROJECTION_SAMPLE_PREFIX,
        "sample_full_length": 321237,
        "ts_cnt": 1,
        "Query_time_max": 0.806,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    first_call = MCPModelToolCall(
        call_id="id-40",
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _TRUNCATED_ID_SQL_40,
            "max_result_chars": 24000,
        },
        request_id="request-id-40",
    )
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("ids", _MERGE_IDS_SQL),
            first_call,
            _call("id-40-projection", _PROJECTION_ID_SQL_40),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-truncated-high-limit-projection",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[{"id": 24413640}, {"id": 24413454}],
                    ),
                    _truncated_id_retrieval_fixture(
                        _TRUNCATED_ID_SQL_40,
                        max_result_chars=24000,
                    ),
                    _success(_PROJECTION_ID_SQL_40, rows=[row_40]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    # The very first truncation under max_result_chars=24000 goes straight to
    # the field-level projection hint; the level-1 retry hint never appears.
    hint_request = model.requests[4]["messages"]
    tool_contents = [
        str(message.get("content"))
        for message in hint_request
        if message.get("role") == "tool"
    ]
    assert any("字段级" in content for content in tool_contents)
    assert any(
        "LEFT(sample, '4000') AS sample" in content for content in tool_contents
    )
    assert not any(
        "请立即用相同的 SQL 重试一次" in content for content in tool_contents
    )

    assert result.query_completed is True
    payload_rows = result.payload["rows"]
    assert [row["id"] for row in payload_rows] == [24413640, 24413454]
    assert payload_rows[0]["sample"] == _PROJECTION_SAMPLE_PREFIX
    assert payload_rows[0]["sample_full_length"] == 321237
    assert result.payload["merged_query_count"] == 3


@pytest.mark.asyncio
async def test_window_positional_truncation_hint_and_deferred_decode() -> None:
    """Replay of run 2c18cb74 (attempt=18): the truncated window query
    recovered positional rows whose column_list sat behind the truncation
    point, so the rows could not be structured and the merge silently lost
    them (merged 8 of 14). The window tool message now explains the loss, the
    id-listing message lists every id still missing from the merge (including
    the row that straddled the truncation point), and the deferred positional
    rows are decoded once a structured per-id row reveals the column order.
    """
    row_44 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413644,
        "checksum": "e" * 32,
        "sample": "SELECT e FROM t5",
        "ts_cnt": 3,
    }
    row_54 = {
        **_MERGE_RECOVERED_ROW,
        "id": 24413454,
        "checksum": "c" * 32,
        "sample": "SELECT /* full scan */ * FROM orders",
        "ts_cnt": 610,
        "Query_time_sum": 96.5,
    }
    model = _ScriptedModel(
        [
            _call("member", MEMBER_SQL),
            _call("instance", INSTANCE_SQL),
            _call("window", _MERGE_WINDOW_SQL),
            _call("ids", _MERGE_IDS_SQL),
            _call("id-44", _MERGE_ID_SQL_44),
            _call("id-54", _MERGE_ID_SQL_54),
            _finish(),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-window-positional-decode",
                tools=_tools(),
                calls=[
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(
                        INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]
                    ),
                    _truncated_window_positional_fixture(),
                    _success(
                        _MERGE_IDS_SQL,
                        rows=[
                            {"id": 24413648},
                            {"id": 24413647},
                            {"id": 24413646},
                            {"id": 24413645},
                            {"id": 24413644},
                            {"id": 24413454},
                        ],
                    ),
                    _success(_MERGE_ID_SQL_44, rows=[row_44]),
                    _success(_MERGE_ID_SQL_54, rows=[row_54]),
                ],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    # The truncated window query message explains the column_list loss.
    window_request = model.requests[3]["messages"]
    assert any(
        "列名缺失" in str(message.get("content"))
        for message in window_request
        if message.get("role") == "tool"
    )

    # The id-listing message lists every id still missing from the merge,
    # including the row that straddled the truncation point (24413644).
    ids_request = model.requests[4]["messages"]
    missing_hint = [
        str(message.get("content"))
        for message in ids_request
        if message.get("role") == "tool"
        and "【程序合并检测】" in str(message.get("content"))
    ]
    assert missing_hint, "missing-id hint absent from the id-listing message"
    for row_id in (24413648, 24413647, 24413646, 24413645, 24413644, 24413454):
        assert str(row_id) in missing_hint[0]

    # The model only re-queried two ids; the deferred positional rows are
    # decoded with the first structured row's column order, so all six ids
    # reach the final evidence.
    assert result.query_completed is True
    payload = result.payload
    assert payload["rows_merged_from_per_id_queries"] is True
    assert payload["merged_query_count"] == 2
    merged_ids = sorted(row["id"] for row in payload["rows"])
    assert merged_ids == [
        24413454,
        24413644,
        24413645,
        24413646,
        24413647,
        24413648,
    ]
    decoded = next(row for row in payload["rows"] if row["id"] == 24413648)
    assert decoded["hostname_max"] == "db-1.example:3306"
    assert decoded["db_max"] == "dpm"


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
    assert len(model.requests) == 4
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
    assistant_message = feedback_messages[-2]
    tool_message = feedback_messages[-1]
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
    assert model.received_callbacks == [None, None, None, None]

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
        and event.payload.get("action") == "finish"
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
    raw_feedback = model.requests[1]["messages"][-1]["content"]
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
            content = messages[-1].get("content")
            assert isinstance(content, str)
            return json.loads(content)

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
            turn = len(self.requests)
            if turn == 1:
                return MCPModelToolCall(
                    call_id="discover-instance",
                    name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
                    arguments=discovery_arguments,
                    request_id="request-discover-instance",
                )

            raw_response = self.raw_response(messages)
            structured = self.structured_payload(raw_response)
            if turn == 2:
                self.discovery_feedback = str(messages[-1]["content"])
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
    assert len(model.requests) == 5
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
    model = _ScriptedModel([first, _finish()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-responses-replay",
                tools=_tools(),
                calls=[_success(MEMBER_SQL, rows=[{"f_instance_id": 53}])],
            )
        ],
    )

    await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    second_input = model.requests[1]["messages"]
    assert second_input[-3]["type"] == "reasoning"
    assert second_input[-3]["encrypted_content"] == "encrypted-member"
    assert second_input[-2]["type"] == "function_call"
    assert second_input[-2]["call_id"] == base_call.call_id
    assert second_input[-1]["type"] == "function_call_output"
    assert second_input[-1]["call_id"] == base_call.call_id
    assert json.loads(second_input[-1]["output"]) == {
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
                calls=[_success(MEMBER_SQL, rows=[{"f_instance_id": 53}])],
            )
        ],
    )
    resumed_model = _ScriptedModel([_finish("finish-after-durable-call")])
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
    assert sum(
        item.get("id") == "durable-archery-reasoning" for item in resumed_messages
    ) == 1
    assert sum(
        item.get("id") == "durable-archery-function" for item in resumed_messages
    ) == 1
    assert sum(
        item.get("type") == "function_call_output"
        and item.get("call_id") == base_call.call_id
        for item in resumed_messages
    ) == 1


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
            len(snapshot.invocations) == 4
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
            if self.request_count == 4:
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
            sql = {
                1: MEMBER_SQL,
                2: INSTANCE_SQL,
                3: FINAL_SQL,
            }[self.request_count]
            selected_action = {
                **action,
                "arguments": {**TARGET_ARGUMENTS, "sql_content": sql},
            }
            return SimpleNamespace(
                id=f"archery-text-action-request-{self.request_count}",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(
                                content=json.dumps(selected_action),
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
                    _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
                    _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
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
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 3
    assert result.model_request_ids == (
        "archery-text-action-request-1",
        "archery-text-action-request-2",
        "archery-text-action-request-3",
    )
    assert completions.request_count == 4
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
        "WHERE table_schema = 'archery' "
        "AND table_name = 'mysql_slow_query_review_history' LIMIT 20"
    )
    interrupted_sql = FINAL_SQL.replace("LIMIT 20", "LIMIT 10")
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
    broad_sql = FINAL_SQL.replace("LIMIT 20", "LIMIT 10")
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
async def test_archery_raw_response_store_ignores_legacy_sanitized_artifact() -> None:
    invocation_id = uuid4()
    run_id = uuid4()
    arguments = {"query": "legacy"}
    legacy_id = uuid5(invocation_id, "archery-mcp-remote-response/v1")
    legacy_artifact = SimpleNamespace(
        artifact_id=legacy_id,
        kind="archery_mcp_remote_response",
        media_type="application/json",
        uri=f"agent-artifact://{legacy_id}",
        metadata={
            "contract": "archery-mcp-remote-response/v1",
            "provider": ARCHERY_HARNESS_PROVIDER,
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
                    "contract": "archery-mcp-remote-response/v1",
                    "provider": ARCHERY_HARNESS_PROVIDER,
                    "run_id": str(run_id),
                    "tool_name": "legacy_tool",
                    "arguments": arguments,
                    "response": {"secret_key": "[REDACTED]"},
                }
            return None

    repository = LegacyOnlyRepository()
    store = archery_harness_module.RepositoryArcheryRemoteResponseStore(repository)

    recovered = await store.load(
        run_id=run_id,
        invocation_id=invocation_id,
        tool_name="legacy_tool",
        arguments=arguments,
    )

    assert recovered is None
    assert repository.requested_ids == [str(store.artifact_id(invocation_id))]


@pytest.mark.asyncio
async def test_shared_harness_recovers_raw_response_from_checkpoint_after_process_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'artifact-recovery.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    manifest, run = await _create_durable_run(
        repository,
        external_id="archery-artifact-recovery",
    )
    raw_secret = "archery-checkpoint-secret-key"
    raw_member_result = {
        "structuredContent": {
            "status": "success",
            "full_sql": MEMBER_SQL,
            "rows": [{"f_instance_id": 53}],
            "secret_key": raw_secret,
        }
    }
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
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
                        expected_arguments={**TARGET_ARGUMENTS, "sql_content": MEMBER_SQL},
                        result=raw_member_result,
                    ),
                ],
            )
        ],
    )

    original_checkpoint = archery_harness_module.RepositoryMCPCheckpointStore.__call__
    interrupted = False

    async def interrupt_after_raw_response_checkpoint(store: Any, snapshot: Any) -> None:
        nonlocal interrupted
        await original_checkpoint(store, snapshot)
        if not interrupted and snapshot.remote_responses and snapshot.finish is None:
            interrupted = True
            raise asyncio.CancelledError

    monkeypatch.setattr(
        archery_harness_module.RepositoryMCPCheckpointStore,
        "__call__",
        interrupt_after_raw_response_checkpoint,
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
    interrupted_artifact = await repository.get_agent_artifact(artifacts[0].id)
    assert interrupted_artifact is not None
    artifact, artifact_content = interrupted_artifact
    assert artifact.metadata["internal_only"] is True
    assert artifact.metadata["sanitized"] is False
    assert artifact.metadata["raw_response_unmodified"] is True
    assert isinstance(artifact_content, bytes)
    decoded_interrupted_artifact = json.loads(artifact_content.decode("utf-8"))
    assert decoded_interrupted_artifact["response"] == raw_member_result
    assert decoded_interrupted_artifact["invocation_id"] == artifact.metadata["invocation_id"]
    assert (
        decoded_interrupted_artifact["outer_dispatch_id"]
        == artifact.metadata["outer_dispatch_id"]
    )
    checkpoint_store = archery_harness_module.RepositoryMCPCheckpointStore(
        repository,
        provider=ARCHERY_HARNESS_PROVIDER,
        manifest_hash=manifest.digest(),
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )
    staged_checkpoint = await checkpoint_store.load(run.id)
    assert staged_checkpoint is not None
    assert len(staged_checkpoint.remote_responses) == 1
    assert staged_checkpoint.remote_responses[0].response == raw_member_result
    assert raw_secret in json.dumps(
        staged_checkpoint.remote_responses[0].response,
        ensure_ascii=False,
    )
    await repository.close()

    monkeypatch.setattr(
        archery_harness_module.RepositoryMCPCheckpointStore,
        "__call__",
        original_checkpoint,
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
    persisted_contents: list[dict[str, Any]] = []
    for artifact_row in recovered_artifacts:
        persisted_artifact = await restarted_repository.get_agent_artifact(artifact_row.id)
        assert persisted_artifact is not None
        artifact, content = persisted_artifact
        assert artifact.metadata["internal_only"] is True
        assert artifact.metadata["sanitized"] is False
        assert artifact.metadata["raw_response_unmodified"] is True
        assert isinstance(content, bytes)
        persisted_contents.append(json.loads(content.decode("utf-8")))
    assert any(item["response"] == raw_member_result for item in persisted_contents)
    assert any(
        item["response"]
        == {
            "structuredContent": {
                "status": "success",
                "full_sql": FINAL_SQL,
                "rows": rows,
            }
        }
        for item in persisted_contents
    )
    assert raw_secret in json.dumps(persisted_contents, ensure_ascii=False)
    assert not hasattr(resumed, "raw_mcp_call_results")
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_shared_harness_persists_raw_tool_error_after_investigation(
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
    raw_secret = "archery-tool-error-secret-key"
    raw_error = {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": "Archery rejected the query",
                "secret_key": raw_secret,
            }
        ],
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
    assert artifact.metadata["sanitized"] is False
    assert artifact.metadata["raw_response_unmodified"] is True
    assert isinstance(content, bytes)
    decoded = json.loads(content.decode("utf-8"))
    assert decoded["response"] == raw_error
    assert raw_secret in content.decode("utf-8")
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
