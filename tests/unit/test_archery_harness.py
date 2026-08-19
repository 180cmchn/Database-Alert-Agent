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
    model = _ScriptedModel([_call("wrapped-history", FINAL_SQL), _finish()])
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-response-result-history",
                tools=_tools(),
                calls=[
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
    assert len(model.requests) == 2


_MERGE_WINDOW_SQL = (
    "SELECT id, hostname_max, db_max, user_max, checksum, sample, ts_min, ts_max, ts_cnt, "
    "Query_time_sum, Query_time_max, Query_time_pct_95 "
    f"FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784793300) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "AND ts_max >= FROM_UNIXTIME(1784793300) "
    "ORDER BY id DESC"
)
_MERGE_IDS_SQL = (
    f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784793300) "
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
            [24413648, "db-1.example:3306", "dpm"],
            [24413647, "db-1.example:3306", "dpm"],
            [24413646, "db-1.example:3306", "dpm"],
            [24413645, "db-1.example:3306", "dpm"],
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
_PROJECTION_ID_SQL_40 = (
    "SELECT id, hostname_max, client_max, user_max, db_max, checksum, "
    "ts_min, ts_max, ts_cnt, Query_time_sum, Query_time_max, "
    "Query_time_pct_95, Query_time_median, Lock_time_sum, Lock_time_max, "
    "Rows_sent_sum, Rows_examined_sum, Full_scan_cnt, Tmp_table_cnt, "
    "Filesort_cnt, Bytes_sum, LEFT(sample, '4000') AS sample, "
    f"LENGTH(sample) AS sample_full_length FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE id = 24413640"
)


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
