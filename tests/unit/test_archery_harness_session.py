from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest

import app.adapters.archery_harness as archery_harness_module
from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
    ArcheryMCPConnector,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_RESOURCE_GROUPS_TOOL_NAME,
    ARCHERY_MCP_TABLES_TOOL_NAME,
    ArcheryMCPClient,
    ArcheryMCPProtocolError,
)
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    DiscoveredMCPTool,
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
    TARGET_ARGUMENTS,
    _call,
    _client,
    _finish,
    _lineage_actions,
    _lineage_replay_calls,
    _named_call,
    _scenario,
    _ScriptedModel,
    _success,
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
@pytest.mark.parametrize("mcp_transport", ("sse", "streamable_http"))
async def test_connector_uses_configured_mcp_transport(
    monkeypatch: pytest.MonkeyPatch,
    mcp_transport: str,
) -> None:
    calls: dict[str, Any] = {}
    read_stream = object()
    write_stream = object()

    class _Context:
        def __init__(self, value: Any) -> None:
            self.value = value

        async def __aenter__(self) -> Any:
            return self.value

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class _InitializedSession:
        async def __aenter__(self) -> _InitializedSession:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        async def initialize(self) -> None:
            return None

    monkeypatch.setattr(
        archery_harness_module,
        "ClientSession",
        lambda *_args, **_kwargs: _InitializedSession(),
    )
    client = _client(
        _ScriptedModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
        mcp_transport=mcp_transport,  # type: ignore[arg-type]
    )
    if mcp_transport == "sse":

        def sse_connector(url: str, **kwargs: Any) -> _Context:
            calls["sse"] = {"url": url, **kwargs}
            return _Context((read_stream, write_stream))

        def unexpected_streamable(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("streamable HTTP connector must not be used")

        monkeypatch.setattr(archery_harness_module, "sse_client", sse_connector)
        monkeypatch.setattr(
            archery_harness_module,
            "streamable_http_client",
            unexpected_streamable,
        )
    else:
        http_client = object()

        def async_http_client(**kwargs: Any) -> _Context:
            calls["http_client"] = kwargs
            return _Context(http_client)

        def streamable_connector(url: str, *, http_client: Any) -> _Context:
            calls["streamable"] = {"url": url, "http_client": http_client}
            return _Context((read_stream, write_stream, lambda: "streamable-session"))

        def unexpected_sse(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("SSE connector must not be used")

        monkeypatch.setattr(
            archery_harness_module.httpx,
            "AsyncClient",
            async_http_client,
        )
        monkeypatch.setattr(
            archery_harness_module,
            "streamable_http_client",
            streamable_connector,
        )
        monkeypatch.setattr(archery_harness_module, "sse_client", unexpected_sse)

    session = await ArcheryMCPConnector(client).open_session()
    try:
        if mcp_transport == "sse":
            assert calls["sse"]["url"] == "https://archery.example.test/mcp"
            assert calls["sse"]["headers"] == {"X-Archery-Token": "fixture-token"}
            assert calls["sse"]["timeout"] == 60
            assert calls["sse"]["sse_read_timeout"] == 60
            assert calls["sse"]["httpx_client_factory"].keywords == {"transport": None}
            assert session.session_id.startswith("archery-session-")
        else:
            assert calls["streamable"] == {
                "url": "https://archery.example.test/mcp",
                "http_client": http_client,
            }
            assert calls["http_client"]["headers"] == {"X-Archery-Token": "fixture-token"}
            assert calls["http_client"]["follow_redirects"] is False
            assert calls["http_client"]["timeout"].connect == 60
            assert session.session_id == "streamable-session"
    finally:
        await session.close()


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
    assert [tool.name for tool in tools] == [f"archery_tool_{page}" for page in range(1, 13)]
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
    model = _ScriptedModel([RuntimeError("model returned zero tool calls"), *_lineage_actions()])
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
    assert len(model.requests) == 6
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
            _named_call("terminal-login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
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
                calls=[_terminal_auth_failure()],
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
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 1
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
            _named_call("terminal-login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
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
                calls=[_terminal_auth_failure()],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.diagnostics is not None
    assert result.diagnostics["mcp_roundtrip_count"] == 1
    assert result.diagnostics["model_attempted_tool_calls"] == [
        tool_name,
        ARCHERY_MCP_LOGIN_TOOL_NAME,
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
    assert rejected.metadata["local_rejection"]["reason_code"] == ("pre_history_tool_forbidden")


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
    assert len(model.requests) == 5
