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
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ARCHERY_SLOW_LOG_TABLE,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPClient,
    ArcheryMCPConfigurationError,
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
from app.mcp_runtime import (
    DiscoveredMCPTool,
    ReplayCallFixture,
    ReplayCallOutcome,
    ReplayErrorFixture,
    ReplayMCPConnector,
    ReplaySessionFixture,
    RepositoryMCPCheckpointStore,
)

OCCURRED_AT = datetime.fromisoformat("2026-07-23T16:00:00+08:00")
ALERT_CONTEXT = {"alert_endpoint": "db-1.example:3306"}
TARGET_ARGUMENTS = {
    "instance_id": 17,
    "db_name": "archery",
    "limit_num": 20,
    "max_result_chars": 24_000,
}
FINAL_SQL = (
    "SELECT hostname_max, ts_min, ts_max, sql_text "
    f"FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784793300) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "ORDER BY ts_min DESC LIMIT 20"
)


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


def _tools() -> list[DiscoveredMCPTool]:
    return [
        DiscoveredMCPTool(
            name=ARCHERY_MCP_LOGIN_TOOL_NAME,
            description="Confirm the configured Archery identity",
            input_schema={"type": "object", "properties": {}},
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
        ),
    ]


def _login() -> ReplayCallFixture:
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
        expected_arguments={},
        result={"structuredContent": {"status": "success", "username": "fixture"}},
    )


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
    max_agent_steps: int = 4,
    repository: SQLAlchemyAlertRepository | None = None,
) -> ArcheryMCPClient:
    return ArcheryMCPClient(
        MCPServerSettings(
            url="https://archery.example.test/mcp",
            headers={"X-Archery-Token": "fixture-token"},
        ),
        model,
        max_agent_steps=max_agent_steps,
        harness_connector=connector,
        harness_runtime_dependencies=(
            ArcheryHarnessRuntimeDependencies(repository)
            if repository is not None
            else None
        ),
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
async def test_shared_harness_repairs_a_model_response_without_a_tool_call() -> None:
    model = _ScriptedModel(
        [RuntimeError("model returned zero tool calls"), _call("final", FINAL_SQL)]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[
                    _login(),
                    _success(
                        FINAL_SQL,
                        rows=[{"hostname_max": "db-1.example:3306", "sql_text": "SELECT 1"}],
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
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert len(model.requests) == 2
    assert "Return exactly one valid Agent action" in str(model.requests[1]["messages"])
    assert connector.opened_session_ids == ["archery-1"]


@pytest.mark.asyncio
async def test_shared_archery_harness_executes_text_agent_action_history_query() -> None:
    action = {
        "action": "call_tool",
        "tool_name": ARCHERY_MCP_QUERY_TOOL_NAME,
        "objective": "Collect read-only Archery evidence for the fixed alert window",
        "hypothesis_ids": ["slow_query_evidence"],
        "arguments": {**TARGET_ARGUMENTS, "sql_content": FINAL_SQL},
    }

    class TextActionCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
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
    advisor._client = SimpleNamespace(
        chat=SimpleNamespace(completions=TextActionCompletions())
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-text-action",
                tools=_tools(),
                calls=[
                    _login(),
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
    assert connector.opened_session_ids == ["archery-text-action"]


@pytest.mark.asyncio
async def test_shared_harness_stops_after_one_model_repair_and_keeps_diagnostics() -> None:
    model = _ScriptedModel(
        [
            RuntimeError("provider returned zero tool calls request-1"),
            RuntimeError("provider returned zero tool calls request-2"),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[_login()],
            )
        ],
    )

    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is False
    assert len(model.requests) == 2
    assert result.diagnostics is not None
    assert [
        item["error"] for item in result.diagnostics["model_selection_errors"]
    ] == [
        "provider returned zero tool calls request-1",
        "provider returned zero tool calls request-2",
    ]
    assert result.diagnostics["mcp_tool_call_count"] == 0


@pytest.mark.asyncio
async def test_shared_harness_resume_does_not_grant_a_third_model_selection(
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
                        calls=[_login()],
                    )
                ],
            ),
            repository=repository,
        ).execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            outer_dispatch_id=outer_dispatch_id,
            outer_dispatch_attempt=1,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resumed_model = _ScriptedModel(
        [RuntimeError("second selection failed after restart")]
    )
    result = await _client(
        resumed_model,
        ReplayMCPConnector(
            ARCHERY_HARNESS_PROVIDER,
            [
                ReplaySessionFixture(
                    session_id="archery-model-after-restart",
                    tools=_tools(),
                    calls=[_login()],
                )
            ],
        ),
        repository=restarted_repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=outer_dispatch_id,
        outer_dispatch_attempt=2,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert len(resumed_model.requests) == 1
    assert result.query_completed is False
    assert result.diagnostics is not None
    assert [
        item["error"] for item in result.diagnostics["model_selection_errors"]
    ] == [
        "first selection failed before restart",
        "second selection failed after restart",
    ]
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
            _call("interrupted", interrupted_sql),
            _call("final", FINAL_SQL),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[
                    _login(),
                    _success(auxiliary_sql, rows=[{"index_name": "idx_host_ts"}]),
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
                    _login(),
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
    assert result.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_session_attempts"] == 2
    assert "idx_host_ts" in str(model.requests[2]["messages"])
    assert "MISSING" in str(model.requests[2]["messages"])


@pytest.mark.asyncio
async def test_shared_harness_rejects_write_and_legacy_slow_log_without_remote_calls() -> None:
    write_sql = "DELETE FROM mysql_slow_query_review_history"
    legacy_sql = (
        f"SELECT * FROM {ARCHERY_SLOW_LOG_TABLE} "
        "WHERE f_insert_time >= FROM_UNIXTIME(1784793300) "
        "AND f_insert_time < FROM_UNIXTIME(1784793600) LIMIT 20"
    )
    model = _ScriptedModel(
        [
            _call("write", write_sql),
            _call("legacy", legacy_sql),
            _call("final", FINAL_SQL),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[_login(), _success(FINAL_SQL)],
            )
        ],
    )
    result = await _client(model, connector, max_agent_steps=2).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,)
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_tool_call_count"] == 1
    assert result.diagnostics["model_decision_count"] == 3
    assert "legacy_slow_log_table_not_approved" in str(model.requests[2]["messages"])


@pytest.mark.asyncio
async def test_shared_harness_returns_progressive_repair_after_server_timeout() -> None:
    broad_sql = FINAL_SQL.replace(
        "AND ts_min >= FROM_UNIXTIME(1784793300) ",
        "AND ts_max >= FROM_UNIXTIME(1784793300) ",
    )
    model = _ScriptedModel([_call("broad", broad_sql), _call("final", FINAL_SQL)])
    timeout = ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={**TARGET_ARGUMENTS, "sql_content": broad_sql},
        result={
            "structuredContent": {
                "status": "failed",
                "message": "查询超时被 kill",
            }
        },
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[_login(), timeout, _success(FINAL_SQL)],
            )
        ],
    )
    result = await _client(model, connector).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    repair_messages = str(model.requests[1]["messages"])
    assert "information_schema.statistics" in repair_messages
    assert "ts_min >= FROM_UNIXTIME(1784793300)" in repair_messages
    assert result.diagnostics is not None
    assert result.diagnostics["query_trace"][0]["outcome"] == "tool_error"


@pytest.mark.asyncio
async def test_shared_harness_reserves_final_calls_and_recovers_actual_mysql_timeout() -> None:
    member_sql = (
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE f_ip = 'db-1.example' AND f_port = 3306 LIMIT 1"
    )
    instance_sql = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"
    redundant_instance_sql = (
        "SELECT host, port, instance_name FROM sql_instance WHERE id = 53 LIMIT 1"
    )
    expensive_history_sql = FINAL_SQL.replace(
        "ORDER BY ts_min DESC",
        "ORDER BY Query_time_sum DESC",
    )
    overlap_history_sql = FINAL_SQL.replace(
        "ts_min >= FROM_UNIXTIME(1784793300) ",
        "ts_max >= FROM_UNIXTIME(1784793300) ",
    )
    index_sql = (
        "SELECT index_name, seq_in_index, column_name "
        "FROM information_schema.statistics "
        "WHERE table_schema = 'archery' "
        "AND table_name = 'mysql_slow_query_review_history' LIMIT 20"
    )
    timeout_message = (
        "SQL 查询失败：{'errors': ErrorDetail(string=\"(1028, 'Sort aborted: "
        "Query execution was interrupted, maximum statement execution time exceeded')\", "
        "code='invalid')}"
    )
    model = _ScriptedModel(
        [
            _call("member", member_sql),
            _call("instance", instance_sql),
            _call("redundant-instance", redundant_instance_sql),
            _call("expensive-history", expensive_history_sql),
            _call("overlap-history", overlap_history_sql),
            _call("history-index", index_sql),
            _call("recovered-history", FINAL_SQL),
        ]
    )
    timeout = ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={**TARGET_ARGUMENTS, "sql_content": overlap_history_sql},
        result={
            "structuredContent": {
                "status": "failed",
                "message": timeout_message,
            }
        },
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-finalization-reserve",
                tools=_tools(),
                calls=[
                    _login(),
                    _success(member_sql, rows=[{"f_instance_id": 53}]),
                    _success(instance_sql, rows=[{"host": "db-1.example", "port": 3306}]),
                    timeout,
                    _success(
                        index_sql,
                        rows=[
                            {
                                "index_name": "idx_hostname_ts_min",
                                "seq_in_index": 1,
                                "column_name": "hostname_max",
                            },
                            {
                                "index_name": "idx_hostname_ts_min",
                                "seq_in_index": 2,
                                "column_name": "ts_min",
                            },
                        ],
                    ),
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "ts_min": "2026-07-23 15:59:00",
                                "sql_text": "SELECT recovered",
                            }
                        ],
                    ),
                ],
            )
        ],
    )

    result = await _client(
        model,
        connector,
        max_agent_steps=6,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
    )

    assert result.query_completed is True
    assert result.requested_sql == FINAL_SQL
    assert result.model_tool_calls == (ARCHERY_MCP_QUERY_TOOL_NAME,) * 5
    assert result.diagnostics is not None
    assert result.diagnostics["mcp_tool_call_count"] == 5
    trace = result.diagnostics["query_trace"]
    assert len(trace) == 7
    assert trace[2]["outcome"] == "host_rejected"
    assert "sql_instance 已完成" in trace[2]["continuation_reason"]
    assert trace[3]["outcome"] == "host_rejected"
    assert "只能按真实ts_min字段排序" in trace[3]["continuation_reason"]
    assert trace[4]["outcome"] == "tool_error"
    assert "maximum statement execution time exceeded" in trace[4]["error_detail"]
    assert "Host最终取证保留区" in str(model.requests[2]["messages"])
    timeout_feedback = str(model.requests[5]["messages"])
    assert "实时证据暂缺" in timeout_feedback
    assert "不能作为任何根因假设的反证" in timeout_feedback
    assert "ts_min >= FROM_UNIXTIME(1784793300)" in timeout_feedback


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
                calls=[
                    _login(),
                    _success(
                        FINAL_SQL,
                        rows=[
                            {
                                "hostname_max": "db-1.example:3306",
                                "sql_text": "SELECT durable",
                            }
                        ],
                    ),
                ],
            )
        ],
    )
    client = _client(
        _ScriptedModel([_call("durable", FINAL_SQL)]),
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
        outer_dispatch_attempt=1,
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
    assert len(invocations) == 1
    assert invocations[0].status == ToolInvocationStatus.SUCCEEDED.value
    assert len(artifacts) == 1
    assert artifacts[0].invocation_id == invocations[0].id
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
        outer_dispatch_attempt=2,
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
    auxiliary_sql = (
        "SELECT index_name, column_name FROM information_schema.statistics "
        "WHERE table_schema = 'archery' LIMIT 20"
    )
    first_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-before-restart",
                tools=_tools(),
                calls=[
                    _login(),
                    _success(auxiliary_sql, rows=[{"index_name": "idx_host_ts"}]),
                ],
            )
        ],
    )
    with pytest.raises(asyncio.CancelledError):
        await _client(
            InterruptingModel([_call("auxiliary-before-restart", auxiliary_sql)]),
            first_connector,
            repository=repository,
        ).execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            outer_dispatch_id=outer_dispatch_id,
            outer_dispatch_attempt=1,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resumed_login = ReplayCallFixture(
        tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
        expected_arguments={},
        result={
            "structuredContent": {
                "status": "success",
                "username": "resumed-fixture",
            }
        },
    )
    resume_connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-after-restart",
                tools=_tools(),
                calls=[resumed_login, _success(FINAL_SQL)],
            )
        ],
    )
    resumed_model = _ScriptedModel([_call("final-after-restart", FINAL_SQL)])
    resumed = await _client(
        resumed_model,
        resume_connector,
        repository=restarted_repository,
    ).execute_slow_log_query(
        OCCURRED_AT,
        alert_context=ALERT_CONTEXT,
        run_id=run.id,
        outer_dispatch_id=outer_dispatch_id,
        outer_dispatch_attempt=2,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )

    assert resumed.query_completed is True
    assert resumed.model_tool_calls == (
        ARCHERY_MCP_QUERY_TOOL_NAME,
        ARCHERY_MCP_QUERY_TOOL_NAME,
    )
    assert resumed.diagnostics is not None
    assert resumed.diagnostics["model_decision_count"] == 2
    assert "resumed-fixture" in str(resumed_model.requests[0]["messages"])
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_outer_recovery_without_scoped_checkpoint_never_opens_archery_session(
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
    connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    client = _client(_ScriptedModel([]), connector, repository=repository)
    assert run.lease_owner is not None

    with pytest.raises(ArcheryMCPConfigurationError, match="no matching child checkpoint"):
        await client.execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            outer_dispatch_id=uuid4(),
            outer_dispatch_attempt=2,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )

    assert connector.opened_session_ids == []
    await repository.close()


@pytest.mark.asyncio
async def test_shared_harness_recovers_artifact_from_checkpoint_after_process_restart(
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
                calls=[_login(), _success(FINAL_SQL, rows=rows)],
            )
        ],
    )

    async def interrupt_artifact_write(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise asyncio.CancelledError

    monkeypatch.setattr(repository, "save_agent_artifact", interrupt_artifact_write)
    assert run.lease_owner is not None
    with pytest.raises(asyncio.CancelledError):
        await _client(
            _ScriptedModel([_call("artifact-recovery", FINAL_SQL)]),
            first_connector,
            repository=repository,
        ).execute_slow_log_query(
            OCCURRED_AT,
            alert_context=ALERT_CONTEXT,
            run_id=run.id,
            lease_owner=run.lease_owner,
            fencing_token=run.fencing_token,
        )

    checkpoint = await repository.load_checkpoint(
        str(run.id),
        namespace=f"mcp:{ARCHERY_HARNESS_PROVIDER}",
    )
    assert checkpoint is not None
    interrupted_checkpoint_store = RepositoryMCPCheckpointStore[
        Any,
        dict[str, Any],
    ](
        repository,
        provider=ARCHERY_HARNESS_PROVIDER,
        manifest_hash=manifest.digest(),
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )
    interrupted_snapshot = await interrupted_checkpoint_store.load(run.id)
    assert interrupted_snapshot is not None
    assert len(interrupted_snapshot.state.pending_artifact_content) == 1
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
    assert artifacts == []
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resume_connector = ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, [])
    resumed = await _client(
        _ScriptedModel([]),
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
    assert resume_connector.opened_session_ids == []
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
    assert len(recovered_invocations) == 1
    assert recovered_invocations[0].status == ToolInvocationStatus.SUCCEEDED.value
    assert len(recovered_artifacts) == 1
    artifact_id = recovered_artifacts[0].id
    persisted_artifact = await restarted_repository.get_agent_artifact(artifact_id)
    assert persisted_artifact is not None
    assert persisted_artifact[1] == {
        "structuredContent": {
            "status": "success",
            "full_sql": FINAL_SQL,
            "rows": rows,
        }
    }
    checkpoint_store = RepositoryMCPCheckpointStore[
        Any,
        dict[str, Any],
    ](
        restarted_repository,
        provider=ARCHERY_HARNESS_PROVIDER,
        manifest_hash=manifest.digest(),
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )
    recovered_checkpoint = await checkpoint_store.load(run.id)
    assert recovered_checkpoint is not None
    assert recovered_checkpoint.state.pending_artifact_content == {}
    await restarted_repository.close()


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
