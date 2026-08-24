from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4, uuid5

import pytest
from sqlalchemy import select

import app.adapters.archery_harness as archery_harness_module
from app.adapters.ai import OpenAICompatibleAdvisor
from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
)
from app.adapters.persistence import (
    AgentArtifactRow,
    SQLAlchemyAlertRepository,
    ToolInvocationRow,
)
from app.agent_runtime import (
    AgentEventKind,
    ToolInvocationStatus,
)
from app.domain.ports import RunLeaseConflict
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import (
    ReplayCallFixture,
    ReplayCallOutcome,
    ReplayErrorFixture,
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
    _ScriptedModel,
    _success,
    _tools,
)


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
            self.request_count += 1
            tools = kwargs.get("tools")
            available_names = {
                item["function"]["name"]
                for item in tools
                if isinstance(item, dict)
                and isinstance(item.get("function"), dict)
                and isinstance(item["function"].get("name"), str)
            } if isinstance(tools, list) else set()
            if available_names == {RESULT_ASSESSMENT_TOOL_NAME}:
                messages = kwargs.get("messages")
                pending = next(
                    (
                        payload
                        for message in reversed(messages)
                        if isinstance(message, dict)
                        and isinstance(message.get("content"), str)
                        and isinstance((payload := json.loads(message["content"])), dict)
                        and payload.get("type")
                        == "archery_result_assessment_required"
                    ),
                    None,
                ) if isinstance(messages, list) else None
                assert pending is not None
                return SimpleNamespace(
                    id="archery-text-assessment-request",
                    choices=[
                        SimpleNamespace(
                            finish_reason="tool_calls",
                            message=SimpleNamespace(
                                content=None,
                                tool_calls=[
                                    SimpleNamespace(
                                        id="archery-text-assessment-call",
                                        function=SimpleNamespace(
                                            name=RESULT_ASSESSMENT_TOOL_NAME,
                                            arguments=json.dumps(
                                                {
                                                    "source_invocation_id": pending[
                                                        "source_invocation_id"
                                                    ],
                                                    "scope": pending["scope"],
                                                    "stage": pending["stage"],
                                                    "history_id": pending.get("history_id"),
                                                    "content_state": "complete",
                                                    "basis": "appears_complete",
                                                }
                                            ),
                                        ),
                                    )
                                ],
                            ),
                        )
                    ],
                )
            if self.request_count == 5:
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
    assert completions.request_count == 5
    assert connector.opened_session_ids == ["archery-text-action"]


@pytest.mark.asyncio
async def test_shared_harness_keeps_repairing_until_model_explicitly_finishes() -> None:
    model = _ScriptedModel(
        [
            RuntimeError("provider returned zero tool calls request-1"),
            RuntimeError("provider returned zero tool calls request-2"),
            RuntimeError("provider returned zero tool calls request-3"),
            _named_call("login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
            _finish(reason="No useful Archery call remains"),
        ]
    )
    connector = ReplayMCPConnector(
        ARCHERY_HARNESS_PROVIDER,
        [
            ReplaySessionFixture(
                session_id="archery-1",
                tools=_tools(),
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                        expected_arguments={},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "authentication rejected",
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
    assert len(model.requests) == 5
    assert result.diagnostics is not None
    assert result.diagnostics["model_selection_errors"] == []
    assert result.diagnostics["mcp_tool_call_count"] == 1
    assert result.diagnostics["history_window_state"] == "FAILED_TERMINAL"
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
            _named_call("login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
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
                    calls=[
                        ReplayCallFixture(
                            tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                            expected_arguments={},
                            result={
                                "structuredContent": {
                                    "status": "failed",
                                    "message": "authentication rejected",
                                }
                            },
                        )
                    ],
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

    assert len(resumed_model.requests) == 4
    assert result.query_completed is False
    assert result.diagnostics is not None
    assert result.diagnostics["model_selection_errors"] == []
    assert result.diagnostics["history_window_state"] == "FAILED_TERMINAL"
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
    assert len(invocations) == 5
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
                calls=[
                    ReplayCallFixture(
                        tool_name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                        expected_arguments={},
                        result={
                            "structuredContent": {
                                "status": "failed",
                                "message": "authentication rejected",
                            }
                        },
                    )
                ],
            )
        ],
    )
    client = _client(
        _ScriptedModel(
            [
                _finish("History has not been attempted"),
                _named_call("login", ARCHERY_MCP_LOGIN_TOOL_NAME, {}),
                _finish("Archery authentication failed terminally"),
            ]
        ),
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
    assert len(recovered_invocations) == 5
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
