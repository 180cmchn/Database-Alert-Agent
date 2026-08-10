from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from anyio import ClosedResourceError, EndOfStream
from sqlalchemy import select

import app.adapters.prometheus_mcp as prometheus_module
from app.adapters.persistence import SQLAlchemyAlertRepository, ToolInvocationRow
from app.adapters.prometheus_harness import (
    PrometheusHarnessRuntimeDependencies,
    PrometheusHarnessState,
)
from app.adapters.prometheus_mcp import (
    PROMETHEUS_MCP_SERVER_NAME,
    PrometheusMCPClient,
    PrometheusMCPConfigurationError,
    PrometheusMCPServerSettings,
    PrometheusMCPToolPolicy,
)
from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    RepositoryEventSink,
    RunManifest,
    ToolInvocationStatus,
)
from app.domain.models import (
    InvestigationContext,
    InvestigationRun,
    InvestigationStrategy,
    NormalizedAlert,
    Severity,
)
from app.domain.ports import RunLeaseConflict
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_runtime import RepositoryMCPCheckpointStore

_ALERT_TIME = datetime(2026, 8, 7, 2, 0, tzinfo=UTC)


class _AsyncContext:
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _HarnessSession:
    calls: list[tuple[str, dict[str, Any]]] = []
    results: list[dict[str, Any] | Exception] = []
    session_count = 0

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        type(self).session_count += 1

    async def __aenter__(self) -> _HarnessSession:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def initialize(self) -> None:
        return None

    async def list_tools(self, cursor: str | None = None) -> Any:
        assert cursor is None
        tool = type(
            "PrometheusTool",
            (),
            {
                "model_dump": lambda _self, **_: {
                    "name": "query_range",
                    "description": "Run a read-only Prometheus range query",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                            "operation": {"type": "string"},
                        },
                        "required": ["query", "start", "end", "operation"],
                        "additionalProperties": False,
                    },
                    "annotations": {"readOnlyHint": True},
                }
            },
        )()
        return type("ToolList", (), {"tools": [tool], "nextCursor": None})()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        type(self).calls.append((name, arguments))
        result = type(self).results.pop(0)
        if isinstance(result, Exception):
            raise result
        return type("ToolResult", (), {"model_dump": lambda _self, **_: result})()


class _SequenceModel:
    def __init__(self, responses: list[MCPModelToolCall | Exception]) -> None:
        self.responses = responses
        self.messages: list[list[dict[str, Any]]] = []
        self.tools: list[list[dict[str, Any]]] = []

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        self.messages.append(messages)
        self.tools.append(tools)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _context(
    *,
    run_id: Any | None = None,
    lease_owner: str | None = None,
    fencing_token: int | None = None,
    external_id: str = "prometheus-harness-alert",
) -> InvestigationContext:
    return InvestigationContext(
        run_id=run_id or uuid4(),
        alert=NormalizedAlert(
            external_id=external_id,
            source="canonical",
            raw_severity="WARNING",
            severity=Severity.WARNING,
            title="Database latency elevated",
            reason="database_latency",
            occurred_at=_ALERT_TIME,
        ),
        strategy=InvestigationStrategy(
            strategy_id="prometheus-harness-test",
            title="Prometheus harness test",
            description="test",
        ),
        lease_owner=lease_owner,
        fencing_token=fencing_token,
    )


def _client(
    model: _SequenceModel,
    *,
    max_agent_steps: int = 4,
    repository: SQLAlchemyAlertRepository | None = None,
) -> PrometheusMCPClient:
    return PrometheusMCPClient(
        PrometheusMCPServerSettings(
            url="https://prometheus.example.test/sse",
            headers={},
            tool_policies=(
                PrometheusMCPToolPolicy(
                    name="query_range",
                    capability="range_query",
                    start_argument_path=("start",),
                    end_argument_path=("end",),
                    timestamp_encoding="rfc3339",
                    fixed_arguments={"operation": "query"},
                ),
            ),
        ),
        model,
        max_agent_steps=max_agent_steps,
        use_shared_harness=True,
        harness_runtime_dependencies=(
            PrometheusHarnessRuntimeDependencies(repository)
            if repository is not None
            else None
        ),
    )


async def _durable_context(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
) -> tuple[InvestigationContext, RunManifest, InvestigationRun]:
    run_id = uuid4()
    context = _context(run_id=run_id, external_id=external_id)
    stored, created = await repository.create_or_get(context.alert)
    assert created is True
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="prometheus-harness-test",
    )
    run = await repository.create_run(
        str(stored.alert.id),
        "prometheus-worker",
        300,
        manifest=manifest,
    )
    assert run is not None
    assert run.lease_owner is not None
    return (
        context.model_copy(
            update={
                "alert": stored.alert,
                "lease_owner": run.lease_owner,
                "fencing_token": run.fencing_token,
            }
        ),
        manifest,
        run,
    )


@pytest.fixture(autouse=True)
def _fake_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    _HarnessSession.calls = []
    _HarnessSession.results = []
    _HarnessSession.session_count = 0
    monkeypatch.setattr(
        prometheus_module,
        "sse_client",
        lambda *_args, **_kwargs: _AsyncContext((object(), object())),
    )
    monkeypatch.setattr(prometheus_module, "ClientSession", _HarnessSession)


@pytest.mark.asyncio
async def test_shared_harness_repairs_one_missing_model_tool_call() -> None:
    _HarnessSession.results = [
        {"structuredContent": {"series": [{"value": 1}]}}
    ]
    model = _SequenceModel(
        [
            RuntimeError("provider returned zero tool calls"),
            MCPModelToolCall(
                call_id="query-1",
                name="query_range",
                arguments={"query": "mysql_up"},
                request_id="request-query-1",
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
                request_id="request-finish-1",
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert len(model.messages) == 3
    assert "上一轮没有形成有效的单工具调用" in model.messages[1][-1]["content"]
    assert result.finished_by_model is True
    assert result.has_monitoring_data is True
    assert result.model_request_ids == ("request-query-1",)
    assert result.termination_error_type is None


@pytest.mark.asyncio
async def test_shared_harness_binds_window_and_fixed_arguments_before_schema_validation() -> None:
    _HarnessSession.results = [
        {"structuredContent": {"series": [{"value": 1}]}}
    ]
    model = _SequenceModel(
        [
            MCPModelToolCall(
                call_id="query-1",
                name="query_range",
                arguments={
                    "query": "rate(mysql_global_status_slow_queries[5m])",
                    "start": "2099-01-01T00:00:00+00:00",
                    "end": "2099-01-01T00:05:00+00:00",
                    "operation": "delete",
                },
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert _HarnessSession.calls == [
        (
            "query_range",
            {
                "query": "rate(mysql_global_status_slow_queries[5m])",
                "start": "2026-08-07T01:55:00+00:00",
                "end": "2026-08-07T02:00:00+00:00",
                "operation": "query",
            },
        )
    ]
    assert result.responses[0]["model_arguments"]["operation"] == "delete"
    assert result.responses[0]["arguments"]["operation"] == "query"
    assert result.responses[0]["window_verification"] == "exact"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "transport_error",
    [
        ConnectionError("stream closed while awaiting response"),
        ExceptionGroup(
            "SSE task group failed",
            [
                RuntimeError("cancel-scope cleanup failed"),
                httpx.RemoteProtocolError("peer closed the response stream"),
            ],
        ),
        EndOfStream(),
        ClosedResourceError(),
    ],
    ids=["connection-error", "nested-httpx-error", "end-of-stream", "closed-resource"],
)
async def test_shared_harness_reconnects_retries_read_only_call_and_keeps_prior_result(
    transport_error: Exception,
) -> None:
    _HarnessSession.results = [
        {"structuredContent": {"series": [{"value": 1}]}},
        transport_error,
        {"structuredContent": {"series": [{"value": 2}]}},
    ]
    model = _SequenceModel(
        [
            MCPModelToolCall(
                call_id="query-1",
                name="query_range",
                arguments={"query": "mysql_up"},
                request_id="request-query-1",
            ),
            MCPModelToolCall(
                call_id="query-2",
                name="query_range",
                arguments={"query": "rate(mysql_global_status_slow_queries[5m])"},
                request_id="request-query-2",
            ),
            MCPModelToolCall(
                call_id="finish-1",
                name="finish_prometheus_investigation",
                arguments={},
            ),
        ]
    )

    result = await _client(model).collect_alert_window(_context())

    assert _HarnessSession.session_count == 2
    assert [arguments["query"] for _, arguments in _HarnessSession.calls] == [
        "mysql_up",
        "rate(mysql_global_status_slow_queries[5m])",
        "rate(mysql_global_status_slow_queries[5m])",
    ]
    assert len(result.responses) == 2
    assert result.has_monitoring_data is True
    assert result.finished_by_model is True
    assert [attempt["outcome"] for attempt in result.tool_attempts] == [
        "observation",
        "transport_error",
        "observation",
    ]
    assert result.tool_attempts[1]["error_type"] == "prometheus_sse_transport_error"
    assert result.tool_attempts[1]["evidence_disposition"] == "MISSING"
    assert result.tool_attempts[1]["is_contradiction"] is False
    assert result.model_request_ids == (
        "request-query-1",
        "request-query-2",
        "request-query-2",
    )


@pytest.mark.asyncio
async def test_terminal_model_failure_diagnostics_survive_checkpoint_restart(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'prometheus-model-resume.db'}"
    repository = SQLAlchemyAlertRepository(database_url)
    await repository.initialize()
    context, manifest, _run = await _durable_context(
        repository,
        external_id="prometheus-model-resume",
    )
    assert context.lease_owner is not None
    assert context.fencing_token is not None

    first = await _client(
        _SequenceModel(
            [
                RuntimeError("provider returned zero tool calls"),
                RuntimeError("provider returned text instead of a tool call"),
            ]
        ),
        repository=repository,
    ).collect_alert_window(context)

    assert first.termination_reason == "model_error_no_result"
    assert first.termination_error_type == "PrometheusMCPModelError"
    assert first.has_monitoring_data is False
    model_attempt = first.tool_attempts[-1]
    assert model_attempt["outcome"] == "model_selection_error"
    assert [
        error["error"] for error in model_attempt["diagnostics"]["errors"]
    ] == [
        "provider returned zero tool calls",
        "provider returned text instead of a tool call",
    ]
    checkpoint_store = RepositoryMCPCheckpointStore[
        PrometheusHarnessState,
        dict[str, Any],
    ](
        repository,
        provider=PROMETHEUS_MCP_SERVER_NAME,
        manifest_hash=manifest.digest(),
        lease_owner=context.lease_owner,
        fencing_token=context.fencing_token,
    )
    checkpoint = await checkpoint_store.load(context.run_id)
    assert checkpoint is not None
    assert len(checkpoint.state.consecutive_model_errors) == 2
    sessions_after_first_process = _HarnessSession.session_count
    await repository.close()

    restarted_repository = SQLAlchemyAlertRepository(database_url)
    await restarted_repository.initialize()
    resumed = await _client(
        _SequenceModel([]),
        repository=restarted_repository,
    ).collect_alert_window(context)

    assert resumed == first
    assert _HarnessSession.session_count == sessions_after_first_process
    await restarted_repository.close()


@pytest.mark.asyncio
async def test_semantically_empty_range_result_is_persisted_as_missing_no_data(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-no-data.db'}"
    )
    await repository.initialize()
    try:
        context, _, run = await _durable_context(
            repository,
            external_id="prometheus-semantic-no-data",
        )
        _HarnessSession.results = [
            {
                "structuredContent": {
                    "status": "success",
                    "data": {"resultType": "matrix", "result": []},
                }
            }
        ]
        result = await _client(
            _SequenceModel(
                [
                    MCPModelToolCall(
                        call_id="empty-query",
                        name="query_range",
                        arguments={"query": "mysql_up"},
                    ),
                    MCPModelToolCall(
                        call_id="over-budget-query",
                        name="query_range",
                        arguments={"query": "mysql_threads_running"},
                    ),
                ]
            ),
            max_agent_steps=1,
            repository=repository,
        ).collect_alert_window(context)

        assert result.has_monitoring_data is False
        assert result.call_limit_reached is True
        assert len(result.responses) == 1
        assert result.responses[0]["has_monitoring_observation"] is False
        assert result.tool_attempts == (
            {
                "tool_name": "query_range",
                "model_arguments": {"query": "mysql_up"},
                "arguments": {
                    "query": "mysql_up",
                    "start": "2026-08-07T01:55:00+00:00",
                    "end": "2026-08-07T02:00:00+00:00",
                    "operation": "query",
                },
                "capability": "range_query",
                "outcome": "no_data",
                "window_verification": "exact",
                "evidence_disposition": "MISSING",
                "is_contradiction": False,
            },
        )
        events = await repository.list_agent_events(str(run.id))
        no_data_events = [
            event
            for event in events
            if event.kind == AgentEventKind.TOOL_INVOCATION_NO_DATA
            and event.payload.get("provider") == PROMETHEUS_MCP_SERVER_NAME
        ]
        assert len(no_data_events) == 1
        async with repository.session_factory() as session:
            invocations = (
                await session.execute(
                    select(ToolInvocationRow).where(
                        ToolInvocationRow.run_id == str(run.id)
                    )
                )
            ).scalars().all()
        assert len(invocations) == 1
        assert invocations[0].status == ToolInvocationStatus.NO_DATA.value
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_repository_harness_uses_context_fencing_and_ignores_foreign_events(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-harness.db'}"
    )
    await repository.initialize()
    try:
        context, manifest, run = await _durable_context(
            repository,
            external_id="prometheus-durable-run",
        )
        assert context.lease_owner is not None
        assert context.fencing_token is not None
        foreign_sink = RepositoryEventSink(
            repository,
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )
        await foreign_sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.HOST_REJECTED,
                payload={
                    "provider": "archery_mcp",
                    "code": "tool_not_approved",
                    "message": "foreign-host-rejection",
                },
            )
        )
        await foreign_sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.MCP_SESSION_FAILED,
                payload={
                    "provider": "archery_mcp",
                    "error_code": "ForeignSessionError",
                    "message": "foreign-session-failure",
                },
            )
        )
        await foreign_sink.append(
            AgentEvent(
                run_id=run.id,
                kind=AgentEventKind.HOST_REJECTED,
                payload={
                    "provider": PROMETHEUS_MCP_SERVER_NAME,
                    "dispatch_scope_id": str(uuid4()),
                    "code": "tool_not_approved",
                    "message": "sibling-dispatch-host-rejection",
                },
            )
        )
        _HarnessSession.results = [
            {"structuredContent": {"series": [{"value": 1}]}}
        ]
        result = await _client(
            _SequenceModel(
                [
                    MCPModelToolCall(
                        call_id="query-1",
                        name="query_range",
                        arguments={"query": "mysql_up"},
                    ),
                    MCPModelToolCall(
                        call_id="query-over-budget",
                        name="query_range",
                        arguments={"query": "mysql_threads_running"},
                    ),
                ]
            ),
            max_agent_steps=1,
            repository=repository,
        ).collect_alert_window(context)

        assert result.call_limit_reached is True
        assert [attempt["outcome"] for attempt in result.tool_attempts] == [
            "observation"
        ]
        assert result.termination_error_type is None
        assert result.termination_error_detail is None
        events = await repository.list_agent_events(str(run.id))
        assert {event.payload.get("provider") for event in events} == {
            "archery_mcp",
            PROMETHEUS_MCP_SERVER_NAME,
        }
        checkpoint = await repository.load_checkpoint(
            str(run.id),
            namespace=f"mcp:{PROMETHEUS_MCP_SERVER_NAME}",
        )
        assert checkpoint is not None
        assert checkpoint.manifest_hash == manifest.digest()
        async with repository.session_factory() as session:
            invocations = (
                await session.execute(
                    select(ToolInvocationRow).where(
                        ToolInvocationRow.run_id == str(run.id)
                    )
                )
            ).scalars().all()
        assert len(invocations) == 1
        assert invocations[0].provider == PROMETHEUS_MCP_SERVER_NAME

        stale_context, _, stale_run = await _durable_context(
            repository,
            external_id="prometheus-stale-run",
        )
        assert stale_context.fencing_token is not None
        sessions_before_stale_call = _HarnessSession.session_count
        with pytest.raises(RunLeaseConflict):
            await _client(
                _SequenceModel([]),
                repository=repository,
            ).collect_alert_window(
                stale_context.model_copy(
                    update={"fencing_token": stale_context.fencing_token + 1}
                )
            )

        assert _HarnessSession.session_count == sessions_before_stale_call
        assert await repository.list_agent_events(str(stale_run.id)) == []
        assert await repository.load_checkpoint(
            str(stale_run.id),
            namespace=f"mcp:{PROMETHEUS_MCP_SERVER_NAME}",
        ) is None
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_outer_recovery_without_scoped_checkpoint_never_opens_prometheus_session(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'prometheus-missing-outer-checkpoint.db'}"
    )
    await repository.initialize()
    try:
        context, _manifest, _run = await _durable_context(
            repository,
            external_id="prometheus-missing-outer-checkpoint",
        )
        recovery_context = context.model_copy(
            update={
                "outer_dispatch_id": uuid4(),
                "outer_dispatch_attempt": 2,
            }
        )

        with pytest.raises(
            PrometheusMCPConfigurationError,
            match="no matching child checkpoint",
        ):
            await _client(
                _SequenceModel([]),
                repository=repository,
            ).collect_alert_window(recovery_context)

        assert _HarnessSession.session_count == 0
        assert _HarnessSession.calls == []
    finally:
        await repository.close()
