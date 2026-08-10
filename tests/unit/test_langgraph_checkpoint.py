from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict
from uuid import uuid4

import pytest
from langgraph.graph import END, StateGraph

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import InvestigationRunRow, SQLAlchemyAlertRepository
from app.agent_runtime.contracts import RunManifest
from app.agent_runtime.langgraph_checkpoint import (
    LangGraphCheckpointDecodeError,
    RepositoryLangGraphCheckpointer,
)
from app.agents import graph as investigation_graph_module
from app.agents.graph import InvestigationAgent
from app.agents.state import AgentState
from app.domain.ports import RunLeaseConflict


class _RecoveryState(TypedDict):
    value: int


def _sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


async def _create_run(
    repository: SQLAlchemyAlertRepository,
) -> tuple[RunManifest, str, str]:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "langgraph-checkpoint",
            "severity": "WARNING",
            "title": "Durable graph checkpoint",
            "reason": "test",
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    run = await repository.create_run(
        str(stored.alert.id),
        "test-worker",
        300,
        manifest=manifest,
    )
    assert run is not None
    return manifest, str(run.id), str(stored.alert.id)


def _build_recovery_graph(
    checkpointer: RepositoryLangGraphCheckpointer,
    calls: dict[str, int],
):
    async def first(state: _RecoveryState) -> dict[str, int]:
        calls["first"] += 1
        return {"value": state["value"] + 1}

    async def flaky_second(state: _RecoveryState) -> dict[str, int]:
        calls["second"] += 1
        if calls["second"] == 1:
            raise RuntimeError("simulated worker crash")
        return {"value": state["value"] + 1}

    graph = StateGraph(_RecoveryState)
    graph.add_node("first", first)
    graph.add_node("second", flaky_second)
    graph.set_entry_point("first")
    graph.add_edge("first", "second")
    graph.add_edge("second", END)
    return graph.compile(checkpointer=checkpointer)


def _build_agent_state_recovery_graph(
    checkpointer: RepositoryLangGraphCheckpointer,
    calls: dict[str, int],
    *,
    expected_recovery_owner: str | None = None,
):
    async def first(_state: AgentState) -> dict[str, object]:
        calls["first"] += 1
        return {}

    async def flaky_second(state: AgentState) -> dict[str, object]:
        calls["second"] += 1
        if calls["second"] == 1:
            raise RuntimeError("simulated Agent node crash")
        assert state.run is not None
        assert state.run.lease_owner == expected_recovery_owner
        return {}

    graph = StateGraph(AgentState)
    graph.add_node("first", first)
    graph.add_node("second", flaky_second)
    graph.set_entry_point("first")
    graph.add_edge("first", "second")
    graph.add_edge("second", END)
    return graph.compile(checkpointer=checkpointer)


@pytest.mark.asyncio
async def test_langgraph_checkpoint_resumes_after_completed_node(tmp_path: Path) -> None:
    database = tmp_path / "langgraph-resume.db"
    repository = SQLAlchemyAlertRepository(_sqlite_url(database))
    await repository.initialize()
    manifest, run_id, alert_id = await _create_run(repository)
    config = {"configurable": {"thread_id": run_id}}
    calls = {"first": 0, "second": 0}
    first_checkpointer = RepositoryLangGraphCheckpointer(
        repository,
        run_id=manifest.run_id,
        manifest_hash=manifest.digest(),
        lease_owner="test-worker",
        fencing_token=1,
    )
    first_graph = _build_recovery_graph(first_checkpointer, calls)

    with pytest.raises(RuntimeError, match="simulated worker crash"):
        await first_graph.ainvoke({"value": 0}, config)
    assert calls == {"first": 1, "second": 1}
    assert await repository.load_checkpoint(run_id, namespace="agent") is not None
    async with repository.session_factory() as session:
        row = await session.get(InvestigationRunRow, run_id)
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    await repository.close()

    reopened = SQLAlchemyAlertRepository(_sqlite_url(database))
    await reopened.initialize()
    reclaimed = await reopened.reclaim_expired_run(alert_id, "recovery-worker", 300)
    assert reclaimed is not None
    assert str(reclaimed.id) == run_id
    assert reclaimed.attempt == 1
    assert reclaimed.fencing_token == 2
    resumed_checkpointer = RepositoryLangGraphCheckpointer(
        reopened,
        run_id=manifest.run_id,
        manifest_hash=manifest.digest(),
        lease_owner="recovery-worker",
        fencing_token=2,
    )
    resumed_graph = _build_recovery_graph(resumed_checkpointer, calls)

    result = await resumed_graph.ainvoke(None, config)

    assert result == {"value": 2}
    assert calls == {"first": 1, "second": 2}
    checkpoints = await reopened.list_checkpoints(run_id, namespace="agent")
    assert len(checkpoints) >= 3
    await reopened.close()


@pytest.mark.asyncio
async def test_langgraph_checkpoint_rejects_stale_lease_and_manifest(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "langgraph-fencing.db"))
    await repository.initialize()
    manifest, run_id, _alert_id = await _create_run(repository)
    stale = RepositoryLangGraphCheckpointer(
        repository,
        run_id=manifest.run_id,
        manifest_hash=manifest.digest(),
        lease_owner="test-worker",
        fencing_token=2,
    )
    calls = {"first": 0, "second": 1}
    graph = _build_recovery_graph(stale, calls)

    with pytest.raises(RunLeaseConflict):
        await graph.ainvoke({"value": 0}, {"configurable": {"thread_id": run_id}})
    assert await repository.load_checkpoint(run_id, namespace="agent") is None

    valid = RepositoryLangGraphCheckpointer(
        repository,
        run_id=manifest.run_id,
        manifest_hash=manifest.digest(),
        lease_owner="test-worker",
        fencing_token=1,
    )
    valid_graph = _build_recovery_graph(valid, {"first": 0, "second": 1})
    assert await valid_graph.ainvoke(
        {"value": 0}, {"configurable": {"thread_id": run_id}}
    ) == {"value": 2}

    mismatched = RepositoryLangGraphCheckpointer(
        repository,
        run_id=manifest.run_id,
        manifest_hash="f" * 64,
        lease_owner="test-worker",
        fencing_token=1,
    )
    with pytest.raises(LangGraphCheckpointDecodeError, match="manifest"):
        await mismatched.aget_tuple({"configurable": {"thread_id": run_id}})
    await repository.close()


@pytest.mark.asyncio
async def test_investigation_agent_refreshes_reclaimed_lease_before_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "agent-lease-refresh.db"
    repository = SQLAlchemyAlertRepository(_sqlite_url(database))
    await repository.initialize()
    manifest, run_id, alert_id = await _create_run(repository)
    stored = await repository.get(alert_id)
    assert stored is not None and stored.latest_run is not None
    calls = {"first": 0, "second": 0}
    initial_checkpointer = RepositoryLangGraphCheckpointer(
        repository,
        run_id=manifest.run_id,
        manifest_hash=manifest.digest(),
        lease_owner="test-worker",
        fencing_token=1,
    )
    initial_graph = _build_agent_state_recovery_graph(initial_checkpointer, calls)
    config = {"configurable": {"thread_id": run_id}}
    with pytest.raises(RuntimeError, match="simulated Agent node crash"):
        await initial_graph.ainvoke(AgentState(run=stored.latest_run), config)
    async with repository.session_factory() as session:
        row = await session.get(InvestigationRunRow, run_id)
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    await repository.close()

    reopened = SQLAlchemyAlertRepository(_sqlite_url(database))
    await reopened.initialize()
    reclaimed = await reopened.reclaim_expired_run(alert_id, "recovery-worker", 300)
    assert reclaimed is not None and reclaimed.fencing_token == 2

    def build_recovery_graph(_ctx, *, checkpointer):  # type: ignore[no-untyped-def]
        return _build_agent_state_recovery_graph(
            checkpointer,
            calls,
            expected_recovery_owner="recovery-worker",
        )

    monkeypatch.setattr(
        investigation_graph_module,
        "build_investigation_graph",
        build_recovery_graph,
    )
    agent = object.__new__(InvestigationAgent)
    agent.ctx = SimpleNamespace(repository=reopened)
    agent.graph = None

    result = await agent.run(AgentState(run=reclaimed))

    assert result.run is not None
    assert result.run.lease_owner == "recovery-worker"
    assert result.run.fencing_token == 2
    assert calls == {"first": 1, "second": 2}
    await reopened.close()
