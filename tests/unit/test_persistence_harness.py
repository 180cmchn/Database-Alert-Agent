from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import (
    AgentArtifactRow,
    AgentCheckpointRow,
    InvestigationRunRow,
    SQLAlchemyAlertRepository,
    ToolInvocationRow,
)
from app.agent_runtime.budgets import BudgetLedger
from app.agent_runtime.contracts import (
    ArtifactRef,
    InvocationError,
    RunCheckpoint,
    RunManifest,
    RuntimeStopReason,
    ToolInvocation,
    ToolInvocationStatus,
)
from app.agent_runtime.events import AgentEvent, AgentEventKind
from app.agent_runtime.persistence import RepositoryEventSink, RepositoryInvocationStore
from app.application.sanitization import REDACTED
from app.domain.models import (
    AlertStatus,
    AnalysisConfigSnapshot,
    EvidenceRecord,
    InvestigationStage,
    ProgressRecord,
    RunbookExcerpt,
    RunStatus,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)
from app.domain.ports import (
    AgentCheckpointVersionConflict,
    AgentEventSequenceConflict,
    RunLeaseConflict,
    ToolInvocationConflict,
)
from app.mcp_runtime.contracts import MCPHarnessSnapshot, PreparedCall
from app.mcp_runtime.persistence import (
    MCPCheckpointDecodeError,
    RepositoryMCPCheckpointStore,
)


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


async def _create_run(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
    manifest: RunManifest | None = None,
    config_snapshot: AnalysisConfigSnapshot | None = None,
) -> UUID:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": external_id,
            "severity": "WARNING",
            "title": "Durable Agent harness test",
            "reason": "persistence contract",
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    run = await repository.create_run(
        str(stored.alert.id),
        "test-worker",
        300,
        config_snapshot=config_snapshot,
        manifest=manifest,
    )
    assert run is not None
    return run.id


@pytest.mark.asyncio
async def test_update_alert_requires_active_run_lease(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "update-alert.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "detail-enrichment",
            "severity": "WARNING",
            "title": "Database alert",
            "reason": "slow_query",
            "database": {"engine": "mysql"},
        }
    )
    stored, _ = await repository.create_or_get(alert)
    run = await repository.create_run(str(alert.id), "detail-worker", 300)
    assert run is not None
    enriched = alert.model_copy(
        update={
            "database": alert.database.model_copy(
                update={"host": "detail-host", "port": 3306}
            )
        }
    )

    with pytest.raises(RunLeaseConflict):
        await repository.update_alert(
            str(alert.id),
            enriched,
            run_id=str(run.id),
            lease_owner="stale-worker",
            fencing_token=run.fencing_token,
        )

    await repository.update_alert(
        str(alert.id),
        enriched,
        run_id=str(run.id),
        lease_owner="detail-worker",
        fencing_token=run.fencing_token,
    )
    updated = await repository.get(str(alert.id))
    assert updated is not None
    assert updated.alert.database is not None
    assert updated.alert.database.host == "detail-host"
    assert updated.alert.database.port == 3306
    assert stored.alert.database is not None
    assert stored.alert.database.host is None
    await repository.close()


@pytest.mark.asyncio
async def test_create_run_persists_manifest_and_config_snapshot(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "manifest.db"))
    await repository.initialize()
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-agent",
        code_version="test-revision",
        model_provider="openai_compatible",
        model_name="test-model",
        configuration={"react_max_rounds": 3},
    )
    snapshot = AnalysisConfigSnapshot(
        react_max_rounds=3,
        ai_model="test-model",
    )

    saved_run_id = await _create_run(
        repository,
        external_id="manifest-run",
        manifest=manifest,
        config_snapshot=snapshot,
    )

    assert saved_run_id == run_id
    assert await repository.get_run_manifest(str(run_id)) == manifest
    async with repository.session_factory() as session:
        row = await session.get(InvestigationRunRow, str(run_id))
        assert row is not None
        assert row.config_snapshot_json == snapshot.model_dump(mode="json")
        assert row.manifest_hash == manifest.digest()
    await repository.close()


@pytest.mark.asyncio
async def test_run_lease_renewal_requires_current_owner_and_fencing_token(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "lease-fencing.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "lease-fencing",
            "severity": "WARNING",
            "title": "Fenced lease renewal",
            "reason": "persistence contract",
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    first = await repository.create_run(str(stored.alert.id), "worker-a", 30)
    assert first is not None
    assert first.fencing_token == first.attempt == 1

    await repository.finalize_run(
        str(stored.alert.id),
        str(first.id),
        lease_owner="worker-a",
        fencing_token=first.fencing_token,
        run_status=RunStatus.FAILED,
        final_stage=InvestigationStage.FAILED,
        alert_status=AlertStatus.FAILED,
        progress=ProgressRecord(
            run_id=first.id,
            stage=InvestigationStage.FAILED,
            message="结束首个租约测试运行。",
        ),
        error="test setup",
    )
    second = await repository.create_run(str(stored.alert.id), "worker-b", 30)
    assert second is not None
    assert second.fencing_token == second.attempt == 2

    assert (
        await repository.renew_run_lease(str(second.id), "worker-b", first.fencing_token, 60)
        is False
    )
    assert (
        await repository.renew_run_lease(str(second.id), "worker-a", second.fencing_token, 60)
        is False
    )
    with pytest.raises(RunLeaseConflict):
        await repository.update_run(
            str(second.id),
            stage=InvestigationStage.INVESTIGATING,
            lease_owner="worker-b",
            fencing_token=first.fencing_token,
        )
    assert await repository.renew(str(second.id), "worker-b", second.fencing_token, 60) is True
    await repository.update_run(
        str(second.id),
        stage=InvestigationStage.INVESTIGATING,
        lease_owner="worker-b",
        fencing_token=second.fencing_token,
    )
    restored = await repository.get(str(stored.alert.id))
    assert restored is not None
    assert restored.latest_run is not None
    assert restored.latest_run.fencing_token == second.fencing_token
    assert restored.latest_run.current_stage == InvestigationStage.INVESTIGATING

    async with repository.session_factory() as session:
        second_row = await session.get(InvestigationRunRow, str(second.id))
        assert second_row is not None
        second_row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert (
        await repository.renew_run_lease(str(second.id), "worker-b", second.fencing_token, 60)
        is False
    )
    with pytest.raises(RunLeaseConflict):
        await repository.update_run(
            str(second.id),
            stage=InvestigationStage.ADVISING,
            lease_owner="worker-b",
            fencing_token=second.fencing_token,
        )
    unchanged = await repository.get(str(stored.alert.id))
    assert unchanged is not None
    assert unchanged.latest_run is not None
    assert unchanged.latest_run.current_stage == InvestigationStage.INVESTIGATING
    await repository.close()


@pytest.mark.asyncio
async def test_forced_reanalysis_fences_an_active_run_and_creates_one_replacement(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "force-reanalysis.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "force-reanalysis",
            "severity": "WARNING",
            "title": "Force a new fenced attempt",
            "reason": "persistence contract",
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    first = await repository.create_run(str(stored.alert.id), "worker-a", 300)
    assert first is not None
    snapshot = AnalysisConfigSnapshot(code_version="replacement")

    refused = await repository.create_run_for_reanalyze(
        str(stored.alert.id),
        "worker-b",
        300,
        snapshot,
    )
    assert refused is None

    replacement = await repository.create_run_for_reanalyze(
        str(stored.alert.id),
        "worker-b",
        300,
        snapshot,
        force=True,
    )
    assert replacement is not None
    assert replacement.attempt == first.attempt + 1
    assert replacement.fencing_token == replacement.attempt
    assert (
        await repository.renew_run_lease(
            str(first.id),
            "worker-a",
            first.fencing_token,
            300,
        )
        is False
    )
    with pytest.raises(RunLeaseConflict):
        await repository.update_run(
            str(first.id),
            stage=InvestigationStage.INVESTIGATING,
            lease_owner="worker-a",
            fencing_token=first.fencing_token,
        )

    current = await repository.get(str(stored.alert.id))
    assert current is not None and current.latest_run is not None
    assert current.status == AlertStatus.ANALYZING
    assert current.latest_run.id == replacement.id
    prior = next(item for item in current.all_runs if item.id == first.id)
    assert prior.status == RunStatus.FAILED
    assert prior.current_stage == InvestigationStage.FAILED
    assert prior.error == "Superseded by forced re-analysis"
    assert prior.lease_expires_at is None
    await repository.close()


@pytest.mark.asyncio
async def test_finalize_run_commits_terminal_projection_and_progress_together(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "finalize-run.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "finalize-run",
            "severity": "WARNING",
            "title": "Atomic terminal result",
            "reason": "persistence contract",
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    run = await repository.create_run(str(stored.alert.id), "test-worker", 300)
    assert run is not None
    progress = ProgressRecord(
        run_id=run.id,
        stage=InvestigationStage.INCONCLUSIVE,
        message="调查结束，但结论不充分。",
        details={"evidence_sufficient": False},
    )

    saved = await repository.finalize_run(
        str(stored.alert.id),
        str(run.id),
        lease_owner="test-worker",
        fencing_token=run.fencing_token,
        run_status=RunStatus.INCONCLUSIVE,
        final_stage=InvestigationStage.INCONCLUSIVE,
        alert_status=AlertStatus.INCONCLUSIVE,
        progress=progress,
        runbooks=[],
    )

    current = await repository.get(str(stored.alert.id))
    assert current is not None and current.latest_run is not None
    assert current.status == AlertStatus.INCONCLUSIVE
    assert current.latest_run.status == RunStatus.INCONCLUSIVE
    assert current.latest_run.current_stage == InvestigationStage.INCONCLUSIVE
    assert current.progress == [saved]
    assert saved.sequence == 1
    await repository.close()


@pytest.mark.asyncio
async def test_finalize_run_rolls_back_all_terminal_writes_on_progress_conflict(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "finalize-rollback.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "finalize-rollback",
            "severity": "WARNING",
            "title": "Rollback terminal result",
            "reason": "persistence contract",
        }
    )
    stored, _ = await repository.create_or_get(alert)
    run = await repository.create_run(str(stored.alert.id), "test-worker", 300)
    assert run is not None
    duplicate_id = uuid4()
    await repository.append_progress(
        str(stored.alert.id),
        ProgressRecord(
            id=duplicate_id,
            run_id=run.id,
            stage=InvestigationStage.RECEIVED,
            message="已领取。",
        ),
        lease_owner="test-worker",
        fencing_token=run.fencing_token,
    )

    with pytest.raises(IntegrityError):
        await repository.finalize_run(
            str(stored.alert.id),
            str(run.id),
            lease_owner="test-worker",
            fencing_token=run.fencing_token,
            run_status=RunStatus.FAILED,
            final_stage=InvestigationStage.FAILED,
            alert_status=AlertStatus.FAILED,
            progress=ProgressRecord(
                id=duplicate_id,
                run_id=run.id,
                stage=InvestigationStage.FAILED,
                message="调查执行失败。",
            ),
            error="simulated failure",
        )

    current = await repository.get(str(stored.alert.id))
    assert current is not None and current.latest_run is not None
    assert current.status == AlertStatus.ANALYZING
    assert current.latest_run.status == RunStatus.RUNNING
    assert current.latest_run.current_stage == InvestigationStage.RECEIVED
    assert current.error is None
    assert len(current.progress) == 1

    with pytest.raises(RunLeaseConflict):
        await repository.finalize_run(
            str(stored.alert.id),
            str(run.id),
            lease_owner="test-worker",
            fencing_token=run.fencing_token + 1,
            run_status=RunStatus.FAILED,
            final_stage=InvestigationStage.FAILED,
            alert_status=AlertStatus.FAILED,
            progress=ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.FAILED,
                message="stale worker",
            ),
            error="must not persist",
        )
    unchanged = await repository.get(str(stored.alert.id))
    assert unchanged is not None and unchanged.latest_run is not None
    assert unchanged.status == AlertStatus.ANALYZING
    assert unchanged.latest_run.status == RunStatus.RUNNING
    assert len(unchanged.progress) == 1
    await repository.close()


@pytest.mark.asyncio
async def test_agent_event_append_detects_stale_and_concurrent_sequences(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "events.db"))
    await repository.initialize()
    run_id = await _create_run(repository, external_id="event-run")
    first = AgentEvent(
        run_id=run_id,
        sequence=1,
        version=1,
        kind=AgentEventKind.RUN_STARTED,
        payload={"worker": "one"},
    )

    assert await repository.append_agent_events(str(run_id), [first], expected_sequence=0) == 1
    with pytest.raises(AgentEventSequenceConflict) as stale:
        await repository.append_agent_events(
            str(run_id),
            [
                AgentEvent(
                    run_id=run_id,
                    sequence=1,
                    version=1,
                    kind=AgentEventKind.RUN_FAILED,
                )
            ],
            expected_sequence=0,
        )
    assert stale.value.actual == 1

    second = AgentEvent(
        run_id=run_id,
        sequence=2,
        version=2,
        kind=AgentEventKind.MODEL_DECISION,
        payload={"decision": "probe"},
    )
    third = AgentEvent(
        run_id=run_id,
        sequence=3,
        version=3,
        kind=AgentEventKind.BUDGET_DEBITED,
        payload={"tool_calls": 1},
    )
    assert (
        await repository.append_agent_events(str(run_id), [second, third], expected_sequence=1) == 3
    )
    restored = await repository.list_agent_events(str(run_id), after_sequence=1)
    assert restored == [second, third]

    secret_event = AgentEvent(
        run_id=run_id,
        sequence=4,
        version=4,
        kind=AgentEventKind.ARTIFACT_CREATED,
        payload={"artifact_id": str(uuid4()), "token": "event-secret"},
    )
    await repository.append_agent_events(str(run_id), [secret_event], expected_sequence=3)
    sanitized_event = (await repository.list_agent_events(str(run_id), after_sequence=3))[0]
    assert sanitized_event.payload["token"] == REDACTED
    large_event = AgentEvent(
        run_id=run_id,
        sequence=5,
        version=5,
        kind=AgentEventKind.EVIDENCE_RECORDED,
        payload={"projection": "x" * 20_000, "token": "large-event-secret"},
    )
    await repository.append_agent_events(
        str(run_id),
        [large_event],
        expected_sequence=4,
    )
    restored_large_event = (
        await repository.list_agent_events(str(run_id), after_sequence=4)
    )[0]
    assert restored_large_event.payload["projection"] == "x" * 20_000
    assert restored_large_event.payload["token"] == REDACTED

    concurrent_run_id = await _create_run(repository, external_id="concurrent-events")
    candidates = [
        AgentEvent(
            run_id=concurrent_run_id,
            sequence=1,
            version=1,
            kind=AgentEventKind.RUN_STARTED,
            payload={"writer": writer},
        )
        for writer in ("a", "b")
    ]
    outcomes = await asyncio.gather(
        *(
            repository.append_agent_events(str(concurrent_run_id), [candidate], expected_sequence=0)
            for candidate in candidates
        ),
        return_exceptions=True,
    )
    assert sum(outcome == 1 for outcome in outcomes) == 1
    assert sum(isinstance(outcome, AgentEventSequenceConflict) for outcome in outcomes) == 1
    await repository.close()


@pytest.mark.asyncio
async def test_repository_event_sink_assigns_and_returns_sanitized_events(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "event-sink.db"))
    await repository.initialize()
    run_id = await _create_run(repository, external_id="repository-event-sink")
    sink = RepositoryEventSink(repository)

    stored = await sink.append(
        AgentEvent(
            run_id=run_id,
            kind=AgentEventKind.MODEL_DECISION,
            payload={"token": "event-secret", "action": "probe"},
        ),
        expected_version=0,
    )

    assert (stored.sequence, stored.version) == (1, 1)
    assert stored.payload["token"] == REDACTED
    assert await sink.current_version(run_id) == 1
    assert await sink.read(run_id) == [stored]
    await repository.close()


@pytest.mark.asyncio
async def test_checkpoint_save_uses_optimistic_version_and_restores_latest(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "checkpoints.db"))
    await repository.initialize()
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    await _create_run(
        repository,
        external_id="checkpoint-run",
        manifest=manifest,
    )
    first = RunCheckpoint(
        run_id=run_id,
        version=1,
        sequence=2,
        state={"stage": "INVESTIGATING", "hypotheses": ["lock wait"]},
        budget_snapshot={"tool_calls": {"used": 1, "limit": 4}},
        manifest_hash=manifest.digest(),
    )

    mismatched = first.model_copy(update={"checkpoint_id": uuid4(), "manifest_hash": "f" * 64})
    with pytest.raises(RuntimeError, match="manifest mismatch"):
        await repository.save_checkpoint(mismatched, expected_version=0)
    assert await repository.save_checkpoint(first, expected_version=0) == first
    assert await repository.load_checkpoint(str(run_id)) == first

    stale = first.model_copy(update={"checkpoint_id": uuid4()})
    with pytest.raises(AgentCheckpointVersionConflict) as conflict:
        await repository.save_checkpoint(stale, expected_version=0)
    assert conflict.value.actual == 1

    second = RunCheckpoint(
        run_id=run_id,
        version=2,
        sequence=4,
        state={"stage": "ADVISING", "evidence_ids": ["ev-1"]},
        budget_snapshot={"tool_calls": {"used": 2, "limit": 4}},
        manifest_hash=manifest.digest(),
        stop_reason=RuntimeStopReason.EVIDENCE_SUFFICIENT,
    )
    assert await repository.save_checkpoint(second, expected_version=1) == second
    assert await repository.load_checkpoint(str(run_id)) == second

    provider_snapshot = RunCheckpoint(
        run_id=run_id,
        namespace="mcp:prometheus",
        version=1,
        sequence=4,
        state={"provider": "prometheus", "messages": []},
        budget_snapshot={"remote_tool_calls": {"used": 1, "limit": 8}},
        manifest_hash=manifest.digest(),
    )
    assert (
        await repository.save_checkpoint(provider_snapshot, expected_version=0) == provider_snapshot
    )
    assert (
        await repository.load_checkpoint(
            str(run_id),
            namespace="mcp:prometheus",
        )
        == provider_snapshot
    )
    assert await repository.load_checkpoint(str(run_id)) == second
    await repository.close()


@pytest.mark.asyncio
async def test_checkpoint_writes_are_isolated_by_run_before_checkpoint_exists(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "checkpoint-writes.db"))
    await repository.initialize()
    run_a = uuid4()
    run_b = uuid4()
    manifest_a = RunManifest(
        run_id=run_a,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    manifest_b = manifest_a.model_copy(update={"run_id": run_b})
    await _create_run(repository, external_id="checkpoint-write-a", manifest=manifest_a)
    await _create_run(repository, external_id="checkpoint-write-b", manifest=manifest_b)
    checkpoint = RunCheckpoint(
        run_id=run_a,
        version=1,
        sequence=1,
        state={"stage": "first"},
        manifest_hash=manifest_a.digest(),
    )
    await repository.save_checkpoint(checkpoint, expected_version=0)
    base_write = {
        "task_id": "task-1",
        "write_index": 0,
        "channel": "state",
        "value_type": "json",
        "value_base64": "Qg==",
        "task_path": "root",
    }
    await repository.put_checkpoint_writes(
        str(run_b),
        str(checkpoint.checkpoint_id),
        [base_write],
        lease_owner="test-worker",
        fencing_token=1,
    )
    write_a = {**base_write, "value_base64": "QQ=="}
    await repository.put_checkpoint_writes(
        str(run_a),
        str(checkpoint.checkpoint_id),
        [write_a],
        lease_owner="test-worker",
        fencing_token=1,
    )

    assert await repository.list_checkpoint_writes(str(run_a), str(checkpoint.checkpoint_id)) == [
        write_a
    ]
    assert await repository.list_checkpoint_writes(str(run_b), str(checkpoint.checkpoint_id)) == []
    await repository.close()


@pytest.mark.asyncio
async def test_reclaim_rejects_corrupt_latest_checkpoint_without_fallback(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "reclaim-corrupt.db"))
    await repository.initialize()
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    await _create_run(repository, external_id="reclaim-corrupt", manifest=manifest)
    first = RunCheckpoint(
        run_id=run_id,
        version=1,
        sequence=1,
        state={"stage": "valid"},
        manifest_hash=manifest.digest(),
    )
    second = RunCheckpoint(
        run_id=run_id,
        version=2,
        sequence=2,
        state={"stage": "latest"},
        manifest_hash=manifest.digest(),
    )
    await repository.save_checkpoint(first, expected_version=0)
    await repository.save_checkpoint(second, expected_version=1)
    async with repository.session_factory() as session:
        run_row = await session.get(InvestigationRunRow, str(run_id))
        checkpoint_row = await session.get(AgentCheckpointRow, str(second.checkpoint_id))
        assert run_row is not None and checkpoint_row is not None
        alert_id = run_row.alert_id
        run_row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        checkpoint_row.state_hash = "0" * 64
        await session.commit()

    with pytest.raises(RuntimeError, match="state hash mismatch"):
        await repository.reclaim_expired_run(alert_id, "recovery-worker", 300)
    async with repository.session_factory() as session:
        run_row = await session.get(InvestigationRunRow, str(run_id))
        assert run_row is not None
        assert run_row.lease_owner == "test-worker"
        assert run_row.fencing_token == 1
    await repository.close()


@pytest.mark.asyncio
async def test_reclaim_skips_legacy_run_without_checkpoint_and_allows_new_attempt(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "reclaim-legacy.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "reclaim-legacy",
            "severity": "WARNING",
            "title": "Replace non-resumable legacy run",
            "reason": "persistence contract",
        }
    )
    stored, _ = await repository.create_or_get(alert)
    legacy = await repository.create_run(str(stored.alert.id), "legacy-worker", 300)
    assert legacy is not None
    async with repository.session_factory() as session:
        row = await session.get(InvestigationRunRow, str(legacy.id))
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    assert (
        await repository.reclaim_expired_run(str(stored.alert.id), "recovery-worker", 300) is None
    )
    replacement = await repository.create_run(str(stored.alert.id), "new-worker", 300)

    assert replacement is not None
    assert replacement.attempt == legacy.attempt + 1
    current = await repository.get(str(stored.alert.id))
    assert current is not None and current.latest_run is not None
    assert current.latest_run.id == replacement.id
    assert [item.status for item in current.all_runs] == [
        RunStatus.RUNNING,
        RunStatus.FAILED,
    ]
    await repository.close()


@pytest.mark.asyncio
async def test_mcp_checkpoint_store_round_trips_snapshot_and_budget(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "mcp-checkpoint.db"))
    await repository.initialize()
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    await _create_run(
        repository,
        external_id="mcp-checkpoint",
        manifest=manifest,
    )
    budget = BudgetLedger({"remote_tool_calls": 3, "planner_requests": 4})
    budget.debit(remote_tool_calls=1, planner_requests=1)
    snapshot = MCPHarnessSnapshot(
        run_id=run_id,
        parent_run_id=None,
        state={"stage": "query_metrics", "successful_results": [{"value": 1}]},
        messages=({"role": "user", "content": "collect metrics"},),
        observations=(),
        invocations=(),
        tool_specs=(),
        fingerprints=frozenset({"fingerprint-1"}),
        budget=budget.snapshot(),
        finish=None,
        event_version=0,
        deadline=None,
        active_call=PreparedCall(
            tool_name="query_range",
            objective="Collect the fixed alert window",
            effective_arguments={"query": "mysql_up"},
            metadata={"call_id": "call-1", "capability": "range_query"},
        ),
    )
    store = RepositoryMCPCheckpointStore[dict[str, object], object](
        repository,
        provider="prometheus",
        manifest_hash=manifest.digest(),
    )

    await store(snapshot)
    restored = await store.load(run_id)

    assert restored is not None
    assert restored.run_id == snapshot.run_id
    assert restored.state == snapshot.state
    assert restored.messages == snapshot.messages
    assert restored.fingerprints == snapshot.fingerprints
    assert restored.active_call == snapshot.active_call
    assert BudgetLedger.from_snapshot(restored.budget).snapshot() == snapshot.budget
    mismatched = RepositoryMCPCheckpointStore[dict[str, object], object](
        repository,
        provider="prometheus",
        manifest_hash="b" * 64,
    )
    with pytest.raises(MCPCheckpointDecodeError, match="manifest"):
        await mismatched.load(run_id)
    await repository.close()


@pytest.mark.asyncio
async def test_tool_invocation_survives_reopen_and_can_resume(tmp_path: Path) -> None:
    database = tmp_path / "invocations.db"
    repository = SQLAlchemyAlertRepository(sqlite_url(database))
    await repository.initialize()
    run_id = await _create_run(repository, external_id="invocation-run")
    created_at = datetime.now(UTC)
    invocation = ToolInvocation(
        run_id=run_id,
        tool_name="query_range",
        provider="prometheus_mcp",
        objective="Collect the fixed alert window",
        hypothesis_ids=["resource_saturation"],
        model_arguments={"query": "mysql_threads_running"},
        effective_arguments={
            "query": "mysql_threads_running",
            "start": "2026-08-09T01:55:00Z",
            "end": "2026-08-09T02:00:00Z",
        },
        fingerprint=ToolInvocation.build_fingerprint(
            tool_name="query_range",
            effective_arguments={
                "query": "mysql_threads_running",
                "start": "2026-08-09T01:55:00Z",
                "end": "2026-08-09T02:00:00Z",
            },
        ),
        created_at=created_at,
    )
    await repository.save_tool_invocation(invocation)
    async with repository.session_factory() as session:
        row = await session.get(ToolInvocationRow, str(invocation.invocation_id))
        assert row is not None
        assert row.request_hash != row.effective_hash
    await repository.close()

    reopened = SQLAlchemyAlertRepository(sqlite_url(database))
    await reopened.initialize()
    assert await reopened.get_tool_invocation(str(invocation.invocation_id)) == invocation

    started_at = created_at + timedelta(seconds=1)
    started = ToolInvocation.model_validate(
        {
            **invocation.model_dump(mode="python"),
            "status": ToolInvocationStatus.STARTED,
            "started_at": started_at,
        }
    )
    await reopened.update_tool_invocation(started)
    error = InvocationError(
        code="MCP_SESSION_CLOSED",
        message="Stream closed before a terminal response",
        retryable=True,
    )
    failed = ToolInvocation.model_validate(
        {
            **started.model_dump(mode="python"),
            "status": ToolInvocationStatus.FAILED,
            "completed_at": started_at + timedelta(seconds=1),
            "error": error,
        }
    )
    await reopened.update_tool_invocation(
        failed,
        result={
            "status": "failed",
            "token": "result-secret",
            "diagnostic": "x" * 20_000,
        },
    )
    assert await reopened.get_tool_invocation(str(invocation.invocation_id)) == failed
    result_summary = await reopened.get_tool_invocation_result(str(invocation.invocation_id))
    assert result_summary is not None
    assert result_summary["status"] == "failed"
    assert "result-secret" not in str(result_summary)
    assert REDACTED in str(result_summary)
    assert result_summary["diagnostic"] == "x" * 20_000

    artifact = ArtifactRef(
        kind="mcp_response",
        media_type="application/json",
        uri=f"agent-artifact://{uuid4()}",
        sha256=None,
        size_bytes=None,
        metadata={"sanitized": True, "token": "metadata-secret"},
    )
    stored_artifact = await reopened.save_agent_artifact(
        str(run_id),
        artifact,
        {"status": "failed", "token": "artifact-secret"},
        invocation_id=str(invocation.invocation_id),
    )
    assert stored_artifact.sha256 is not None
    assert stored_artifact.size_bytes is not None
    assert stored_artifact.metadata["token"] == REDACTED
    restored_artifact = await reopened.get_agent_artifact(str(stored_artifact.artifact_id))
    assert restored_artifact == (
        stored_artifact,
        {"status": "failed", "token": REDACTED},
    )
    async with reopened.session_factory() as session:
        artifact_row = await session.get(AgentArtifactRow, str(artifact.artifact_id))
        assert artifact_row is not None
        assert artifact_row.size_bytes == stored_artifact.size_bytes
        assert artifact_row.content_encoding == "json"
        assert "artifact-secret" not in artifact_row.sanitized_content
        invocation_rows = (
            (
                await session.execute(
                    select(ToolInvocationRow).where(ToolInvocationRow.run_id == str(run_id))
                )
            )
            .scalars()
            .all()
        )
        assert [row.status for row in invocation_rows] == [ToolInvocationStatus.FAILED.value]
    await reopened.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift_kind",
    ["model_arguments", "effective_arguments", "provider", "deadline"],
)
async def test_tool_invocation_update_rejects_audit_identity_drift(
    tmp_path: Path,
    drift_kind: str,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "immutable-invocation.db"))
    await repository.initialize()
    run_id = await _create_run(repository, external_id=f"invocation-drift-{drift_kind}")
    created_at = datetime.now(UTC)
    effective_arguments = {"query": "up", "step": "30s"}
    invocation = ToolInvocation(
        run_id=run_id,
        tool_name="query_range",
        provider="prometheus_mcp",
        objective="Collect one bounded metric range",
        hypothesis_ids=["resource_saturation"],
        model_arguments={"query": "up"},
        effective_arguments=effective_arguments,
        fingerprint=ToolInvocation.build_fingerprint(
            tool_name="query_range",
            effective_arguments=effective_arguments,
        ),
        tool_policy_version="policy-v1",
        tool_schema_version="schema-v1",
        request_timeout_seconds=90,
        deadline=created_at + timedelta(minutes=2),
        created_at=created_at,
    )
    await repository.save_tool_invocation(invocation)

    drift: dict[str, object]
    if drift_kind == "model_arguments":
        drift = {"model_arguments": {"query": "mysql_up"}}
    elif drift_kind == "effective_arguments":
        changed_arguments = {"query": "up", "step": "60s"}
        drift = {
            "effective_arguments": changed_arguments,
            "fingerprint": ToolInvocation.build_fingerprint(
                tool_name="query_range",
                effective_arguments=changed_arguments,
            ),
        }
    elif drift_kind == "provider":
        drift = {"provider": "another_prometheus_mcp"}
    else:
        drift = {"deadline": created_at + timedelta(minutes=3)}
    changed = ToolInvocation.model_validate(
        {
            **invocation.model_dump(mode="python"),
            **drift,
            "status": ToolInvocationStatus.STARTED,
            "started_at": created_at + timedelta(seconds=1),
        }
    )

    with pytest.raises(ToolInvocationConflict, match="immutable invocation identity"):
        await repository.update_tool_invocation(changed)

    assert await repository.get_tool_invocation(str(invocation.invocation_id)) == invocation
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("drifted_column", ["request_hash", "effective_hash", "fingerprint"])
async def test_tool_invocation_update_rejects_persisted_hash_drift(
    tmp_path: Path,
    drifted_column: str,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "invocation-hash-drift.db"))
    await repository.initialize()
    run_id = await _create_run(repository, external_id=f"hash-drift-{drifted_column}")
    created_at = datetime.now(UTC)
    arguments = {"query": "up"}
    invocation = ToolInvocation(
        run_id=run_id,
        tool_name="query_range",
        provider="prometheus_mcp",
        objective="Collect one bounded metric range",
        model_arguments=arguments,
        effective_arguments=arguments,
        fingerprint=ToolInvocation.build_fingerprint(
            tool_name="query_range",
            effective_arguments=arguments,
        ),
        created_at=created_at,
    )
    await repository.save_tool_invocation(invocation)
    async with repository.session_factory() as session:
        row = await session.get(ToolInvocationRow, str(invocation.invocation_id))
        assert row is not None
        setattr(row, drifted_column, "tampered-audit-value")
        await session.commit()

    started = ToolInvocation.model_validate(
        {
            **invocation.model_dump(mode="python"),
            "status": ToolInvocationStatus.STARTED,
            "started_at": created_at + timedelta(seconds=1),
        }
    )
    with pytest.raises(ToolInvocationConflict):
        await repository.update_tool_invocation(started)
    await repository.close()


@pytest.mark.asyncio
async def test_repository_invocation_store_maps_pending_and_started_lifecycle(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "invocation-store.db"))
    await repository.initialize()
    run_id = await _create_run(repository, external_id="repository-invocation-store")
    invocation = ToolInvocation(
        run_id=run_id,
        tool_name="query_range",
        provider="prometheus_mcp",
        objective="Collect one bounded metric range",
        model_arguments={"query": "up"},
        effective_arguments={"query": "up"},
        fingerprint=ToolInvocation.build_fingerprint(
            tool_name="query_range",
            effective_arguments={"query": "up"},
        ),
    )
    store = RepositoryInvocationStore(repository)

    await store.save(invocation)
    started = ToolInvocation.model_validate(
        {
            **invocation.model_dump(mode="python"),
            "status": ToolInvocationStatus.STARTED,
            "started_at": datetime.now(UTC),
        }
    )
    await store.save(started)

    assert await repository.get_tool_invocation(str(invocation.invocation_id)) == started
    await repository.close()


@pytest.mark.asyncio
async def test_repository_harness_adapters_reject_stale_fencing_token(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "harness-fencing.db"))
    await repository.initialize()
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    await _create_run(
        repository,
        external_id="harness-fencing",
        manifest=manifest,
    )
    stale_token = 2

    event_sink = RepositoryEventSink(
        repository,
        lease_owner="test-worker",
        fencing_token=stale_token,
    )
    with pytest.raises(RunLeaseConflict):
        await event_sink.append(
            AgentEvent(run_id=run_id, kind=AgentEventKind.RUN_STARTED),
            expected_version=0,
        )

    invocation = ToolInvocation(
        run_id=run_id,
        tool_name="query_range",
        provider="prometheus_mcp",
        objective="Collect one bounded metric range",
        model_arguments={"query": "up"},
        effective_arguments={"query": "up"},
        fingerprint=ToolInvocation.build_fingerprint(
            tool_name="query_range",
            effective_arguments={"query": "up"},
        ),
    )
    invocation_store = RepositoryInvocationStore(
        repository,
        lease_owner="test-worker",
        fencing_token=stale_token,
    )
    with pytest.raises(RunLeaseConflict):
        await invocation_store.save(invocation)

    budget = BudgetLedger({"remote_tool_calls": 1})
    checkpoint_store = RepositoryMCPCheckpointStore[dict[str, object], dict[str, object]](
        repository,
        provider="prometheus_mcp",
        manifest_hash=manifest.digest(),
        lease_owner="test-worker",
        fencing_token=stale_token,
    )
    snapshot = MCPHarnessSnapshot(
        run_id=run_id,
        parent_run_id=None,
        state={"stage": "query_metrics"},
        messages=(),
        observations=(),
        invocations=(),
        tool_specs=(),
        fingerprints=frozenset(),
        budget=budget.snapshot(),
        finish=None,
        event_version=0,
        deadline=None,
    )
    with pytest.raises(RunLeaseConflict):
        await checkpoint_store(snapshot)

    artifact = ArtifactRef(
        kind="mcp_response",
        media_type="application/json",
        uri=f"agent-artifact://{uuid4()}",
    )
    with pytest.raises(RunLeaseConflict):
        await repository.save_agent_artifact(
            str(run_id),
            artifact,
            {"status": "success"},
            lease_owner="test-worker",
            fencing_token=stale_token,
        )

    assert await repository.get_agent_event_sequence(str(run_id)) == 0
    assert await repository.get_tool_invocation(str(invocation.invocation_id)) is None
    assert await repository.load_checkpoint(str(run_id), namespace="mcp:prometheus_mcp") is None
    assert await repository.get_agent_artifact(str(artifact.artifact_id)) is None
    await repository.close()


@pytest.mark.asyncio
async def test_domain_run_writes_reject_stale_fencing_token(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "domain-fencing.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "domain-fencing",
            "severity": "WARNING",
            "title": "Reject stale domain writes",
            "reason": "persistence contract",
        }
    )
    stored, _ = await repository.create_or_get(alert)
    run = await repository.create_run(str(stored.alert.id), "current-worker", 300)
    assert run is not None
    stale_fence = {
        "lease_owner": "stale-worker",
        "fencing_token": run.fencing_token,
    }

    with pytest.raises(RunLeaseConflict):
        await repository.save_runbooks(
            str(stored.alert.id),
            [
                RunbookExcerpt(
                    runbook_id="stale-runbook",
                    title="Stale runbook",
                    content="must not persist",
                )
            ],
            run_id=str(run.id),
            **stale_fence,
        )
    with pytest.raises(RunLeaseConflict):
        await repository.append_progress(
            str(stored.alert.id),
            ProgressRecord(
                run_id=run.id,
                stage=InvestigationStage.INVESTIGATING,
                message="stale progress",
            ),
            **stale_fence,
        )
    with pytest.raises(RunLeaseConflict):
        await repository.save_evidence(
            str(stored.alert.id),
            EvidenceRecord(
                run_id=run.id,
                tool_name="stale-tool",
                source_system="test",
                status=ToolStatus.SUCCESS,
                summary="must not persist",
            ),
            **stale_fence,
        )
    with pytest.raises(RunLeaseConflict):
        await repository.save_validation(
            str(stored.alert.id),
            ValidationRecord(
                run_id=run.id,
                kind=ValidationKind.RULE,
                passed=True,
                evidence_sufficient=True,
            ),
            **stale_fence,
        )

    current = await repository.get(str(stored.alert.id))
    assert current is not None
    assert current.manual_matches == []
    assert current.progress == []
    assert current.evidence_records == []
    assert current.validations == []
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("reanalyze", [False, True])
async def test_reclaim_and_new_run_creation_serialize_on_alert_row(
    tmp_path: Path,
    reanalyze: bool,
) -> None:
    database_url = sqlite_url(tmp_path / f"claim-race-{reanalyze}.db")
    reclaim_repository = SQLAlchemyAlertRepository(database_url)
    create_repository = SQLAlchemyAlertRepository(database_url)
    await reclaim_repository.initialize()
    await create_repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": f"claim-race-{reanalyze}",
            "severity": "WARNING",
            "title": "Serialize run claims",
            "reason": "persistence contract",
        }
    )
    stored, _ = await reclaim_repository.create_or_get(alert)
    original_run_id = uuid4()
    original_manifest = RunManifest(
        run_id=original_run_id,
        agent_name="database-alert-investigation",
        code_version="test",
    )
    original = await reclaim_repository.create_run(
        str(stored.alert.id),
        "expired-worker",
        300,
        manifest=original_manifest,
    )
    assert original is not None
    await reclaim_repository.save_checkpoint(
        RunCheckpoint(
            run_id=original.id,
            version=1,
            sequence=1,
            state={"stage": "received"},
            manifest_hash=original_manifest.digest(),
        ),
        expected_version=0,
        lease_owner="expired-worker",
        fencing_token=original.fencing_token,
    )
    async with reclaim_repository.session_factory() as session:
        row = await session.get(InvestigationRunRow, str(original.id))
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    replacement_run_id = uuid4()
    replacement_snapshot = AnalysisConfigSnapshot(code_version="test")
    replacement_manifest = original_manifest.model_copy(update={"run_id": replacement_run_id})

    async def create_replacement():
        if reanalyze:
            return await create_repository.create_run_for_reanalyze(
                str(stored.alert.id),
                "new-worker",
                300,
                replacement_snapshot,
                manifest=replacement_manifest,
            )
        return await create_repository.create_run(
            str(stored.alert.id),
            "new-worker",
            300,
            config_snapshot=replacement_snapshot,
            manifest=replacement_manifest,
        )

    reclaimed, created = await asyncio.gather(
        reclaim_repository.reclaim_expired_run(str(stored.alert.id), "recovery-worker", 300),
        create_replacement(),
    )

    assert sum(item is not None for item in (reclaimed, created)) == 1
    current = await reclaim_repository.get(str(stored.alert.id))
    assert current is not None and current.latest_run is not None
    running = [item for item in current.all_runs if item.status == RunStatus.RUNNING]
    assert len(running) == 1
    assert running[0].id == current.latest_run.id
    if reclaimed is not None:
        assert current.latest_run.id == original.id
        assert current.latest_run.lease_owner == "recovery-worker"
        assert current.latest_run.fencing_token == original.fencing_token + 1
    else:
        assert created is not None
        assert current.latest_run.id == replacement_run_id
        assert current.latest_run.lease_owner == "new-worker"

    await create_repository.close()
    await reclaim_repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("suffix", "content", "expected"),
    [
        ("bytes", b"\x00\xff", b"\x00\xff"),
        ("text", "token=text-secret", f"token={REDACTED}"),
        ("json", {"token": "json-secret", "value": 1}, {"token": REDACTED, "value": 1}),
    ],
)
async def test_agent_artifact_validates_hash_and_restores_supported_content(
    tmp_path: Path,
    suffix: str,
    content: bytes | str | dict[str, object],
    expected: bytes | str | dict[str, object],
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / f"artifact-{suffix}.db"))
    await repository.initialize()
    run_id = await _create_run(repository, external_id=f"artifact-{suffix}")
    artifact = ArtifactRef(
        kind="tool_result",
        media_type="application/octet-stream" if suffix == "bytes" else "application/json",
        uri=f"agent-artifact://{uuid4()}",
    )

    stored = await repository.save_agent_artifact(str(run_id), artifact, content)
    assert stored.sha256 is not None and len(stored.sha256) == 64
    assert stored.size_bytes is not None
    assert await repository.get_agent_artifact(str(stored.artifact_id)) == (
        stored,
        expected,
    )

    mismatched = ArtifactRef(
        kind="tool_result",
        media_type="text/plain",
        uri=f"agent-artifact://{uuid4()}",
        sha256="b" * 64,
        size_bytes=1,
    )
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        await repository.save_agent_artifact(str(run_id), mismatched, "different")
    await repository.close()
