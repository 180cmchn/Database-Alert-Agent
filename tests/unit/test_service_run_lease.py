from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from app.adapters.persistence import InvestigationRunRow
from app.agent_runtime.contracts import RunCheckpoint
from app.agent_runtime.leases import LeaseLostError
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.errors import AnalysisFailedError
from app.domain.models import AlertStatus, InvestigationStage, RunStatus


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
    )


class BlockingAgent:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def run(self, _: object) -> None:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


class RecordingTerminalAgent:
    def __init__(self) -> None:
        self.called = False

    async def run(self, state):  # type: ignore[no-untyped-def]
        self.called = True
        return state.model_copy(
            update={
                "status": AlertStatus.INCONCLUSIVE,
                "run_status": RunStatus.INCONCLUSIVE,
                "current_stage": InvestigationStage.INCONCLUSIVE,
            }
        )


def test_run_manifest_uses_harness_only_mcp_configuration(tmp_path: Path) -> None:
    runtime = build_runtime(_settings(tmp_path))

    snapshot = runtime.service._create_config_snapshot()
    manifest = runtime.service._create_run_manifest(uuid4(), snapshot)

    assert "archery_mcp_use_shared_harness" not in type(snapshot).model_fields
    assert "prometheus_mcp_use_shared_harness" not in type(snapshot).model_fields
    assert "archery_mcp_use_shared_harness" not in manifest.configuration
    assert "prometheus_mcp_use_shared_harness" not in manifest.configuration


@pytest.mark.asyncio
async def test_service_force_reanalysis_supersedes_an_active_run(tmp_path: Path) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "force-active-service-run",
            "severity": "WARNING",
            "title": "Force active analysis replacement",
            "reason": "test",
        },
    )
    first = await runtime.repository.create_run(
        str(stored.alert.id),
        "first-worker",
        300,
    )
    assert first is not None
    try:
        replacement, _ = await runtime.service.reanalyze(
            str(stored.alert.id),
            force=True,
        )

        current = await runtime.repository.get(str(stored.alert.id))
        assert current is not None and current.latest_run is not None
        assert current.latest_run.id == replacement.id
        assert current.latest_run.status == RunStatus.RUNNING

        async with asyncio.timeout(3):
            while current.latest_run.status == RunStatus.RUNNING:
                await asyncio.sleep(0.01)
                current = await runtime.repository.get(str(stored.alert.id))
                assert current is not None and current.latest_run is not None
        assert current.latest_run.status == RunStatus.INCONCLUSIVE
        prior = next(item for item in current.all_runs if item.id == first.id)
        assert prior.status == RunStatus.FAILED
        assert prior.error == "Superseded by forced re-analysis"
        assert (
            await runtime.repository.renew_run_lease(
                str(first.id),
                "first-worker",
                first.fencing_token,
                300,
            )
            is False
        )
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_service_lost_heartbeat_cancels_agent_without_writing_final_state(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    blocking_agent = BlockingAgent()
    runtime.service.agent = blocking_agent  # type: ignore[assignment]
    runtime.service.lease_heartbeat_interval_seconds = 0.005
    renew_calls: list[tuple[str, str, int, int]] = []

    async def reject_renewal(
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool:
        renew_calls.append((run_id, lease_owner, fencing_token, lease_seconds))
        return False

    runtime.repository.renew = reject_renewal  # type: ignore[method-assign]
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "lost-service-lease",
            "severity": "WARNING",
            "title": "Lease lost during investigation",
            "reason": "test",
        },
    )
    alert_id = str(stored.alert.id)
    try:
        with pytest.raises(LeaseLostError):
            async with asyncio.timeout(1):
                await runtime.service.analyze_by_id(alert_id)

        current = await runtime.repository.get(alert_id)
        assert current is not None
        assert current.status == AlertStatus.ANALYZING
        assert current.error is None
        assert current.recommendation is None
        assert current.latest_run is not None
        assert current.latest_run.status == RunStatus.RUNNING
        assert all(item.stage != InvestigationStage.FAILED for item in current.progress)
        assert blocking_agent.started.is_set()
        assert blocking_agent.cancelled.is_set()
        assert renew_calls == [
            (
                str(current.latest_run.id),
                current.latest_run.lease_owner,
                current.latest_run.fencing_token,
                runtime.service.investigation_lease_seconds,
            )
        ]
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_analysis_timeout_cancels_agent_and_persists_failed_run(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    blocking_agent = BlockingAgent()
    runtime.service.agent = blocking_agent  # type: ignore[assignment]
    run_with_controls = runtime.service._run_agent_with_controls

    async def run_with_short_timeout(*, run_id: str, operation: Any, timeout_seconds: int) -> Any:
        del timeout_seconds
        return await run_with_controls(
            run_id=run_id,
            operation=operation,
            timeout_seconds=0.01,  # type: ignore[arg-type]
        )

    runtime.service._run_agent_with_controls = run_with_short_timeout  # type: ignore[method-assign]
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "whole-analysis-timeout",
            "severity": "WARNING",
            "title": "Whole analysis timeout",
            "reason": "test",
        },
    )
    alert_id = str(stored.alert.id)
    try:
        with pytest.raises(AnalysisFailedError, match="Analysis timed out after 0.01 seconds"):
            await runtime.service.analyze_by_id(alert_id)

        current = await runtime.repository.get(alert_id)
        assert current is not None and current.latest_run is not None
        assert current.status == AlertStatus.FAILED
        assert current.latest_run.status == RunStatus.FAILED
        assert current.latest_run.current_stage == InvestigationStage.FAILED
        assert current.latest_run.error is not None
        assert "Analysis timed out after 0.01 seconds" in current.latest_run.error
        assert blocking_agent.cancelled.is_set()
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_same_process_cancellation_persists_cancelled_run(tmp_path: Path) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    blocking_agent = BlockingAgent()
    runtime.service.agent = blocking_agent  # type: ignore[assignment]
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "same-process-cancel",
            "severity": "WARNING",
            "title": "Same process cancellation",
            "reason": "test",
        },
    )
    alert_id = str(stored.alert.id)
    analysis = asyncio.create_task(runtime.service.analyze_by_id(alert_id))
    try:
        await blocking_agent.started.wait()
        current = await runtime.repository.get(alert_id)
        assert current is not None and current.latest_run is not None
        run_id = str(current.latest_run.id)

        requested = await runtime.service.cancel_run(
            alert_id,
            run_id,
            requested_by="unit-test",
        )
        assert requested.cancel_requested_at is not None

        result = await analysis
        assert result.status == AlertStatus.CANCELLED
        assert result.latest_run is not None
        assert result.latest_run.status == RunStatus.CANCELLED
        assert result.latest_run.cancel_requested_by == "unit-test"
        assert result.latest_run.cancelled_at is not None
        assert blocking_agent.cancelled.is_set()
    finally:
        if not analysis.done():
            analysis.cancel()
            await asyncio.gather(analysis, return_exceptions=True)
        await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_cross_service_cancellation_is_observed_from_database(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    worker_runtime = build_runtime(settings)
    api_runtime = build_runtime(settings)
    await worker_runtime.repository.initialize()
    await api_runtime.repository.initialize()
    blocking_agent = BlockingAgent()
    worker_runtime.service.agent = blocking_agent  # type: ignore[assignment]
    stored, _ = await worker_runtime.service.ingest(
        "canonical",
        {
            "external_id": "cross-process-cancel",
            "severity": "WARNING",
            "title": "Cross process cancellation",
            "reason": "test",
        },
    )
    alert_id = str(stored.alert.id)
    analysis = asyncio.create_task(worker_runtime.service.analyze_by_id(alert_id))
    try:
        await blocking_agent.started.wait()
        current = await worker_runtime.repository.get(alert_id)
        assert current is not None and current.latest_run is not None
        run_id = str(current.latest_run.id)

        requested = await api_runtime.service.cancel_run(
            alert_id,
            run_id,
            requested_by="remote-api",
        )
        assert requested.cancel_requested_at is not None
        async with asyncio.timeout(2):
            result = await analysis

        assert result.status == AlertStatus.CANCELLED
        assert result.latest_run is not None
        assert result.latest_run.status == RunStatus.CANCELLED
        assert blocking_agent.cancelled.is_set()
    finally:
        if not analysis.done():
            analysis.cancel()
            await asyncio.gather(analysis, return_exceptions=True)
        await api_runtime.repository.close()  # type: ignore[attr-defined]
        await worker_runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_service_shutdown_cancellation_is_not_recorded_as_user_cancel(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    blocking_agent = BlockingAgent()
    runtime.service.agent = blocking_agent  # type: ignore[assignment]
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "shutdown-cancel",
            "severity": "WARNING",
            "title": "Shutdown cancellation",
            "reason": "test",
        },
    )
    alert_id = str(stored.alert.id)
    analysis = asyncio.create_task(runtime.service.analyze_by_id(alert_id))
    try:
        await blocking_agent.started.wait()
        await runtime.service.close()
        with pytest.raises(asyncio.CancelledError):
            await analysis

        current = await runtime.repository.get(alert_id)
        assert current is not None and current.latest_run is not None
        assert current.status == AlertStatus.ANALYZING
        assert current.latest_run.status == RunStatus.RUNNING
        assert current.latest_run.cancel_requested_at is None
        assert current.latest_run.cancelled_at is None
    finally:
        if not analysis.done():
            analysis.cancel()
            await asyncio.gather(analysis, return_exceptions=True)
        await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_graph_updates_are_fenced_with_the_claimed_run_identity(tmp_path: Path) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    update_calls: list[tuple[str, dict[str, Any]]] = []
    finalize_calls: list[tuple[str, str, dict[str, Any]]] = []
    original_update_run = runtime.repository.update_run
    original_finalize_run = runtime.repository.finalize_run

    async def record_update(run_id: str, **changes: Any) -> None:
        update_calls.append((run_id, dict(changes)))
        await original_update_run(run_id, **changes)

    async def record_finalize(alert_id: str, run_id: str, **changes: Any) -> Any:
        finalize_calls.append((alert_id, run_id, dict(changes)))
        return await original_finalize_run(alert_id, run_id, **changes)

    runtime.repository.update_run = record_update  # type: ignore[method-assign]
    runtime.repository.finalize_run = record_finalize  # type: ignore[method-assign]
    try:
        result = await runtime.service.analyze(
            "canonical",
            {
                "external_id": "fenced-graph-updates",
                "severity": "WARNING",
                "title": "Verify graph write fencing",
                "reason": "test",
            },
        )

        assert result.latest_run is not None
        run = result.latest_run
        assert update_calls
        assert all(run_id == str(run.id) for run_id, _ in update_calls)
        assert all(changes.get("lease_owner") == run.lease_owner for _, changes in update_calls)
        assert all(changes.get("fencing_token") == run.fencing_token for _, changes in update_calls)
        assert len(finalize_calls) == 1
        finalized_alert_id, finalized_run_id, final_changes = finalize_calls[0]
        assert finalized_alert_id == str(result.alert.id)
        assert finalized_run_id == str(run.id)
        assert final_changes["lease_owner"] == run.lease_owner
        assert final_changes["fencing_token"] == run.fencing_token
        assert final_changes["run_status"] == RunStatus.INCONCLUSIVE
        assert final_changes["alert_status"] == AlertStatus.INCONCLUSIVE
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_reclaimed_run_with_changed_prompt_fails_without_new_attempt(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(_settings(tmp_path))
    await runtime.repository.initialize()
    stored, _ = await runtime.service.ingest(
        "canonical",
        {
            "external_id": "incompatible-resume",
            "severity": "WARNING",
            "title": "Restart mixed runtime recovery",
            "reason": "test",
        },
    )
    run_id = uuid4()
    snapshot = runtime.service._create_config_snapshot()
    manifest = runtime.service._create_run_manifest(run_id, snapshot)
    run = await runtime.repository.create_run(
        str(stored.alert.id),
        "original-worker",
        300,
        config_snapshot=snapshot,
        manifest=manifest,
    )
    assert run is not None
    await runtime.repository.save_checkpoint(
        RunCheckpoint(
            run_id=run.id,
            version=1,
            sequence=0,
            state={"stage": "received"},
            manifest_hash=manifest.digest(),
        ),
        expected_version=0,
        lease_owner="original-worker",
        fencing_token=run.fencing_token,
    )
    async with runtime.repository.session_factory() as session:  # type: ignore[attr-defined]
        row = await session.get(InvestigationRunRow, str(run.id))
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    replacement_agent = RecordingTerminalAgent()
    runtime.service.agent = replacement_agent  # type: ignore[assignment]
    runtime.service.runtime_manifest_config["prompt_version"] = "next-prompt-version"
    try:
        result = await runtime.service.analyze_by_id(str(stored.alert.id))

        assert result.status == AlertStatus.FAILED
        assert replacement_agent.called is False
        assert result.latest_run is not None
        assert result.latest_run.id == run.id
        assert result.latest_run.attempt == run.attempt
        assert result.latest_run.fencing_token == run.fencing_token + 1
        assert result.latest_run.status == RunStatus.FAILED
        assert result.latest_run.model_failure is not None
        assert result.latest_run.model_failure.category.value == "INTERNAL"
        assert result.latest_run.error == (
            "Frozen run manifest is incompatible with the current runtime: "
            "configuration, prompt_version"
        )
        assert len(result.all_runs) == 1
    finally:
        await runtime.repository.close()  # type: ignore[attr-defined]
