from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import (
    AgentArtifactRow,
    EvidenceRow,
    InvestigationRunRow,
    SQLAlchemyAlertRepository,
    ToolInvocationRow,
)
from app.adapters.tool_result_analysis import DeterministicToolResultProcessor
from app.agent_runtime.contracts import (
    RunCheckpoint,
    RunManifest,
    ToolInvocationStatus,
    ToolSpec,
)
from app.agent_runtime.outer_dispatch import (
    OUTER_EVIDENCE_RESULT_CONTRACT,
    DurableOuterToolDispatcher,
    OuterDispatchError,
    OuterDispatchFaultPoint,
)
from app.domain.models import (
    EVIDENCE_RECORD_V2,
    EvidenceRecord,
    EvidenceUnit,
    EvidenceUnitKind,
    EvidenceUnitStatus,
    InvestigationContext,
    ToolExecutionRequest,
    ToolResultAnalysis,
    ToolResultObservation,
    ToolStatus,
)
from app.domain.ports import EvidenceRecordConflict, ToolInvocationConflict


def _sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


class RecordingExecutor:
    def __init__(
        self,
        outcomes: Sequence[dict[str, object]] | None = None,
        *,
        source_system: str = "test_host",
        status: ToolStatus = ToolStatus.SUCCESS,
    ) -> None:
        self.outcomes = list(outcomes or [{}])
        self.source_system = source_system
        self.status = status
        self.calls: list[ToolExecutionRequest] = []
        self.contexts: list[InvestigationContext] = []

    async def execute(
        self,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> EvidenceRecord:
        self.calls.append(request)
        self.contexts.append(context)
        index = min(len(self.calls) - 1, len(self.outcomes) - 1)
        structured_data = dict(self.outcomes[index])
        return EvidenceRecord(
            run_id=context.run_id,
            tool_name=request.tool_name,
            source_system=self.source_system,
            status=self.status,
            request=request.parameters,
            summary="collected",
            structured_data=structured_data,
        )


class RecordingResultProcessor:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls: list[dict[str, object]] = []

    async def analyze(self, **payload):  # type: ignore[no-untyped-def]
        self.calls.append(payload)
        if self.failure is not None:
            raise self.failure
        artifact = payload["artifact"]
        assert artifact.sha256 is not None
        return ToolResultAnalysis(
            summary="程序事实投影已从完整结果中提取可核验事实。",
            observations=[
                ToolResultObservation(
                    statement="工具返回了完整的大结果。",
                    source_paths=["/structured_data/payload"],
                )
            ],
            anomalies=[],
            limitations=[],
            analysis_usable=True,
            source_coverage_complete=True,
            source_artifact_id=artifact.artifact_id,
            source_sha256=artifact.sha256,
            provider="fake",
            model="tool-result-test",
            prompt_version="tool-result-analysis-test-v1",
        )


class ArcheryUnitResultProcessor(RecordingResultProcessor):
    async def analyze(self, **payload):  # type: ignore[no-untyped-def]
        artifact = payload["artifact"]
        assert artifact.sha256 is not None
        raw_data = payload["raw_result"]["structured_data"]
        history = dict(raw_data["final_result_payload"])
        slow_query_analysis = dict(raw_data["slow_query_analysis"])
        return ToolResultAnalysis(
            summary="Archery history and supplemental results projected.",
            observations=[
                ToolResultObservation(
                    statement="Archery history returned one row.",
                    source_paths=["/structured_data/final_result_payload"],
                )
            ],
            analysis_usable=True,
            source_coverage_complete=True,
            source_artifact_id=artifact.artifact_id,
            source_sha256=artifact.sha256,
            provider="deterministic_host",
            model="none",
            prompt_version="tool-result-analysis-test-v1",
            passthrough_payload=history,
            slow_query_analysis=slow_query_analysis,
        )


class SlowExecutor(RecordingExecutor):
    async def execute(
        self,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> EvidenceRecord:
        self.calls.append(request)
        self.contexts.append(context)
        await asyncio.sleep(1)
        raise AssertionError("dispatcher did not enforce the frozen deadline")


class BlockingExecutor(RecordingExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(
        self,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> EvidenceRecord:
        self.calls.append(request)
        self.contexts.append(context)
        self.started.set()
        await self.release.wait()
        return EvidenceRecord(
            run_id=context.run_id,
            tool_name=request.tool_name,
            source_system=self.source_system,
            status=ToolStatus.SUCCESS,
            request=request.parameters,
            summary="collected",
        )


class CrashAt:
    def __init__(self, point: OuterDispatchFaultPoint) -> None:
        self.point = point
        self.triggered = False

    async def __call__(
        self,
        point: OuterDispatchFaultPoint,
        _invocation,
        _evidence,
    ) -> None:
        if point == self.point and not self.triggered:
            self.triggered = True
            raise RuntimeError(f"simulated crash at {point.value}")


class HoldAfterHandler:
    def __init__(self) -> None:
        self.reached = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(
        self,
        point: OuterDispatchFaultPoint,
        _invocation,
        _evidence,
    ) -> None:
        if point == OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED:
            self.reached.set()
            await self.release.wait()


async def _context(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
) -> tuple[str, InvestigationContext]:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": external_id,
            "severity": "WARNING",
            "title": "Durable outer tool dispatch",
            "reason": "test",
        }
    )
    stored, _created = await repository.create_or_get(alert)
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="outer-dispatch-test",
        code_version="test",
    )
    run = await repository.create_run(
        str(stored.alert.id),
        "outer-worker",
        300,
        manifest=manifest,
    )
    assert run is not None and run.lease_owner is not None
    await repository.save_checkpoint(
        RunCheckpoint(
            run_id=run.id,
            version=1,
            sequence=0,
            manifest_hash=manifest.digest(),
        ),
        expected_version=0,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )
    return str(stored.alert.id), InvestigationContext(
        run_id=run.id,
        alert=alert,
        lease_owner=run.lease_owner,
        fencing_token=run.fencing_token,
    )


async def _reclaim_context(
    repository: SQLAlchemyAlertRepository,
    *,
    alert_id: str,
    context: InvestigationContext,
) -> InvestigationContext:
    async with repository.session_factory() as session:
        row = await session.get(InvestigationRunRow, str(context.run_id))
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    next_token = (context.fencing_token or 0) + 1
    reclaimed = await repository.reclaim_expired_run(
        alert_id,
        f"outer-recovery-worker-{next_token}",
        300,
    )
    assert reclaimed is not None and reclaimed.lease_owner is not None
    assert reclaimed.fencing_token == next_token
    return context.model_copy(
        update={
            "lease_owner": reclaimed.lease_owner,
            "fencing_token": reclaimed.fencing_token,
        }
    )


def _request(*, timeout_seconds: float = 30) -> ToolExecutionRequest:
    return ToolExecutionRequest(
        tool_name="test_probe",
        parameters={"labels": {"b": "2", "a": "1"}},
        objective="collect test evidence",
        timeout_seconds=timeout_seconds,
    )


def _spec() -> ToolSpec:
    return ToolSpec(
        name="test_probe",
        provider="test_host",
        capability="test.probe",
        input_schema={"type": "object", "additionalProperties": True},
        policy_version="test-policy-v1",
        schema_version="test-schema-v1",
    )


async def _invocation_rows(
    repository: SQLAlchemyAlertRepository,
    run_id: str,
) -> list[ToolInvocationRow]:
    async with repository.session_factory() as session:
        return list(
            (
                await session.execute(
                    select(ToolInvocationRow)
                    .where(ToolInvocationRow.run_id == run_id)
                    .order_by(ToolInvocationRow.attempt)
                )
            )
            .scalars()
            .all()
        )


@pytest.mark.asyncio
async def test_pending_dispatch_resumes_without_replaying_completed_handler(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "pending.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-pending")
    executor = RecordingExecutor()
    crash = CrashAt(OuterDispatchFaultPoint.AFTER_PENDING_PERSISTED)

    with pytest.raises(RuntimeError, match="AFTER_PENDING_PERSISTED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=crash,
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [ToolInvocationStatus.PENDING.value]
    assert executor.calls == []

    dispatcher = DurableOuterToolDispatcher(repository, executor)
    evidence = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    await repository.save_evidence(
        alert_id,
        evidence,
        lease_owner=context.lease_owner or "",
        fencing_token=context.fencing_token or 0,
    )
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    await repository.save_evidence(
        alert_id,
        replayed,
        lease_owner=context.lease_owner or "",
        fencing_token=context.fencing_token or 0,
    )

    assert replayed == evidence
    assert len(executor.calls) == 1
    async with repository.session_factory() as session:
        evidence_rows = (
            (
                await session.execute(
                    select(EvidenceRow).where(EvidenceRow.run_id == str(context.run_id))
                )
            )
            .scalars()
            .all()
        )
    assert len(evidence_rows) == 1
    await repository.close()


@pytest.mark.asyncio
async def test_expired_pending_dispatch_becomes_timeout_without_handler_call(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "pending-expired.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-pending-expired")
    executor = RecordingExecutor()
    request = _request(timeout_seconds=0.001)

    with pytest.raises(RuntimeError, match="AFTER_PENDING_PERSISTED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_PENDING_PERSISTED),
        ).execute(
            alert_id=alert_id,
            request=request,
            context=context,
            tool_spec=_spec(),
        )
    await asyncio.sleep(0.01)

    evidence = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=_spec(),
    )

    assert executor.calls == []
    assert evidence.status == ToolStatus.TIMEOUT
    assert evidence.structured_data["reason_code"] == "invocation_deadline_exceeded_before_dispatch"
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [item.status for item in rows] == [ToolInvocationStatus.TIMED_OUT.value]
    await repository.close()


@pytest.mark.asyncio
async def test_new_fencing_epoch_marks_started_action_unknown_without_replay(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "started-retry.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-started-retry")
    executor = RecordingExecutor()

    with pytest.raises(RuntimeError, match="AFTER_HANDLER_RETURNED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED),
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    assert len(executor.calls) == 1

    recovery_context = await _reclaim_context(
        repository,
        alert_id=alert_id,
        context=context,
    )

    dispatcher = DurableOuterToolDispatcher(repository, executor)
    evidence = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=recovery_context,
        tool_spec=_spec(),
    )
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=recovery_context,
        tool_spec=_spec(),
    )

    assert evidence == replayed
    assert evidence.status == ToolStatus.FAILED
    assert evidence.structured_data["reason_code"] == "unknown_outcome"
    assert len(executor.calls) == 1
    assert all(item.outer_dispatch_id is not None for item in executor.contexts)
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME.value,
    ]
    assert len(rows) == 1
    await repository.close()


@pytest.mark.asyncio
async def test_same_epoch_recovers_started_only_after_persisted_deadline(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "deadline-recovery.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-deadline-recovery")
    executor = RecordingExecutor()
    request = _request(timeout_seconds=0.5)

    with pytest.raises(RuntimeError, match="AFTER_HANDLER_RETURNED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED),
        ).execute(
            alert_id=alert_id,
            request=request,
            context=context,
            tool_spec=_spec(),
        )
    await asyncio.sleep(0.55)

    evidence = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=_spec(),
    )

    assert evidence.status == ToolStatus.FAILED
    assert evidence.structured_data["reason_code"] == "unknown_outcome"
    assert len(executor.calls) == 1
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME.value,
    ]
    await repository.close()


@pytest.mark.asyncio
async def test_late_same_epoch_result_cannot_overwrite_deadline_recovery(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "late-result.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-late-result")
    executor = RecordingExecutor()
    hold = HoldAfterHandler()
    request = _request(timeout_seconds=0.5)
    tool_spec = _spec()

    first_task = asyncio.create_task(
        DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=hold,
        ).execute(
            alert_id=alert_id,
            request=request,
            context=context,
            tool_spec=tool_spec,
        )
    )
    await hold.reached.wait()
    recovered = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=tool_spec,
    )

    assert recovered.structured_data["reason_code"] == "unknown_outcome"
    hold.release.set()
    original = await first_task

    assert original == recovered
    assert len(executor.calls) == 1
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [ToolInvocationStatus.UNKNOWN_OUTCOME.value]
    await repository.close()


@pytest.mark.asyncio
async def test_same_epoch_concurrent_dispatch_joins_inflight_invocation(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "same-epoch.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-same-epoch")
    executor = BlockingExecutor()
    dispatcher = DurableOuterToolDispatcher(repository, executor)

    first_task = asyncio.create_task(
        dispatcher.execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    )
    await executor.started.wait()
    second_task = asyncio.create_task(
        dispatcher.execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    )
    await asyncio.sleep(0.1)

    assert second_task.done() is False
    assert len(executor.calls) == 1
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [ToolInvocationStatus.STARTED.value]
    assert rows[0].invocation_json["execution_lease_owner"] == context.lease_owner
    assert rows[0].invocation_json["execution_fencing_token"] == context.fencing_token

    executor.release.set()
    first, second = await asyncio.gather(first_task, second_task)

    assert first == second
    assert len(executor.calls) == 1
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [ToolInvocationStatus.SUCCEEDED.value]
    await repository.close()


@pytest.mark.asyncio
async def test_started_execution_epoch_is_immutable(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "epoch-frozen.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-epoch-frozen")

    with pytest.raises(RuntimeError, match="AFTER_STARTED_PERSISTED"):
        await DurableOuterToolDispatcher(
            repository,
            RecordingExecutor(),
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_STARTED_PERSISTED),
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    rows = await _invocation_rows(repository, str(context.run_id))
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.execution_fencing_token is not None
    tampered = invocation.model_copy(
        update={"execution_fencing_token": invocation.execution_fencing_token + 1}
    )

    with pytest.raises(ToolInvocationConflict, match="immutable invocation identity"):
        await repository.update_tool_invocation(
            tampered,
            expected_status=ToolInvocationStatus.STARTED,
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )
    await repository.close()


@pytest.mark.asyncio
async def test_frozen_outer_deadline_bounds_handler_execution(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "handler-timeout.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-handler-timeout")
    executor = SlowExecutor()
    processor = RecordingResultProcessor()

    evidence = await DurableOuterToolDispatcher(
        repository,
        executor,
        result_analyzer=processor,
    ).execute(
        alert_id=alert_id,
        # The frozen budget includes durable PENDING and STARTED writes. Leave
        # enough room for those SQLite commits so this test reaches the handler
        # boundary before verifying cancellation by the same persisted deadline.
        request=_request(timeout_seconds=0.2),
        context=context,
        tool_spec=_spec(),
    )

    assert len(executor.calls) == 1
    assert processor.calls == []
    assert evidence.status == ToolStatus.TIMEOUT
    assert evidence.summary == "调查工具 test_probe 已达到持久化调用期限。"
    assert evidence.structured_data["reason_code"] == "outer_invocation_deadline_exceeded"
    assert evidence.structured_data["processing_status"] == "unavailable"
    assert evidence.structured_data["root_cause_eligible"] is False
    assert evidence.structured_data["root_cause_ineligible_reason"] == ("tool_status_not_success")
    assert evidence.duration_ms > 0
    assert evidence.duration_ms == max(
        0,
        int((evidence.collected_at - evidence.started_at).total_seconds() * 1000),
    )
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [ToolInvocationStatus.TIMED_OUT.value]
    await repository.close()


@pytest.mark.asyncio
async def test_pending_recovery_rejects_request_timeout_drift(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "timeout-drift.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-timeout-drift")
    executor = RecordingExecutor()

    with pytest.raises(RuntimeError, match="AFTER_PENDING_PERSISTED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_PENDING_PERSISTED),
        ).execute(
            alert_id=alert_id,
            request=_request(timeout_seconds=30),
            context=context,
            tool_spec=_spec(),
        )

    with pytest.raises(OuterDispatchError, match="identity does not match"):
        await DurableOuterToolDispatcher(repository, executor).execute(
            alert_id=alert_id,
            request=_request(timeout_seconds=60),
            context=context,
            tool_spec=_spec(),
        )
    assert executor.calls == []
    await repository.close()


@pytest.mark.asyncio
async def test_executor_cannot_spoof_frozen_provider_provenance(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "provider-spoof.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-provider-spoof")

    evidence = await DurableOuterToolDispatcher(
        repository,
        RecordingExecutor(source_system="spoofed_live_provider"),
    ).execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert evidence.status == ToolStatus.FAILED
    assert evidence.source_system == "test_host"
    assert evidence.structured_data["reason_code"] == "host_result_processing_error"
    assert evidence.structured_data["root_cause_eligible"] is False
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["run_id", "tool_name", "request", "source_system"])
async def test_terminal_recovery_rejects_tampered_evidence_provenance(
    tmp_path: Path,
    field: str,
) -> None:
    repository = SQLAlchemyAlertRepository(
        _sqlite_url(tmp_path / f"terminal-provenance-{field}.db")
    )
    await repository.initialize()
    alert_id, context = await _context(
        repository,
        external_id=f"outer-terminal-provenance-{field}",
    )
    dispatcher = DurableOuterToolDispatcher(repository, RecordingExecutor())
    await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    row = (await _invocation_rows(repository, str(context.run_id)))[0]
    replacements: dict[str, object] = {
        "run_id": "00000000-0000-0000-0000-000000000001",
        "tool_name": "another_probe",
        "request": {"labels": {"a": "changed"}},
        "source_system": "spoofed_live_provider",
    }
    async with repository.session_factory() as session:
        stored = await session.get(ToolInvocationRow, row.id)
        assert stored is not None and isinstance(stored.result_json, dict)
        result = dict(stored.result_json)
        record = dict(result["evidence_record"])
        record[field] = replacements[field]
        result["evidence_record"] = record
        stored.result_json = result
        await session.commit()

    with pytest.raises(OuterDispatchError, match="provenance does not match"):
        await dispatcher.execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    await repository.close()


@pytest.mark.asyncio
async def test_unregistered_started_action_recovers_unknown_without_replay(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "unregistered-unknown.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="unregistered-unknown")
    executor = RecordingExecutor()

    with pytest.raises(RuntimeError, match="AFTER_HANDLER_RETURNED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED),
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=None,
        )
    recovery_context = await _reclaim_context(
        repository,
        alert_id=alert_id,
        context=context,
    )
    evidence = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=_request(),
        context=recovery_context,
        tool_spec=None,
    )

    assert len(executor.calls) == 1
    assert evidence.status == ToolStatus.FAILED
    assert evidence.structured_data["reason_code"] == "unknown_outcome"
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [ToolInvocationStatus.UNKNOWN_OUTCOME.value]
    await repository.close()


@pytest.mark.asyncio
async def test_recovery_fails_closed_when_frozen_tool_contract_drifts(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "spec-drift.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-spec-drift")
    executor = RecordingExecutor()

    with pytest.raises(RuntimeError, match="AFTER_PENDING_PERSISTED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_PENDING_PERSISTED),
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    drifted = _spec().model_copy(update={"policy_version": "test-policy-v2"})

    with pytest.raises(OuterDispatchError, match="identity does not match"):
        await DurableOuterToolDispatcher(repository, executor).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=drifted,
        )
    assert executor.calls == []
    await repository.close()


@pytest.mark.asyncio
async def test_second_started_recovery_never_creates_a_third_attempt(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "second-started.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-second-started")
    executor = RecordingExecutor()

    with pytest.raises(RuntimeError, match="AFTER_HANDLER_RETURNED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED),
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )

    active_context = context
    recovered: list[EvidenceRecord] = []
    for _recovery in range(2):
        active_context = await _reclaim_context(
            repository,
            alert_id=alert_id,
            context=active_context,
        )
        recovered.append(
            await DurableOuterToolDispatcher(repository, executor).execute(
                alert_id=alert_id,
                request=_request(),
                context=active_context,
                tool_spec=_spec(),
            )
        )

    assert recovered[0] == recovered[1]
    assert len(executor.calls) == 1
    assert recovered[-1].structured_data["reason_code"] == "unknown_outcome"
    rows = await _invocation_rows(repository, str(context.run_id))
    assert len(rows) == 1
    assert {row.status for row in rows} == {ToolInvocationStatus.UNKNOWN_OUTCOME.value}
    await repository.close()


@pytest.mark.asyncio
async def test_terminal_result_backfills_evidence_without_handler_replay(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "terminal.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-terminal")
    executor = RecordingExecutor([{"payload": "x" * 13_000}])

    with pytest.raises(RuntimeError, match="AFTER_TERMINAL_PERSISTED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_TERMINAL_PERSISTED),
        ).execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(),
        )
    dispatcher = DurableOuterToolDispatcher(repository, executor)
    evidence = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    await repository.save_evidence(
        alert_id,
        evidence,
        lease_owner=context.lease_owner or "",
        fencing_token=context.fencing_token or 0,
    )
    await repository.save_evidence(
        alert_id,
        evidence,
        lease_owner=context.lease_owner or "",
        fencing_token=context.fencing_token or 0,
    )

    assert len(executor.calls) == 1
    assert evidence.structured_data["processing_status"] == "unavailable"
    assert "payload" not in evidence.structured_data
    assert "source_artifact" not in evidence.structured_data
    rows = await _invocation_rows(repository, str(context.run_id))
    result = await repository.get_tool_invocation_result(rows[0].id)
    assert result is not None
    assert result["contract"] == OUTER_EVIDENCE_RESULT_CONTRACT
    assert "payload" not in result["evidence_record"]["structured_data"]
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.artifact_ref is not None
    stored = await repository.get_agent_artifact(str(invocation.artifact_ref.artifact_id))
    assert stored is not None
    assert stored[1]["structured_data"]["payload"] == "x" * 13_000
    await repository.close()


@pytest.mark.asyncio
async def test_result_is_artifacted_and_projected_by_program_processor(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "large-analysis.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-large-analysis")
    executor = RecordingExecutor([{"payload": "x" * 20_000}])
    processor = RecordingResultProcessor()
    dispatcher = DurableOuterToolDispatcher(
        repository,
        executor,
        result_analyzer=processor,
    )

    evidence = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert replayed == evidence
    assert len(executor.calls) == 1
    assert len(processor.calls) == 1
    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.truncated is False
    assert evidence.structured_data["processing_status"] == "completed"
    assert "source_artifact" not in evidence.structured_data
    assert "source_artifact_id" not in evidence.structured_data["tool_result_analysis"]
    assert "source_sha256" not in evidence.structured_data["tool_result_analysis"]
    assert "x" * 1_000 not in str(evidence.structured_data)
    rows = await _invocation_rows(repository, str(context.run_id))
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.artifact_ref is not None
    assert invocation.artifact_ref.metadata["internal_only"] is True
    stored = await repository.get_agent_artifact(str(invocation.artifact_ref.artifact_id))
    assert stored is not None
    assert stored[1]["structured_data"]["payload"] == "x" * 20_000
    await repository.close()


@pytest.mark.asyncio
async def test_small_result_is_always_projected_when_processor_is_configured(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "small-analysis.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-small-analysis")
    processor = RecordingResultProcessor()

    evidence = await DurableOuterToolDispatcher(
        repository,
        RecordingExecutor([{"payload": "small"}]),
        result_analyzer=processor,
    ).execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert len(processor.calls) == 1
    assert evidence.structured_data["processing_status"] == "completed"
    rows = await _invocation_rows(repository, str(context.run_id))
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.artifact_ref is not None
    stored = await repository.get_agent_artifact(str(invocation.artifact_ref.artifact_id))
    assert stored is not None
    assert stored[1]["structured_data"]["payload"] == "small"
    await repository.close()


@pytest.mark.asyncio
async def test_dispatcher_keeps_complete_raw_generic_result_out_of_main_context(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "raw-projection.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-raw-projection")
    raw_text = "slow-log-line\n" * 2_000
    outcome = {
        "observations": [
            {
                "tool_name": "read_logs",
                "response_ordinal": 1,
                "decision_round": 1,
                "projection": {
                    "projection_type": "deterministic_fact_projection",
                    "source_path": "/result",
                    "source_sha256": "d" * 64,
                    "source_json_chars": len(raw_text),
                    "scalar_groups": [
                        {
                            "path_pattern": "/content",
                            "value_count": 1,
                            "samples": [
                                {
                                    "value": {
                                        "excerpt": raw_text[:500],
                                        "sha256": "e" * 64,
                                        "total_chars": len(raw_text),
                                    },
                                    "source_path": "/content",
                                }
                            ],
                        }
                    ],
                },
                "is_error": False,
                "has_data": True,
            }
        ],
        "partial": False,
        "root_cause_eligible": True,
    }

    evidence = await DurableOuterToolDispatcher(
        repository,
        RecordingExecutor([outcome]),
        result_analyzer=DeterministicToolResultProcessor(),
    ).execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert evidence.structured_data["processing_status"] == "completed"
    assert raw_text not in evidence.model_dump_json()
    assert "total_chars" in evidence.model_dump_json()
    rows = await _invocation_rows(repository, str(context.run_id))
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.artifact_ref is not None
    stored = await repository.get_agent_artifact(str(invocation.artifact_ref.artifact_id))
    assert stored is not None
    stored_text = str(stored[1])
    assert raw_text not in stored_text
    assert "result" not in stored[1]["structured_data"]["observations"][0]
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_id", "series", "expected_eligible"),
    [
        (
            "valid",
            [
                {
                    "metric": {
                        "__name__": "mysql:all_server_status:all",
                        "metric": "threads_connected",
                    },
                    "value_semantics": "raw",
                    "sample_count": 2,
                    "min": 3,
                    "max": 5,
                    "avg": 4,
                    "latest": 5,
                    "delta": 2,
                }
            ],
            True,
        ),
        (
            "anonymous",
            [
                {
                    "metric": {},
                    "value_semantics": "raw",
                    "sample_count": 2,
                    "min": 3,
                    "max": 5,
                    "avg": 4,
                    "latest": 5,
                    "delta": 2,
                }
            ],
            False,
        ),
        (
            "collision",
            [
                {
                    "metric": {
                        "__name__": "mysql:all_server_status:all",
                        "metric": "threads_connected",
                    },
                    "value_semantics": "raw",
                    "sample_count": 2,
                    "min": 3,
                    "max": 5,
                    "avg": 4,
                    "latest": 5,
                    "delta": 2,
                },
                {
                    "metric": {
                        "__name__": "mysql:all_server_status:all",
                        "metric": "threads_connected",
                    },
                    "value_semantics": "raw",
                    "sample_count": 2,
                    "min": 6,
                    "max": 8,
                    "avg": 7,
                    "latest": 8,
                    "delta": 2,
                },
            ],
            False,
        ),
    ],
)
async def test_prometheus_identity_gate_controls_outer_root_cause_eligibility(
    tmp_path: Path,
    case_id: str,
    series: list[dict[str, object]],
    expected_eligible: bool,
) -> None:
    repository = SQLAlchemyAlertRepository(
        _sqlite_url(tmp_path / f"prometheus-identity-{case_id}.db")
    )
    await repository.initialize()
    alert_id, context = await _context(
        repository,
        external_id=f"outer-prometheus-identity-{case_id}",
    )
    window_end = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
    outcome = {
        "schema_version": "prometheus-evidence-v5",
        "window_start": (window_end - timedelta(minutes=5)).isoformat(),
        "window_end": window_end.isoformat(),
        "required_target": {"database_engine": "mysql"},
        "monitoring_results": [
            {
                "tool_name": "query_range",
                "projection_kind": "alert_window_range",
                "projection": {
                    "projection_kind": "alert_window_range",
                    "window": {
                        "start": (window_end - timedelta(minutes=5)).isoformat(),
                        "end": window_end.isoformat(),
                    },
                    "target_match": {
                        "matched": True,
                        "authoritative_fields": ["cluster"],
                    },
                    "timeseries": {
                        "has_numeric_samples": True,
                        "series_count": len(series),
                        "sample_count": sum(int(item["sample_count"]) for item in series),
                        "series": series,
                        "omitted_series_count": 0,
                        "excluded_metric_identity_missing_count": 0,
                        "excluded_metric_identity_collision_count": 0,
                    },
                },
            }
        ],
        "range_query_success_count": 1,
        "range_query_empty_count": 0,
    }
    request = ToolExecutionRequest(
        tool_name="query_mcp_prometheus",
        parameters={"case": case_id},
        objective="collect prometheus evidence",
        timeout_seconds=30,
    )
    spec = ToolSpec(
        name="query_mcp_prometheus",
        provider="prometheus_mcp",
        capability="monitoring.query",
        input_schema={"type": "object", "additionalProperties": True},
        policy_version="prometheus-test-policy-v1",
        schema_version="prometheus-evidence-v5",
    )

    evidence = await DurableOuterToolDispatcher(
        repository,
        RecordingExecutor([outcome], source_system="prometheus_mcp"),
        result_analyzer=DeterministicToolResultProcessor(),
    ).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=spec,
    )

    assert evidence.structured_data["processing_status"] == "completed"
    assert evidence.structured_data["root_cause_eligible"] is expected_eligible
    assert evidence.is_root_cause_support_eligible() is expected_eligible
    if expected_eligible:
        assert "threads_connected" in evidence.model_dump_json()
    else:
        assert evidence.structured_data["root_cause_ineligible_reason"] == (
            "program_fact_projection_unusable"
        )
    await repository.close()


@pytest.mark.asyncio
async def test_archery_projection_persists_independent_v2_evidence_units(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "evidence-units.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-evidence-units")
    history_payload = {
        "column_list": [
            "id",
            "raw",
            "raw_metric",
            "artifact_count",
            "hash",
            "content_hash",
            "request_id",
            "usage",
            "sha256",
            "sample_sha256",
            "sample",
            "business_blob",
        ],
        "rows": [
            {
                "id": 41,
                "raw": {"nested": ["original", {"raw": "business"}]},
                "raw_metric": 7,
                "artifact_count": 2,
                "hash": "business-hash",
                "content_hash": "business-content-hash",
                "request_id": "business-request-id",
                "usage": {"business_units": 9},
                "sha256": "business-sha256",
                "sample_sha256": "business-sample-sha256",
                "sample": "SELECT * FROM orders WHERE id IN ("
                + ",".join(map(str, range(4_000)))
                + ")",
                "business_blob": "业务字段" * 10_001,
            }
        ],
        "row_count": 1,
    }
    executor = RecordingExecutor(
        [
            {
                "final_result_payload": history_payload,
                "slow_query_analysis": {
                    "status": "partial",
                    "explain_results": [{"result": {"row_count": 1}}],
                    "table_structure_results": [],
                    "index_results": [],
                    "missing_stages": ["indexes"],
                    "failures": [{"stage": "indexes", "reason_code": "permission_denied"}],
                },
            }
        ],
        source_system="archery_mcp",
    )
    request = ToolExecutionRequest(
        tool_name="query_mcp_archery",
        parameters={"scope": "alert_window"},
        objective="collect slow-query history",
    )
    spec = ToolSpec(
        name=request.tool_name,
        provider="archery_mcp",
        capability="database.slow_query",
        input_schema={"type": "object", "additionalProperties": True},
        policy_version="test-policy-v1",
        schema_version="test-schema-v1",
    )

    dispatcher = DurableOuterToolDispatcher(
        repository,
        executor,
        result_analyzer=ArcheryUnitResultProcessor(),
    )
    evidence = await dispatcher.execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=spec,
    )

    assert evidence.contract_version == EVIDENCE_RECORD_V2
    assert evidence.source_artifact_id is not None
    assert evidence.structured_data["root_cause_eligible"] is False
    assert evidence.is_root_cause_support_eligible() is False
    assert len(evidence.evidence_units) == 3
    history = next(unit for unit in evidence.evidence_units if unit.unit_key == "history")
    explain = next(
        unit
        for unit in evidence.evidence_units
        if unit.stage == "explain" and unit.status == EvidenceUnitStatus.SUCCESS
    )
    indexes = next(
        unit
        for unit in evidence.evidence_units
        if unit.stage == "indexes" and unit.status == EvidenceUnitStatus.FAILED
    )
    assert history.id == EvidenceUnit.build_id(evidence.id, "history")
    assert history.source_artifact_id == evidence.source_artifact_id
    assert history.status == EvidenceUnitStatus.SUCCESS
    assert history.root_cause_eligible is True
    assert history.source_paths == ["/structured_data/final_result_payload"]
    assert history.data == history_payload
    assert explain.status == EvidenceUnitStatus.SUCCESS
    assert explain.root_cause_eligible is True
    assert explain.source_paths == ["/structured_data/slow_query_analysis/explain_results/0"]
    assert indexes.status == EvidenceUnitStatus.FAILED
    assert indexes.root_cause_eligible is False
    assert indexes.source_paths == ["/structured_data/slow_query_analysis/failures/0"]
    stored_artifact = await repository.get_agent_artifact(str(history.source_artifact_id))
    assert stored_artifact is not None
    artifact_payload = stored_artifact[1]
    assert isinstance(artifact_payload, dict)
    assert artifact_payload["structured_data"]["final_result_payload"] == history_payload
    assert (
        artifact_payload["structured_data"]["slow_query_analysis"]["failures"][0]["stage"]
        == "indexes"
    )

    assert context.lease_owner is not None and context.fencing_token is not None
    with pytest.raises(EvidenceRecordConflict, match="invocation binding is invalid"):
        await repository.save_evidence(
            alert_id,
            evidence.model_copy(update={"summary": "tampered projected evidence"}),
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )
    await repository.save_evidence(
        alert_id,
        evidence,
        lease_owner=context.lease_owner,
        fencing_token=context.fencing_token,
    )
    stored = await repository.get(alert_id, run_id=str(context.run_id))
    assert stored is not None
    assert stored.evidence_records == [evidence]
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=spec,
    )
    assert replayed == evidence
    assert len(executor.calls) == 1

    invocation_rows = await _invocation_rows(repository, str(context.run_id))
    async with repository.session_factory() as session:
        artifact_row = await session.get(AgentArtifactRow, str(history.source_artifact_id))
        assert artifact_row is not None
        original_content = artifact_row.sanitized_content
        artifact_row.sanitized_content = original_content.replace('"id":41', '"id":42')
        assert artifact_row.sanitized_content != original_content
        await session.commit()

    with pytest.raises(RuntimeError, match="artifact content hash is invalid"):
        await repository.get(alert_id, run_id=str(context.run_id))

    async with repository.session_factory() as session:
        artifact_row = await session.get(AgentArtifactRow, str(history.source_artifact_id))
        assert artifact_row is not None
        artifact_row.sanitized_content = original_content
        await session.commit()

    history_index = next(
        index for index, unit in enumerate(evidence.evidence_units) if unit.unit_key == "history"
    )
    async with repository.session_factory() as session:
        evidence_row = await session.get(EvidenceRow, str(evidence.id))
        invocation_row = await session.get(ToolInvocationRow, invocation_rows[0].id)
        assert evidence_row is not None and invocation_row is not None
        tampered_units = [item.model_dump(mode="json") for item in evidence.evidence_units]
        tampered_units[history_index]["data"] = {"full_sql": "SELECT 1"}
        evidence_row.evidence_units_json = tampered_units
        result_payload = dict(invocation_row.result_json)
        evidence_payload = dict(result_payload["evidence_record"])
        evidence_payload["evidence_units"] = tampered_units
        result_payload["evidence_record"] = evidence_payload
        invocation_row.result_json = result_payload
        await session.commit()

    with pytest.raises(RuntimeError, match="data does not match its raw source path"):
        await repository.get(alert_id, run_id=str(context.run_id))

    async with repository.session_factory() as session:
        evidence_row = await session.get(EvidenceRow, str(evidence.id))
        invocation_row = await session.get(ToolInvocationRow, invocation_rows[0].id)
        assert evidence_row is not None and invocation_row is not None
        original_units = [item.model_dump(mode="json") for item in evidence.evidence_units]
        evidence_row.evidence_units_json = original_units
        result_payload = dict(invocation_row.result_json)
        evidence_payload = dict(result_payload["evidence_record"])
        evidence_payload["evidence_units"] = original_units
        result_payload["evidence_record"] = evidence_payload
        invocation_row.result_json = result_payload
        await session.commit()

    async with repository.session_factory() as session:
        invocation_row = await session.get(ToolInvocationRow, invocation_rows[0].id)
        assert invocation_row is not None
        result_payload = dict(invocation_row.result_json)
        evidence_payload = dict(result_payload["evidence_record"])
        evidence_units = [dict(item) for item in evidence_payload["evidence_units"]]
        evidence_units[0]["source_paths"] = ["/structured_data/does_not_exist"]
        evidence_payload["evidence_units"] = evidence_units
        result_payload["evidence_record"] = evidence_payload
        invocation_row.result_json = result_payload
        await session.commit()

    with pytest.raises(OuterDispatchError, match="source path does not resolve"):
        await dispatcher.execute(
            alert_id=alert_id,
            request=request,
            context=context,
            tool_spec=spec,
        )
    await repository.close()


def test_not_applicable_status_is_derived_from_each_supplemental_failure() -> None:
    artifact_id = uuid4()
    history = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "rows": [{"id": 41}],
    }
    supplemental = {
        "status": "not_applicable",
        "explain_results": [],
        "table_structure_results": [],
        "index_results": [],
        "missing_stages": [],
        "failures": [
            {"stage": "indexes", "reason_code": "permission_denied"},
            {"stage": "explain", "reason_code": "no_safe_explainable_sample"},
        ],
    }
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery result",
        structured_data={
            "final_result_payload": history,
            "slow_query_analysis": supplemental,
        },
    )
    analysis = ToolResultAnalysis(
        summary="Archery result",
        analysis_usable=False,
        source_coverage_complete=True,
        source_artifact_id=artifact_id,
        source_sha256="a" * 64,
        provider="deterministic_host",
        model="none",
        prompt_version="test-v1",
        passthrough_payload=history,
        slow_query_analysis=supplemental,
    )

    units = DurableOuterToolDispatcher._archery_evidence_units(parent, analysis=analysis)
    by_reason = {
        unit.data.get("reason_code"): unit.status
        for unit in units
        if unit.kind.value == "SUPPLEMENTAL"
    }

    assert by_reason == {
        "permission_denied": EvidenceUnitStatus.FAILED,
        "no_safe_explainable_sample": EvidenceUnitStatus.NOT_APPLICABLE,
    }
    DurableOuterToolDispatcher._validate_evidence_unit_sources(
        parent.model_dump(mode="json"),
        units,
        artifact_id=artifact_id,
    )


def test_missing_stage_with_successful_results_is_partial() -> None:
    artifact_id = uuid4()
    history = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "rows": [{"id": 41}],
    }
    index_result = {
        "stage": "indexes",
        "target": {"table_name": "orders"},
        "result": {
            "row_count": 1,
            "rows": [{"INDEX_NAME": "PRIMARY", "COLUMN_NAME": "id"}],
        },
    }
    supplemental = {
        "status": "partial",
        "stage_states": {"indexes": "SUCCEEDED"},
        "explain_results": [],
        "table_structure_results": [],
        "index_results": [index_result],
        "missing_stages": ["indexes"],
        "failures": [],
    }
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery result",
        structured_data={
            "final_result_payload": history,
            "slow_query_analysis": supplemental,
        },
    )
    analysis = ToolResultAnalysis(
        summary="Archery result",
        analysis_usable=False,
        source_coverage_complete=True,
        source_artifact_id=artifact_id,
        source_sha256="a" * 64,
        provider="deterministic_host",
        model="none",
        prompt_version="test-v1",
        passthrough_payload=history,
        slow_query_analysis=supplemental,
    )

    units = DurableOuterToolDispatcher._archery_evidence_units(parent, analysis=analysis)
    completed = next(unit for unit in units if unit.stage == "indexes" and unit.result_index == 0)
    partial = next(unit for unit in units if unit.unit_key == "supplemental:indexes:missing")

    assert completed.status == EvidenceUnitStatus.SUCCESS
    assert completed.root_cause_eligible is True
    assert partial.status == EvidenceUnitStatus.PARTIAL
    assert partial.summary == "Archery supplemental indexes 已取得部分结果，但覆盖不完整。"
    assert partial.root_cause_eligible is False
    assert partial.root_cause_ineligible_reason == "supplemental_partial"
    DurableOuterToolDispatcher._validate_evidence_unit_sources(
        parent.model_dump(mode="json"),
        units,
        artifact_id=artifact_id,
    )


def test_recovered_history_failures_and_unavailable_stages_keep_final_status() -> None:
    artifact_id = uuid4()
    history = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "rows": [{"id": 41}],
        "result_completeness_assessment": "complete",
    }
    supplemental = {
        "status": "failed",
        "stage_states": {
            "target_resolution": "FAILED_TERMINAL",
            "explain": "UNAVAILABLE",
            "table_structure": "UNAVAILABLE",
            "indexes": "UNAVAILABLE",
        },
        "explain_results": [],
        "table_structure_results": [],
        "index_results": [],
        "missing_stages": ["explain", "table_structure", "indexes"],
        "failures": [
            {
                "stage": "history_recovery",
                "reason_code": "history_recovery_result_size_forbidden",
                "terminal": False,
            },
            {
                "stage": "history_recovery",
                "reason_code": "history_recovery_incomplete",
                "terminal": True,
            },
            {
                "stage": "target_resolution",
                "reason_code": "instance_not_allowlisted",
                "terminal": True,
            },
        ],
    }
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery result",
        structured_data={
            "final_result_payload": history,
            "slow_query_analysis": supplemental,
        },
    )
    analysis = ToolResultAnalysis(
        summary="Archery result",
        analysis_usable=False,
        source_coverage_complete=True,
        source_artifact_id=artifact_id,
        source_sha256="a" * 64,
        provider="deterministic_host",
        model="none",
        prompt_version="test-v1",
        passthrough_payload=history,
        slow_query_analysis=supplemental,
    )

    units = DurableOuterToolDispatcher._archery_evidence_units(parent, analysis=analysis)
    by_reason = {
        str(unit.data.get("reason_code")): unit for unit in units if unit.data.get("reason_code")
    }
    by_stage = {unit.stage: unit for unit in units if unit.unit_key.endswith(":missing")}

    recovered = by_reason["history_recovery_result_size_forbidden"]
    assert recovered.status == EvidenceUnitStatus.RECOVERED
    assert recovered.root_cause_ineligible_reason == "supplemental_recovered"
    assert by_reason["history_recovery_incomplete"].status == EvidenceUnitStatus.FAILED
    assert by_reason["instance_not_allowlisted"].status == EvidenceUnitStatus.FAILED
    assert set(by_stage) == {"explain", "table_structure", "indexes"}
    assert all(unit.status == EvidenceUnitStatus.UNAVAILABLE for unit in by_stage.values())
    assert all(unit.data["stage_state"] == "UNAVAILABLE" for unit in by_stage.values())
    DurableOuterToolDispatcher._validate_evidence_unit_sources(
        parent.model_dump(mode="json"),
        units,
        artifact_id=artifact_id,
    )


def test_nonterminal_history_failure_stays_failed_while_recovery_is_incomplete() -> None:
    artifact_id = uuid4()
    history = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "rows": [{"id": 41}],
        "history_recovery_complete": False,
        "history_recovery_missing_ids": [42],
    }
    supplemental = {
        "status": "failed",
        "explain_results": [],
        "table_structure_results": [],
        "index_results": [],
        "missing_stages": [],
        "failures": [
            {
                "stage": "history_recovery",
                "reason_code": "history_recovery_result_size_forbidden",
                "terminal": False,
            }
        ],
    }
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery result",
        structured_data={
            "final_result_payload": history,
            "slow_query_analysis": supplemental,
        },
    )
    analysis = ToolResultAnalysis(
        summary="Archery result",
        analysis_usable=False,
        source_coverage_complete=True,
        source_artifact_id=artifact_id,
        source_sha256="a" * 64,
        provider="deterministic_host",
        model="none",
        prompt_version="test-v1",
        passthrough_payload=history,
        slow_query_analysis=supplemental,
    )

    units = DurableOuterToolDispatcher._archery_evidence_units(parent, analysis=analysis)
    recovery_failure = next(unit for unit in units if unit.stage == "history_recovery")

    assert recovery_failure.status == EvidenceUnitStatus.FAILED
    assert recovery_failure.root_cause_ineligible_reason == "supplemental_failed"


def test_missing_history_payload_uses_an_existing_raw_source_path() -> None:
    artifact_id = uuid4()
    supplemental = {
        "status": "failed",
        "explain_results": [],
        "table_structure_results": [],
        "index_results": [],
        "missing_stages": [],
        "failures": [{"stage": "explain", "reason_code": "query_failed"}],
    }
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery result",
        structured_data={"slow_query_analysis": supplemental},
    )
    analysis = ToolResultAnalysis(
        summary="Archery result",
        analysis_usable=False,
        source_coverage_complete=True,
        source_artifact_id=artifact_id,
        source_sha256="a" * 64,
        provider="deterministic_host",
        model="none",
        prompt_version="test-v1",
        slow_query_analysis=supplemental,
    )

    units = DurableOuterToolDispatcher._archery_evidence_units(parent, analysis=analysis)
    history = next(unit for unit in units if unit.unit_key == "history")

    assert history.status == EvidenceUnitStatus.FAILED
    assert history.source_paths == ["/structured_data"]
    DurableOuterToolDispatcher._validate_evidence_unit_sources(
        parent.model_dump(mode="json"),
        units,
        artifact_id=artifact_id,
    )


def test_supplemental_unit_ids_do_not_depend_on_result_order() -> None:
    parent = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery result",
    )
    history = {
        "full_sql": "SELECT * FROM mysql_slow_query_review_history",
        "rows": [{"id": 41}],
    }
    first = {"marker": "first", "result": {"type": "range"}}
    second = {"marker": "second", "result": {"type": "ref"}}

    def project(results: list[dict[str, object]]) -> list[EvidenceUnit]:
        analysis = ToolResultAnalysis(
            summary="Archery result",
            observations=[
                ToolResultObservation(
                    statement="History returned one row.",
                    source_paths=["/structured_data/final_result_payload"],
                )
            ],
            analysis_usable=True,
            source_coverage_complete=True,
            source_artifact_id=uuid4(),
            source_sha256="a" * 64,
            provider="deterministic_host",
            model="none",
            prompt_version="test-v1",
            passthrough_payload=history,
            slow_query_analysis={
                "status": "completed",
                "explain_results": results,
                "table_structure_results": [],
                "index_results": [],
                "missing_stages": [],
                "failures": [],
            },
        )
        return DurableOuterToolDispatcher._archery_evidence_units(
            parent,
            analysis=analysis,
        )

    forward = {
        unit.data["marker"]: unit.id
        for unit in project([first, second, first])
        if unit.stage == "explain"
    }
    reversed_order = {
        unit.data["marker"]: unit.id for unit in project([second, first]) if unit.stage == "explain"
    }

    assert forward == reversed_order
    assert set(forward) == {"first", "second"}


def test_parse_failed_history_text_is_wrapped_verbatim_and_exactly_validated() -> None:
    artifact_id = uuid4()
    raw_text = (
        "mysql_slow_query_review_history result: "
        "SELECT  * FROM t WHERE request_id = 'biz'  ;\n"
        '{"usage":1,"raw_metric":7}'
    )
    raw_result = {"structured_data": {"final_result_text": raw_text}}
    evidence = EvidenceRecord(
        run_id=uuid4(),
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        status=ToolStatus.SUCCESS,
        summary="Archery parse failed",
        structured_data=raw_result["structured_data"],
        source_artifact_id=artifact_id,
    )
    analysis = ToolResultAnalysis(
        summary="Archery final result could not be parsed.",
        analysis_usable=False,
        source_coverage_complete=False,
        source_artifact_id=artifact_id,
        source_sha256="a" * 64,
        provider="deterministic_host",
        model="none",
        prompt_version="test-v1",
        passthrough_payload={"final_result_text": raw_text},
        passthrough_parse_failed=True,
    )

    units = DurableOuterToolDispatcher._archery_evidence_units(
        evidence,
        analysis=analysis,
    )

    assert len(units) == 1
    assert units[0].kind == EvidenceUnitKind.HISTORY
    assert units[0].status == EvidenceUnitStatus.FAILED
    assert units[0].data == {"final_result_text": raw_text}
    DurableOuterToolDispatcher._validate_evidence_unit_sources(
        raw_result,
        units,
        artifact_id=artifact_id,
    )
    tampered = units[0].model_copy(update={"data": {"final_result_text": raw_text[:-1]}})
    with pytest.raises(OuterDispatchError, match="not identical"):
        DurableOuterToolDispatcher._validate_evidence_unit_sources(
            raw_result,
            [tampered],
            artifact_id=artifact_id,
        )


@pytest.mark.asyncio
async def test_incomplete_history_unit_is_ineligible_without_downgrading_supplemental(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "incomplete-history-unit.db"))
    await repository.initialize()
    alert_id, context = await _context(
        repository,
        external_id="outer-incomplete-history-unit",
    )
    executor = RecordingExecutor(
        [
            {
                "partial": True,
                "history_scan_complete": False,
                "final_result_payload": {
                    "column_list": ["id", "sample"],
                    "rows": [{"id": 41, "sample": "SELECT 1"}],
                    "row_count": 1,
                },
                "slow_query_analysis": {
                    "status": "partial",
                    "explain_results": [{"result": {"row_count": 1}}],
                    "table_structure_results": [],
                    "index_results": [],
                    "missing_stages": [],
                    "failures": [],
                },
            }
        ],
        source_system="archery_mcp",
    )
    request = ToolExecutionRequest(
        tool_name="query_mcp_archery",
        parameters={"scope": "alert_window"},
        objective="collect slow-query history",
    )
    spec = ToolSpec(
        name=request.tool_name,
        provider="archery_mcp",
        capability="database.slow_query",
        input_schema={"type": "object", "additionalProperties": True},
        policy_version="test-policy-v1",
        schema_version="test-schema-v1",
    )

    evidence = await DurableOuterToolDispatcher(
        repository,
        executor,
        result_analyzer=ArcheryUnitResultProcessor(),
    ).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=spec,
    )

    history = next(unit for unit in evidence.evidence_units if unit.unit_key == "history")
    explain = next(
        unit
        for unit in evidence.evidence_units
        if unit.stage == "explain" and unit.status == EvidenceUnitStatus.SUCCESS
    )
    assert history.status == EvidenceUnitStatus.FAILED
    assert history.root_cause_eligible is False
    assert history.root_cause_ineligible_reason == "history_recovery_incomplete"
    assert explain.status == EvidenceUnitStatus.SUCCESS
    assert explain.root_cause_eligible is True
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source_system",
    ["alert_platform", "flashduty_api", "flashduty_similar"],
)
async def test_similar_incidents_stays_usable_context_but_never_root_cause_evidence(
    tmp_path: Path,
    source_system: str,
) -> None:
    repository = SQLAlchemyAlertRepository(
        _sqlite_url(tmp_path / f"similar-context-{source_system}.db")
    )
    await repository.initialize()
    alert_id, context = await _context(
        repository, external_id=f"outer-similar-context-{source_system}"
    )
    executor = RecordingExecutor(
        [{"observations": [{"incident_id": "similar-1"}]}],
        source_system=source_system,
    )
    request = ToolExecutionRequest(
        tool_name="query_similar_incidents",
        parameters={"incident_id": "current-1"},
        objective="collect similar incident context",
    )
    spec = ToolSpec(
        name=request.tool_name,
        provider=source_system,
        capability="flashduty.similar_incidents",
        input_schema={"type": "object", "additionalProperties": True},
        policy_version="test-policy-v1",
        schema_version="test-schema-v1",
    )

    evidence = await DurableOuterToolDispatcher(
        repository,
        executor,
        result_analyzer=RecordingResultProcessor(),
    ).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=spec,
    )

    analysis = evidence.structured_data["tool_result_analysis"]
    assert analysis["analysis_usable"] is True
    assert evidence.structured_data["root_cause_eligible"] is False
    assert evidence.structured_data["root_cause_ineligible_reason"] == (
        "similar_incidents_are_context_only"
    )
    assert evidence.evidence_units == []
    assert evidence.is_root_cause_support_eligible() is False
    await repository.close()


@pytest.mark.asyncio
async def test_program_projection_failure_keeps_artifact_and_fails_closed(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "analysis-failed.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-analysis-failed")
    processor = RecordingResultProcessor(failure=RuntimeError("processor unavailable"))

    evidence = await DurableOuterToolDispatcher(
        repository,
        RecordingExecutor([{"payload": "x" * 20_000}]),
        result_analyzer=processor,
    ).execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert evidence.status == ToolStatus.SUCCESS
    assert evidence.structured_data["processing_status"] == "failed"
    assert evidence.structured_data["root_cause_eligible"] is False
    assert evidence.is_root_cause_support_eligible() is False
    rows = await _invocation_rows(repository, str(context.run_id))
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.artifact_ref is not None
    stored = await repository.get_agent_artifact(str(invocation.artifact_ref.artifact_id))
    assert stored is not None
    assert stored[1]["structured_data"]["payload"] == "x" * 20_000
    await repository.close()


@pytest.mark.asyncio
async def test_program_projection_ignores_provider_partial_sentinels(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "provider-partial.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-provider-partial")
    processor = RecordingResultProcessor()

    evidence = await DurableOuterToolDispatcher(
        repository,
        RecordingExecutor(
            [
                {
                    "payload": "x" * 20_000,
                    "partial": True,
                    "allow_followup_dispatch": False,
                    "root_cause_eligible": False,
                    "root_cause_ineligible_reason": "provider_partial_result",
                }
            ]
        ),
        result_analyzer=processor,
    ).execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert evidence.structured_data["processing_status"] == "completed"
    assert "partial" not in evidence.structured_data
    assert "allow_followup_dispatch" not in evidence.structured_data
    assert evidence.structured_data["root_cause_eligible"] is True
    assert evidence.structured_data["tool_result_analysis"]["source_coverage_complete"] is True
    assert "root_cause_ineligible_reason" not in evidence.structured_data
    assert evidence.is_root_cause_support_eligible() is True
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [ToolStatus.FAILED, ToolStatus.TIMEOUT],
)
async def test_failed_or_timed_out_result_bypasses_projection(
    tmp_path: Path,
    status: ToolStatus,
) -> None:
    repository = SQLAlchemyAlertRepository(
        _sqlite_url(tmp_path / f"large-{status.value.casefold()}.db")
    )
    await repository.initialize()
    alert_id, context = await _context(
        repository,
        external_id=f"outer-large-{status.value.casefold()}",
    )
    processor = RecordingResultProcessor()
    executor = RecordingExecutor(
        [
            {
                "payload": "x" * 20_000,
                "reason_code": "database_not_monitored",
                "root_cause_eligible": False,
                "root_cause_ineligible_reason": "database_not_monitored",
            }
        ],
        status=status,
    )

    evidence = await DurableOuterToolDispatcher(
        repository,
        executor,
        result_analyzer=processor,
    ).execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )

    assert processor.calls == []
    assert evidence.status == status
    assert evidence.summary == "collected"
    assert evidence.structured_data["processing_status"] == "unavailable"
    assert evidence.structured_data["reason_code"] == "database_not_monitored"
    assert evidence.structured_data["root_cause_eligible"] is False
    assert evidence.structured_data["root_cause_ineligible_reason"] == ("tool_status_not_success")
    assert "tool_result_analysis" not in evidence.structured_data
    assert "payload" not in evidence.structured_data
    assert evidence.is_root_cause_support_eligible() is False
    assert "x" * 1_000 not in str(evidence.structured_data)
    rows = await _invocation_rows(repository, str(context.run_id))
    invocation = await repository.get_tool_invocation(rows[0].id)
    assert invocation is not None and invocation.artifact_ref is not None
    stored = await repository.get_agent_artifact(str(invocation.artifact_ref.artifact_id))
    assert stored is not None
    assert stored[1]["structured_data"]["payload"] == "x" * 20_000
    await repository.close()


@pytest.mark.asyncio
async def test_partial_success_allocates_next_logical_dispatch_only_after_checkpoint(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "partial.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-partial")
    executor = RecordingExecutor([{"partial": True}, {"partial": False}])
    dispatcher = DurableOuterToolDispatcher(repository, executor)

    first = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    second = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
        prior_evidence=[first],
    )
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
        prior_evidence=[first],
    )

    assert first.id != second.id
    assert second == replayed
    assert len(executor.calls) == 2
    assert executor.contexts[0].outer_dispatch_id != executor.contexts[1].outer_dispatch_id
    assert len(await _invocation_rows(repository, str(context.run_id))) == 2
    await repository.close()


@pytest.mark.asyncio
async def test_provider_followup_hint_does_not_block_second_explicit_action(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "partial-terminal.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-partial-terminal")
    executor = RecordingExecutor([{"partial": True, "allow_followup_dispatch": False}])
    dispatcher = DurableOuterToolDispatcher(repository, executor)

    first = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
    )
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=context,
        tool_spec=_spec(),
        prior_evidence=[first],
    )

    assert replayed != first
    assert "allow_followup_dispatch" not in replayed.structured_data
    assert replayed.structured_data["processing_status"] == "unavailable"
    assert len(executor.calls) == 2
    assert executor.contexts[0].outer_dispatch_id != executor.contexts[1].outer_dispatch_id
    assert len(await _invocation_rows(repository, str(context.run_id))) == 2
    await repository.close()
