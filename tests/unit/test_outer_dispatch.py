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
    EvidenceRow,
    InvestigationRunRow,
    SQLAlchemyAlertRepository,
    ToolInvocationRow,
)
from app.agent_runtime.contracts import (
    RetryPolicy,
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
    EvidenceRecord,
    InvestigationContext,
    InvestigationStrategy,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.ports import ToolInvocationConflict


def _sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


class RecordingExecutor:
    def __init__(
        self,
        outcomes: Sequence[dict[str, object]] | None = None,
        *,
        source_system: str = "test_host",
    ) -> None:
        self.outcomes = list(outcomes or [{}])
        self.source_system = source_system
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
            status=ToolStatus.SUCCESS,
            request=request.parameters,
            summary="collected",
            structured_data=structured_data,
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
        strategy=InvestigationStrategy(
            strategy_id="outer-dispatch-test",
            title="test",
            description="test",
        ),
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


def _spec(*, read_only: bool = True, max_attempts: int = 2) -> ToolSpec:
    return ToolSpec(
        name="test_probe",
        provider="test_host",
        capability="test.probe",
        input_schema={"type": "object", "additionalProperties": True},
        read_only=read_only,
        policy_version="test-policy-v1",
        schema_version="test-schema-v1",
        retry=RetryPolicy(max_attempts=max_attempts),
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
            await session.execute(
                select(EvidenceRow).where(EvidenceRow.run_id == str(context.run_id))
            )
        ).scalars().all()
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
    assert (
        evidence.structured_data["reason_code"]
        == "invocation_deadline_exceeded_before_dispatch"
    )
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [item.status for item in rows] == [ToolInvocationStatus.TIMED_OUT.value]
    await repository.close()


@pytest.mark.asyncio
async def test_new_fencing_epoch_allows_one_explicit_read_only_retry(
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
            tool_spec=_spec(read_only=True, max_attempts=2),
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
        tool_spec=_spec(read_only=True, max_attempts=2),
    )
    replayed = await dispatcher.execute(
        alert_id=alert_id,
        request=_request(),
        context=recovery_context,
        tool_spec=_spec(read_only=True, max_attempts=2),
    )

    assert evidence == replayed
    assert evidence.status == ToolStatus.SUCCESS
    assert len(executor.calls) == 2
    assert [item.outer_dispatch_attempt for item in executor.contexts] == [1, 2]
    assert executor.contexts[0].outer_dispatch_id == executor.contexts[1].outer_dispatch_id
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME.value,
        ToolInvocationStatus.SUCCEEDED.value,
    ]
    assert len(rows) == 2
    await repository.close()


@pytest.mark.asyncio
async def test_same_epoch_recovers_started_only_after_persisted_deadline(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "deadline-recovery.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-deadline-recovery")
    executor = RecordingExecutor()
    request = _request(timeout_seconds=0.05)

    with pytest.raises(RuntimeError, match="AFTER_HANDLER_RETURNED"):
        await DurableOuterToolDispatcher(
            repository,
            executor,
            fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED),
        ).execute(
            alert_id=alert_id,
            request=request,
            context=context,
            tool_spec=_spec(read_only=True, max_attempts=2),
        )
    await asyncio.sleep(0.06)

    evidence = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=request,
        context=context,
        tool_spec=_spec(read_only=True, max_attempts=2),
    )

    assert evidence.status == ToolStatus.SUCCESS
    assert len(executor.calls) == 2
    rows = await _invocation_rows(repository, str(context.run_id))
    assert [row.status for row in rows] == [
        ToolInvocationStatus.UNKNOWN_OUTCOME.value,
        ToolInvocationStatus.SUCCEEDED.value,
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
    request = _request(timeout_seconds=0.05)
    tool_spec = _spec(read_only=False, max_attempts=1)

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
            tool_spec=_spec(read_only=True, max_attempts=2),
        )
    )
    await executor.started.wait()
    second_task = asyncio.create_task(
        dispatcher.execute(
            alert_id=alert_id,
            request=_request(),
            context=context,
            tool_spec=_spec(read_only=True, max_attempts=2),
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

    evidence = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=_request(timeout_seconds=0.01),
        context=context,
        tool_spec=_spec(),
    )

    assert len(executor.calls) == 1
    assert evidence.status == ToolStatus.TIMEOUT
    assert (
        evidence.structured_data["reason_code"]
        == "outer_invocation_deadline_exceeded"
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
@pytest.mark.parametrize(
    ("read_only", "max_attempts"),
    [(False, 2), (True, 1)],
)
async def test_started_recovery_without_host_retry_authorization_stays_unknown(
    tmp_path: Path,
    read_only: bool,
    max_attempts: int,
) -> None:
    repository = SQLAlchemyAlertRepository(
        _sqlite_url(tmp_path / f"no-retry-{read_only}-{max_attempts}.db")
    )
    await repository.initialize()
    alert_id, context = await _context(repository, external_id=f"no-retry-{read_only}")
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
            tool_spec=_spec(read_only=read_only, max_attempts=max_attempts),
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
        tool_spec=_spec(read_only=read_only, max_attempts=max_attempts),
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
            tool_spec=_spec(read_only=True, max_attempts=2),
        )
    drifted = _spec(read_only=True, max_attempts=1).model_copy(
        update={"policy_version": "test-policy-v2"}
    )

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

    active_context = context
    for _attempt in range(2):
        with pytest.raises(RuntimeError, match="AFTER_HANDLER_RETURNED"):
            await DurableOuterToolDispatcher(
                repository,
                executor,
                fault_hook=CrashAt(OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED),
            ).execute(
                alert_id=alert_id,
                request=_request(),
                context=active_context,
                tool_spec=_spec(read_only=True, max_attempts=20),
            )
        active_context = await _reclaim_context(
            repository,
            alert_id=alert_id,
            context=active_context,
        )

    evidence = await DurableOuterToolDispatcher(repository, executor).execute(
        alert_id=alert_id,
        request=_request(),
        context=active_context,
        tool_spec=_spec(read_only=True, max_attempts=20),
    )

    assert len(executor.calls) == 2
    assert evidence.structured_data["reason_code"] == "unknown_outcome"
    rows = await _invocation_rows(repository, str(context.run_id))
    assert len(rows) == 2
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
    assert evidence.structured_data["payload"] == "x" * 13_000
    rows = await _invocation_rows(repository, str(context.run_id))
    result = await repository.get_tool_invocation_result(rows[0].id)
    assert result is not None
    assert result["contract"] == OUTER_EVIDENCE_RESULT_CONTRACT
    assert result["evidence_record"]["structured_data"]["payload"] == "x" * 13_000
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
    assert [item.outer_dispatch_attempt for item in executor.contexts] == [1, 1]
    assert len(await _invocation_rows(repository, str(context.run_id))) == 2
    await repository.close()


@pytest.mark.asyncio
async def test_partial_success_can_explicitly_disable_followup_dispatch(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(_sqlite_url(tmp_path / "partial-terminal.db"))
    await repository.initialize()
    alert_id, context = await _context(repository, external_id="outer-partial-terminal")
    executor = RecordingExecutor(
        [{"partial": True, "allow_followup_dispatch": False}]
    )
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

    assert replayed == first
    assert len(executor.calls) == 1
    assert len(await _invocation_rows(repository, str(context.run_id))) == 1
    await repository.close()
