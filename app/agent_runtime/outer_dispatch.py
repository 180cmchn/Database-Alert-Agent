"""Durable dispatch for outer investigation tools executed by LangGraph nodes."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID, uuid5

from app.agent_runtime.contracts import (
    InvocationError,
    ToolInvocation,
    ToolInvocationStatus,
    ToolSpec,
)
from app.application.sanitization import sanitize, sanitize_text
from app.domain.models import (
    EvidenceRecord,
    InvestigationContext,
    ToolExecutionRequest,
    ToolStatus,
)
from app.domain.ports import (
    AlertRepository,
    RunLeaseConflict,
    ToolInvocationConflict,
)

OUTER_EVIDENCE_RESULT_CONTRACT = "outer-evidence-record/v1"
_DISPATCH_ID_VERSION = "outer-tool-dispatch/v1"
_EVIDENCE_ID_VERSION = "outer-tool-evidence/v1"
_INFLIGHT_POLL_INTERVAL_SECONDS = 0.05


class OuterDispatchError(RuntimeError):
    """Durable outer dispatch state is missing, inconsistent, or corrupt."""


class OuterDispatchFaultPoint(StrEnum):
    """Stable lifecycle boundaries used by crash-recovery tests."""

    AFTER_PENDING_PERSISTED = "AFTER_PENDING_PERSISTED"
    AFTER_STARTED_PERSISTED = "AFTER_STARTED_PERSISTED"
    AFTER_HANDLER_RETURNED = "AFTER_HANDLER_RETURNED"
    AFTER_TERMINAL_PERSISTED = "AFTER_TERMINAL_PERSISTED"


class OuterToolExecutor(Protocol):
    async def execute(
        self,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> EvidenceRecord: ...


OuterDispatchFaultHook = Callable[
    [OuterDispatchFaultPoint, ToolInvocation, EvidenceRecord | None],
    Awaitable[None] | None,
]


class DurableOuterToolDispatcher:
    """Execute one outer tool request without replaying a durable outcome.

    A logical dispatch has a deterministic identity. Its first invocation is
    persisted as PENDING before it can cross the handler boundary. Recovery of
    STARTED is conservative: callers in the execution lease epoch join the
    in-flight attempt. Only a newer fencing epoch or an expired durable deadline
    may mark its outcome unknown, after which a Host-declared read-only tool may
    receive one fixed second attempt.
    """

    def __init__(
        self,
        repository: AlertRepository,
        executor: OuterToolExecutor,
        *,
        fault_hook: OuterDispatchFaultHook | None = None,
    ) -> None:
        self.repository = repository
        self.executor = executor
        self.fault_hook = fault_hook

    async def execute(
        self,
        *,
        alert_id: str,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        tool_spec: ToolSpec | None,
        prior_evidence: Sequence[EvidenceRecord] = (),
    ) -> EvidenceRecord:
        lease_owner, fencing_token = self._lease_identity(context)
        if str(context.alert.id) != alert_id:
            raise OuterDispatchError("outer dispatch alert identity does not match context")
        normalized_request = self._normalize_request(request)
        if tool_spec is not None and tool_spec.name != normalized_request.tool_name:
            raise OuterDispatchError("tool spec does not match the requested tool")
        fingerprint = ToolInvocation.build_fingerprint(
            tool_name=normalized_request.tool_name,
            effective_arguments=normalized_request.parameters,
        )
        dispatch_ordinal = self._dispatch_ordinal(
            normalized_request,
            prior_evidence,
        )
        dispatch_id = self.build_dispatch_id(
            context.run_id,
            fingerprint=fingerprint,
            ordinal=dispatch_ordinal,
        )
        first_context = context.model_copy(
            update={
                "outer_dispatch_id": dispatch_id,
                "outer_dispatch_attempt": 1,
            }
        )

        first = await self._load_or_create(
            dispatch_id=dispatch_id,
            attempt=1,
            request=normalized_request,
            context=first_context,
            tool_spec=tool_spec,
            fingerprint=fingerprint,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        first_terminal, first_evidence = await self._resolve_attempt(
            first,
            request=normalized_request,
            context=first_context,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        if (
            first_terminal.status != ToolInvocationStatus.UNKNOWN_OUTCOME
            or not first_terminal.tool_read_only
            or first_terminal.tool_max_attempts < 2
        ):
            return first_evidence

        retry_context = context.model_copy(
            update={
                "outer_dispatch_id": dispatch_id,
                "outer_dispatch_attempt": 2,
            }
        )
        retry = await self._load_or_create(
            dispatch_id=dispatch_id,
            attempt=2,
            request=normalized_request,
            context=retry_context,
            tool_spec=tool_spec,
            fingerprint=fingerprint,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        _retry_terminal, retry_evidence = await self._resolve_attempt(
            retry,
            request=normalized_request,
            context=retry_context,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        return retry_evidence

    @staticmethod
    def build_dispatch_id(run_id: UUID, *, fingerprint: str, ordinal: int = 1) -> UUID:
        if ordinal < 1:
            raise ValueError("dispatch ordinal must be positive")
        return uuid5(run_id, f"{_DISPATCH_ID_VERSION}:{fingerprint}:{ordinal}")

    @staticmethod
    def build_invocation_id(dispatch_id: UUID, *, attempt: int) -> UUID:
        if attempt not in {1, 2}:
            raise ValueError("outer dispatch supports only the initial and recovery attempts")
        return uuid5(dispatch_id, f"attempt:{attempt}")

    @staticmethod
    def build_evidence_id(invocation_id: UUID) -> UUID:
        return uuid5(invocation_id, _EVIDENCE_ID_VERSION)

    async def _load_or_create(
        self,
        *,
        dispatch_id: UUID,
        attempt: int,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        tool_spec: ToolSpec | None,
        fingerprint: str,
        lease_owner: str,
        fencing_token: int,
    ) -> ToolInvocation:
        invocation_id = self.build_invocation_id(dispatch_id, attempt=attempt)
        provider = "unregistered" if tool_spec is None else tool_spec.provider
        existing = await self.repository.get_tool_invocation(str(invocation_id))
        if existing is not None:
            self._validate_identity(
                existing,
                request=request,
                context=context,
                tool_spec=tool_spec,
                fingerprint=fingerprint,
                attempt=attempt,
            )
            return existing

        now = datetime.now(UTC)
        objective = sanitize_text(request.objective).strip() or (
            f"Execute approved investigation tool {request.tool_name}"
        )
        invocation = ToolInvocation(
            invocation_id=invocation_id,
            run_id=context.run_id,
            tool_name=request.tool_name,
            provider=provider,
            objective=objective[:4000],
            hypothesis_ids=[str(sanitize(item))[:200] for item in request.hypothesis_ids],
            model_arguments=request.parameters,
            effective_arguments=request.parameters,
            fingerprint=fingerprint,
            tool_read_only=tool_spec.read_only if tool_spec is not None else False,
            tool_max_attempts=(
                tool_spec.retry.max_attempts if tool_spec is not None else 1
            ),
            tool_policy_version=(
                tool_spec.policy_version if tool_spec is not None else ""
            ),
            tool_schema_version=(
                tool_spec.schema_version if tool_spec is not None else ""
            ),
            request_timeout_seconds=request.timeout_seconds,
            attempt=attempt,
            deadline=now + timedelta(seconds=request.timeout_seconds),
            created_at=now,
        )
        try:
            await self.repository.save_tool_invocation(
                invocation,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        except ToolInvocationConflict:
            existing = await self.repository.get_tool_invocation(str(invocation_id))
            if existing is None:
                raise
            self._validate_identity(
                existing,
                request=request,
                context=context,
                tool_spec=tool_spec,
                fingerprint=fingerprint,
                attempt=attempt,
            )
            return existing
        await self._fault(
            OuterDispatchFaultPoint.AFTER_PENDING_PERSISTED,
            invocation,
            None,
        )
        return invocation

    async def _resolve_attempt(
        self,
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        lease_owner: str,
        fencing_token: int,
    ) -> tuple[ToolInvocation, EvidenceRecord]:
        if invocation.status == ToolInvocationStatus.PENDING:
            if invocation.deadline is not None and invocation.deadline <= datetime.now(UTC):
                return await self._expire_pending(
                    invocation,
                    request=request,
                    context=context,
                    lease_owner=lease_owner,
                    fencing_token=fencing_token,
                )
            return await self._execute_pending(
                invocation,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        if invocation.status == ToolInvocationStatus.STARTED:
            return await self._resolve_started(
                invocation,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        return invocation, await self._load_terminal_evidence(invocation)

    async def _expire_pending(
        self,
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        lease_owner: str,
        fencing_token: int,
    ) -> tuple[ToolInvocation, EvidenceRecord]:
        completed_at = max(datetime.now(UTC), invocation.created_at)
        evidence = EvidenceRecord(
            id=self.build_evidence_id(invocation.invocation_id),
            run_id=context.run_id,
            tool_name=request.tool_name,
            source_system=invocation.provider,
            status=ToolStatus.TIMEOUT,
            request=request.parameters,
            summary=(
                f"调查工具 {request.tool_name} 在恢复前已超过持久化调用期限，未执行。"
            ),
            structured_data={
                "reason_code": "invocation_deadline_exceeded_before_dispatch",
                "root_cause_eligible": False,
            },
            error="Outer tool invocation deadline expired before dispatch",
            started_at=completed_at,
            collected_at=completed_at,
            duration_ms=0,
        )
        expired = self._transition(
            invocation,
            status=ToolInvocationStatus.TIMED_OUT,
            started_at=completed_at,
            completed_at=completed_at,
            error=InvocationError(
                code="outer_invocation_deadline_exceeded",
                message="The persisted outer tool deadline expired before dispatch",
                retryable=False,
            ),
        )
        try:
            await self.repository.update_tool_invocation(
                expired,
                result=self._evidence_result(evidence),
                expected_status=ToolInvocationStatus.PENDING,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        except ToolInvocationConflict:
            current = await self.repository.get_tool_invocation(str(invocation.invocation_id))
            if current is None:
                raise
            return await self._resolve_attempt(
                current,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        await self._fault(
            OuterDispatchFaultPoint.AFTER_TERMINAL_PERSISTED,
            expired,
            evidence,
        )
        return expired, evidence

    async def _execute_pending(
        self,
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        lease_owner: str,
        fencing_token: int,
    ) -> tuple[ToolInvocation, EvidenceRecord]:
        started_at = datetime.now(UTC)
        started = self._transition(
            invocation,
            status=ToolInvocationStatus.STARTED,
            started_at=started_at,
            execution_lease_owner=lease_owner,
            execution_fencing_token=fencing_token,
        )
        try:
            await self.repository.update_tool_invocation(
                started,
                expected_status=ToolInvocationStatus.PENDING,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        except ToolInvocationConflict:
            current = await self.repository.get_tool_invocation(str(invocation.invocation_id))
            if current is None:
                raise
            return await self._resolve_attempt(
                current,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        await self._fault(
            OuterDispatchFaultPoint.AFTER_STARTED_PERSISTED,
            started,
            None,
        )

        if started.deadline is None:
            raise OuterDispatchError("outer invocation is missing its frozen deadline")
        remaining_seconds = (started.deadline - datetime.now(UTC)).total_seconds()
        try:
            if remaining_seconds <= 0:
                raise TimeoutError("Outer tool invocation deadline expired")
            async with asyncio.timeout(remaining_seconds):
                raw_evidence = await self.executor.execute(request, context)
        except RunLeaseConflict:
            raise
        except TimeoutError as exc:
            raw_evidence = self._execution_timeout_evidence(
                invocation=started,
                request=request,
                error=exc,
            )
        except Exception as exc:
            raw_evidence = self._execution_failure_evidence(
                invocation=started,
                request=request,
                error=exc,
            )
        evidence = self._normalize_evidence(
            raw_evidence,
            invocation=started,
            request=request,
        )
        await self._fault(
            OuterDispatchFaultPoint.AFTER_HANDLER_RETURNED,
            started,
            evidence,
        )
        completed = self._terminal_invocation(started, evidence)
        try:
            await self.repository.update_tool_invocation(
                completed,
                result=self._evidence_result(evidence),
                expected_status=ToolInvocationStatus.STARTED,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        except ToolInvocationConflict:
            current = await self.repository.get_tool_invocation(
                str(invocation.invocation_id)
            )
            if current is None:
                raise
            return await self._resolve_attempt(
                current,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        await self._fault(
            OuterDispatchFaultPoint.AFTER_TERMINAL_PERSISTED,
            completed,
            evidence,
        )
        return completed, evidence

    async def _resolve_started(
        self,
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        lease_owner: str,
        fencing_token: int,
    ) -> tuple[ToolInvocation, EvidenceRecord]:
        if invocation.deadline is None:
            raise OuterDispatchError("outer invocation is missing its frozen deadline")
        if invocation.deadline <= datetime.now(UTC):
            return await self._recover_started(
                invocation,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )

        execution_token = invocation.execution_fencing_token
        execution_owner = invocation.execution_lease_owner
        if execution_token is not None:
            if fencing_token > execution_token:
                return await self._recover_started(
                    invocation,
                    request=request,
                    context=context,
                    lease_owner=lease_owner,
                    fencing_token=fencing_token,
                )
            if fencing_token < execution_token:
                raise RunLeaseConflict(
                    str(context.run_id),
                    "outer invocation was started under a newer fencing epoch",
                )
            if execution_owner != lease_owner:
                raise OuterDispatchError(
                    "outer invocation execution owner changed without a new fencing epoch"
                )

        return await self._wait_for_inflight_terminal(
            invocation,
            request=request,
            context=context,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )

    async def _wait_for_inflight_terminal(
        self,
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        lease_owner: str,
        fencing_token: int,
    ) -> tuple[ToolInvocation, EvidenceRecord]:
        """Join an invocation still owned by this lease epoch."""

        current = invocation
        while True:
            if current.status != ToolInvocationStatus.STARTED:
                return await self._resolve_attempt(
                    current,
                    request=request,
                    context=context,
                    lease_owner=lease_owner,
                    fencing_token=fencing_token,
                )
            if current.deadline is None:
                raise OuterDispatchError("outer invocation is missing its frozen deadline")
            remaining_seconds = (current.deadline - datetime.now(UTC)).total_seconds()
            if remaining_seconds <= 0:
                return await self._recover_started(
                    current,
                    request=request,
                    context=context,
                    lease_owner=lease_owner,
                    fencing_token=fencing_token,
                )
            await asyncio.sleep(
                min(_INFLIGHT_POLL_INTERVAL_SECONDS, remaining_seconds)
            )
            persisted = await self.repository.get_tool_invocation(
                str(current.invocation_id)
            )
            if persisted is None:
                raise OuterDispatchError(
                    f"in-flight outer invocation {current.invocation_id} disappeared"
                )
            current = persisted

    async def _recover_started(
        self,
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        lease_owner: str,
        fencing_token: int,
    ) -> tuple[ToolInvocation, EvidenceRecord]:
        completed_at = max(datetime.now(UTC), invocation.started_at or invocation.created_at)
        evidence = EvidenceRecord(
            id=self.build_evidence_id(invocation.invocation_id),
            run_id=context.run_id,
            tool_name=request.tool_name,
            source_system=invocation.provider,
            status=ToolStatus.FAILED,
            request=request.parameters,
            summary=(
                f"调查工具 {request.tool_name} 的进程在调用期间中断，远端结果未知。"
            ),
            structured_data={
                "reason_code": "unknown_outcome",
                "invocation_status": ToolInvocationStatus.UNKNOWN_OUTCOME.value,
                "root_cause_eligible": False,
            },
            error="Outer tool invocation outcome is unknown after process recovery",
            started_at=invocation.started_at or invocation.created_at,
            collected_at=completed_at,
            duration_ms=max(
                0,
                int(
                    (
                        completed_at - (invocation.started_at or invocation.created_at)
                    ).total_seconds()
                    * 1000
                ),
            ),
        )
        recovery_attempt_allowed = (
            invocation.attempt == 1
            and invocation.tool_read_only
            and invocation.tool_max_attempts >= 2
        )
        recovered = self._transition(
            invocation,
            status=ToolInvocationStatus.UNKNOWN_OUTCOME,
            completed_at=completed_at,
            error=InvocationError(
                code="outer_invocation_recovered_unknown_outcome",
                message="The process stopped while the outer tool invocation was in flight",
                retryable=recovery_attempt_allowed,
                details={"recovery_attempt_allowed": recovery_attempt_allowed},
            ),
        )
        try:
            await self.repository.update_tool_invocation(
                recovered,
                result=self._evidence_result(evidence),
                expected_status=ToolInvocationStatus.STARTED,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        except ToolInvocationConflict:
            current = await self.repository.get_tool_invocation(str(invocation.invocation_id))
            if current is None:
                raise
            return await self._resolve_attempt(
                current,
                request=request,
                context=context,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
        return recovered, evidence

    async def _load_terminal_evidence(self, invocation: ToolInvocation) -> EvidenceRecord:
        if invocation.status in {
            ToolInvocationStatus.PENDING,
            ToolInvocationStatus.STARTED,
        }:
            raise OuterDispatchError("cannot load evidence from a non-terminal invocation")
        result = await self.repository.get_tool_invocation_result(str(invocation.invocation_id))
        if result is None:
            raise OuterDispatchError(
                f"terminal invocation {invocation.invocation_id} has no durable evidence result"
            )
        if result.get("contract") != OUTER_EVIDENCE_RESULT_CONTRACT:
            raise OuterDispatchError(
                "terminal outer invocation uses an unsupported result contract"
            )
        try:
            evidence = EvidenceRecord.model_validate(result.get("evidence_record"))
        except Exception as exc:
            raise OuterDispatchError("terminal outer invocation evidence is invalid") from exc
        expected_id = self.build_evidence_id(invocation.invocation_id)
        if evidence.id != expected_id:
            raise OuterDispatchError("terminal outer invocation evidence identity does not match")
        if (
            evidence.run_id != invocation.run_id
            or evidence.tool_name != invocation.tool_name
            or evidence.request != invocation.effective_arguments
            or evidence.source_system != invocation.provider
        ):
            raise OuterDispatchError(
                "terminal outer invocation evidence provenance does not match"
            )
        self._validate_evidence_status(invocation, evidence)
        return evidence

    @classmethod
    def _normalize_request(cls, request: ToolExecutionRequest) -> ToolExecutionRequest:
        payload = request.model_dump(mode="json")
        safe_parameters = sanitize(payload.get("parameters") or {})
        canonical_parameters = json.loads(
            json.dumps(
                safe_parameters,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        )
        return ToolExecutionRequest.model_validate(
            {
                **payload,
                "tool_name": sanitize_text(str(payload["tool_name"])),
                "parameters": canonical_parameters,
                "objective": sanitize_text(str(payload.get("objective") or "")),
                "hypothesis_ids": sanitize(payload.get("hypothesis_ids") or []),
            }
        )

    @classmethod
    def _dispatch_ordinal(
        cls,
        request: ToolExecutionRequest,
        prior_evidence: Sequence[EvidenceRecord],
    ) -> int:
        """Allocate a new logical dispatch only after an explicit partial success."""

        partial_ids = {
            evidence.id
            for evidence in prior_evidence
            if evidence.tool_name == request.tool_name
            and evidence.request == request.parameters
            and evidence.status == ToolStatus.SUCCESS
            and evidence.structured_data.get("partial") is True
            and evidence.structured_data.get("allow_followup_dispatch") is not False
        }
        return len(partial_ids) + 1

    @staticmethod
    def _validate_identity(
        invocation: ToolInvocation,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        tool_spec: ToolSpec | None,
        fingerprint: str,
        attempt: int,
    ) -> None:
        provider = "unregistered" if tool_spec is None else tool_spec.provider
        read_only = tool_spec.read_only if tool_spec is not None else False
        max_attempts = tool_spec.retry.max_attempts if tool_spec is not None else 1
        policy_version = tool_spec.policy_version if tool_spec is not None else ""
        schema_version = tool_spec.schema_version if tool_spec is not None else ""
        expected_objective = sanitize_text(request.objective).strip() or (
            f"Execute approved investigation tool {request.tool_name}"
        )
        expected_hypothesis_ids = [
            str(sanitize(item))[:200] for item in request.hypothesis_ids
        ]
        expected_deadline = invocation.created_at + timedelta(
            seconds=request.timeout_seconds
        )
        if (
            invocation.run_id != context.run_id
            or invocation.tool_name != request.tool_name
            or invocation.provider != provider
            or invocation.fingerprint != fingerprint
            or invocation.attempt != attempt
            or invocation.model_arguments != request.parameters
            or invocation.effective_arguments != request.parameters
            or invocation.tool_read_only != read_only
            or invocation.tool_max_attempts != max_attempts
            or invocation.tool_policy_version != policy_version
            or invocation.tool_schema_version != schema_version
            or invocation.objective != expected_objective[:4000]
            or invocation.hypothesis_ids != expected_hypothesis_ids
            or invocation.request_timeout_seconds != request.timeout_seconds
            or invocation.deadline != expected_deadline
        ):
            raise OuterDispatchError("persisted outer invocation identity does not match request")

    @classmethod
    def _normalize_evidence(
        cls,
        evidence: EvidenceRecord,
        *,
        invocation: ToolInvocation,
        request: ToolExecutionRequest,
    ) -> EvidenceRecord:
        if (
            evidence.run_id != invocation.run_id
            or evidence.tool_name != request.tool_name
            or evidence.source_system != invocation.provider
        ):
            return cls._host_processing_failure_evidence(
                invocation=invocation,
                request=request,
                detail=(
                    "tool executor returned evidence for another run, tool, or provider"
                ),
            )
        payload = sanitize(evidence.model_dump(mode="json"))
        payload.update(
            {
                "id": str(cls.build_evidence_id(invocation.invocation_id)),
                "run_id": str(invocation.run_id),
                "tool_name": request.tool_name,
                "request": request.parameters,
            }
        )
        try:
            return EvidenceRecord.model_validate(payload)
        except Exception as exc:
            return cls._host_processing_failure_evidence(
                invocation=invocation,
                request=request,
                detail=f"invalid evidence contract: {type(exc).__name__}",
            )

    @classmethod
    def _execution_failure_evidence(
        cls,
        *,
        invocation: ToolInvocation,
        request: ToolExecutionRequest,
        error: Exception,
    ) -> EvidenceRecord:
        detail = sanitize_text(f"{type(error).__name__}: {error}")[:4000]
        return EvidenceRecord(
            id=cls.build_evidence_id(invocation.invocation_id),
            run_id=invocation.run_id,
            tool_name=request.tool_name,
            source_system=invocation.provider,
            status=ToolStatus.FAILED,
            request=request.parameters,
            summary=f"调查工具 {request.tool_name} 执行失败。",
            structured_data={
                "reason_code": type(error).__name__,
                "root_cause_eligible": False,
            },
            error=detail,
            started_at=invocation.started_at or invocation.created_at,
            collected_at=datetime.now(UTC),
        )

    @classmethod
    def _execution_timeout_evidence(
        cls,
        *,
        invocation: ToolInvocation,
        request: ToolExecutionRequest,
        error: TimeoutError,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            id=cls.build_evidence_id(invocation.invocation_id),
            run_id=invocation.run_id,
            tool_name=request.tool_name,
            source_system=invocation.provider,
            status=ToolStatus.TIMEOUT,
            request=request.parameters,
            summary=f"调查工具 {request.tool_name} 已达到持久化调用期限。",
            structured_data={
                "reason_code": "outer_invocation_deadline_exceeded",
                "root_cause_eligible": False,
            },
            error=sanitize_text(f"{type(error).__name__}: {error}")[:4000],
            started_at=invocation.started_at or invocation.created_at,
            collected_at=datetime.now(UTC),
        )

    @classmethod
    def _host_processing_failure_evidence(
        cls,
        *,
        invocation: ToolInvocation,
        request: ToolExecutionRequest,
        detail: str,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            id=cls.build_evidence_id(invocation.invocation_id),
            run_id=invocation.run_id,
            tool_name=request.tool_name,
            source_system=invocation.provider,
            status=ToolStatus.FAILED,
            request=request.parameters,
            summary=f"调查工具 {request.tool_name} 的本地结果处理失败。",
            structured_data={
                "reason_code": "host_result_processing_error",
                "root_cause_eligible": False,
            },
            error=sanitize_text(detail)[:4000],
            started_at=invocation.started_at or invocation.created_at,
            collected_at=datetime.now(UTC),
        )

    @staticmethod
    def _terminal_invocation(
        invocation: ToolInvocation,
        evidence: EvidenceRecord,
    ) -> ToolInvocation:
        status_by_evidence = {
            ToolStatus.SUCCESS: ToolInvocationStatus.SUCCEEDED,
            ToolStatus.NO_DATA: ToolInvocationStatus.NO_DATA,
            ToolStatus.FAILED: ToolInvocationStatus.FAILED,
            ToolStatus.TIMEOUT: ToolInvocationStatus.TIMED_OUT,
            ToolStatus.SKIPPED: ToolInvocationStatus.SKIPPED,
        }
        status = status_by_evidence[evidence.status]
        error = None
        if status in {ToolInvocationStatus.FAILED, ToolInvocationStatus.TIMED_OUT}:
            code = str(evidence.structured_data.get("reason_code") or status.value.lower())
            error = InvocationError(
                code=sanitize_text(code)[:256] or status.value.lower(),
                message=(sanitize_text(evidence.error) or evidence.summary)[:4000],
                retryable=status == ToolInvocationStatus.TIMED_OUT,
            )
        return DurableOuterToolDispatcher._transition(
            invocation,
            status=status,
            completed_at=max(datetime.now(UTC), invocation.started_at or datetime.now(UTC)),
            error=error,
        )

    @staticmethod
    def _validate_evidence_status(
        invocation: ToolInvocation,
        evidence: EvidenceRecord,
    ) -> None:
        expected = {
            ToolInvocationStatus.SUCCEEDED: ToolStatus.SUCCESS,
            ToolInvocationStatus.NO_DATA: ToolStatus.NO_DATA,
            ToolInvocationStatus.FAILED: ToolStatus.FAILED,
            ToolInvocationStatus.TIMED_OUT: ToolStatus.TIMEOUT,
            ToolInvocationStatus.UNKNOWN_OUTCOME: ToolStatus.FAILED,
            ToolInvocationStatus.SKIPPED: ToolStatus.SKIPPED,
        }.get(invocation.status)
        if expected is None or evidence.status != expected:
            raise OuterDispatchError("terminal invocation and evidence statuses do not match")
        if (
            invocation.status == ToolInvocationStatus.UNKNOWN_OUTCOME
            and evidence.structured_data.get("reason_code") != "unknown_outcome"
        ):
            raise OuterDispatchError("unknown-outcome invocation lacks matching evidence semantics")

    @staticmethod
    def _evidence_result(evidence: EvidenceRecord) -> dict[str, Any]:
        return {
            "contract": OUTER_EVIDENCE_RESULT_CONTRACT,
            "evidence_record": evidence.model_dump(mode="json"),
        }

    @staticmethod
    def _transition(invocation: ToolInvocation, **updates: Any) -> ToolInvocation:
        return ToolInvocation.model_validate(
            {
                **invocation.model_dump(mode="python"),
                **updates,
            }
        )

    async def _fault(
        self,
        point: OuterDispatchFaultPoint,
        invocation: ToolInvocation,
        evidence: EvidenceRecord | None,
    ) -> None:
        if self.fault_hook is None:
            return
        result = self.fault_hook(point, invocation, evidence)
        if inspect.isawaitable(result):
            await result

    @staticmethod
    def _lease_identity(context: InvestigationContext) -> tuple[str, int]:
        if context.lease_owner is None or context.fencing_token is None:
            raise ValueError("durable outer dispatch requires an active fenced run lease")
        return context.lease_owner, context.fencing_token
