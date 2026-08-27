"""Durable dispatch for outer investigation tools executed by LangGraph nodes."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Any, Protocol
from uuid import UUID, uuid5

from jsonpointer import JsonPointerException, resolve_pointer

from app.agent_runtime.contracts import (
    ArtifactRef,
    InvocationError,
    ToolInvocation,
    ToolInvocationStatus,
    ToolSpec,
)
from app.application.sanitization import sanitize, sanitize_text
from app.domain.models import (
    EVIDENCE_RECORD_V2,
    EvidenceRecord,
    EvidenceUnit,
    EvidenceUnitKind,
    EvidenceUnitStatus,
    InvestigationContext,
    ToolExecutionRequest,
    ToolResultAnalysis,
    ToolStatus,
)
from app.domain.ports import (
    AlertRepository,
    RunLeaseConflict,
    ToolInvocationConflict,
    ToolResultAnalyzer,
)

OUTER_EVIDENCE_RESULT_CONTRACT = "outer-evidence-record/v1"
_DISPATCH_ID_VERSION = "outer-tool-dispatch/v1"
_EVIDENCE_ID_VERSION = "outer-tool-evidence/v1"
_RAW_RESULT_ARTIFACT_VERSION = "raw-tool-result/v1"
_INFLIGHT_POLL_INTERVAL_SECONDS = 0.05
_PROJECTED_STATUS_FIELDS = (
    "termination_reason",
    "termination_error_type",
    "reason_code",
    "monitoring_scope_status",
    "monitoring_scope_reason",
)


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
    in-flight attempt. A newer fencing epoch or expired durable deadline records
    an unknown outcome without automatically replaying the remote command.
    """

    def __init__(
        self,
        repository: AlertRepository,
        executor: OuterToolExecutor,
        *,
        result_analyzer: ToolResultAnalyzer | None = None,
        fault_hook: OuterDispatchFaultHook | None = None,
    ) -> None:
        self.repository = repository
        self.executor = executor
        self.result_analyzer = result_analyzer
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
        _first_terminal, first_evidence = await self._resolve_attempt(
            first,
            request=normalized_request,
            context=first_context,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        return first_evidence

    @staticmethod
    def build_dispatch_id(run_id: UUID, *, fingerprint: str, ordinal: int = 1) -> UUID:
        if ordinal < 1:
            raise ValueError("dispatch ordinal must be positive")
        return uuid5(run_id, f"{_DISPATCH_ID_VERSION}:{fingerprint}:{ordinal}")

    @staticmethod
    def build_invocation_id(dispatch_id: UUID, *, attempt: int) -> UUID:
        if attempt != 1:
            raise ValueError("outer dispatch executes each explicit Agent action at most once")
        return uuid5(dispatch_id, f"attempt:{attempt}")

    @staticmethod
    def build_evidence_id(invocation_id: UUID) -> UUID:
        return uuid5(invocation_id, _EVIDENCE_ID_VERSION)

    @staticmethod
    def build_raw_result_artifact_id(invocation_id: UUID) -> UUID:
        return uuid5(invocation_id, _RAW_RESULT_ARTIFACT_VERSION)

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
        artifact_ref = await self._persist_raw_result(
            invocation=started,
            evidence=evidence,
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )
        evidence = await self._project_tool_result(
            evidence,
            request=request,
            artifact_ref=artifact_ref,
        )
        completed = self._terminal_invocation(
            started,
            evidence,
            artifact_ref=artifact_ref,
        )
        try:
            await self.repository.update_tool_invocation(
                completed,
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
        recovered = self._transition(
            invocation,
            status=ToolInvocationStatus.UNKNOWN_OUTCOME,
            completed_at=completed_at,
            error=InvocationError(
                code="outer_invocation_recovered_unknown_outcome",
                message="The process stopped while the outer tool invocation was in flight",
                retryable=False,
                details={"automatic_replay": False},
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
        if invocation.artifact_ref is not None:
            stored = await self.repository.get_agent_artifact(
                str(invocation.artifact_ref.artifact_id)
            )
            if stored is None or stored[0] != invocation.artifact_ref:
                raise OuterDispatchError(
                    "terminal outer invocation raw-result artifact is missing or corrupt"
                )
            source_artifact = evidence.structured_data.get("source_artifact")
            if source_artifact is not None:
                try:
                    projected_ref = ArtifactRef.model_validate(source_artifact)
                except Exception as exc:
                    raise OuterDispatchError(
                        "terminal outer invocation has an invalid artifact reference"
                    ) from exc
                if projected_ref != invocation.artifact_ref:
                    raise OuterDispatchError(
                        "terminal evidence artifact provenance does not match invocation"
                    )
            if (
                evidence.contract_version == EVIDENCE_RECORD_V2
                and evidence.source_artifact_id != invocation.artifact_ref.artifact_id
            ):
                raise OuterDispatchError(
                    "terminal evidence source artifact does not match invocation"
                )
            if any(
                unit.source_artifact_id != invocation.artifact_ref.artifact_id
                for unit in evidence.evidence_units
            ):
                raise OuterDispatchError(
                    "terminal evidence-unit artifact provenance does not match invocation"
                )
            if evidence.evidence_units:
                raw_result = stored[1]
                if not isinstance(raw_result, Mapping):
                    raise OuterDispatchError(
                        "terminal evidence-unit raw-result artifact is not a JSON object"
                    )
                self._validate_evidence_unit_sources(
                    raw_result,
                    evidence.evidence_units,
                    artifact_id=invocation.artifact_ref.artifact_id,
                )
        elif evidence.evidence_units or evidence.source_artifact_id is not None:
            raise OuterDispatchError(
                "terminal evidence provenance requires a raw-result artifact"
            )
        return evidence

    async def _persist_raw_result(
        self,
        *,
        invocation: ToolInvocation,
        evidence: EvidenceRecord,
        lease_owner: str,
        fencing_token: int,
    ) -> ArtifactRef:
        artifact_id = self.build_raw_result_artifact_id(invocation.invocation_id)
        artifact = ArtifactRef(
            artifact_id=artifact_id,
            kind="raw_tool_result",
            media_type="application/json",
            uri=f"agent-artifact://{artifact_id}",
            metadata={
                "contract": _RAW_RESULT_ARTIFACT_VERSION,
                "tool_name": invocation.tool_name,
                "source_system": invocation.provider,
                "sanitized": True,
                "internal_only": True,
            },
        )
        return await self.repository.save_agent_artifact(
            str(invocation.run_id),
            artifact,
            evidence.model_dump(mode="json"),
            invocation_id=str(invocation.invocation_id),
            lease_owner=lease_owner,
            fencing_token=fencing_token,
        )

    async def _project_tool_result(
        self,
        evidence: EvidenceRecord,
        *,
        request: ToolExecutionRequest,
        artifact_ref: ArtifactRef,
    ) -> EvidenceRecord:
        if evidence.status in {ToolStatus.FAILED, ToolStatus.TIMEOUT}:
            projected_data = self._status_metadata(evidence)
            projected_data.update(
                {
                    "processing_status": "unavailable",
                    "root_cause_eligible": False,
                    "root_cause_ineligible_reason": "tool_status_not_success",
                }
            )
            return evidence.model_copy(
                update={
                    "structured_data": projected_data,
                    "truncated": False,
                }
            )
        raw_result = evidence.model_dump(mode="json")
        if self.result_analyzer is None:
            projected_data = self._status_metadata(evidence)
            projected_data.update(
                {
                    "processing_status": "unavailable",
                    "root_cause_eligible": False,
                    "root_cause_ineligible_reason": (
                        "program_fact_projection_not_configured"
                    ),
                }
            )
            return evidence.model_copy(
                update={
                    "summary": (
                        f"调查工具 {evidence.tool_name} 已返回结果，但程序事实投影器未配置，"
                        "原始响应仅保存在审计工件中。"
                    ),
                    "structured_data": projected_data,
                    "truncated": False,
                }
            )

        try:
            analysis = await self.result_analyzer.analyze(
                tool_name=evidence.tool_name,
                source_system=evidence.source_system,
                request=request.parameters,
                raw_result=raw_result,
                artifact=artifact_ref,
            )
            if (
                analysis.source_artifact_id != artifact_ref.artifact_id
                or analysis.source_sha256 != artifact_ref.sha256
            ):
                raise OuterDispatchError(
                    "tool-result analysis provenance does not match its raw artifact"
                )
            result_usable_by_main_agent = (
                evidence.status == ToolStatus.SUCCESS
                and analysis.analysis_usable
                and analysis.source_coverage_complete
            )
            context_only_similar_incidents = evidence.is_context_only()
            evidence_units = self._archery_evidence_units(
                evidence,
                analysis=analysis,
            )
            if evidence_units:
                self._validate_evidence_unit_sources(
                    raw_result,
                    evidence_units,
                    artifact_id=artifact_ref.artifact_id,
                )
            parent_root_cause_eligible = (
                result_usable_by_main_agent
                and evidence.source_system.casefold() != "alert_platform"
                and not context_only_similar_incidents
                and not evidence_units
            )
            # A passthrough provider whose final-result JSON could not be parsed
            # still reaches the main Agent verbatim, but stays mechanically
            # unavailable so it can never support a root cause.
            passthrough_parse_failed = bool(getattr(analysis, "passthrough_parse_failed", False))
            projected_data: dict[str, Any] = {
                **self._status_metadata(evidence),
                "processing_status": ("unavailable" if passthrough_parse_failed else "completed"),
                "tool_result_analysis": analysis.model_dump(
                    mode="json",
                    exclude={"source_artifact_id", "source_sha256"},
                ),
                # Mechanical completeness gate only. The main Agent alone decides
                # whether these facts, combined with other evidence, imply a cause.
                "root_cause_eligible": parent_root_cause_eligible,
            }
            if passthrough_parse_failed:
                projected_data["root_cause_ineligible_reason"] = "final_result_json_unparseable"
            elif context_only_similar_incidents:
                projected_data["root_cause_ineligible_reason"] = (
                    "similar_incidents_are_context_only"
                )
            elif evidence_units:
                projected_data["root_cause_ineligible_reason"] = "reference_eligible_evidence_unit"
            elif evidence.source_system.casefold() == "alert_platform":
                projected_data["root_cause_ineligible_reason"] = "alert_platform_context_only"
            elif not analysis.analysis_usable:
                projected_data["root_cause_ineligible_reason"] = "program_fact_projection_unusable"
            elif not result_usable_by_main_agent and not projected_data.get(
                "root_cause_ineligible_reason"
            ):
                projected_data["root_cause_ineligible_reason"] = (
                    "tool_result_incomplete_or_unusable"
                )
            projected = evidence.model_copy(
                update={
                    "summary": analysis.summary,
                    "structured_data": projected_data,
                    "truncated": False,
                    "contract_version": (
                        EVIDENCE_RECORD_V2 if evidence_units else evidence.contract_version
                    ),
                    "source_artifact_id": (
                        artifact_ref.artifact_id if evidence_units else None
                    ),
                    "evidence_units": evidence_units,
                }
            )
            return EvidenceRecord.model_validate(projected.model_dump(mode="python"))
        except Exception as exc:
            request_id = getattr(exc, "request_id", None)
            error_data: dict[str, Any] = {
                **self._status_metadata(evidence),
                "processing_status": "failed",
                "processing_error_type": type(exc).__name__,
                "root_cause_eligible": False,
                "root_cause_ineligible_reason": (
                    "program_fact_projection_failed"
                ),
            }
            if isinstance(request_id, str) and request_id:
                error_data["processing_request_id"] = sanitize_text(request_id)[:512]
            return evidence.model_copy(
                update={
                    "summary": (
                        f"调查工具 {evidence.tool_name} 已返回结果，但程序事实投影失败，"
                        "该结果不能用于根因判断。"
                    ),
                    "structured_data": error_data,
                    "truncated": False,
                }
            )

    @staticmethod
    def _archery_evidence_units(
        evidence: EvidenceRecord,
        *,
        analysis: ToolResultAnalysis,
    ) -> list[EvidenceUnit]:
        """Split Archery history and supplemental results into qualified v2 units."""

        if evidence.source_system.casefold() not in {"archery", "archery_mcp"}:
            return []
        payload = analysis.passthrough_payload
        supplemental = analysis.slow_query_analysis
        full_sql = str(payload.get("full_sql") or "") if isinstance(payload, Mapping) else ""
        raw_text = (
            str(payload.get("final_result_text") or "") if isinstance(payload, Mapping) else ""
        )
        if not isinstance(supplemental, Mapping) and (
            "mysql_slow_query_review_history" not in full_sql.casefold()
            and "mysql_slow_query_review_history" not in raw_text.casefold()
        ):
            return []

        artifact_id = analysis.source_artifact_id
        units: list[EvidenceUnit] = []
        unit_keys: set[str] = set()

        def stable_unit_key(
            *,
            stage: str,
            outcome: str,
            data: Mapping[str, Any],
        ) -> str:
            canonical = json.dumps(
                sanitize(dict(data)),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            digest = sha256(canonical.encode()).hexdigest()[:24]
            return f"supplemental:{stage}:{outcome}:{digest}"

        def append_unit(
            *,
            unit_key: str,
            kind: EvidenceUnitKind,
            stage: str,
            status: EvidenceUnitStatus,
            summary: str,
            data: Mapping[str, Any] | None,
            source_paths: list[str],
            eligible: bool,
            ineligible_reason: str | None = None,
            result_index: int | None = None,
        ) -> None:
            if unit_key in unit_keys:
                return
            unit_keys.add(unit_key)
            units.append(
                EvidenceUnit(
                    id=EvidenceUnit.build_id(evidence.id, unit_key),
                    parent_evidence_id=evidence.id,
                    unit_key=unit_key,
                    kind=kind,
                    stage=stage,
                    result_index=result_index,
                    status=status,
                    summary=summary,
                    data=dict(data or {}),
                    root_cause_eligible=eligible,
                    root_cause_ineligible_reason=(
                        None if eligible else ineligible_reason or "evidence_unit_unusable"
                    ),
                    source_artifact_id=artifact_id,
                    source_paths=source_paths,
                )
            )

        history_path = "/structured_data/final_result_payload"
        raw_structured_data = evidence.structured_data
        history_data = payload if isinstance(payload, Mapping) else None
        rows = history_data.get("rows") if history_data is not None else None
        history_incomplete = bool(
            history_data is not None
            and (
                history_data.get("result_incomplete") is True
                or history_data.get("history_recovery_complete") is False
            )
        )
        if analysis.passthrough_parse_failed:
            parse_failure_path = (
                "/structured_data/final_result_text"
                if "final_result_text" in raw_structured_data
                else "/structured_data/final_result_parse_failed"
                if "final_result_parse_failed" in raw_structured_data
                else "/structured_data"
            )
            append_unit(
                unit_key="history",
                kind=EvidenceUnitKind.HISTORY,
                stage="history",
                status=EvidenceUnitStatus.FAILED,
                summary="Archery history 返回内容无法解析。",
                data=history_data,
                source_paths=[parse_failure_path],
                eligible=False,
                ineligible_reason="history_result_unparseable",
            )
        elif isinstance(rows, list) and rows and history_incomplete:
            append_unit(
                unit_key="history",
                kind=EvidenceUnitKind.HISTORY,
                stage="history",
                status=EvidenceUnitStatus.FAILED,
                summary=(f"Archery history 仅恢复 {len(rows)} 行，仍有未完整恢复的内容。"),
                data=history_data,
                source_paths=[history_path],
                eligible=False,
                ineligible_reason="history_recovery_incomplete",
            )
        elif isinstance(rows, list) and rows:
            history_eligible = (
                evidence.status == ToolStatus.SUCCESS and analysis.source_coverage_complete
            )
            append_unit(
                unit_key="history",
                kind=EvidenceUnitKind.HISTORY,
                stage="history",
                status=EvidenceUnitStatus.SUCCESS,
                summary=f"Archery history 已完整恢复 {len(rows)} 行。",
                data=history_data,
                source_paths=[history_path],
                eligible=history_eligible,
                ineligible_reason="history_source_coverage_incomplete",
            )
        elif isinstance(rows, list):
            append_unit(
                unit_key="history",
                kind=EvidenceUnitKind.HISTORY,
                stage="history",
                status=EvidenceUnitStatus.NO_DATA,
                summary="Archery history 查询没有返回数据行。",
                data=history_data,
                source_paths=[history_path],
                eligible=False,
                ineligible_reason="history_no_data",
            )
        else:
            append_unit(
                unit_key="history",
                kind=EvidenceUnitKind.HISTORY,
                stage="history",
                status=EvidenceUnitStatus.FAILED,
                summary="Archery history 结果缺少可验证的 rows。",
                data=history_data,
                source_paths=["/structured_data"],
                eligible=False,
                ineligible_reason="history_rows_missing",
            )

        if not isinstance(supplemental, Mapping):
            return units

        result_fields = {
            "explain_results": "explain",
            "table_structure_results": "table_structure",
            "index_results": "indexes",
        }
        supplemental_eligible = (
            evidence.status == ToolStatus.SUCCESS and analysis.source_coverage_complete
        )
        successful_result_stages: set[str] = set()
        for field_name, stage in result_fields.items():
            results = supplemental.get(field_name)
            if not isinstance(results, list):
                continue
            for index, result in enumerate(results):
                if not isinstance(result, Mapping):
                    continue
                successful_result_stages.add(stage)
                append_unit(
                    unit_key=stable_unit_key(
                        stage=stage,
                        outcome="result",
                        data=result,
                    ),
                    kind=EvidenceUnitKind.SUPPLEMENTAL,
                    stage=stage,
                    result_index=index,
                    status=EvidenceUnitStatus.SUCCESS,
                    summary=f"Archery supplemental {stage} 第 {index + 1} 项已完成。",
                    data=result,
                    source_paths=[f"/structured_data/slow_query_analysis/{field_name}/{index}"],
                    eligible=supplemental_eligible,
                    ineligible_reason="supplemental_source_coverage_incomplete",
                )

        overall_status = str(supplemental.get("status") or "").casefold()
        history_recovery_succeeded = bool(
            isinstance(rows, list)
            and not history_incomplete
            and not analysis.passthrough_parse_failed
        )
        failure_stages: set[str] = set()
        failures = supplemental.get("failures")
        if isinstance(failures, list):
            for index, failure in enumerate(failures):
                if not isinstance(failure, Mapping):
                    continue
                stage = str(failure.get("stage") or "supplemental")
                recovered = bool(
                    stage == "history_recovery"
                    and failure.get("terminal") is False
                    and history_recovery_succeeded
                )
                if not recovered:
                    failure_stages.add(stage)
                not_applicable = (
                    str(failure.get("reason_code") or "").casefold()
                    == "no_safe_explainable_sample"
                )
                status = (
                    EvidenceUnitStatus.RECOVERED
                    if recovered
                    else EvidenceUnitStatus.NOT_APPLICABLE
                    if not_applicable
                    else EvidenceUnitStatus.FAILED
                )
                summary = (
                    f"Archery supplemental {stage} 第 {index + 1} 项失败后已恢复。"
                    if recovered
                    else f"Archery supplemental {stage} 第 {index + 1} 项未成功。"
                )
                append_unit(
                    unit_key=stable_unit_key(
                        stage=stage,
                        outcome="recovered" if recovered else "failure",
                        data=failure,
                    ),
                    kind=EvidenceUnitKind.SUPPLEMENTAL,
                    stage=stage,
                    result_index=index,
                    status=status,
                    summary=summary,
                    data=failure,
                    source_paths=[f"/structured_data/slow_query_analysis/failures/{index}"],
                    eligible=False,
                    ineligible_reason=(
                        "supplemental_recovered"
                        if recovered
                        else "supplemental_not_applicable"
                        if not_applicable
                        else "supplemental_failed"
                    ),
                )

        raw_stage_states = supplemental.get("stage_states")
        stage_states = raw_stage_states if isinstance(raw_stage_states, Mapping) else {}
        missing_stages = supplemental.get("missing_stages")
        if isinstance(missing_stages, list):
            for index, raw_stage in enumerate(missing_stages):
                stage = str(raw_stage or "supplemental")
                if stage in failure_stages:
                    continue
                stage_state = str(stage_states.get(stage) or "").upper()
                partially_covered = (
                    stage_state == "SUCCEEDED" and stage in successful_result_stages
                )
                status = (
                    EvidenceUnitStatus.UNAVAILABLE
                    if stage_state == "UNAVAILABLE"
                    else EvidenceUnitStatus.FAILED
                    if stage_state == "FAILED_TERMINAL"
                    else EvidenceUnitStatus.NOT_APPLICABLE
                    if stage_state == "NOT_APPLICABLE"
                    else EvidenceUnitStatus.PARTIAL
                    if partially_covered
                    else EvidenceUnitStatus.NO_DATA
                )
                summary = (
                    f"Archery supplemental {stage} 因前置条件不可用而未执行。"
                    if status == EvidenceUnitStatus.UNAVAILABLE
                    else f"Archery supplemental {stage} 已取得部分结果，但覆盖不完整。"
                    if status == EvidenceUnitStatus.PARTIAL
                    else f"Archery supplemental {stage} 未取得结果。"
                )
                ineligible_reason = (
                    "supplemental_unavailable"
                    if status == EvidenceUnitStatus.UNAVAILABLE
                    else "supplemental_failed"
                    if status == EvidenceUnitStatus.FAILED
                    else "supplemental_not_applicable"
                    if status == EvidenceUnitStatus.NOT_APPLICABLE
                    else "supplemental_partial"
                    if status == EvidenceUnitStatus.PARTIAL
                    else "supplemental_result_missing"
                )
                source_paths = [
                    f"/structured_data/slow_query_analysis/missing_stages/{index}"
                ]
                missing_data = {"stage": stage, "overall_status": overall_status}
                if stage_state:
                    escaped_stage = stage.replace("~", "~0").replace("/", "~1")
                    source_paths.append(
                        f"/structured_data/slow_query_analysis/stage_states/{escaped_stage}"
                    )
                    missing_data["stage_state"] = stage_state
                append_unit(
                    unit_key=f"supplemental:{stage}:missing",
                    kind=EvidenceUnitKind.SUPPLEMENTAL,
                    stage=stage,
                    status=status,
                    summary=summary,
                    data=missing_data,
                    source_paths=source_paths,
                    eligible=False,
                    ineligible_reason=ineligible_reason,
                )
        return units

    @classmethod
    def _validate_evidence_unit_sources(
        cls,
        raw_result: Mapping[str, Any],
        units: Sequence[EvidenceUnit],
        *,
        artifact_id: UUID,
    ) -> None:
        """Require every unit path to resolve inside its bound raw artifact."""

        for unit in units:
            if unit.source_artifact_id != artifact_id:
                raise OuterDispatchError(
                    "evidence-unit source artifact does not match the raw artifact"
                )
            resolved_values: list[Any] = []
            for source_path in unit.source_paths:
                try:
                    resolved_values.append(resolve_pointer(raw_result, source_path))
                except (JsonPointerException, TypeError, ValueError) as exc:
                    raise OuterDispatchError(
                        f"evidence-unit source path does not resolve: {source_path}"
                    ) from exc
            if unit.status == EvidenceUnitStatus.SUCCESS and not any(
                cls._projected_value_matches_source(unit.data, source)
                for source in resolved_values
            ):
                raise OuterDispatchError(
                    "successful evidence-unit data does not match its raw source path"
                )

    @classmethod
    def _projected_value_matches_source(cls, projected: Any, source: Any) -> bool:
        """Match a bounded projection against the corresponding raw source value."""

        if isinstance(projected, Mapping):
            return isinstance(source, Mapping) and all(
                key in source and cls._projected_value_matches_source(value, source[key])
                for key, value in projected.items()
            )
        if isinstance(projected, list):
            return isinstance(source, list) and len(projected) == len(source) and all(
                cls._projected_value_matches_source(item, raw_item)
                for item, raw_item in zip(projected, source, strict=True)
            )
        return projected == source

    @staticmethod
    def _status_metadata(evidence: EvidenceRecord) -> dict[str, Any]:
        """Keep non-payload execution metadata while raw content stays in the artifact."""

        return {
            key: evidence.structured_data[key]
            for key in _PROJECTED_STATUS_FIELDS
            if key in evidence.structured_data
        }

    @classmethod
    def _normalize_request(cls, request: ToolExecutionRequest) -> ToolExecutionRequest:
        return request.model_copy(deep=True)

    @classmethod
    def _dispatch_ordinal(
        cls,
        request: ToolExecutionRequest,
        prior_evidence: Sequence[EvidenceRecord],
    ) -> int:
        """Allocate one durable dispatch for each explicit ReAct action."""

        prior_ids = {
            evidence.id
            for evidence in prior_evidence
            if evidence.tool_name == request.tool_name
            and evidence.request == request.parameters
        }
        return len(prior_ids) + 1

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
        collected_at = datetime.now(UTC)
        started_at = invocation.started_at or invocation.created_at
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
            started_at=started_at,
            collected_at=collected_at,
            duration_ms=max(
                0,
                int((collected_at - started_at).total_seconds() * 1000),
            ),
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
        *,
        artifact_ref: ArtifactRef | None = None,
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
            artifact_ref=artifact_ref,
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
