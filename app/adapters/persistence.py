from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from jsonpointer import JsonPointerException, resolve_pointer
from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    delete,
    desc,
    event,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.application.sanitization import sanitize, sanitize_text
from app.domain.models import (
    AdvisorMetadata,
    AlertListResult,
    AlertStatus,
    AlertSummary,
    AnalysisConfigSnapshot,
    AnalysisDispatchControl,
    AnalysisDispatchState,
    AnalysisFailureEvent,
    DashboardSummary,
    DispatchValidationResult,
    EvidenceRecord,
    FlashDutyPollState,
    FlashDutyPollStatus,
    InvestigationRun,
    InvestigationStage,
    ModelFailure,
    ModelFailureCategory,
    NormalizedAlert,
    NotificationDelivery,
    NotificationDeliveryStatus,
    NotificationKind,
    ProgressRecord,
    Recommendation,
    RunStatus,
    StoredAlert,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)
from app.domain.ports import (
    AgentCheckpointVersionConflict,
    AgentEventSequenceConflict,
    AnalysisDispatchConflict,
    EvidenceRecordConflict,
    RunCancellationConflict,
    RunCancellationRequested,
    RunLeaseConflict,
    ToolInvocationConflict,
)

if TYPE_CHECKING:
    from app.agent_runtime.contracts import (
        ArtifactRef,
        RunCheckpoint,
        RunManifest,
        ToolInvocation,
        ToolInvocationStatus,
    )
    from app.agent_runtime.events import AgentEvent


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def _require_active_run_lease(
    session: AsyncSession,
    run_id: str,
    *,
    lease_owner: str | None,
    fencing_token: int | None,
    allow_terminal: bool = False,
) -> InvestigationRunRow:
    if (lease_owner is None) != (fencing_token is None):
        raise ValueError("lease_owner and fencing_token must be provided together")
    if lease_owner is not None and fencing_token is not None:
        now = _utc_now()
        conditions = [
            InvestigationRunRow.id == run_id,
            InvestigationRunRow.lease_owner == lease_owner,
            InvestigationRunRow.fencing_token == fencing_token,
        ]
        if allow_terminal:
            conditions.append(
                InvestigationRunRow.status.in_(
                    {
                        RunStatus.COMPLETED.value,
                        RunStatus.INCONCLUSIVE.value,
                        RunStatus.FAILED.value,
                    }
                )
            )
        else:
            conditions.extend(
                (
                    InvestigationRunRow.status == RunStatus.RUNNING.value,
                    InvestigationRunRow.lease_expires_at.is_not(None),
                    InvestigationRunRow.lease_expires_at > now,
                )
            )
        statement = (
            update(InvestigationRunRow)
            .where(*conditions)
            # A conditional no-op update acquires the run row's write lock until
            # this transaction commits, closing the validate-then-write race.
            .values(lease_owner=lease_owner)
        )
        result = await session.execute(statement)
        if result.rowcount != 1:
            raise RunLeaseConflict(
                run_id,
                "owner/token mismatch, incompatible run status, or expired lease",
            )
    row = await session.get(InvestigationRunRow, run_id)
    if row is None:
        if lease_owner is None:
            raise ValueError(f"Investigation run does not exist: {run_id}")
        raise RunLeaseConflict(
            run_id,
            "run disappeared while its lease was being validated",
        )
    return row


async def _lock_alert_row(
    session: AsyncSession,
    alert_id: str,
) -> AlertRow | None:
    result = await session.execute(
        update(AlertRow)
        .where(AlertRow.id == alert_id)
        .values(id=AlertRow.id, updated_at=AlertRow.updated_at)
    )
    if result.rowcount != 1:
        return None
    return await session.get(AlertRow, alert_id)


def _model_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        raise TypeError(f"Expected a Pydantic model or mapping, got {type(value).__name__}")
    if not isinstance(payload, dict):
        raise TypeError("Persisted contract payload must be an object")
    return payload


def _canonical_json_hash(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    raw = getattr(value, "value", value)
    return str(raw)


def _datetime_value(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError(f"Expected datetime value, got {type(value).__name__}")
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _mysql_datetime_zero_value(value: datetime) -> datetime:
    normalized = value.astimezone(UTC) if value.tzinfo is not None else value
    if normalized.microsecond >= 500_000:
        normalized += timedelta(seconds=1)
    return normalized.replace(microsecond=0)


def _datetime_mirror_matches(
    persisted: datetime | None,
    expected: datetime | None,
    *,
    dialect_name: str,
) -> bool:
    if persisted == expected:
        return True
    if dialect_name != "mysql" or persisted is None or expected is None:
        return False
    # The deployed schema uses DATETIME(0), and the migration preflight requires
    # MySQL's default fractional-second rounding mode.
    return persisted == _mysql_datetime_zero_value(expected)


def _bounded_invocation_result(result: Mapping[str, Any]) -> dict[str, Any]:
    safe = sanitize(dict(result))
    if safe.get("contract") == "outer-evidence-record/v1":
        evidence = EvidenceRecord.model_validate(safe.get("evidence_record"))
        return {
            "contract": "outer-evidence-record/v1",
            "evidence_record": evidence.model_dump(mode="json"),
        }
    serialized = json.dumps(
        safe,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return json.loads(serialized)


def _safe_agent_event_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    safe = sanitize(dict(payload))
    serialized = json.dumps(
        safe,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    decoded = json.loads(serialized)
    if not isinstance(decoded, dict):
        raise TypeError("AgentEvent payload must be an object")
    return decoded


def _artifact_content(
    content: bytes | str | dict[str, Any],
) -> tuple[str, str, bytes]:
    if isinstance(content, bytes):
        return base64.b64encode(content).decode("ascii"), "base64", content
    if isinstance(content, str):
        safe_text = sanitize_text(content)
        return safe_text, "utf-8", safe_text.encode("utf-8")
    if isinstance(content, dict):
        safe_payload = sanitize(content)
        serialized = json.dumps(
            safe_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return serialized, "json", serialized.encode("utf-8")
    raise TypeError("Agent artifact content must be bytes, str, or dict")


def _decoded_artifact_content(row: AgentArtifactRow) -> bytes | str | dict[str, Any]:
    content = row.sanitized_content or ""
    if row.content_encoding == "base64":
        return base64.b64decode(content.encode("ascii"), validate=True)
    if row.content_encoding == "json":
        decoded = json.loads(content)
        if not isinstance(decoded, dict):
            raise RuntimeError(f"Agent artifact {row.id} did not contain a JSON object")
        return decoded
    if row.content_encoding == "utf-8":
        return content
    raise RuntimeError(f"Unsupported Agent artifact encoding: {row.content_encoding}")


class UTCDateTime(TypeDecorator[datetime]):
    """Persist UTC datetimes and restore timezone data dropped by SQLite."""

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[no-untyped-def]
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(
        self,
        value: datetime | None,
        _dialect,  # type: ignore[no-untyped-def]
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(
        self,
        value: datetime | None,
        _dialect,  # type: ignore[no-untyped-def]
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


_UNBOUNDED_TEXT = Text().with_variant(LONGTEXT(), "mysql")
DATABASE_SCHEMA_REVISION = "0019"
_TOOL_INVOCATION_LIFECYCLE_FIELDS = frozenset(
    {"status", "started_at", "completed_at", "error", "artifact_ref"}
)
_TOOL_INVOCATION_EXECUTION_CLAIM_FIELDS = frozenset(
    {"execution_lease_owner", "execution_fencing_token"}
)


class Base(DeclarativeBase):
    pass


_migration_metadata = MetaData()
_alembic_version = Table(
    "alembic_version",
    _migration_metadata,
    Column("version_num", String(32), primary_key=True),
)


class AlertRow(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_alert_identity"),
        Index("ix_alerts_status_created_at", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    alert_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    recommendation_json: Mapped[dict | None] = mapped_column(JSON)
    advisor_metadata_json: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class InvestigationRunRow(Base):
    __tablename__ = "investigation_runs"
    __table_args__ = (UniqueConstraint("alert_id", "attempt", name="uq_run_attempt"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_stage: Mapped[str] = mapped_column(String(40), nullable=False)
    # Legacy schema column retained so existing databases remain readable. New
    # runs never read, write, or expose the removed strategy-branch contract.
    strategy_id: Mapped[str | None] = mapped_column(String(255))
    error: Mapped[str | None] = mapped_column(Text)
    lease_owner: Mapped[str | None] = mapped_column(String(255))
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    cancel_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    cancel_requested_by: Mapped[str | None] = mapped_column(String(255))
    cancelled_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    config_snapshot_json: Mapped[dict | None] = mapped_column(JSON)
    manifest_json: Mapped[dict | None] = mapped_column(JSON)
    manifest_hash: Mapped[str | None] = mapped_column(String(64))
    recommendation_json: Mapped[dict | None] = mapped_column(JSON)
    advisor_metadata_json: Mapped[dict | None] = mapped_column(JSON)
    model_failure_json: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)


class AnalysisDispatchControlRow(Base):
    __tablename__ = "analysis_dispatch_control"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    reason_json: Mapped[dict | None] = mapped_column(JSON)
    trigger_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="SET NULL")
    )
    paused_settings_revision: Mapped[str | None] = mapped_column(String(64))
    last_validation_json: Mapped[dict | None] = mapped_column(JSON)
    paused_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    resumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    resumed_by: Mapped[str | None] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)


class NotificationDeliveryRow(Base):
    __tablename__ = "analysis_notification_deliveries"
    __table_args__ = (
        UniqueConstraint("run_id", "kind", name="uq_notification_run_kind"),
        Index(
            "ix_notification_delivery_status_due",
            "status",
            "next_attempt_at",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    event_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    message_id: Mapped[str | None] = mapped_column(String(255))
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    claim_owner: Mapped[str | None] = mapped_column(String(255))
    claim_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class FlashDutyPollStateRow(Base):
    __tablename__ = "flashduty_poll_state"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    last_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_error: Mapped[str | None] = mapped_column(Text)
    start_time: Mapped[int | None] = mapped_column(Integer)
    end_time: Mapped[int | None] = mapped_column(Integer)
    fetched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deduplicated_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)


class ProgressRow(Base):
    __tablename__ = "investigation_progress"
    __table_args__ = (UniqueConstraint("run_id", "sequence", name="uq_progress_sequence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    stage: Mapped[str] = mapped_column(String(40), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)


class EvidenceRow(Base):
    __tablename__ = "evidence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    contract_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="evidence-record/v1"
    )
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_system: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    request_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    data_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source_artifact_id: Mapped[str | None] = mapped_column(String(36))
    evidence_units_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    truncated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ValidationRow(Base):
    __tablename__ = "validation_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    passed: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_sufficient: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    issues_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AgentEventRow(Base):
    __tablename__ = "agent_events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_agent_event_sequence"),
        Index("ix_agent_events_run_sequence", "run_id", "sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    parent_run_id: Mapped[str | None] = mapped_column(String(36))
    invocation_id: Mapped[str | None] = mapped_column(String(36))
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    causation_id: Mapped[str | None] = mapped_column(String(36))
    correlation_id: Mapped[str | None] = mapped_column(String(36))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AgentCheckpointRow(Base):
    __tablename__ = "agent_checkpoints"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "namespace",
            "version",
            name="uq_agent_checkpoint_namespace_version",
        ),
        Index(
            "ix_agent_checkpoints_run_namespace_version",
            "run_id",
            "namespace",
            "version",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    namespace: Mapped[str] = mapped_column(String(256), nullable=False, default="agent")
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    stop_reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AgentCheckpointWriteRow(Base):
    __tablename__ = "agent_checkpoint_writes"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "checkpoint_id",
            "task_id",
            "write_index",
            name="uq_agent_checkpoint_write_task_index",
        ),
        Index(
            "ix_agent_checkpoint_writes_checkpoint",
            "run_id",
            "checkpoint_id",
            "id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    checkpoint_id: Mapped[str] = mapped_column(String(36), nullable=False)
    task_id: Mapped[str] = mapped_column(String(255), nullable=False)
    write_index: Mapped[int] = mapped_column(Integer, nullable=False)
    channel: Mapped[str] = mapped_column(String(255), nullable=False)
    value_type: Mapped[str] = mapped_column(String(255), nullable=False)
    value_base64: Mapped[str] = mapped_column(_UNBOUNDED_TEXT, nullable=False)
    task_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class ToolInvocationRow(Base):
    __tablename__ = "tool_invocations"
    __table_args__ = (Index("ix_tool_invocations_run_status", "run_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    parent_run_id: Mapped[str | None] = mapped_column(String(36))
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    hypothesis_ids_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    model_arguments_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    effective_arguments_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    deadline: Mapped[datetime | None] = mapped_column(UTCDateTime())
    result_json: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON)
    error_json: Mapped[dict | None] = mapped_column(JSON)
    artifact_ref_json: Mapped[dict | None] = mapped_column(JSON)
    invocation_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AgentArtifactRow(Base):
    __tablename__ = "agent_artifacts"
    __table_args__ = (Index("ix_agent_artifacts_run_id", "run_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    invocation_id: Mapped[str | None] = mapped_column(String(36))
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    uri: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    content_encoding: Mapped[str] = mapped_column(String(16), nullable=False)
    sanitized_content: Mapped[str] = mapped_column(_UNBOUNDED_TEXT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utc_now)


def _decode_run_manifest(row: InvestigationRunRow) -> RunManifest:
    from app.agent_runtime.contracts import RunManifest

    if row.manifest_json is None or row.manifest_hash is None:
        raise RuntimeError(f"Run {row.id} does not have a frozen manifest")
    actual_hash = _canonical_json_hash(row.manifest_json)
    if actual_hash != row.manifest_hash:
        raise RuntimeError(f"Run manifest hash mismatch for run {row.id}")
    try:
        manifest = RunManifest.model_validate(row.manifest_json)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Run manifest is invalid for run {row.id}") from exc
    if str(manifest.run_id) != row.id:
        raise RuntimeError(f"Run manifest identity mismatch for run {row.id}")
    if manifest.digest() != row.manifest_hash:
        raise RuntimeError(f"Run manifest digest mismatch for run {row.id}")
    return manifest


def _decode_checkpoint_row(
    row: AgentCheckpointRow,
    *,
    expected_run_id: str,
    expected_namespace: str,
    expected_manifest_hash: str,
) -> RunCheckpoint:
    from app.agent_runtime.contracts import RunCheckpoint

    payload = row.payload_json or {}
    if not isinstance(payload, Mapping):
        raise RuntimeError(f"Checkpoint payload is invalid for run {expected_run_id}")
    if _canonical_json_hash(payload.get("state") or {}) != row.state_hash:
        raise RuntimeError(f"Checkpoint state hash mismatch for run {expected_run_id}")
    try:
        checkpoint = RunCheckpoint.model_validate(payload)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Checkpoint payload is invalid for run {expected_run_id}") from exc
    if str(checkpoint.checkpoint_id) != row.id:
        raise RuntimeError(f"Checkpoint identity mismatch for run {expected_run_id}")
    if str(checkpoint.run_id) != expected_run_id:
        raise RuntimeError(f"Checkpoint run identity mismatch for run {expected_run_id}")
    if checkpoint.namespace != expected_namespace or row.namespace != expected_namespace:
        raise RuntimeError(f"Checkpoint namespace mismatch for run {expected_run_id}")
    if checkpoint.version != row.version or checkpoint.sequence != row.sequence:
        raise RuntimeError(f"Checkpoint metadata mismatch for run {expected_run_id}")
    if _enum_value(checkpoint.stop_reason) != row.stop_reason:
        raise RuntimeError(f"Checkpoint stop reason mismatch for run {expected_run_id}")
    if checkpoint.manifest_hash != row.manifest_hash:
        raise RuntimeError(f"Checkpoint manifest metadata mismatch for run {expected_run_id}")
    if checkpoint.manifest_hash != expected_manifest_hash:
        raise RuntimeError(f"Checkpoint manifest mismatch for run {expected_run_id}")
    return checkpoint


class SQLAlchemyAlertRepository:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._ensure_sqlite_directory()
        engine_options: dict[str, object] = {"future": True}
        if database_url.startswith(("sqlite+aiosqlite://", "sqlite://")):
            engine_options["connect_args"] = {"timeout": 30}
        self.engine = create_async_engine(database_url, **engine_options)
        if database_url.startswith(("sqlite+aiosqlite://", "sqlite://")):
            event.listen(self.engine.sync_engine, "connect", self._configure_sqlite)
        self.session_factory = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    @staticmethod
    def _configure_sqlite(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
        finally:
            cursor.close()

    def _ensure_sqlite_directory(self) -> None:
        prefixes = ("sqlite+aiosqlite:///", "sqlite:///")
        for prefix in prefixes:
            if self.database_url.startswith(prefix):
                path = self.database_url.removeprefix(prefix)
                if path and path != ":memory:":
                    Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self) -> None:
        async with self.engine.begin() as connection:
            snapshot = await connection.run_sync(self._schema_snapshot)

            if not snapshot:
                # Keep a brand-new local/test SQLite database convenient while still
                # recording a real schema revision. Existing or partially initialized
                # databases must always go through Alembic instead of being patched by
                # create_all, which cannot apply data migrations.
                await connection.run_sync(Base.metadata.create_all)
                await connection.run_sync(_migration_metadata.create_all)
                revision = await connection.scalar(select(_alembic_version.c.version_num))
                if revision is None:
                    await connection.execute(
                        _alembic_version.insert().values(version_num=DATABASE_SCHEMA_REVISION)
                    )

            await self._assert_schema_current(connection)
            now = _utc_now()
            dispatch_exists = await connection.scalar(
                select(AnalysisDispatchControlRow.id).where(
                    AnalysisDispatchControlRow.id == "global"
                )
            )
            if dispatch_exists is None:
                await connection.execute(
                    AnalysisDispatchControlRow.__table__.insert().values(
                        id="global",
                        state=AnalysisDispatchState.ENABLED.value,
                        version=1,
                        updated_at=now,
                    )
                )
            poll_state_exists = await connection.scalar(
                select(FlashDutyPollStateRow.id).where(FlashDutyPollStateRow.id == "global")
            )
            if poll_state_exists is None:
                await connection.execute(
                    FlashDutyPollStateRow.__table__.insert().values(
                        id="global",
                        status=FlashDutyPollStatus.NEVER.value,
                        fetched_count=0,
                        created_count=0,
                        deduplicated_count=0,
                        updated_at=now,
                    )
                )

    async def close(self) -> None:
        await self.engine.dispose()

    async def ping(self) -> None:
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
            await self._assert_schema_current(connection)

    async def get_dispatch_control(self) -> AnalysisDispatchControl:
        async with self.session_factory() as session:
            row = await session.get(AnalysisDispatchControlRow, "global")
            if row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            return self._dispatch_control(row)

    async def pause_analysis_dispatch(
        self,
        failure: ModelFailure,
        *,
        trigger_run_id: str,
        settings_revision: str,
    ) -> AnalysisDispatchControl:
        if not failure.pauses_dispatch:
            raise ValueError("Only a dispatch-pausing model failure may pause analysis")
        async with self.session_factory() as session:
            row = await session.scalar(
                select(AnalysisDispatchControlRow)
                .where(AnalysisDispatchControlRow.id == "global")
                .with_for_update()
            )
            if row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            now = _utc_now()
            row.state = AnalysisDispatchState.PAUSED.value
            row.version += 1
            row.reason_json = failure.model_dump(mode="json")
            row.trigger_run_id = trigger_run_id
            row.paused_settings_revision = settings_revision
            row.paused_at = now
            row.resumed_at = None
            row.resumed_by = None
            row.last_validation_json = None
            row.updated_at = now
            await session.commit()
            return self._dispatch_control(row)

    async def record_dispatch_validation(
        self,
        *,
        expected_version: int,
        validation: DispatchValidationResult,
    ) -> AnalysisDispatchControl:
        if validation.success:
            raise ValueError("Failed validation recording requires success=false")
        async with self.session_factory() as session:
            row = await session.scalar(
                select(AnalysisDispatchControlRow)
                .where(AnalysisDispatchControlRow.id == "global")
                .with_for_update()
            )
            if row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            if row.version != expected_version:
                raise AnalysisDispatchConflict(expected_version, row.version)
            if row.state != AnalysisDispatchState.PAUSED.value:
                raise ValueError("Analysis dispatch is not paused")
            row.version += 1
            row.last_validation_json = validation.model_dump(mode="json")
            row.updated_at = _utc_now()
            await session.commit()
            return self._dispatch_control(row)

    async def resume_analysis_dispatch(
        self,
        *,
        expected_version: int,
        expected_settings_revision: str,
        resumed_by: str,
        validation: DispatchValidationResult,
    ) -> AnalysisDispatchControl:
        if not validation.success:
            raise ValueError("Successful dispatch resume requires success=true")
        if validation.settings_revision != expected_settings_revision:
            raise ValueError("Validated AI settings revision does not match resume request")
        async with self.session_factory() as session:
            row = await session.scalar(
                select(AnalysisDispatchControlRow)
                .where(AnalysisDispatchControlRow.id == "global")
                .with_for_update()
            )
            if row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            if row.version != expected_version:
                raise AnalysisDispatchConflict(expected_version, row.version)
            if row.state != AnalysisDispatchState.PAUSED.value:
                raise ValueError("Analysis dispatch is not paused")
            now = _utc_now()
            row.state = AnalysisDispatchState.ENABLED.value
            row.version += 1
            row.resumed_at = now
            row.resumed_by = resumed_by
            row.last_validation_json = validation.model_dump(mode="json")
            row.updated_at = now
            await session.commit()
            return self._dispatch_control(row)

    async def get_flashduty_poll_state(self) -> FlashDutyPollState:
        async with self.session_factory() as session:
            row = await session.get(FlashDutyPollStateRow, "global")
            if row is None:
                raise RuntimeError("FlashDuty poll state is not initialized")
            return self._flashduty_poll_state(row)

    async def record_flashduty_poll_started(self, *, start_time: int, end_time: int) -> None:
        async with self.session_factory() as session:
            row = await session.get(FlashDutyPollStateRow, "global")
            if row is None:
                raise RuntimeError("FlashDuty poll state is not initialized")
            now = _utc_now()
            row.last_started_at = now
            row.start_time = start_time
            row.end_time = end_time
            row.last_error = None
            row.updated_at = now
            await session.commit()

    async def record_flashduty_poll_completed(
        self,
        *,
        start_time: int,
        end_time: int,
        fetched_count: int,
        created_count: int,
        deduplicated_count: int,
    ) -> None:
        async with self.session_factory() as session:
            row = await session.get(FlashDutyPollStateRow, "global")
            if row is None:
                raise RuntimeError("FlashDuty poll state is not initialized")
            now = _utc_now()
            row.status = FlashDutyPollStatus.SUCCESS.value
            row.last_completed_at = now
            row.last_error = None
            row.start_time = start_time
            row.end_time = end_time
            row.fetched_count = fetched_count
            row.created_count = created_count
            row.deduplicated_count = deduplicated_count
            row.updated_at = now
            await session.commit()

    async def record_flashduty_poll_failed(
        self,
        *,
        start_time: int | None,
        end_time: int | None,
        error: str,
    ) -> None:
        async with self.session_factory() as session:
            row = await session.get(FlashDutyPollStateRow, "global")
            if row is None:
                raise RuntimeError("FlashDuty poll state is not initialized")
            row.status = FlashDutyPollStatus.FAILED.value
            row.last_error = sanitize_text(error)[:2000]
            row.start_time = start_time
            row.end_time = end_time
            row.updated_at = _utc_now()
            await session.commit()

    async def claim_notification_deliveries(
        self,
        *,
        owner: str,
        limit: int,
        lease_seconds: int,
    ) -> list[NotificationDelivery]:
        if limit < 1 or lease_seconds < 1:
            raise ValueError("Notification claim limits must be positive")
        now = _utc_now()
        async with self.session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(NotificationDeliveryRow)
                        .where(
                            NotificationDeliveryRow.attempts < 3,
                            or_(
                                NotificationDeliveryRow.status
                                == NotificationDeliveryStatus.PENDING.value,
                                (
                                    (
                                        NotificationDeliveryRow.status
                                        == NotificationDeliveryStatus.FAILED.value
                                    )
                                    & (
                                        (NotificationDeliveryRow.next_attempt_at.is_(None))
                                        | (NotificationDeliveryRow.next_attempt_at <= now)
                                    )
                                ),
                                (
                                    (
                                        NotificationDeliveryRow.status
                                        == NotificationDeliveryStatus.SENDING.value
                                    )
                                    & (NotificationDeliveryRow.claim_expires_at <= now)
                                ),
                            ),
                        )
                        .order_by(NotificationDeliveryRow.created_at)
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                row.status = NotificationDeliveryStatus.SENDING.value
                row.claim_owner = owner
                row.claim_expires_at = now + timedelta(seconds=lease_seconds)
                row.attempts += 1
                row.updated_at = now
            await session.commit()
            return [self._notification_delivery(row) for row in rows]

    async def complete_notification_delivery(
        self,
        delivery_id: str,
        *,
        owner: str,
        message_id: str | None,
    ) -> None:
        now = _utc_now()
        async with self.session_factory() as session:
            result = await session.execute(
                update(NotificationDeliveryRow)
                .where(
                    NotificationDeliveryRow.id == delivery_id,
                    NotificationDeliveryRow.status == NotificationDeliveryStatus.SENDING.value,
                    NotificationDeliveryRow.claim_owner == owner,
                )
                .values(
                    status=NotificationDeliveryStatus.SENT.value,
                    message_id=message_id,
                    error=None,
                    claim_owner=None,
                    claim_expires_at=None,
                    next_attempt_at=None,
                    sent_at=now,
                    updated_at=now,
                )
            )
            if result.rowcount != 1:
                raise RuntimeError("Notification delivery claim was lost")
            await session.commit()

    async def fail_notification_delivery(
        self,
        delivery_id: str,
        *,
        owner: str,
        error: str,
        unknown_outcome: bool,
    ) -> None:
        now = _utc_now()
        async with self.session_factory() as session:
            row = await session.scalar(
                select(NotificationDeliveryRow)
                .where(
                    NotificationDeliveryRow.id == delivery_id,
                    NotificationDeliveryRow.status == NotificationDeliveryStatus.SENDING.value,
                    NotificationDeliveryRow.claim_owner == owner,
                )
                .with_for_update()
            )
            if row is None:
                raise RuntimeError("Notification delivery claim was lost")
            row.status = (
                NotificationDeliveryStatus.UNKNOWN.value
                if unknown_outcome
                else NotificationDeliveryStatus.FAILED.value
            )
            row.error = sanitize_text(error)[:2000]
            row.claim_owner = None
            row.claim_expires_at = None
            row.next_attempt_at = (
                None if unknown_outcome or row.attempts >= 3 else now + timedelta(seconds=30)
            )
            row.updated_at = now
            await session.commit()

    async def cleanup_expired_alerts(self, cutoff: datetime) -> int:
        """Delete expired terminal alerts."""

        if cutoff.tzinfo is None:
            raise ValueError("cleanup cutoff must be timezone-aware")
        async with self.session_factory() as session:
            statement = delete(AlertRow).where(
                AlertRow.created_at < cutoff.astimezone(UTC),
                AlertRow.status.in_(
                    [
                        AlertStatus.COMPLETED.value,
                        AlertStatus.INCONCLUSIVE.value,
                        AlertStatus.FAILED.value,
                        AlertStatus.FILTERED.value,
                        AlertStatus.CANCELLED.value,
                    ]
                ),
            )
            result = await session.execute(statement)
            await session.commit()
            return int(result.rowcount or 0)

    @staticmethod
    def _schema_snapshot(
        connection,  # type: ignore[no-untyped-def]
    ) -> dict[str, tuple[dict[str, Any], ...]]:
        inspector = inspect(connection)
        return {
            table_name: tuple(dict(column) for column in inspector.get_columns(table_name))
            for table_name in inspector.get_table_names()
        }

    @staticmethod
    def _blocking_unmapped_columns(
        snapshot: Mapping[str, tuple[Mapping[str, Any], ...]],
        expected_columns: Mapping[str, set[str]],
    ) -> dict[str, list[str]]:
        blocking: dict[str, list[str]] = {}
        for table_name, mapped_columns in expected_columns.items():
            columns: list[str] = []
            for column in snapshot.get(table_name, ()):
                name = str(column["name"])
                generated = (
                    column.get("default") is not None
                    or column.get("identity") is not None
                    or column.get("computed") is not None
                    or column.get("autoincrement") in {True, "auto"}
                )
                if (
                    name not in mapped_columns
                    and not bool(column.get("nullable", True))
                    and not generated
                ):
                    columns.append(name)
            if columns:
                blocking[table_name] = sorted(columns)
        return blocking

    async def _assert_schema_current(self, connection) -> None:  # type: ignore[no-untyped-def]
        snapshot = await connection.run_sync(self._schema_snapshot)
        snapshot_columns = {
            table_name: {str(column["name"]) for column in columns}
            for table_name, columns in snapshot.items()
        }
        expected_columns = {
            table_name: {column.name for column in table.columns}
            for table_name, table in Base.metadata.tables.items()
        }
        missing_tables = sorted(set(expected_columns) - set(snapshot_columns))
        missing_columns = {
            table_name: sorted(columns - snapshot_columns.get(table_name, set()))
            for table_name, columns in expected_columns.items()
            if columns - snapshot_columns.get(table_name, set())
        }
        blocking_unmapped_columns = self._blocking_unmapped_columns(
            snapshot,
            expected_columns,
        )

        revision: str | None = None
        if "alembic_version" in snapshot:
            revision = await connection.scalar(select(_alembic_version.c.version_num))
        if (
            revision != DATABASE_SCHEMA_REVISION
            or missing_tables
            or missing_columns
            or blocking_unmapped_columns
        ):
            details: list[str] = [
                f"revision={revision or 'unversioned'}",
                f"expected={DATABASE_SCHEMA_REVISION}",
            ]
            if missing_tables:
                details.append(f"missing_tables={','.join(missing_tables)}")
            if missing_columns:
                details.append(
                    "missing_columns="
                    + ",".join(
                        f"{table}.{column}"
                        for table, columns in sorted(missing_columns.items())
                        for column in columns
                    )
                )
            if blocking_unmapped_columns:
                details.append(
                    "blocking_unmapped_columns="
                    + ",".join(
                        f"{table}.{column}"
                        for table, columns in sorted(blocking_unmapped_columns.items())
                        for column in columns
                    )
                )
            recovery = (
                "Back up the database and follow the unversioned SQLite recovery "
                "instructions in README.md."
                if revision is None
                else "Back up the database and run `alembic upgrade head`."
            )
            raise RuntimeError(
                "Database schema is not current (" + "; ".join(details) + f"). {recovery}"
            )

    async def create_or_get(
        self,
        alert: NormalizedAlert,
        *,
        initial_status: AlertStatus = AlertStatus.QUEUED,
    ) -> tuple[StoredAlert, bool]:
        if initial_status not in (AlertStatus.QUEUED, AlertStatus.FILTERED):
            raise ValueError("initial alert status must be QUEUED or FILTERED")
        async with self.session_factory() as session:
            existing = await self._find_by_identity(session, alert.source, alert.external_id)
            if existing:
                return await self._to_stored(session, existing), False

            row = AlertRow(
                id=str(alert.id),
                source=alert.source,
                external_id=alert.external_id,
                status=initial_status.value,
                alert_json=alert.model_dump(mode="json"),
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = await self._find_by_identity(session, alert.source, alert.external_id)
                if not existing:
                    raise
                return await self._to_stored(session, existing), False
            await session.refresh(row)
            return await self._to_stored(session, row), True

    async def update_alert(
        self,
        alert_id: str,
        alert: NormalizedAlert,
        *,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        """Replace the normalized alert while holding the active run lease."""

        if str(alert.id) != alert_id:
            raise ValueError("updated alert identity does not match alert_id")
        async with self.session_factory() as session:
            row = await _lock_alert_row(session, alert_id)
            if row is None:
                raise RunLeaseConflict(run_id, "alert does not exist")
            run_row = await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            if run_row.alert_id != alert_id:
                raise RunLeaseConflict(run_id, "run does not belong to the requested alert")
            if row.source != alert.source or row.external_id != alert.external_id:
                raise ValueError("updated alert source identity cannot change")
            row.alert_json = alert.model_dump(mode="json")
            row.updated_at = _utc_now()
            await session.commit()

    async def list_by_status(self, statuses: set[AlertStatus]) -> list[StoredAlert]:
        async with self.session_factory() as session:
            query = select(AlertRow).where(AlertRow.status.in_([item.value for item in statuses]))
            rows = (await session.execute(query)).scalars().all()
            return [await self._to_stored(session, row) for row in rows]

    async def list_alerts(
        self,
        *,
        page: int,
        page_size: int,
        statuses: set[AlertStatus] | None = None,
        severities: set[str] | None = None,
        source: str | None = None,
        environment: str | None = None,
        search: str | None = None,
    ) -> AlertListResult:
        """Return lightweight alert cards for the operations UI.

        Severity, environment and free-text fields live inside the canonical JSON
        payload, so they are filtered in Python for database portability. Status and
        source remain SQL predicates. This keeps the first implementation compatible
        with SQLite, PostgreSQL and MySQL without vendor-specific JSON expressions.
        """

        async with self.session_factory() as session:
            query = select(AlertRow).order_by(desc(AlertRow.created_at), desc(AlertRow.id))
            if statuses:
                query = query.where(AlertRow.status.in_([item.value for item in statuses]))
            if source:
                query = query.where(AlertRow.source == source)
            rows = list((await session.execute(query)).scalars().all())

            normalized_severities = {item.upper() for item in severities or set()}
            normalized_environment = environment.casefold() if environment else None
            normalized_search = search.strip().casefold() if search and search.strip() else None
            filtered: list[tuple[AlertRow, NormalizedAlert]] = []
            for row in rows:
                alert = NormalizedAlert.model_validate(row.alert_json)
                if normalized_severities and alert.severity.value not in normalized_severities:
                    continue
                if (
                    normalized_environment
                    and alert.environment.casefold() != normalized_environment
                ):
                    continue
                if normalized_search:
                    database_values = ""
                    if alert.database:
                        database_values = " ".join(
                            str(item or "")
                            for item in (
                                alert.database.engine,
                                alert.database.instance,
                                alert.database.database,
                                alert.database.host,
                            )
                        )
                    haystack = " ".join(
                        (
                            alert.external_id,
                            alert.title,
                            alert.reason,
                            alert.description,
                            alert.service_name,
                            alert.environment,
                            database_values,
                        )
                    ).casefold()
                    if normalized_search not in haystack:
                        continue
                filtered.append((row, alert))

            total = len(filtered)
            offset = (page - 1) * page_size
            selected = filtered[offset : offset + page_size]
            items = await self._summaries(session, selected)
            return AlertListResult(
                items=items,
                total=total,
                page=page,
                page_size=page_size,
                pages=(total + page_size - 1) // page_size,
            )

    async def dashboard_summary(self) -> DashboardSummary:
        recent = await self.list_alerts(page=1, page_size=5)
        async with self.session_factory() as session:
            rows = list(
                (await session.execute(select(AlertRow).order_by(desc(AlertRow.created_at))))
                .scalars()
                .all()
            )
        by_status = {item.value: 0 for item in AlertStatus}
        by_severity = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
        active = 0
        critical_open = 0
        active_statuses = {
            AlertStatus.RECEIVED.value,
            AlertStatus.QUEUED.value,
            AlertStatus.ANALYZING.value,
        }
        for row in rows:
            alert = NormalizedAlert.model_validate(row.alert_json)
            by_status[row.status] = by_status.get(row.status, 0) + 1
            severity = alert.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
            if row.status in active_statuses:
                active += 1
            if severity == "CRITICAL" and row.status != AlertStatus.COMPLETED.value:
                critical_open += 1
        return DashboardSummary(
            total=len(rows),
            active=active,
            critical_open=critical_open,
            by_status=by_status,
            by_severity=by_severity,
            recent_alerts=recent.items,
        )

    async def _summaries(
        self,
        session: AsyncSession,
        rows: list[tuple[AlertRow, NormalizedAlert]],
    ) -> list[AlertSummary]:
        if not rows:
            return []
        alert_ids = [row.id for row, _ in rows]
        run_rows = list(
            (
                await session.execute(
                    select(InvestigationRunRow)
                    .where(InvestigationRunRow.alert_id.in_(alert_ids))
                    .order_by(
                        InvestigationRunRow.alert_id,
                        desc(InvestigationRunRow.attempt),
                    )
                )
            )
            .scalars()
            .all()
        )
        latest_runs: dict[str, InvestigationRunRow] = {}
        for run in run_rows:
            latest_runs.setdefault(run.alert_id, run)

        summaries: list[AlertSummary] = []
        for row, alert in rows:
            recommendation = row.recommendation_json or {}
            run = latest_runs.get(row.id)
            summaries.append(
                AlertSummary(
                    id=alert.id,
                    external_id=alert.external_id,
                    source=alert.source,
                    severity=alert.severity,
                    status=AlertStatus(row.status),
                    title=alert.title,
                    reason=alert.reason,
                    environment=alert.environment,
                    service_name=alert.service_name,
                    occurred_at=alert.occurred_at,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                    current_stage=(InvestigationStage(run.current_stage) if run else None),
                    confidence=recommendation.get("confidence"),
                )
            )
        return summaries

    @staticmethod
    def _archive_legacy_alert_result(
        run_row: InvestigationRunRow | None,
        alert_row: AlertRow,
    ) -> None:
        """Attach the last pre-0011 alert result before a newer run replaces it."""

        if run_row is None or any(
            value is not None
            for value in (
                run_row.recommendation_json,
                run_row.advisor_metadata_json,
            )
        ):
            return
        run_row.recommendation_json = alert_row.recommendation_json
        run_row.advisor_metadata_json = alert_row.advisor_metadata_json

    @staticmethod
    def _clear_current_alert_result(alert_row: AlertRow) -> None:
        """Clear the denormalized current view after its result has been archived."""

        alert_row.recommendation_json = None
        alert_row.advisor_metadata_json = None
        alert_row.error = None

    @staticmethod
    def _queue_internal_failure_notification(
        session: AsyncSession,
        *,
        alert_row: AlertRow,
        run_row: InvestigationRunRow,
        error: str,
        now: datetime,
    ) -> None:
        failure = ModelFailure(
            category=ModelFailureCategory.INTERNAL,
            provider="database-alert-agent",
            phase="unknown",
            safe_detail=sanitize_text(error),
        )
        run_row.model_failure_json = failure.model_dump(mode="json")
        event = AnalysisFailureEvent(
            alert=NormalizedAlert.model_validate(alert_row.alert_json),
            status=AlertStatus.FAILED,
            message=sanitize_text(error),
            run_id=run_row.id,
            failure=failure,
        )
        session.add(
            NotificationDeliveryRow(
                id=str(uuid4()),
                alert_id=alert_row.id,
                run_id=run_row.id,
                kind=NotificationKind.ANALYSIS_FAILURE.value,
                status=NotificationDeliveryStatus.PENDING.value,
                event_json=event.model_dump(mode="json"),
                attempts=0,
                created_at=now,
                updated_at=now,
            )
        )

    async def create_run(
        self,
        alert_id: str,
        lease_owner: str,
        lease_seconds: int,
        *,
        config_snapshot: AnalysisConfigSnapshot | None = None,
        manifest: RunManifest | None = None,
    ) -> InvestigationRun | None:
        manifest_payload = _model_payload(manifest) if manifest is not None else None
        async with self.session_factory() as session:
            alert_row = await _lock_alert_row(session, alert_id)
            dispatch_row = await session.scalar(
                select(AnalysisDispatchControlRow)
                .where(AnalysisDispatchControlRow.id == "global")
                .with_for_update()
            )
            if dispatch_row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            if dispatch_row.state == AnalysisDispatchState.PAUSED.value:
                return None
            if not alert_row or alert_row.status in {
                AlertStatus.COMPLETED.value,
                AlertStatus.INCONCLUSIVE.value,
                AlertStatus.FILTERED.value,
                AlertStatus.CANCELLED.value,
                AlertStatus.FAILED.value,
            }:
                return None
            latest_query = (
                select(InvestigationRunRow)
                .where(InvestigationRunRow.alert_id == alert_id)
                .order_by(desc(InvestigationRunRow.attempt))
                .limit(1)
            )
            latest = (await session.execute(latest_query)).scalar_one_or_none()
            now = _utc_now()
            if latest and latest.status == RunStatus.RUNNING.value:
                lease_expires = latest.lease_expires_at
                if lease_expires and lease_expires.tzinfo is None:
                    lease_expires = lease_expires.replace(tzinfo=UTC)
                if lease_expires and lease_expires > now:
                    return None
                latest.status = RunStatus.FAILED.value
                latest.current_stage = InvestigationStage.FAILED.value
                latest.error = "Investigation lease expired without a recoverable checkpoint"
                latest.lease_expires_at = None
                latest.updated_at = now
                alert_row.status = AlertStatus.FAILED.value
                alert_row.error = latest.error
                alert_row.updated_at = now
                self._queue_internal_failure_notification(
                    session,
                    alert_row=alert_row,
                    run_row=latest,
                    error=latest.error,
                    now=now,
                )
                await session.commit()
                return None
            self._archive_legacy_alert_result(latest, alert_row)
            attempt = (latest.attempt + 1) if latest else 1
            run_identity = (
                {"id": manifest_payload["run_id"]} if manifest_payload is not None else {}
            )
            run = InvestigationRun(
                **run_identity,
                alert_id=alert_id,
                attempt=attempt,
                fencing_token=attempt,
                lease_owner=lease_owner,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                config_snapshot=config_snapshot,
            )
            session.add(
                InvestigationRunRow(
                    id=str(run.id),
                    alert_id=alert_id,
                    attempt=attempt,
                    fencing_token=attempt,
                    status=run.status.value,
                    current_stage=run.current_stage.value,
                    lease_owner=lease_owner,
                    lease_expires_at=run.lease_expires_at,
                    config_snapshot_json=(
                        config_snapshot.model_dump(mode="json")
                        if config_snapshot is not None
                        else None
                    ),
                    manifest_json=manifest_payload,
                    manifest_hash=(
                        _canonical_json_hash(manifest_payload)
                        if manifest_payload is not None
                        else None
                    ),
                    created_at=run.created_at,
                    updated_at=run.updated_at,
                )
            )
            self._clear_current_alert_result(alert_row)
            alert_row.status = AlertStatus.ANALYZING.value
            alert_row.updated_at = now
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return None
            return run

    async def create_run_for_reanalyze(
        self,
        alert_id: str,
        lease_owner: str,
        lease_seconds: int,
        config_snapshot: AnalysisConfigSnapshot,
        *,
        manifest: RunManifest | None = None,
        force: bool = False,
    ) -> InvestigationRun | None:
        """Create a new investigation run for re-analysis with config snapshot.

        Unlike create_run, this method allows re-analyzing completed/inconclusive alerts
        and saves the configuration snapshot for tracking.
        """
        if not isinstance(force, bool):
            raise TypeError("force must be a boolean")
        manifest_payload = _model_payload(manifest) if manifest is not None else None
        async with self.session_factory() as session:
            alert_row = await _lock_alert_row(session, alert_id)
            dispatch_row = await session.scalar(
                select(AnalysisDispatchControlRow)
                .where(AnalysisDispatchControlRow.id == "global")
                .with_for_update()
            )
            if dispatch_row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            if dispatch_row.state == AnalysisDispatchState.PAUSED.value:
                return None
            if not alert_row:
                return None
            latest_query = (
                select(InvestigationRunRow)
                .where(InvestigationRunRow.alert_id == alert_id)
                .order_by(desc(InvestigationRunRow.attempt))
                .limit(1)
            )
            latest = (await session.execute(latest_query)).scalar_one_or_none()
            now = _utc_now()
            if latest and latest.status == RunStatus.RUNNING.value:
                lease_expires = latest.lease_expires_at
                if lease_expires and lease_expires.tzinfo is None:
                    lease_expires = lease_expires.replace(tzinfo=UTC)
                lease_is_active = lease_expires is not None and lease_expires > now
                if lease_is_active and not force:
                    return None
                latest.status = RunStatus.FAILED.value
                latest.current_stage = InvestigationStage.FAILED.value
                latest.error = (
                    "Superseded by forced re-analysis"
                    if lease_is_active
                    else "Investigation lease expired"
                )
                latest.lease_expires_at = None
                latest.updated_at = now
            self._archive_legacy_alert_result(latest, alert_row)
            attempt = (latest.attempt + 1) if latest else 1
            run_identity = (
                {"id": manifest_payload["run_id"]} if manifest_payload is not None else {}
            )
            run = InvestigationRun(
                **run_identity,
                alert_id=alert_id,
                attempt=attempt,
                fencing_token=attempt,
                lease_owner=lease_owner,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                config_snapshot=config_snapshot,
            )
            session.add(
                InvestigationRunRow(
                    id=str(run.id),
                    alert_id=alert_id,
                    attempt=attempt,
                    fencing_token=attempt,
                    status=run.status.value,
                    current_stage=run.current_stage.value,
                    lease_owner=lease_owner,
                    lease_expires_at=run.lease_expires_at,
                    config_snapshot_json=config_snapshot.model_dump(mode="json"),
                    manifest_json=manifest_payload,
                    manifest_hash=(
                        _canonical_json_hash(manifest_payload)
                        if manifest_payload is not None
                        else None
                    ),
                    created_at=run.created_at,
                    updated_at=run.updated_at,
                )
            )
            self._clear_current_alert_result(alert_row)
            alert_row.status = AlertStatus.ANALYZING.value
            alert_row.updated_at = now
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return None
            return run

    async def reclaim_expired_run(
        self,
        alert_id: str,
        lease_owner: str,
        lease_seconds: int,
    ) -> InvestigationRun | None:
        if not isinstance(lease_owner, str):
            raise TypeError("lease_owner must be a string")
        if not lease_owner.strip():
            raise ValueError("lease_owner must not be empty")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
            raise TypeError("lease_seconds must be an integer")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be a positive integer")

        now = _utc_now()
        async with self.session_factory() as session:
            alert_row = await _lock_alert_row(session, alert_id)
            if alert_row is None:
                return None
            dispatch_row = await session.scalar(
                select(AnalysisDispatchControlRow)
                .where(AnalysisDispatchControlRow.id == "global")
                .with_for_update()
            )
            if dispatch_row is None:
                raise RuntimeError("Analysis dispatch control is not initialized")
            if dispatch_row.state == AnalysisDispatchState.PAUSED.value:
                return None
            latest_query = (
                select(InvestigationRunRow)
                .where(InvestigationRunRow.alert_id == alert_id)
                .order_by(desc(InvestigationRunRow.attempt))
                .limit(1)
            )
            latest = (await session.execute(latest_query)).scalar_one_or_none()
            if latest is None or latest.status != RunStatus.RUNNING.value:
                return None
            if latest.cancel_requested_at is not None:
                await self._finalize_cancelled_row(
                    session,
                    alert_id=alert_id,
                    run_row=latest,
                    requested_by=latest.cancel_requested_by or "unknown",
                    now=now,
                )
                await session.commit()
                return None
            lease_expires_at = latest.lease_expires_at
            if lease_expires_at is None:
                return None
            if lease_expires_at.tzinfo is None:
                lease_expires_at = lease_expires_at.replace(tzinfo=UTC)
            if lease_expires_at > now:
                return None
            checkpoint_query = (
                select(AgentCheckpointRow)
                .where(
                    AgentCheckpointRow.run_id == latest.id,
                    AgentCheckpointRow.namespace == "agent",
                )
                .order_by(desc(AgentCheckpointRow.version))
                .limit(1)
            )
            checkpoint_row = (await session.execute(checkpoint_query)).scalar_one_or_none()
            recovery_error: str | None = None
            if checkpoint_row is None:
                recovery_error = "Investigation lease expired without a recoverable checkpoint"
            else:
                try:
                    manifest = _decode_run_manifest(latest)
                    _decode_checkpoint_row(
                        checkpoint_row,
                        expected_run_id=latest.id,
                        expected_namespace="agent",
                        expected_manifest_hash=manifest.digest(),
                    )
                except RuntimeError as exc:
                    recovery_error = sanitize_text(str(exc))
            if recovery_error is not None:
                latest_sequence = await session.scalar(
                    select(ProgressRow.sequence)
                    .where(ProgressRow.run_id == latest.id)
                    .order_by(desc(ProgressRow.sequence))
                    .limit(1)
                )
                latest.status = RunStatus.FAILED.value
                latest.current_stage = InvestigationStage.FAILED.value
                latest.error = recovery_error
                latest.lease_expires_at = None
                latest.updated_at = now
                alert_row.status = AlertStatus.FAILED.value
                alert_row.error = recovery_error
                alert_row.updated_at = now
                session.add(
                    ProgressRow(
                        id=str(uuid4()),
                        alert_id=alert_id,
                        run_id=latest.id,
                        sequence=(latest_sequence or 0) + 1,
                        stage=InvestigationStage.FAILED.value,
                        message="调查运行无法安全恢复。",
                        details_json={"reason": "unrecoverable_expired_run"},
                        created_at=now,
                    )
                )
                self._queue_internal_failure_notification(
                    session,
                    alert_row=alert_row,
                    run_row=latest,
                    error=recovery_error,
                    now=now,
                )
                await session.commit()
                return None

            previous_token = latest.fencing_token
            statement = (
                update(InvestigationRunRow)
                .where(
                    InvestigationRunRow.id == latest.id,
                    InvestigationRunRow.status == RunStatus.RUNNING.value,
                    InvestigationRunRow.fencing_token == previous_token,
                    InvestigationRunRow.lease_expires_at <= now,
                )
                .values(
                    lease_owner=lease_owner,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                    fencing_token=previous_token + 1,
                    updated_at=now,
                )
            )
            result = await session.execute(statement)
            if result.rowcount != 1:
                await session.rollback()
                return None
            await session.commit()
            await session.refresh(latest)
            return self._run(latest)

    async def renew_run_lease(
        self,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool:
        if not isinstance(run_id, str):
            raise TypeError("run_id must be a string")
        if not run_id.strip():
            raise ValueError("run_id must not be empty")
        if not isinstance(lease_owner, str):
            raise TypeError("lease_owner must be a string")
        if not lease_owner.strip():
            raise ValueError("lease_owner must not be empty")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int):
            raise TypeError("fencing_token must be an integer")
        if fencing_token < 1:
            raise ValueError("fencing_token must be a positive integer")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
            raise TypeError("lease_seconds must be an integer")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be a positive integer")

        now = _utc_now()
        statement = (
            update(InvestigationRunRow)
            .where(
                InvestigationRunRow.id == run_id,
                InvestigationRunRow.status == RunStatus.RUNNING.value,
                InvestigationRunRow.lease_owner == lease_owner,
                InvestigationRunRow.fencing_token == fencing_token,
                InvestigationRunRow.lease_expires_at > now,
            )
            .values(
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                updated_at=now,
            )
        )
        async with self.session_factory() as session:
            result = await session.execute(statement)
            await session.commit()
            return result.rowcount == 1

    async def request_run_cancellation(
        self,
        alert_id: str,
        run_id: str,
        requested_by: str,
    ) -> InvestigationRun | None:
        if not requested_by.strip():
            raise ValueError("requested_by must not be empty")
        async with self.session_factory() as session:
            alert_row = await _lock_alert_row(session, alert_id)
            if alert_row is None:
                return None
            run_row = await session.get(InvestigationRunRow, run_id)
            if run_row is None or run_row.alert_id != alert_id:
                return None
            if run_row.status == RunStatus.CANCELLED.value:
                return self._run(run_row)
            if run_row.status != RunStatus.RUNNING.value:
                raise RunCancellationConflict(run_id, run_row.status)
            now = _utc_now()
            if run_row.cancel_requested_at is None:
                run_row.cancel_requested_at = now
                run_row.cancel_requested_by = requested_by
                run_row.updated_at = now
            await session.commit()
            await session.refresh(run_row)
            return self._run(run_row)

    async def is_run_cancellation_requested(self, run_id: str) -> bool:
        async with self.session_factory() as session:
            value = await session.scalar(
                select(InvestigationRunRow.cancel_requested_at).where(
                    InvestigationRunRow.id == run_id,
                    InvestigationRunRow.status == RunStatus.RUNNING.value,
                )
            )
            return value is not None

    async def finalize_requested_cancellation(
        self,
        alert_id: str,
        run_id: str,
    ) -> InvestigationRun | None:
        async with self.session_factory() as session:
            alert_row = await _lock_alert_row(session, alert_id)
            if alert_row is None:
                return None
            run_row = await session.get(InvestigationRunRow, run_id)
            if run_row is None or run_row.alert_id != alert_id:
                return None
            if run_row.status == RunStatus.CANCELLED.value:
                return self._run(run_row)
            if run_row.status != RunStatus.RUNNING.value:
                raise RunCancellationConflict(run_id, run_row.status)
            if run_row.cancel_requested_at is None:
                raise ValueError("run cancellation has not been requested")
            latest_run_id = await session.scalar(
                select(InvestigationRunRow.id)
                .where(InvestigationRunRow.alert_id == alert_id)
                .order_by(desc(InvestigationRunRow.attempt))
                .limit(1)
            )
            if latest_run_id != run_id:
                raise RunCancellationConflict(run_id, "SUPERSEDED")
            await self._finalize_cancelled_row(
                session,
                alert_id=alert_id,
                run_row=run_row,
                requested_by=run_row.cancel_requested_by or "unknown",
                now=_utc_now(),
            )
            await session.commit()
            await session.refresh(run_row)
            return self._run(run_row)

    @staticmethod
    async def _finalize_cancelled_row(
        session: AsyncSession,
        *,
        alert_id: str,
        run_row: InvestigationRunRow,
        requested_by: str,
        now: datetime,
    ) -> None:
        latest_sequence = await session.scalar(
            select(ProgressRow.sequence)
            .where(ProgressRow.run_id == run_row.id)
            .order_by(desc(ProgressRow.sequence))
            .limit(1)
        )
        run_row.status = RunStatus.CANCELLED.value
        run_row.current_stage = InvestigationStage.CANCELLED.value
        run_row.cancelled_at = now
        run_row.lease_expires_at = None
        run_row.error = None
        run_row.updated_at = now
        session.add(
            ProgressRow(
                id=str(uuid4()),
                alert_id=alert_id,
                run_id=run_row.id,
                sequence=(latest_sequence or 0) + 1,
                stage=InvestigationStage.CANCELLED.value,
                message="分析已主动取消。",
                details_json={"requested_by": requested_by},
                created_at=now,
            )
        )
        alert_row = await session.get(AlertRow, alert_id)
        if alert_row is not None:
            alert_row.status = AlertStatus.CANCELLED.value
            alert_row.error = None
            alert_row.updated_at = now

    async def renew(
        self,
        run_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool:
        return await self.renew_run_lease(
            run_id,
            lease_owner,
            fencing_token,
            lease_seconds,
        )

    async def get_run_manifest(self, run_id: str) -> RunManifest | None:
        async with self.session_factory() as session:
            row = await session.get(InvestigationRunRow, run_id)
            if row is None or row.manifest_json is None:
                return None
            return _decode_run_manifest(row)

    async def append_agent_events(
        self,
        run_id: str,
        events: list[AgentEvent],
        *,
        expected_sequence: int,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> int:
        if expected_sequence < 0:
            raise ValueError("expected_sequence must be non-negative")
        payloads: list[dict[str, Any]] = []
        for item in events:
            payload = _model_payload(item)
            payload["payload"] = _safe_agent_event_payload(payload.get("payload") or {})
            payloads.append(payload)
        for offset, payload in enumerate(payloads, start=1):
            event_run_id = str(payload.get("run_id") or "")
            if event_run_id != run_id:
                raise ValueError("Every AgentEvent must belong to the appended run")
            committed_sequence = expected_sequence + offset
            if payload.get("sequence") != committed_sequence:
                raise ValueError("AgentEvent sequences must be contiguous after expected_sequence")
            if payload.get("version") != committed_sequence:
                raise ValueError("Persisted AgentEvent version must match its sequence")

        async with self.session_factory() as session:
            await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            latest_query = (
                select(AgentEventRow.sequence)
                .where(AgentEventRow.run_id == run_id)
                .order_by(desc(AgentEventRow.sequence))
                .limit(1)
            )
            actual_sequence = (await session.execute(latest_query)).scalar_one_or_none() or 0
            if actual_sequence != expected_sequence:
                raise AgentEventSequenceConflict(run_id, expected_sequence, actual_sequence)
            if not payloads:
                return actual_sequence

            for payload in payloads:
                session.add(
                    AgentEventRow(
                        id=str(payload["event_id"]),
                        run_id=run_id,
                        parent_run_id=(
                            str(payload["parent_run_id"])
                            if payload.get("parent_run_id") is not None
                            else None
                        ),
                        invocation_id=(
                            str(payload["invocation_id"])
                            if payload.get("invocation_id") is not None
                            else None
                        ),
                        sequence=int(payload["sequence"]),
                        version=int(payload["version"]),
                        kind=str(payload["kind"]),
                        payload_json=dict(payload.get("payload") or {}),
                        causation_id=(
                            str(payload["causation_id"])
                            if payload.get("causation_id") is not None
                            else None
                        ),
                        correlation_id=(
                            str(payload["correlation_id"])
                            if payload.get("correlation_id") is not None
                            else None
                        ),
                        occurred_at=_datetime_value(payload["occurred_at"]),
                    )
                )
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                actual_sequence = (await session.execute(latest_query)).scalar_one_or_none() or 0
                raise AgentEventSequenceConflict(
                    run_id, expected_sequence, actual_sequence
                ) from exc
            return int(payloads[-1]["sequence"])

    async def list_agent_events(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int | None = None,
    ) -> list[AgentEvent]:
        from app.agent_runtime.events import AgentEvent

        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive")
        async with self.session_factory() as session:
            query = (
                select(AgentEventRow)
                .where(
                    AgentEventRow.run_id == run_id,
                    AgentEventRow.sequence > after_sequence,
                )
                .order_by(AgentEventRow.sequence)
            )
            if limit is not None:
                query = query.limit(limit)
            rows = (await session.execute(query)).scalars().all()
            return [
                AgentEvent.model_validate(
                    {
                        "event_id": row.id,
                        "run_id": row.run_id,
                        "parent_run_id": row.parent_run_id,
                        "invocation_id": row.invocation_id,
                        "sequence": row.sequence,
                        "version": row.version,
                        "kind": row.kind,
                        "payload": row.payload_json or {},
                        "causation_id": row.causation_id,
                        "correlation_id": row.correlation_id,
                        "occurred_at": row.occurred_at,
                    }
                )
                for row in rows
            ]

    async def get_agent_event_sequence(self, run_id: str) -> int:
        async with self.session_factory() as session:
            latest_query = (
                select(AgentEventRow.sequence)
                .where(AgentEventRow.run_id == run_id)
                .order_by(desc(AgentEventRow.sequence))
                .limit(1)
            )
            return (await session.execute(latest_query)).scalar_one_or_none() or 0

    async def save_checkpoint(
        self,
        checkpoint: RunCheckpoint,
        *,
        expected_version: int,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> RunCheckpoint:
        if expected_version < 0:
            raise ValueError("expected_version must be non-negative")
        payload = _model_payload(checkpoint)
        run_id = str(payload["run_id"])
        namespace = str(payload["namespace"])
        proposed_version = int(payload["version"])
        if proposed_version != expected_version + 1:
            raise ValueError("RunCheckpoint.version must equal expected_version + 1")

        async with self.session_factory() as session:
            run_row = await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            manifest_hash = _decode_run_manifest(run_row).digest()
            if checkpoint.manifest_hash != manifest_hash:
                raise RuntimeError(f"Checkpoint manifest mismatch for run {run_id}")
            latest_query = (
                select(AgentCheckpointRow.version)
                .where(
                    AgentCheckpointRow.run_id == run_id,
                    AgentCheckpointRow.namespace == namespace,
                )
                .order_by(desc(AgentCheckpointRow.version))
                .limit(1)
            )
            actual_version = (await session.execute(latest_query)).scalar_one_or_none() or 0
            if actual_version != expected_version:
                raise AgentCheckpointVersionConflict(run_id, expected_version, actual_version)
            state_hash = _canonical_json_hash(payload.get("state") or {})
            session.add(
                AgentCheckpointRow(
                    id=str(payload["checkpoint_id"]),
                    run_id=run_id,
                    namespace=namespace,
                    version=proposed_version,
                    sequence=int(payload["sequence"]),
                    payload_json=payload,
                    state_hash=state_hash,
                    manifest_hash=str(payload["manifest_hash"]),
                    stop_reason=_enum_value(payload.get("stop_reason")),
                    created_at=_datetime_value(payload["created_at"]),
                )
            )
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                actual_version = (await session.execute(latest_query)).scalar_one_or_none() or 0
                raise AgentCheckpointVersionConflict(
                    run_id, expected_version, actual_version
                ) from exc
            return checkpoint

    async def load_checkpoint(
        self,
        run_id: str,
        *,
        namespace: str = "agent",
    ) -> RunCheckpoint | None:
        async with self.session_factory() as session:
            query = (
                select(AgentCheckpointRow)
                .where(
                    AgentCheckpointRow.run_id == run_id,
                    AgentCheckpointRow.namespace == namespace,
                )
                .order_by(desc(AgentCheckpointRow.version))
                .limit(1)
            )
            row = (await session.execute(query)).scalar_one_or_none()
            if row is None:
                return None
            run_row = await session.get(InvestigationRunRow, run_id)
            if run_row is None:
                raise RuntimeError(f"Checkpoint references missing run {run_id}")
            return _decode_checkpoint_row(
                row,
                expected_run_id=run_id,
                expected_namespace=namespace,
                expected_manifest_hash=_decode_run_manifest(run_row).digest(),
            )

    async def load_checkpoint_by_id(
        self,
        run_id: str,
        checkpoint_id: str,
        *,
        namespace: str = "agent",
    ) -> RunCheckpoint | None:
        async with self.session_factory() as session:
            row = await session.get(AgentCheckpointRow, checkpoint_id)
            if row is None or row.run_id != run_id or row.namespace != namespace:
                return None
            run_row = await session.get(InvestigationRunRow, run_id)
            if run_row is None:
                raise RuntimeError(f"Checkpoint references missing run {run_id}")
            return _decode_checkpoint_row(
                row,
                expected_run_id=run_id,
                expected_namespace=namespace,
                expected_manifest_hash=_decode_run_manifest(run_row).digest(),
            )

    async def list_checkpoints(
        self,
        run_id: str,
        *,
        namespace: str = "agent",
        before_version: int | None = None,
        limit: int | None = None,
    ) -> list[RunCheckpoint]:
        if before_version is not None and before_version < 1:
            raise ValueError("before_version must be positive")
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        async with self.session_factory() as session:
            query = select(AgentCheckpointRow).where(
                AgentCheckpointRow.run_id == run_id,
                AgentCheckpointRow.namespace == namespace,
            )
            if before_version is not None:
                query = query.where(AgentCheckpointRow.version < before_version)
            query = query.order_by(desc(AgentCheckpointRow.version))
            if limit is not None:
                query = query.limit(limit)
            rows = (await session.execute(query)).scalars().all()
            if not rows:
                return []
            run_row = await session.get(InvestigationRunRow, run_id)
            if run_row is None:
                raise RuntimeError(f"Checkpoint references missing run {run_id}")
            manifest_hash = _decode_run_manifest(run_row).digest()
            return [
                _decode_checkpoint_row(
                    row,
                    expected_run_id=run_id,
                    expected_namespace=namespace,
                    expected_manifest_hash=manifest_hash,
                )
                for row in rows
            ]

    async def put_checkpoint_writes(
        self,
        run_id: str,
        checkpoint_id: str,
        writes: list[dict[str, Any]],
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        normalized: list[dict[str, Any]] = []
        required = {
            "task_id",
            "write_index",
            "channel",
            "value_type",
            "value_base64",
            "task_path",
        }
        for write in writes:
            if set(write) != required:
                raise ValueError("checkpoint write payload has an invalid shape")
            if not isinstance(write["task_id"], str) or not write["task_id"]:
                raise ValueError("checkpoint write task_id must not be empty")
            if isinstance(write["write_index"], bool) or not isinstance(write["write_index"], int):
                raise TypeError("checkpoint write_index must be an integer")
            if not isinstance(write["channel"], str) or not write["channel"]:
                raise ValueError("checkpoint write channel must not be empty")
            if not isinstance(write["value_type"], str) or not write["value_type"]:
                raise ValueError("checkpoint write value_type must not be empty")
            if not isinstance(write["value_base64"], str):
                raise TypeError("checkpoint write value_base64 must be a string")
            base64.b64decode(write["value_base64"], validate=True)
            if not isinstance(write["task_path"], str):
                raise TypeError("checkpoint write task_path must be a string")
            normalized.append(dict(write))

        async with self.session_factory() as session:
            await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            now = _utc_now()
            for write in normalized:
                existing_query = select(AgentCheckpointWriteRow).where(
                    AgentCheckpointWriteRow.run_id == run_id,
                    AgentCheckpointWriteRow.checkpoint_id == checkpoint_id,
                    AgentCheckpointWriteRow.task_id == write["task_id"],
                    AgentCheckpointWriteRow.write_index == write["write_index"],
                )
                existing = (await session.execute(existing_query)).scalar_one_or_none()
                if existing is not None:
                    if write["write_index"] >= 0:
                        continue
                    existing.channel = write["channel"]
                    existing.value_type = write["value_type"]
                    existing.value_base64 = write["value_base64"]
                    existing.task_path = write["task_path"]
                    existing.updated_at = now
                    continue
                session.add(
                    AgentCheckpointWriteRow(
                        run_id=run_id,
                        checkpoint_id=checkpoint_id,
                        task_id=write["task_id"],
                        write_index=write["write_index"],
                        channel=write["channel"],
                        value_type=write["value_type"],
                        value_base64=write["value_base64"],
                        task_path=write["task_path"],
                        created_at=now,
                        updated_at=now,
                    )
                )
            await session.commit()

    async def list_checkpoint_writes(
        self,
        run_id: str,
        checkpoint_id: str,
    ) -> list[dict[str, Any]]:
        async with self.session_factory() as session:
            checkpoint = await session.get(AgentCheckpointRow, checkpoint_id)
            if checkpoint is None or checkpoint.run_id != run_id:
                return []
            query = (
                select(AgentCheckpointWriteRow)
                .where(
                    AgentCheckpointWriteRow.run_id == run_id,
                    AgentCheckpointWriteRow.checkpoint_id == checkpoint_id,
                )
                .order_by(AgentCheckpointWriteRow.id)
            )
            rows = (await session.execute(query)).scalars().all()
            return [
                {
                    "task_id": row.task_id,
                    "write_index": row.write_index,
                    "channel": row.channel,
                    "value_type": row.value_type,
                    "value_base64": row.value_base64,
                    "task_path": row.task_path,
                }
                for row in rows
            ]

    async def save_tool_invocation(
        self,
        invocation: ToolInvocation,
        *,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ToolInvocation:
        payload = _model_payload(invocation)
        invocation_id = str(payload["invocation_id"])
        self._validate_tool_invocation_fingerprint(payload)
        async with self.session_factory() as session:
            await _require_active_run_lease(
                session,
                str(payload["run_id"]),
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            existing = await session.get(ToolInvocationRow, invocation_id)
            if existing is not None:
                self._validated_tool_invocation_row(
                    existing,
                    dialect_name=self.engine.dialect.name,
                )
                if _canonical_json_hash(existing.invocation_json) == _canonical_json_hash(payload):
                    return invocation
                raise ToolInvocationConflict(invocation_id, "invocation id already exists")
            session.add(self._tool_invocation_row(payload))
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise ToolInvocationConflict(
                    invocation_id, "concurrent insert used the same invocation id"
                ) from exc
            return invocation

    async def update_tool_invocation(
        self,
        invocation: ToolInvocation,
        *,
        result: dict[str, Any] | None = None,
        expected_status: ToolInvocationStatus | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ToolInvocation:
        payload = _model_payload(invocation)
        invocation_id = str(payload["invocation_id"])
        async with self.session_factory() as session:
            row = await session.get(ToolInvocationRow, invocation_id)
            if row is None:
                raise ToolInvocationConflict(invocation_id, "invocation does not exist")
            await _require_active_run_lease(
                session,
                row.run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            stored = self._validated_tool_invocation_row(
                row,
                dialect_name=self.engine.dialect.name,
            )
            self._validate_tool_invocation_fingerprint(payload)
            expected_value = (
                str(getattr(expected_status, "value", expected_status))
                if expected_status is not None
                else None
            )
            stored_identity = {
                key: value
                for key, value in _model_payload(stored).items()
                if key not in _TOOL_INVOCATION_LIFECYCLE_FIELDS
            }
            proposed_identity = {
                key: value
                for key, value in payload.items()
                if key not in _TOOL_INVOCATION_LIFECYCLE_FIELDS
            }
            if _canonical_json_hash(stored_identity) != _canonical_json_hash(
                proposed_identity
            ) and not self._is_valid_tool_invocation_execution_claim(
                stored_identity,
                proposed_identity,
                expected_status=expected_value,
                proposed_status=str(payload["status"]),
            ):
                raise ToolInvocationConflict(invocation_id, "immutable invocation identity changed")
            if expected_value is not None and row.status != expected_value:
                raise ToolInvocationConflict(
                    invocation_id,
                    f"expected status {expected_value}, found {row.status}",
                )
            if expected_value is None:
                self._update_tool_invocation_row(row, payload, result=result)
            else:
                transition = await session.execute(
                    update(ToolInvocationRow)
                    .where(
                        ToolInvocationRow.id == invocation_id,
                        ToolInvocationRow.status == expected_value,
                    )
                    .values(**self._tool_invocation_update_values(payload, result=result))
                )
                if transition.rowcount != 1:
                    await session.rollback()
                    raise ToolInvocationConflict(
                        invocation_id,
                        f"concurrent transition changed status {expected_value}",
                    )
            await session.commit()
            return invocation

    @staticmethod
    def _is_valid_tool_invocation_execution_claim(
        stored_identity: Mapping[str, Any],
        proposed_identity: Mapping[str, Any],
        *,
        expected_status: str | None,
        proposed_status: str,
    ) -> bool:
        """Allow one atomic execution-epoch claim while PENDING becomes STARTED."""

        from app.agent_runtime.contracts import ToolInvocationStatus

        if (
            expected_status != ToolInvocationStatus.PENDING.value
            or proposed_status != ToolInvocationStatus.STARTED.value
            or any(
                stored_identity.get(key) is not None
                for key in _TOOL_INVOCATION_EXECUTION_CLAIM_FIELDS
            )
        ):
            return False
        owner = proposed_identity.get("execution_lease_owner")
        token = proposed_identity.get("execution_fencing_token")
        if (
            not isinstance(owner, str)
            or not owner.strip()
            or isinstance(token, bool)
            or not isinstance(token, int)
            or token < 1
        ):
            return False
        stored_without_claim = {
            key: value
            for key, value in stored_identity.items()
            if key not in _TOOL_INVOCATION_EXECUTION_CLAIM_FIELDS
        }
        proposed_without_claim = {
            key: value
            for key, value in proposed_identity.items()
            if key not in _TOOL_INVOCATION_EXECUTION_CLAIM_FIELDS
        }
        return _canonical_json_hash(stored_without_claim) == _canonical_json_hash(
            proposed_without_claim
        )

    async def get_tool_invocation(self, invocation_id: str) -> ToolInvocation | None:
        async with self.session_factory() as session:
            row = await session.get(ToolInvocationRow, invocation_id)
            if row is None:
                return None
            return self._validated_tool_invocation_row(
                row,
                dialect_name=self.engine.dialect.name,
            )

    async def get_tool_invocation_result(self, invocation_id: str) -> dict[str, Any] | None:
        async with self.session_factory() as session:
            row = await session.get(ToolInvocationRow, invocation_id)
            if row is None or row.result_json is None:
                return None
            if not isinstance(row.result_json, dict):
                raise RuntimeError(f"Tool invocation result was not an object for {invocation_id}")
            return dict(row.result_json)

    async def save_agent_artifact(
        self,
        run_id: str,
        artifact: ArtifactRef,
        content: bytes | str | dict[str, Any],
        *,
        invocation_id: str | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
    ) -> ArtifactRef:
        from app.agent_runtime.contracts import ArtifactRef

        payload = _model_payload(artifact)
        artifact_id = str(payload["artifact_id"])
        stored_content, content_encoding, content_bytes = _artifact_content(content)
        actual_sha256 = sha256(content_bytes).hexdigest()
        actual_size = len(content_bytes)
        provided_sha256 = payload.get("sha256")
        if provided_sha256 is not None and (
            len(str(provided_sha256)) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in str(provided_sha256))
            or str(provided_sha256).casefold() != actual_sha256
        ):
            raise ValueError(f"Agent artifact SHA-256 mismatch for {artifact_id}")
        provided_size = payload.get("size_bytes")
        if provided_size is not None and int(provided_size) != actual_size:
            raise ValueError(f"Agent artifact size mismatch for {artifact_id}")
        stored_payload = {
            **payload,
            "uri": sanitize_text(str(payload["uri"])),
            "sha256": actual_sha256,
            "size_bytes": actual_size,
            "metadata": sanitize(dict(payload.get("metadata") or {})),
        }
        stored_artifact = ArtifactRef.model_validate(stored_payload)
        async with self.session_factory() as session:
            await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            existing = await session.get(AgentArtifactRow, artifact_id)
            if existing is not None:
                existing_payload = {
                    "artifact_id": existing.id,
                    "kind": existing.kind,
                    "media_type": existing.media_type,
                    "uri": existing.uri,
                    "sha256": existing.sha256,
                    "size_bytes": existing.size_bytes,
                    "metadata": existing.metadata_json or {},
                }
                if (
                    _canonical_json_hash(existing_payload) != _canonical_json_hash(stored_payload)
                    or existing.content_encoding != content_encoding
                    or existing.sanitized_content != stored_content
                ):
                    raise ToolInvocationConflict(artifact_id, "artifact id already exists")
                return stored_artifact
            session.add(
                AgentArtifactRow(
                    id=artifact_id,
                    run_id=run_id,
                    invocation_id=invocation_id,
                    kind=str(payload["kind"]),
                    media_type=str(payload["media_type"]),
                    uri=str(stored_payload["uri"]),
                    sha256=actual_sha256,
                    size_bytes=actual_size,
                    metadata_json=dict(stored_payload["metadata"]),
                    content_encoding=content_encoding,
                    sanitized_content=stored_content,
                    created_at=_utc_now(),
                )
            )
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise ToolInvocationConflict(
                    artifact_id, "concurrent insert used the same artifact id"
                ) from exc
            return stored_artifact

    async def get_agent_artifact(
        self, artifact_id: str
    ) -> tuple[ArtifactRef, bytes | str | dict[str, Any]] | None:
        from app.agent_runtime.contracts import ArtifactRef

        async with self.session_factory() as session:
            row = await session.get(AgentArtifactRow, artifact_id)
            if row is None:
                return None
            content = _decoded_artifact_content(row)
            _stored, _encoding, content_bytes = _artifact_content(content)
            if len(content_bytes) != row.size_bytes:
                raise RuntimeError(f"Agent artifact size mismatch for {artifact_id}")
            if sha256(content_bytes).hexdigest() != row.sha256:
                raise RuntimeError(f"Agent artifact SHA-256 mismatch for {artifact_id}")
            reference = ArtifactRef.model_validate(
                {
                    "artifact_id": row.id,
                    "kind": row.kind,
                    "media_type": row.media_type,
                    "uri": row.uri,
                    "sha256": row.sha256,
                    "size_bytes": row.size_bytes,
                    "metadata": row.metadata_json or {},
                }
            )
            return reference, content

    @staticmethod
    def _tool_invocation_row(payload: Mapping[str, Any]) -> ToolInvocationRow:
        now = _utc_now()
        row = ToolInvocationRow(
            id=str(payload["invocation_id"]),
            run_id=str(payload["run_id"]),
            parent_run_id=(
                str(payload["parent_run_id"]) if payload.get("parent_run_id") is not None else None
            ),
            tool_name=str(payload["tool_name"]),
            provider=str(payload["provider"]),
            objective=str(payload["objective"]),
            hypothesis_ids_json=list(payload.get("hypothesis_ids") or []),
            model_arguments_json=dict(payload.get("model_arguments") or {}),
            effective_arguments_json=dict(payload.get("effective_arguments") or {}),
            request_hash=_canonical_json_hash(payload.get("model_arguments") or {}),
            effective_hash=_canonical_json_hash(payload.get("effective_arguments") or {}),
            fingerprint=str(payload["fingerprint"]),
            status=str(payload["status"]),
            attempt=int(payload["attempt"]),
            deadline=_datetime_value(payload.get("deadline")),
            result_json=payload.get("result"),
            error_json=(
                dict(payload["error"]) if isinstance(payload.get("error"), Mapping) else None
            ),
            artifact_ref_json=(
                dict(payload["artifact_ref"])
                if isinstance(payload.get("artifact_ref"), Mapping)
                else None
            ),
            invocation_json=dict(payload),
            created_at=_datetime_value(payload["created_at"]),
            started_at=_datetime_value(payload.get("started_at")),
            completed_at=_datetime_value(payload.get("completed_at")),
            updated_at=now,
        )
        return row

    @staticmethod
    def _validate_tool_invocation_fingerprint(payload: Mapping[str, Any]) -> None:
        from app.agent_runtime.contracts import ToolInvocation

        invocation_id = str(payload["invocation_id"])
        expected = ToolInvocation.build_fingerprint(
            tool_name=str(payload["tool_name"]),
            effective_arguments=dict(payload.get("effective_arguments") or {}),
        )
        if str(payload["fingerprint"]) != expected:
            raise ToolInvocationConflict(
                invocation_id,
                "fingerprint does not match tool name and effective arguments",
            )

    @staticmethod
    def _validated_tool_invocation_row(
        row: ToolInvocationRow,
        *,
        dialect_name: str,
    ) -> ToolInvocation:
        from app.agent_runtime.contracts import ToolInvocation

        invocation_id = row.id
        try:
            stored = ToolInvocation.model_validate(row.invocation_json)
        except (TypeError, ValueError) as exc:
            raise ToolInvocationConflict(
                invocation_id, "persisted invocation payload is invalid"
            ) from exc

        stored_error = stored.error.model_dump(mode="json") if stored.error is not None else None
        stored_artifact = (
            stored.artifact_ref.model_dump(mode="json") if stored.artifact_ref is not None else None
        )
        mirrored_fields = {
            "invocation_id": row.id == str(stored.invocation_id),
            "run_id": row.run_id == str(stored.run_id),
            "parent_run_id": row.parent_run_id
            == (str(stored.parent_run_id) if stored.parent_run_id is not None else None),
            "tool_name": row.tool_name == stored.tool_name,
            "provider": row.provider == stored.provider,
            "objective": row.objective == stored.objective,
            "hypothesis_ids": list(row.hypothesis_ids_json or []) == stored.hypothesis_ids,
            "model_arguments": _canonical_json_hash(row.model_arguments_json or {})
            == _canonical_json_hash(stored.model_arguments),
            "effective_arguments": _canonical_json_hash(row.effective_arguments_json or {})
            == _canonical_json_hash(stored.effective_arguments),
            "fingerprint": row.fingerprint == stored.fingerprint,
            "status": row.status == stored.status.value,
            "attempt": row.attempt == stored.attempt,
            "deadline": _datetime_mirror_matches(
                row.deadline,
                stored.deadline,
                dialect_name=dialect_name,
            ),
            "created_at": _datetime_mirror_matches(
                row.created_at,
                stored.created_at,
                dialect_name=dialect_name,
            ),
            "started_at": _datetime_mirror_matches(
                row.started_at,
                stored.started_at,
                dialect_name=dialect_name,
            ),
            "completed_at": _datetime_mirror_matches(
                row.completed_at,
                stored.completed_at,
                dialect_name=dialect_name,
            ),
            "error": _canonical_json_hash(row.error_json) == _canonical_json_hash(stored_error),
            "artifact_ref": _canonical_json_hash(row.artifact_ref_json)
            == _canonical_json_hash(stored_artifact),
        }
        drifted = sorted(name for name, matches in mirrored_fields.items() if not matches)
        if drifted:
            raise ToolInvocationConflict(
                invocation_id,
                f"persisted invocation columns drifted: {', '.join(drifted)}",
            )

        request_hash = _canonical_json_hash(stored.model_arguments)
        if row.request_hash != request_hash:
            raise ToolInvocationConflict(invocation_id, "request arguments hash mismatch")
        effective_hash = _canonical_json_hash(stored.effective_arguments)
        if row.effective_hash != effective_hash:
            raise ToolInvocationConflict(invocation_id, "effective arguments hash mismatch")

        SQLAlchemyAlertRepository._validate_tool_invocation_fingerprint(
            stored.model_dump(mode="json")
        )
        return stored

    @staticmethod
    def _update_tool_invocation_row(
        row: ToolInvocationRow,
        payload: Mapping[str, Any],
        *,
        result: dict[str, Any] | None,
    ) -> None:
        for field, value in SQLAlchemyAlertRepository._tool_invocation_update_values(
            payload,
            result=result,
        ).items():
            setattr(row, field, value)

    @staticmethod
    def _tool_invocation_update_values(
        payload: Mapping[str, Any],
        *,
        result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        values: dict[str, Any] = {
            "status": str(payload["status"]),
            "error_json": (
                dict(payload["error"]) if isinstance(payload.get("error"), Mapping) else None
            ),
            "artifact_ref_json": (
                dict(payload["artifact_ref"])
                if isinstance(payload.get("artifact_ref"), Mapping)
                else None
            ),
            "invocation_json": dict(payload),
            "started_at": _datetime_value(payload.get("started_at")),
            "completed_at": _datetime_value(payload.get("completed_at")),
            "updated_at": _utc_now(),
        }
        if result is not None:
            values["result_json"] = _bounded_invocation_result(result)
        return values

    async def update_run(
        self,
        run_id: str,
        *,
        stage: InvestigationStage | None = None,
        error: str | None = None,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        if not isinstance(lease_owner, str):
            raise TypeError("lease_owner must be a string")
        if not lease_owner.strip():
            raise ValueError("lease_owner must not be empty")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int):
            raise TypeError("fencing_token must be an integer")
        if fencing_token < 1:
            raise ValueError("fencing_token must be a positive integer")
        if stage in {
            InvestigationStage.COMPLETED,
            InvestigationStage.INCONCLUSIVE,
            InvestigationStage.FAILED,
            InvestigationStage.CANCELLED,
        }:
            raise ValueError("terminal run stages must be persisted with finalize_run")

        now = _utc_now()
        values: dict[str, Any] = {"updated_at": now}
        if stage is not None:
            values["current_stage"] = stage.value
        if error is not None:
            values["error"] = error
        statement = (
            update(InvestigationRunRow)
            .where(
                InvestigationRunRow.id == run_id,
                InvestigationRunRow.status == RunStatus.RUNNING.value,
                InvestigationRunRow.lease_owner == lease_owner,
                InvestigationRunRow.fencing_token == fencing_token,
                InvestigationRunRow.lease_expires_at.is_not(None),
                InvestigationRunRow.lease_expires_at > now,
            )
            .values(**values)
        )
        async with self.session_factory() as session:
            result = await session.execute(statement)
            if result.rowcount != 1:
                await session.rollback()
                raise RunLeaseConflict(
                    run_id,
                    "owner/token mismatch, inactive run, or expired lease",
                )
            await session.commit()

    async def finalize_run(
        self,
        alert_id: str,
        run_id: str,
        *,
        lease_owner: str,
        fencing_token: int,
        run_status: RunStatus,
        final_stage: InvestigationStage,
        alert_status: AlertStatus,
        progress: ProgressRecord,
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
        model_failure: ModelFailure | None = None,
        pause_settings_revision: str | None = None,
        notification_kind: NotificationKind | None = None,
        notification_event: dict[str, Any] | None = None,
    ) -> ProgressRecord:
        expected_terminal = {
            RunStatus.COMPLETED: (
                InvestigationStage.COMPLETED,
                AlertStatus.COMPLETED,
            ),
            RunStatus.INCONCLUSIVE: (
                InvestigationStage.INCONCLUSIVE,
                AlertStatus.INCONCLUSIVE,
            ),
            RunStatus.FAILED: (
                InvestigationStage.FAILED,
                AlertStatus.FAILED,
            ),
        }.get(run_status)
        if expected_terminal is None:
            raise ValueError("finalize_run requires a terminal run status")
        if expected_terminal != (final_stage, alert_status):
            raise ValueError("run, stage, and alert terminal statuses must agree")
        if str(progress.run_id) != run_id:
            raise ValueError("terminal progress must belong to the finalized run")
        if progress.stage != final_stage:
            raise ValueError("terminal progress stage must match the finalized stage")
        if (notification_kind is None) != (notification_event is None):
            raise ValueError("notification kind and event must be provided together")

        serialized_recommendation = (
            recommendation.model_dump(mode="json") if recommendation else None
        )
        serialized_advisor_metadata = (
            advisor_metadata.model_dump(mode="json") if advisor_metadata else None
        )
        serialized_model_failure = (
            model_failure.model_dump(mode="json") if model_failure is not None else None
        )

        async with self.session_factory() as session:
            alert_row = await _lock_alert_row(session, alert_id)
            if alert_row is None:
                raise RuntimeError(f"Alert does not exist for run {run_id}")
            run_row = await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            if run_row.alert_id != alert_id:
                raise RunLeaseConflict(run_id, "run does not belong to the requested alert")
            latest_run_id = await session.scalar(
                select(InvestigationRunRow.id)
                .where(InvestigationRunRow.alert_id == alert_id)
                .order_by(desc(InvestigationRunRow.attempt))
                .limit(1)
            )
            if latest_run_id != run_id:
                raise RunLeaseConflict(run_id, "run is no longer the latest alert attempt")
            if run_row.cancel_requested_at is not None:
                raise RunCancellationRequested(run_id)

            latest_sequence = await session.scalar(
                select(ProgressRow.sequence)
                .where(ProgressRow.run_id == run_id)
                .order_by(desc(ProgressRow.sequence))
                .limit(1)
            )
            saved_progress = progress.model_copy(update={"sequence": (latest_sequence or 0) + 1})
            now = _utc_now()

            run_row.status = run_status.value
            run_row.current_stage = final_stage.value
            run_row.error = error
            run_row.recommendation_json = serialized_recommendation
            run_row.advisor_metadata_json = serialized_advisor_metadata
            run_row.model_failure_json = serialized_model_failure
            run_row.updated_at = now

            session.add(
                ProgressRow(
                    id=str(saved_progress.id),
                    alert_id=alert_id,
                    run_id=run_id,
                    sequence=saved_progress.sequence,
                    stage=saved_progress.stage.value,
                    message=saved_progress.message,
                    details_json=saved_progress.details,
                    created_at=saved_progress.created_at,
                )
            )

            alert_row.status = alert_status.value
            alert_row.recommendation_json = serialized_recommendation
            alert_row.advisor_metadata_json = serialized_advisor_metadata
            alert_row.error = error
            alert_row.updated_at = now

            if (
                model_failure is not None
                and model_failure.pauses_dispatch
                and pause_settings_revision is not None
            ):
                dispatch_row = await session.scalar(
                    select(AnalysisDispatchControlRow)
                    .where(AnalysisDispatchControlRow.id == "global")
                    .with_for_update()
                )
                if dispatch_row is None:
                    raise RuntimeError("Analysis dispatch control is not initialized")
                already_paused = (
                    dispatch_row.state == AnalysisDispatchState.PAUSED.value
                    and dispatch_row.paused_settings_revision == pause_settings_revision
                )
                if not already_paused:
                    dispatch_row.state = AnalysisDispatchState.PAUSED.value
                    dispatch_row.version += 1
                    dispatch_row.reason_json = serialized_model_failure
                    dispatch_row.trigger_run_id = run_id
                    dispatch_row.paused_settings_revision = pause_settings_revision
                    dispatch_row.paused_at = now
                    dispatch_row.resumed_at = None
                    dispatch_row.resumed_by = None
                    dispatch_row.last_validation_json = None
                    dispatch_row.updated_at = now

            if notification_kind is not None and notification_event is not None:
                session.add(
                    NotificationDeliveryRow(
                        id=str(uuid4()),
                        alert_id=alert_id,
                        run_id=run_id,
                        kind=notification_kind.value,
                        status=NotificationDeliveryStatus.PENDING.value,
                        event_json=notification_event,
                        attempts=0,
                        created_at=now,
                        updated_at=now,
                    )
                )

            await session.commit()
            return saved_progress

    async def append_progress(
        self,
        alert_id: str,
        record: ProgressRecord,
        *,
        lease_owner: str,
        fencing_token: int,
        allow_terminal: bool = False,
    ) -> ProgressRecord:
        async with self.session_factory() as session:
            run_id = str(record.run_id)
            run_row = await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
                allow_terminal=allow_terminal,
            )
            if run_row.alert_id != alert_id:
                raise RunLeaseConflict(run_id, "run does not belong to the requested alert")
            latest_sequence = await session.scalar(
                select(ProgressRow.sequence)
                .where(ProgressRow.run_id == run_id)
                .order_by(desc(ProgressRow.sequence))
                .limit(1)
            )
            sequence = (latest_sequence or 0) + 1
            saved = record.model_copy(update={"sequence": sequence})
            session.add(
                ProgressRow(
                    id=str(saved.id),
                    alert_id=alert_id,
                    run_id=run_id,
                    sequence=sequence,
                    stage=saved.stage.value,
                    message=saved.message,
                    details_json=saved.details,
                    created_at=saved.created_at,
                )
            )
            await session.commit()
            return saved

    async def save_evidence(
        self,
        alert_id: str,
        evidence: EvidenceRecord,
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        async with self.session_factory() as session:
            run_id = str(evidence.run_id)
            run_row = await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            if run_row.alert_id != alert_id:
                raise RunLeaseConflict(run_id, "run does not belong to the requested alert")
            evidence_id = str(evidence.id)
            await self._require_evidence_artifact_ownership(
                session,
                evidence,
                error_factory=lambda detail: EvidenceRecordConflict(evidence_id, detail),
            )
            existing = await session.get(EvidenceRow, evidence_id)
            if existing is not None:
                if self._evidence_record(existing) == evidence:
                    return
                raise EvidenceRecordConflict(
                    evidence_id,
                    "evidence id is already associated with different content",
                )
            session.add(
                EvidenceRow(
                    id=evidence_id,
                    contract_version=evidence.contract_version,
                    alert_id=alert_id,
                    run_id=run_id,
                    tool_name=evidence.tool_name,
                    source_system=evidence.source_system,
                    status=evidence.status.value,
                    request_json=evidence.request,
                    summary=evidence.summary,
                    data_json=evidence.structured_data,
                    source_artifact_id=(
                        str(evidence.source_artifact_id)
                        if evidence.source_artifact_id is not None
                        else None
                    ),
                    evidence_units_json=[
                        item.model_dump(mode="json") for item in evidence.evidence_units
                    ],
                    error=evidence.error,
                    started_at=evidence.started_at,
                    collected_at=evidence.collected_at,
                    duration_ms=evidence.duration_ms,
                    truncated=1 if evidence.truncated else 0,
                )
            )
            await session.commit()

    @staticmethod
    def _evidence_record(row: EvidenceRow) -> EvidenceRecord:
        return EvidenceRecord(
            id=row.id,
            contract_version=row.contract_version,
            run_id=row.run_id,
            tool_name=row.tool_name,
            source_system=row.source_system,
            status=ToolStatus(row.status),
            request=row.request_json,
            summary=row.summary,
            structured_data=row.data_json,
            source_artifact_id=row.source_artifact_id,
            evidence_units=row.evidence_units_json or [],
            error=row.error,
            started_at=row.started_at,
            collected_at=row.collected_at,
            duration_ms=row.duration_ms,
            truncated=bool(row.truncated),
        )

    @staticmethod
    def _evidence_mirror_matches(
        evidence: EvidenceRecord,
        authoritative_payload: Mapping[str, Any],
        *,
        dialect_name: str,
    ) -> bool:
        try:
            authoritative = EvidenceRecord.model_validate(authoritative_payload)
        except (TypeError, ValueError):
            return False
        if evidence == authoritative:
            return True
        if not (
            _datetime_mirror_matches(
                evidence.started_at,
                authoritative.started_at,
                dialect_name=dialect_name,
            )
            and _datetime_mirror_matches(
                evidence.collected_at,
                authoritative.collected_at,
                dialect_name=dialect_name,
            )
        ):
            return False
        evidence_payload = evidence.model_dump(mode="json")
        authoritative_payload = authoritative.model_dump(mode="json")
        for field in ("started_at", "collected_at"):
            evidence_payload.pop(field)
            authoritative_payload.pop(field)
        return _canonical_json_hash(evidence_payload) == _canonical_json_hash(authoritative_payload)

    @classmethod
    async def _require_evidence_artifact_ownership(
        cls,
        session: AsyncSession,
        evidence: EvidenceRecord,
        *,
        error_factory: Any = RuntimeError,
    ) -> None:
        if evidence.contract_version != "evidence-record/v2":
            return
        artifact_id = str(evidence.source_artifact_id)
        artifact = await session.get(AgentArtifactRow, artifact_id)
        if artifact is None:
            raise error_factory("v2 source artifact does not exist")
        if artifact.run_id != str(evidence.run_id):
            raise error_factory("v2 source artifact belongs to a different run")
        metadata = artifact.metadata_json or {}
        if (
            artifact.kind != "raw_tool_result"
            or metadata.get("tool_name") != evidence.tool_name
            or metadata.get("source_system") != evidence.source_system
        ):
            raise error_factory("v2 source artifact provenance does not match evidence")
        if artifact.invocation_id is None:
            raise error_factory("v2 source artifact is not bound to an invocation")
        invocation = await session.get(ToolInvocationRow, artifact.invocation_id)
        try:
            stored_invocation = (
                cls._validated_tool_invocation_row(
                    invocation,
                    dialect_name=session.get_bind().dialect.name,
                )
                if invocation is not None
                else None
            )
        except (ToolInvocationConflict, TypeError, ValueError) as exc:
            raise error_factory("v2 source artifact invocation binding is invalid") from exc
        stored_result = invocation.result_json if invocation is not None else None
        stored_evidence = (
            stored_result.get("evidence_record")
            if isinstance(stored_result, Mapping)
            and stored_result.get("contract") == "outer-evidence-record/v1"
            else None
        )
        if (
            stored_invocation is None
            or str(stored_invocation.run_id) != str(evidence.run_id)
            or stored_invocation.tool_name != evidence.tool_name
            or stored_invocation.provider != evidence.source_system
            or stored_invocation.effective_arguments != evidence.request
            or stored_invocation.artifact_ref is None
            or str(stored_invocation.artifact_ref.artifact_id) != artifact_id
            or not isinstance(stored_evidence, Mapping)
            or not cls._evidence_mirror_matches(
                evidence,
                stored_evidence,
                dialect_name=session.get_bind().dialect.name,
            )
        ):
            raise error_factory("v2 source artifact invocation binding is invalid")

        artifact_payload = {
            "artifact_id": artifact.id,
            "kind": artifact.kind,
            "media_type": artifact.media_type,
            "uri": artifact.uri,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "metadata": artifact.metadata_json or {},
        }
        if _canonical_json_hash(artifact_payload) != _canonical_json_hash(
            stored_invocation.artifact_ref.model_dump(mode="json")
        ):
            raise error_factory("v2 source artifact reference is invalid")
        try:
            raw_result = _decoded_artifact_content(artifact)
            _stored, _encoding, content_bytes = _artifact_content(raw_result)
        except Exception as exc:
            raise error_factory("v2 source artifact content is invalid") from exc
        if (
            len(content_bytes) != artifact.size_bytes
            or sha256(content_bytes).hexdigest() != artifact.sha256
        ):
            raise error_factory("v2 source artifact content hash is invalid")
        if not isinstance(raw_result, Mapping):
            raise error_factory("v2 source artifact is not a JSON object")

        for unit in evidence.evidence_units:
            resolved_values: list[Any] = []
            for source_path in unit.source_paths:
                try:
                    resolved_values.append(resolve_pointer(raw_result, source_path))
                except (JsonPointerException, TypeError, ValueError) as exc:
                    raise error_factory(
                        f"v2 evidence-unit source path does not resolve: {source_path}"
                    ) from exc
            if unit.status.value == "SUCCESS" and not any(
                cls._projected_value_matches_source(unit.data, source) for source in resolved_values
            ):
                raise error_factory(
                    "v2 successful evidence-unit data does not match its raw source path"
                )

    @classmethod
    def _projected_value_matches_source(cls, projected: Any, source: Any) -> bool:
        if isinstance(projected, Mapping):
            return isinstance(source, Mapping) and all(
                key in source and cls._projected_value_matches_source(value, source[key])
                for key, value in projected.items()
            )
        if isinstance(projected, list):
            return (
                isinstance(source, list)
                and len(projected) == len(source)
                and all(
                    cls._projected_value_matches_source(item, raw_item)
                    for item, raw_item in zip(projected, source, strict=True)
                )
            )
        return projected == source

    async def save_validation(
        self,
        alert_id: str,
        validation: ValidationRecord,
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        async with self.session_factory() as session:
            run_id = str(validation.run_id)
            run_row = await _require_active_run_lease(
                session,
                run_id,
                lease_owner=lease_owner,
                fencing_token=fencing_token,
            )
            if run_row.alert_id != alert_id:
                raise RunLeaseConflict(run_id, "run does not belong to the requested alert")
            session.add(
                ValidationRow(
                    id=str(validation.id),
                    alert_id=alert_id,
                    run_id=run_id,
                    kind=validation.kind.value,
                    passed=1 if validation.passed else 0,
                    evidence_sufficient=(1 if validation.evidence_sufficient else 0),
                    issues_json=validation.issues,
                    metadata_json=validation.metadata,
                    created_at=validation.created_at,
                )
            )
            await session.commit()

    async def set_status(self, alert_id: str, status: AlertStatus) -> None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return
            row.status = status.value
            row.updated_at = _utc_now()
            await session.commit()

    async def save_analysis(
        self,
        alert_id: str,
        status: AlertStatus,
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
        run_id: str | None = None,
    ) -> None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return
            serialized_recommendation = (
                recommendation.model_dump(mode="json") if recommendation else None
            )
            serialized_advisor_metadata = (
                advisor_metadata.model_dump(mode="json") if advisor_metadata else None
            )
            now = _utc_now()
            update_current = run_id is None
            if run_id:
                run_row = await session.get(InvestigationRunRow, run_id)
                if run_row is None or run_row.alert_id != alert_id:
                    return
                run_row.recommendation_json = serialized_recommendation
                run_row.advisor_metadata_json = serialized_advisor_metadata
                run_row.updated_at = now
                latest_run_id = await session.scalar(
                    select(InvestigationRunRow.id)
                    .where(InvestigationRunRow.alert_id == alert_id)
                    .order_by(desc(InvestigationRunRow.attempt))
                    .limit(1)
                )
                update_current = latest_run_id == run_id
            if update_current:
                row.status = status.value
                row.recommendation_json = serialized_recommendation
                row.advisor_metadata_json = serialized_advisor_metadata
                row.error = error
                row.updated_at = now
            await session.commit()

    async def get(self, alert_id: str, run_id: str | None = None) -> StoredAlert | None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return None
            selected_run_row: InvestigationRunRow | None = None
            if run_id:
                selected_run_row = await session.get(InvestigationRunRow, run_id)
                if selected_run_row is None or selected_run_row.alert_id != alert_id:
                    return None
            return await self._to_stored(session, row, selected_run_row=selected_run_row)

    async def _find_by_identity(
        self, session: AsyncSession, source: str, external_id: str
    ) -> AlertRow | None:
        query = select(AlertRow).where(
            AlertRow.source == source, AlertRow.external_id == external_id
        )
        return (await session.execute(query)).scalar_one_or_none()

    async def _to_stored(
        self,
        session: AsyncSession,
        row: AlertRow,
        *,
        selected_run_row: InvestigationRunRow | None = None,
    ) -> StoredAlert:
        # Get all runs for this alert (for history display)
        all_runs_query = (
            select(InvestigationRunRow)
            .where(InvestigationRunRow.alert_id == row.id)
            .order_by(desc(InvestigationRunRow.attempt))
        )
        all_run_rows = (await session.execute(all_runs_query)).scalars().all()
        all_runs = [self._run(run_row) for run_row in all_run_rows]
        latest_run = all_runs[0] if all_runs else None
        latest_run_row = all_run_rows[0] if all_run_rows else None
        run_row = selected_run_row or latest_run_row
        selected_run = self._run(run_row) if run_row else None
        progress: list[ProgressRecord] = []
        evidence_records: list[EvidenceRecord] = []
        validations: list[ValidationRecord] = []
        if run_row:
            progress_rows = (
                (
                    await session.execute(
                        select(ProgressRow)
                        .where(ProgressRow.run_id == run_row.id)
                        .order_by(ProgressRow.sequence)
                    )
                )
                .scalars()
                .all()
            )
            progress = [
                ProgressRecord(
                    id=item.id,
                    run_id=item.run_id,
                    sequence=item.sequence,
                    stage=item.stage,
                    message=item.message,
                    details=item.details_json,
                    created_at=item.created_at,
                )
                for item in progress_rows
            ]
            evidence_rows = (
                (
                    await session.execute(
                        select(EvidenceRow)
                        .where(EvidenceRow.run_id == run_row.id)
                        .order_by(EvidenceRow.started_at)
                    )
                )
                .scalars()
                .all()
            )
            evidence_records = [
                EvidenceRecord(
                    id=item.id,
                    contract_version=item.contract_version,
                    run_id=item.run_id,
                    tool_name=item.tool_name,
                    source_system=item.source_system,
                    status=ToolStatus(item.status),
                    request=item.request_json,
                    summary=item.summary,
                    structured_data=item.data_json,
                    source_artifact_id=item.source_artifact_id,
                    evidence_units=item.evidence_units_json or [],
                    error=item.error,
                    started_at=item.started_at,
                    collected_at=item.collected_at,
                    duration_ms=item.duration_ms,
                    truncated=bool(item.truncated),
                )
                for item in evidence_rows
            ]
            for evidence in evidence_records:
                await self._require_evidence_artifact_ownership(session, evidence)
            validation_rows = (
                (
                    await session.execute(
                        select(ValidationRow)
                        .where(ValidationRow.run_id == run_row.id)
                        .order_by(ValidationRow.created_at)
                    )
                )
                .scalars()
                .all()
            )
            validations = [
                ValidationRecord(
                    id=item.id,
                    run_id=item.run_id,
                    kind=ValidationKind(item.kind),
                    passed=bool(item.passed),
                    evidence_sufficient=bool(item.evidence_sufficient),
                    issues=item.issues_json,
                    metadata=item.metadata_json,
                    created_at=item.created_at,
                )
                for item in validation_rows
            ]
        normalized_alert = NormalizedAlert.model_validate(row.alert_json)

        selected_result_available = False
        selected_status = AlertStatus(row.status)
        selected_error = row.error
        recommendation_json: dict | None = row.recommendation_json
        advisor_metadata_json: dict | None = row.advisor_metadata_json
        if run_row:
            selected_status = {
                RunStatus.RUNNING.value: AlertStatus.ANALYZING,
                RunStatus.COMPLETED.value: AlertStatus.COMPLETED,
                RunStatus.INCONCLUSIVE.value: AlertStatus.INCONCLUSIVE,
                RunStatus.FAILED.value: AlertStatus.FAILED,
                RunStatus.CANCELLED.value: AlertStatus.CANCELLED,
            }[run_row.status]
            selected_error = run_row.error
            selected_result_available = any(
                value is not None
                for value in (
                    run_row.recommendation_json,
                    run_row.advisor_metadata_json,
                )
            )
            if selected_result_available:
                recommendation_json = run_row.recommendation_json
                advisor_metadata_json = run_row.advisor_metadata_json
            elif (
                latest_run_row is not None
                and run_row.id == latest_run_row.id
                and run_row.status != RunStatus.RUNNING.value
            ):
                # The current terminal result may predate migration 0011. It remains
                # readable from the alert row and is archived onto this run before
                # the next analysis starts.
                selected_result_available = True
            else:
                recommendation_json = None
                advisor_metadata_json = None
        else:
            selected_result_available = bool(recommendation_json or advisor_metadata_json)

        return StoredAlert(
            alert=normalized_alert,
            status=selected_status,
            recommendation=(
                Recommendation.model_validate(recommendation_json) if recommendation_json else None
            ),
            advisor_metadata=(
                AdvisorMetadata.model_validate(advisor_metadata_json)
                if advisor_metadata_json
                else None
            ),
            error=selected_error,
            latest_run=latest_run,
            selected_run=selected_run,
            selected_run_result_available=selected_result_available,
            all_runs=all_runs,
            progress=progress,
            evidence_records=evidence_records,
            validations=validations,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _run(row: InvestigationRunRow) -> InvestigationRun:
        config_snapshot = None
        if row.config_snapshot_json:
            config_snapshot = AnalysisConfigSnapshot.model_validate(row.config_snapshot_json)
        return InvestigationRun(
            id=row.id,
            alert_id=row.alert_id,
            attempt=row.attempt,
            fencing_token=row.fencing_token,
            status=RunStatus(row.status),
            current_stage=InvestigationStage(row.current_stage),
            error=row.error,
            lease_owner=row.lease_owner,
            lease_expires_at=row.lease_expires_at,
            cancel_requested_at=row.cancel_requested_at,
            cancel_requested_by=row.cancel_requested_by,
            cancelled_at=row.cancelled_at,
            config_snapshot=config_snapshot,
            model_failure=(
                ModelFailure.model_validate(row.model_failure_json)
                if row.model_failure_json
                else None
            ),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _dispatch_control(row: AnalysisDispatchControlRow) -> AnalysisDispatchControl:
        return AnalysisDispatchControl(
            state=AnalysisDispatchState(row.state),
            version=row.version,
            reason=ModelFailure.model_validate(row.reason_json) if row.reason_json else None,
            trigger_run_id=row.trigger_run_id,
            paused_settings_revision=row.paused_settings_revision,
            paused_at=row.paused_at,
            resumed_at=row.resumed_at,
            resumed_by=row.resumed_by,
            last_validation=(
                DispatchValidationResult.model_validate(row.last_validation_json)
                if row.last_validation_json
                else None
            ),
            updated_at=row.updated_at,
        )

    @staticmethod
    def _flashduty_poll_state(row: FlashDutyPollStateRow) -> FlashDutyPollState:
        return FlashDutyPollState(
            status=FlashDutyPollStatus(row.status),
            last_started_at=row.last_started_at,
            last_completed_at=row.last_completed_at,
            last_error=row.last_error,
            start_time=row.start_time,
            end_time=row.end_time,
            fetched_count=row.fetched_count,
            created_count=row.created_count,
            deduplicated_count=row.deduplicated_count,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _notification_delivery(row: NotificationDeliveryRow) -> NotificationDelivery:
        return NotificationDelivery(
            id=row.id,
            alert_id=row.alert_id,
            run_id=row.run_id,
            kind=NotificationKind(row.kind),
            status=NotificationDeliveryStatus(row.status),
            event=row.event_json,
            attempts=row.attempts,
            error=row.error,
            message_id=row.message_id,
            next_attempt_at=row.next_attempt_at,
            claim_owner=row.claim_owner,
            claim_expires_at=row.claim_expires_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
            sent_at=row.sent_at,
        )
