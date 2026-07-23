from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    desc,
    event,
    inspect,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.domain.models import (
    AdvisorMetadata,
    AlertListResult,
    AlertStatus,
    AlertSummary,
    DashboardSummary,
    EvidenceRecord,
    FeedbackRecord,
    FeedbackVerdict,
    InvestigationRun,
    InvestigationStage,
    KnowledgeCase,
    NormalizedAlert,
    ProgressRecord,
    Recommendation,
    RunbookExcerpt,
    RunStatus,
    StoredAlert,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


DATABASE_SCHEMA_REVISION = "0006"


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
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_alert_identity"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    alert_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    recommendation_json: Mapped[dict | None] = mapped_column(JSON)
    runbooks_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    advisor_metadata_json: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


class InvestigationRunRow(Base):
    __tablename__ = "investigation_runs"
    __table_args__ = (UniqueConstraint("alert_id", "attempt", name="uq_run_attempt"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_stage: Mapped[str] = mapped_column(String(40), nullable=False)
    strategy_id: Mapped[str | None] = mapped_column(String(255))
    error: Mapped[str | None] = mapped_column(Text)
    lease_owner: Mapped[str | None] = mapped_column(String(255))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )


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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )


class EvidenceRow(Base):
    __tablename__ = "evidence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
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
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
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
    issues_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FeedbackRow(Base):
    __tablename__ = "alert_feedback"
    __table_args__ = (
        UniqueConstraint("alert_id", "idempotency_key", name="uq_feedback_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    final_root_cause: Mapped[str | None] = mapped_column(Text)
    actual_resolution: Mapped[str | None] = mapped_column(Text)
    recovered: Mapped[int | None] = mapped_column(Integer)
    runbook_match_verdict: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )
    correct_runbook_id: Mapped[str | None] = mapped_column(String(128))
    correct_runbook_section: Mapped[str | None] = mapped_column(String(200))
    missed_runbook_ids_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supporting_evidence_ids_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    wrong_agent_claims_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    accepted_step_orders_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reviewer: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KnowledgeCaseRow(Base):
    __tablename__ = "knowledge_cases"
    __table_args__ = (UniqueConstraint("source_run_id", name="uq_case_source_run"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_alert_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    incident_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    fingerprint_version: Mapped[str] = mapped_column(String(20), nullable=False)
    environment: Mapped[str] = mapped_column(String(100), nullable=False)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(255), nullable=False)
    database_engine: Mapped[str | None] = mapped_column(String(100))
    correct_runbook_id: Mapped[str | None] = mapped_column(String(128))
    correct_runbook_section: Mapped[str | None] = mapped_column(String(200))
    supporting_evidence_ids_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    final_root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    actual_resolution: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation_json: Mapped[dict | None] = mapped_column(JSON)
    confirmed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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

    async def close(self) -> None:
        await self.engine.dispose()

    async def ping(self) -> None:
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
            await self._assert_schema_current(connection)

    @staticmethod
    def _schema_snapshot(connection) -> dict[str, set[str]]:  # type: ignore[no-untyped-def]
        inspector = inspect(connection)
        return {
            table_name: {str(column["name"]) for column in inspector.get_columns(table_name)}
            for table_name in inspector.get_table_names()
        }

    async def _assert_schema_current(self, connection) -> None:  # type: ignore[no-untyped-def]
        snapshot = await connection.run_sync(self._schema_snapshot)
        expected_columns = {
            table_name: {column.name for column in table.columns}
            for table_name, table in Base.metadata.tables.items()
        }
        missing_tables = sorted(set(expected_columns) - set(snapshot))
        missing_columns = {
            table_name: sorted(columns - snapshot.get(table_name, set()))
            for table_name, columns in expected_columns.items()
            if columns - snapshot.get(table_name, set())
        }

        revision: str | None = None
        if "alembic_version" in snapshot:
            revision = await connection.scalar(select(_alembic_version.c.version_num))
        if revision != DATABASE_SCHEMA_REVISION or missing_tables or missing_columns:
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
            recovery = (
                "Back up the database and follow the unversioned SQLite recovery "
                "instructions in README.md."
                if revision is None
                else "Back up the database and run `alembic upgrade head`."
            )
            raise RuntimeError(
                "Database schema is not current ("
                + "; ".join(details)
                + f"). {recovery}"
            )

    async def create_or_get(self, alert: NormalizedAlert) -> tuple[StoredAlert, bool]:
        async with self.session_factory() as session:
            existing = await self._find_by_identity(session, alert.source, alert.external_id)
            if existing:
                return await self._to_stored(session, existing), False

            row = AlertRow(
                id=str(alert.id),
                source=alert.source,
                external_id=alert.external_id,
                status=AlertStatus.QUEUED.value,
                alert_json=alert.model_dump(mode="json"),
                runbooks_json=[],
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
                    manual_matched=bool(
                        recommendation.get("manual_matched", bool(row.runbooks_json))
                    ),
                    requires_human=recommendation.get("requires_human"),
                    confidence=recommendation.get("confidence"),
                )
            )
        return summaries

    async def create_run(
        self, alert_id: str, lease_owner: str, lease_seconds: int
    ) -> InvestigationRun | None:
        async with self.session_factory() as session:
            alert_row = await session.get(AlertRow, alert_id)
            if not alert_row or alert_row.status in {
                AlertStatus.COMPLETED.value,
                AlertStatus.REVIEW_REQUIRED.value,
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
                latest.error = "Investigation lease expired"
                latest.updated_at = now
            attempt = (latest.attempt + 1) if latest else 1
            run = InvestigationRun(
                alert_id=alert_id,
                attempt=attempt,
                lease_owner=lease_owner,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
            )
            session.add(
                InvestigationRunRow(
                    id=str(run.id),
                    alert_id=alert_id,
                    attempt=attempt,
                    status=run.status.value,
                    current_stage=run.current_stage.value,
                    lease_owner=lease_owner,
                    lease_expires_at=run.lease_expires_at,
                    created_at=run.created_at,
                    updated_at=run.updated_at,
                )
            )
            alert_row.status = AlertStatus.ANALYZING.value
            alert_row.updated_at = now
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return None
            return run

    async def update_run(
        self,
        run_id: str,
        *,
        status: str | None = None,
        stage: InvestigationStage | None = None,
        strategy_id: str | None = None,
        error: str | None = None,
    ) -> None:
        async with self.session_factory() as session:
            row = await session.get(InvestigationRunRow, run_id)
            if not row:
                return
            if status is not None:
                row.status = status
            if stage is not None:
                row.current_stage = stage.value
            if strategy_id is not None:
                row.strategy_id = strategy_id
            if error is not None:
                row.error = error
            now = _utc_now()
            if row.status == RunStatus.RUNNING.value and row.lease_expires_at is not None:
                lease_expires_at = row.lease_expires_at
                updated_at = row.updated_at
                if lease_expires_at.tzinfo is None:
                    lease_expires_at = lease_expires_at.replace(tzinfo=UTC)
                if updated_at.tzinfo is None:
                    updated_at = updated_at.replace(tzinfo=UTC)
                lease_window = lease_expires_at - updated_at
                if lease_window.total_seconds() > 0:
                    row.lease_expires_at = now + lease_window
            row.updated_at = now
            await session.commit()

    async def append_progress(self, alert_id: str, record: ProgressRecord) -> ProgressRecord:
        async with self.session_factory() as session:
            query = select(ProgressRow.sequence).where(ProgressRow.run_id == str(record.run_id))
            sequences = (await session.execute(query)).scalars().all()
            sequence = max(sequences, default=0) + 1
            saved = record.model_copy(update={"sequence": sequence})
            session.add(
                ProgressRow(
                    id=str(saved.id),
                    alert_id=alert_id,
                    run_id=str(saved.run_id),
                    sequence=sequence,
                    stage=saved.stage.value,
                    message=saved.message,
                    details_json=saved.details,
                    created_at=saved.created_at,
                )
            )
            await session.commit()
            return saved

    async def save_evidence(self, alert_id: str, evidence: EvidenceRecord) -> None:
        async with self.session_factory() as session:
            session.add(
                EvidenceRow(
                    id=str(evidence.id),
                    alert_id=alert_id,
                    run_id=str(evidence.run_id),
                    tool_name=evidence.tool_name,
                    source_system=evidence.source_system,
                    status=evidence.status.value,
                    request_json=evidence.request,
                    summary=evidence.summary,
                    data_json=evidence.structured_data,
                    error=evidence.error,
                    started_at=evidence.started_at,
                    collected_at=evidence.collected_at,
                    duration_ms=evidence.duration_ms,
                    truncated=1 if evidence.truncated else 0,
                )
            )
            await session.commit()

    async def save_validation(self, alert_id: str, validation: ValidationRecord) -> None:
        async with self.session_factory() as session:
            session.add(
                ValidationRow(
                    id=str(validation.id),
                    alert_id=alert_id,
                    run_id=str(validation.run_id),
                    kind=validation.kind.value,
                    passed=1 if validation.passed else 0,
                    issues_json=validation.issues,
                    metadata_json=validation.metadata,
                    created_at=validation.created_at,
                )
            )
            await session.commit()

    async def find_knowledge_cases(
        self, fingerprint: str, fingerprint_version: str, limit: int = 3
    ) -> list[KnowledgeCase]:
        async with self.session_factory() as session:
            query = (
                select(KnowledgeCaseRow)
                .where(
                    KnowledgeCaseRow.incident_fingerprint == fingerprint,
                    KnowledgeCaseRow.fingerprint_version == fingerprint_version,
                )
                .order_by(desc(KnowledgeCaseRow.confirmed_at))
                .limit(limit)
            )
            rows = (await session.execute(query)).scalars().all()
            return [self._knowledge_case(row) for row in rows]

    async def save_feedback(
        self, feedback: FeedbackRecord, knowledge_case: KnowledgeCase | None = None
    ) -> FeedbackRecord:
        async with self.session_factory() as session:
            query = select(FeedbackRow).where(
                FeedbackRow.alert_id == str(feedback.alert_id),
                FeedbackRow.idempotency_key == feedback.idempotency_key,
            )
            existing = (await session.execute(query)).scalar_one_or_none()
            if existing:
                return self._feedback(existing)
            session.add(
                FeedbackRow(
                    id=str(feedback.id),
                    alert_id=str(feedback.alert_id),
                    run_id=str(feedback.run_id),
                    idempotency_key=feedback.idempotency_key,
                    verdict=feedback.verdict.value,
                    final_root_cause=feedback.final_root_cause,
                    actual_resolution=feedback.actual_resolution,
                    recovered=(
                        1
                        if feedback.recovered is True
                        else 0
                        if feedback.recovered is False
                        else None
                    ),
                    runbook_match_verdict=feedback.runbook_match_verdict.value,
                    correct_runbook_id=feedback.correct_runbook_id,
                    correct_runbook_section=feedback.correct_runbook_section,
                    missed_runbook_ids_json=feedback.missed_runbook_ids,
                    supporting_evidence_ids_json=feedback.supporting_evidence_ids,
                    wrong_agent_claims_json=feedback.wrong_agent_claims,
                    accepted_step_orders_json=feedback.accepted_step_orders,
                    reviewer=feedback.reviewer,
                    created_at=feedback.created_at,
                )
            )
            if knowledge_case:
                existing_case = (
                    await session.execute(
                        select(KnowledgeCaseRow).where(
                            KnowledgeCaseRow.source_run_id == str(knowledge_case.source_run_id)
                        )
                    )
                ).scalar_one_or_none()
                if existing_case is None:
                    session.add(
                        KnowledgeCaseRow(
                            id=str(knowledge_case.id),
                            source_alert_id=str(knowledge_case.source_alert_id),
                            source_run_id=str(knowledge_case.source_run_id),
                            incident_fingerprint=knowledge_case.incident_fingerprint,
                            fingerprint_version=knowledge_case.fingerprint_version,
                            environment=knowledge_case.environment,
                            service_name=knowledge_case.service_name,
                            alert_type=knowledge_case.alert_type,
                            database_engine=knowledge_case.database_engine,
                            correct_runbook_id=knowledge_case.correct_runbook_id,
                            correct_runbook_section=knowledge_case.correct_runbook_section,
                            supporting_evidence_ids_json=(knowledge_case.supporting_evidence_ids),
                            final_root_cause=knowledge_case.final_root_cause,
                            actual_resolution=knowledge_case.actual_resolution,
                            recommendation_json=(
                                knowledge_case.recommendation.model_dump(mode="json")
                                if knowledge_case.recommendation
                                else None
                            ),
                            confirmed_by=knowledge_case.confirmed_by,
                            confirmed_at=knowledge_case.confirmed_at,
                            created_at=knowledge_case.created_at,
                        )
                    )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = (await session.execute(query)).scalar_one()
                return self._feedback(existing)
            return feedback

    async def set_status(self, alert_id: str, status: AlertStatus) -> None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return
            row.status = status.value
            row.updated_at = _utc_now()
            await session.commit()

    async def save_runbooks(self, alert_id: str, runbooks: list[RunbookExcerpt]) -> None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return
            row.runbooks_json = [item.model_dump(mode="json") for item in runbooks]
            row.updated_at = _utc_now()
            await session.commit()

    async def save_analysis(
        self,
        alert_id: str,
        status: AlertStatus,
        runbooks: list[RunbookExcerpt] | None = None,
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
    ) -> None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return
            row.status = status.value
            if runbooks is not None:
                row.runbooks_json = [item.model_dump(mode="json") for item in runbooks]
            row.recommendation_json = (
                recommendation.model_dump(mode="json") if recommendation else None
            )
            row.advisor_metadata_json = (
                advisor_metadata.model_dump(mode="json") if advisor_metadata else None
            )
            row.error = error
            row.updated_at = _utc_now()
            await session.commit()

    async def get(self, alert_id: str) -> StoredAlert | None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return None
            return await self._to_stored(session, row)

    async def _find_by_identity(
        self, session: AsyncSession, source: str, external_id: str
    ) -> AlertRow | None:
        query = select(AlertRow).where(
            AlertRow.source == source, AlertRow.external_id == external_id
        )
        return (await session.execute(query)).scalar_one_or_none()

    async def _to_stored(self, session: AsyncSession, row: AlertRow) -> StoredAlert:
        run_query = (
            select(InvestigationRunRow)
            .where(InvestigationRunRow.alert_id == row.id)
            .order_by(desc(InvestigationRunRow.attempt))
            .limit(1)
        )
        run_row = (await session.execute(run_query)).scalar_one_or_none()
        latest_run = self._run(run_row) if run_row else None
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
                    run_id=item.run_id,
                    tool_name=item.tool_name,
                    source_system=item.source_system,
                    status=ToolStatus(item.status),
                    request=item.request_json,
                    summary=item.summary,
                    structured_data=item.data_json,
                    error=item.error,
                    started_at=item.started_at,
                    collected_at=item.collected_at,
                    duration_ms=item.duration_ms,
                    truncated=bool(item.truncated),
                )
                for item in evidence_rows
            ]
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
                    issues=item.issues_json,
                    metadata=item.metadata_json,
                    created_at=item.created_at,
                )
                for item in validation_rows
            ]
        feedback_rows = (
            (
                await session.execute(
                    select(FeedbackRow)
                    .where(FeedbackRow.alert_id == row.id)
                    .order_by(FeedbackRow.created_at)
                )
            )
            .scalars()
            .all()
        )
        feedback = [self._feedback(item) for item in feedback_rows]
        normalized_alert = NormalizedAlert.model_validate(row.alert_json)
        knowledge_matches = await self._find_cases_in_session(
            session,
            normalized_alert.incident_fingerprint,
            normalized_alert.fingerprint_version,
            limit=3,
        )
        return StoredAlert(
            alert=normalized_alert,
            status=AlertStatus(row.status),
            recommendation=(
                Recommendation.model_validate(row.recommendation_json)
                if row.recommendation_json
                else None
            ),
            manual_matches=[RunbookExcerpt.model_validate(item) for item in row.runbooks_json],
            advisor_metadata=(
                AdvisorMetadata.model_validate(row.advisor_metadata_json)
                if row.advisor_metadata_json
                else None
            ),
            error=row.error,
            latest_run=latest_run,
            progress=progress,
            evidence_records=evidence_records,
            validations=validations,
            feedback=feedback,
            knowledge_matches=knowledge_matches,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    async def _find_cases_in_session(
        self,
        session: AsyncSession,
        fingerprint: str,
        fingerprint_version: str,
        limit: int,
    ) -> list[KnowledgeCase]:
        if not fingerprint:
            return []
        query = (
            select(KnowledgeCaseRow)
            .where(
                KnowledgeCaseRow.incident_fingerprint == fingerprint,
                KnowledgeCaseRow.fingerprint_version == fingerprint_version,
            )
            .order_by(desc(KnowledgeCaseRow.confirmed_at))
            .limit(limit)
        )
        rows = (await session.execute(query)).scalars().all()
        return [self._knowledge_case(item) for item in rows]

    @staticmethod
    def _run(row: InvestigationRunRow) -> InvestigationRun:
        return InvestigationRun(
            id=row.id,
            alert_id=row.alert_id,
            attempt=row.attempt,
            status=RunStatus(row.status),
            current_stage=InvestigationStage(row.current_stage),
            strategy_id=row.strategy_id,
            error=row.error,
            lease_owner=row.lease_owner,
            lease_expires_at=row.lease_expires_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _feedback(row: FeedbackRow) -> FeedbackRecord:
        return FeedbackRecord(
            id=row.id,
            alert_id=row.alert_id,
            run_id=row.run_id,
            idempotency_key=row.idempotency_key,
            verdict=FeedbackVerdict(row.verdict),
            final_root_cause=row.final_root_cause,
            actual_resolution=row.actual_resolution,
            recovered=bool(row.recovered) if row.recovered is not None else None,
            runbook_match_verdict=row.runbook_match_verdict,
            correct_runbook_id=row.correct_runbook_id,
            correct_runbook_section=row.correct_runbook_section,
            missed_runbook_ids=row.missed_runbook_ids_json or [],
            supporting_evidence_ids=row.supporting_evidence_ids_json or [],
            wrong_agent_claims=row.wrong_agent_claims_json or [],
            accepted_step_orders=row.accepted_step_orders_json or [],
            reviewer=row.reviewer,
            created_at=row.created_at,
        )

    @staticmethod
    def _knowledge_case(row: KnowledgeCaseRow) -> KnowledgeCase:
        return KnowledgeCase(
            id=row.id,
            source_alert_id=row.source_alert_id,
            source_run_id=row.source_run_id,
            incident_fingerprint=row.incident_fingerprint,
            fingerprint_version=row.fingerprint_version,
            environment=row.environment,
            service_name=row.service_name,
            alert_type=row.alert_type,
            database_engine=row.database_engine,
            correct_runbook_id=row.correct_runbook_id,
            correct_runbook_section=row.correct_runbook_section,
            supporting_evidence_ids=row.supporting_evidence_ids_json or [],
            final_root_cause=row.final_root_cause,
            actual_resolution=row.actual_resolution,
            recommendation=(
                Recommendation.model_validate(row.recommendation_json)
                if row.recommendation_json
                else None
            ),
            confirmed_by=row.confirmed_by,
            confirmed_at=row.confirmed_at,
            created_at=row.created_at,
        )
