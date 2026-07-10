from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.domain.models import (
    AdvisorMetadata,
    AlertStatus,
    NormalizedAlert,
    NotificationRecord,
    Recommendation,
    RunbookExcerpt,
    StoredAlert,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


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


class NotificationRow(Base):
    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("alert_id", "phase", name="uq_notification_phase"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    external_delivery_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )


class SQLAlchemyAlertRepository:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._ensure_sqlite_directory()
        self.engine = create_async_engine(database_url, future=True)
        self.session_factory = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    def _ensure_sqlite_directory(self) -> None:
        prefixes = ("sqlite+aiosqlite:///", "sqlite:///")
        for prefix in prefixes:
            if self.database_url.startswith(prefix):
                path = self.database_url.removeprefix(prefix)
                if path and path != ":memory:":
                    Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self) -> None:
        # Alembic is provided for managed environments; create_all keeps the skeleton runnable.
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()

    async def ping(self) -> None:
        async with self.session_factory() as session:
            await session.execute(text("SELECT 1"))

    async def create_or_get(self, alert: NormalizedAlert) -> tuple[StoredAlert, bool]:
        async with self.session_factory() as session:
            existing = await self._find_by_identity(session, alert.source, alert.external_id)
            if existing:
                return await self._to_stored(session, existing), False

            row = AlertRow(
                id=str(alert.id),
                source=alert.source,
                external_id=alert.external_id,
                status=AlertStatus.RECEIVED.value,
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
        runbooks: list[RunbookExcerpt],
        recommendation: Recommendation | None = None,
        advisor_metadata: AdvisorMetadata | None = None,
        error: str | None = None,
    ) -> None:
        async with self.session_factory() as session:
            row = await session.get(AlertRow, alert_id)
            if not row:
                return
            row.status = status.value
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

    async def save_notification(
        self, alert_id: str, notification: NotificationRecord
    ) -> None:
        async with self.session_factory() as session:
            query = select(NotificationRow).where(
                NotificationRow.alert_id == alert_id,
                NotificationRow.phase == notification.phase.value,
            )
            row = (await session.execute(query)).scalar_one_or_none()
            if row:
                row.status = notification.status.value
                row.attempts = notification.attempts
                row.error = notification.error
                row.external_delivery_id = notification.external_delivery_id
                row.created_at = notification.created_at
            else:
                session.add(
                    NotificationRow(
                        id=str(notification.id),
                        alert_id=alert_id,
                        phase=notification.phase.value,
                        status=notification.status.value,
                        attempts=notification.attempts,
                        error=notification.error,
                        external_delivery_id=notification.external_delivery_id,
                        created_at=notification.created_at,
                    )
                )
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
        query = (
            select(NotificationRow)
            .where(NotificationRow.alert_id == row.id)
            .order_by(NotificationRow.created_at, NotificationRow.phase)
        )
        notification_rows = (await session.execute(query)).scalars().all()
        notifications = [
            NotificationRecord(
                id=item.id,
                phase=item.phase,
                status=item.status,
                attempts=item.attempts,
                error=item.error,
                external_delivery_id=item.external_delivery_id,
                created_at=item.created_at,
            )
            for item in notification_rows
        ]
        return StoredAlert(
            alert=NormalizedAlert.model_validate(row.alert_json),
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
            notifications=notifications,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
