import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import (
    DATABASE_SCHEMA_REVISION,
    SQLAlchemyAlertRepository,
)
from app.config import get_settings
from app.domain.models import AlertStatus


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


@pytest.mark.asyncio
async def test_fresh_database_is_created_with_current_revision(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "fresh.db"))

    await repository.initialize()
    async with repository.engine.connect() as connection:
        revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
    await repository.ping()

    assert revision == DATABASE_SCHEMA_REVISION
    await repository.close()


@pytest.mark.asyncio
async def test_unversioned_partial_database_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "drifted.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE alerts (id TEXT PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE alembic_version "
            "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
        )

    repository = SQLAlchemyAlertRepository(sqlite_url(database))
    with pytest.raises(RuntimeError, match="Database schema is not current"):
        await repository.initialize()

    await repository.close()


@pytest.mark.asyncio
async def test_existing_non_application_database_is_not_mutated(tmp_path: Path) -> None:
    database = tmp_path / "unrelated.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE user_data (id TEXT PRIMARY KEY)")

    repository = SQLAlchemyAlertRepository(sqlite_url(database))
    with pytest.raises(RuntimeError, match="Database schema is not current"):
        await repository.initialize()
    await repository.close()

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert tables == {"user_data"}


@pytest.mark.asyncio
async def test_new_alert_is_atomically_persisted_as_queued(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "queued.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "atomic-queued-1",
            "severity": "INFO",
            "title": "Atomic queue state",
            "reason": "test",
        }
    )

    stored, created = await repository.create_or_get(alert)

    assert created is True
    assert stored.status == AlertStatus.QUEUED
    await repository.close()


def test_harness_migration_fails_unrecoverable_legacy_running_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "legacy-running.db"
    database_url = sqlite_url(database)
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    config.set_main_option(
        "script_location", str(Path(__file__).parents[2] / "migrations")
    )
    try:
        command.upgrade(config, "0011")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO alerts "
                "(id, source, external_id, status, alert_json, runbooks_json, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-alert",
                    "canonical",
                    "legacy-running",
                    "ANALYZING",
                    "{}",
                    "[]",
                    "2026-08-10 00:00:00",
                    "2026-08-10 00:00:00",
                ),
            )
            connection.execute(
                "INSERT INTO investigation_runs "
                "(id, alert_id, attempt, status, current_stage, lease_owner, "
                "lease_expires_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-run",
                    "legacy-alert",
                    3,
                    "RUNNING",
                    "INVESTIGATING",
                    "legacy-worker",
                    "2099-01-01 00:00:00",
                    "2026-08-10 00:00:00",
                    "2026-08-10 00:00:00",
                ),
            )

        command.upgrade(config, "0012")

        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT status, current_stage, error, lease_expires_at, "
                "fencing_token, manifest_json FROM investigation_runs "
                "WHERE id = 'legacy-run'"
            ).fetchone()
        assert row == (
            "FAILED",
            "FAILED",
            "Legacy investigation interrupted by Agent harness migration",
            None,
            3,
            None,
        )
    finally:
        get_settings.cache_clear()
