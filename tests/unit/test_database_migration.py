from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import JSON, Column, MetaData, String, Table, Text, func, select
from sqlalchemy.dialects import mysql, sqlite
from sqlalchemy.ext.asyncio import create_async_engine

import tools.migrate_sqlite_to_mysql as migration_module
from app.adapters.persistence import (
    DATABASE_SCHEMA_REVISION,
    AgentArtifactRow,
    AgentCheckpointWriteRow,
)
from app.config import get_settings
from tools.migrate_sqlite_to_mysql import (
    MigrationError,
    _canonical_row_bytes,
    _copy_table,
    _digest_table,
    _lock_source_snapshot,
    _mysql_version,
    _target_url_from_environment,
)


def test_alembic_head_matches_repository_schema_revision() -> None:
    root = Path(__file__).parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))

    assert ScriptDirectory.from_config(config).get_current_head() == DATABASE_SCHEMA_REVISION


def test_0017_advances_sqlite_revision_without_changing_text_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).parents[2]
    database = tmp_path / "mysql-large-text.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{database}")
    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "false")
    get_settings.cache_clear()
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))

    try:
        command.upgrade(config, "0016")
        command.upgrade(config, "head")

        with sqlite3.connect(database) as connection:
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            artifact_type = connection.execute(
                "SELECT type FROM pragma_table_info('agent_artifacts') "
                "WHERE name = 'sanitized_content'"
            ).fetchone()
            checkpoint_type = connection.execute(
                "SELECT type FROM pragma_table_info('agent_checkpoint_writes') "
                "WHERE name = 'value_base64'"
            ).fetchone()

        assert revision == ("0017",)
        assert artifact_type == ("TEXT",)
        assert checkpoint_type == ("TEXT",)
    finally:
        get_settings.cache_clear()


def test_alembic_accepts_percent_encoded_database_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).parents[2]
    database = tmp_path / "alerts%40encoded.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{database}")
    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "false")
    get_settings.cache_clear()
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))

    try:
        command.upgrade(config, "head")

        with sqlite3.connect(database) as connection:
            revision = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchone()

        assert revision == (DATABASE_SCHEMA_REVISION,)
    finally:
        get_settings.cache_clear()


def test_mysql_unbounded_payload_columns_compile_as_longtext() -> None:
    checkpoint_type = AgentCheckpointWriteRow.__table__.c.value_base64.type
    artifact_type = AgentArtifactRow.__table__.c.sanitized_content.type

    assert checkpoint_type.compile(dialect=mysql.dialect()) == "LONGTEXT"
    assert artifact_type.compile(dialect=mysql.dialect()) == "LONGTEXT"
    assert checkpoint_type.compile(dialect=sqlite.dialect()) == "TEXT"
    assert artifact_type.compile(dialect=sqlite.dialect()) == "TEXT"


def test_target_url_is_loaded_only_from_the_selected_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TEST_MYSQL_URL",
        "mysql+asyncmy://migration:secret@mysql.example:3306/database_alerts?charset=utf8mb4",
    )

    assert _target_url_from_environment("TEST_MYSQL_URL").startswith("mysql+asyncmy://")

    monkeypatch.setenv("TEST_MYSQL_URL", "sqlite+aiosqlite:///target.db")
    with pytest.raises(MigrationError, match=r"must use mysql\+asyncmy"):
        _target_url_from_environment("TEST_MYSQL_URL")


def test_target_url_falls_back_to_local_dotenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TEST_MYSQL_URL", raising=False)
    monkeypatch.setattr(migration_module, "ROOT", tmp_path)
    (tmp_path / ".env").write_text(
        "TEST_MYSQL_URL=mysql+asyncmy://migration:secret@mysql.example:3306/database_alerts"
        "?charset=utf8mb4\n",
        encoding="utf-8",
    )

    assert _target_url_from_environment("TEST_MYSQL_URL").startswith("mysql+asyncmy://")


def test_mysql_version_parser_requires_a_three_part_version() -> None:
    assert _mysql_version("8.0.42-commercial") == (8, 0, 42)

    with pytest.raises(MigrationError, match="Cannot parse"):
        _mysql_version("8.0")


def test_canonical_rows_normalize_json_order_and_utc_datetimes() -> None:
    columns = ("id", "payload", "created_at")
    first = {
        "id": "row-1",
        "payload": {"beta": [2, 1], "alpha": {"enabled": True}},
        "created_at": datetime(2026, 8, 31, 0, 0, tzinfo=UTC),
    }
    second = {
        "id": "row-1",
        "payload": {"alpha": {"enabled": True}, "beta": [2, 1]},
        "created_at": datetime(2026, 8, 31, 8, 0, tzinfo=timezone(timedelta(hours=8))),
    }

    assert _canonical_row_bytes(first, columns) == _canonical_row_bytes(second, columns)


def test_canonical_rows_apply_mysql_datetime_zero_rounding() -> None:
    columns = ("created_at",)

    assert _canonical_row_bytes(
        {"created_at": datetime(2026, 8, 31, 0, 0, 0, 499_999)}, columns
    ) == _canonical_row_bytes({"created_at": datetime(2026, 8, 31, 0, 0, 0)}, columns)
    assert _canonical_row_bytes(
        {"created_at": datetime(2026, 8, 31, 23, 59, 59, 500_000)}, columns
    ) == _canonical_row_bytes({"created_at": datetime(2026, 9, 1, 0, 0, 0)}, columns)


def test_canonical_rows_normalize_mysql_json_float_rendering() -> None:
    columns = ("payload",)

    assert _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 25.900795000000002}}, columns
    ) == _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 25.900795}}, columns
    )
    assert _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 0.058345000000002756}}, columns
    ) == _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 0.058345000000002749}}, columns
    )
    assert _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 0.22456800000000499}}, columns
    ) == _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 0.22456800000000501}}, columns
    )
    assert _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 25.9007}}, columns
    ) != _canonical_row_bytes(
        {"payload": {"wall_time_seconds": 25.9008}}, columns
    )


@pytest.mark.asyncio
async def test_source_snapshot_lock_becomes_query_only_after_begin_immediate() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.connect() as connection:
            await _lock_source_snapshot(connection)

            query_only = (await connection.exec_driver_sql("PRAGMA query_only")).scalar_one()
            await connection.rollback()

        assert query_only == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_copy_table_resumes_by_primary_key_and_verifies_digest() -> None:
    source_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    target_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    metadata = MetaData()
    records = Table(
        "records",
        metadata,
        Column("id", String(36), primary_key=True),
        Column("payload", JSON, nullable=False),
        Column("description", Text, nullable=False),
    )
    try:
        async with source_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            await connection.execute(
                records.insert(),
                [
                    {
                        "id": "row-1",
                        "payload": {"alpha": 1, "beta": 2},
                        "description": "already copied",
                    },
                    {
                        "id": "row-2",
                        "payload": {"items": [1, 2, 3]},
                        "description": "new row",
                    },
                ],
            )
        async with target_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            await connection.execute(
                records.insert(),
                {
                    "id": "row-1",
                    "payload": {"beta": 2, "alpha": 1},
                    "description": "already copied",
                },
            )

        async with source_engine.connect() as source, target_engine.connect() as target:
            stats = await _copy_table(
                source,
                target,
                records,
                records,
                resume=True,
                batch_rows=1,
                batch_bytes=256,
                safe_packet_bytes=1024,
            )
            target_digest = await _digest_table(target, records)
            target_count = await target.scalar(select(func.count()).select_from(records))

        assert stats.inserted == 1
        assert stats.skipped == 1
        assert stats.digest.rows == 2
        assert target_count == 2
        assert target_digest == stats.digest
    finally:
        await source_engine.dispose()
        await target_engine.dispose()


@pytest.mark.asyncio
async def test_copy_table_populates_known_target_only_audit_column() -> None:
    source_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    target_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    source_metadata = MetaData()
    target_metadata = MetaData()
    source_alerts = Table(
        "alerts",
        source_metadata,
        Column("id", String(36), primary_key=True),
        Column("payload", JSON, nullable=False),
    )
    target_alerts = Table(
        "alerts",
        target_metadata,
        Column("id", String(36), primary_key=True),
        Column("payload", JSON, nullable=False),
        Column("legacy_runbooks_json", JSON, nullable=False),
    )
    try:
        async with source_engine.begin() as connection:
            await connection.run_sync(source_metadata.create_all)
            await connection.execute(
                source_alerts.insert(), {"id": "alert-1", "payload": {"status": "ok"}}
            )
        async with target_engine.begin() as connection:
            await connection.run_sync(target_metadata.create_all)

        async with source_engine.connect() as source, target_engine.connect() as target:
            stats = await _copy_table(
                source,
                target,
                source_alerts,
                target_alerts,
                resume=False,
                batch_rows=10,
                batch_bytes=1024,
                safe_packet_bytes=4096,
            )
            legacy_value = await target.scalar(select(target_alerts.c.legacy_runbooks_json))
            target_digest = await _digest_table(
                target,
                target_alerts,
                columns=("id", "payload"),
            )

        assert stats.inserted == 1
        assert legacy_value == []
        assert target_digest == stats.digest
    finally:
        await source_engine.dispose()
        await target_engine.dispose()


@pytest.mark.asyncio
async def test_copy_table_rejects_a_row_above_the_packet_budget_before_insert() -> None:
    source_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    target_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    metadata = MetaData()
    records = Table(
        "records",
        metadata,
        Column("id", String(36), primary_key=True),
        Column("description", Text, nullable=False),
    )
    try:
        async with source_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            await connection.execute(records.insert(), {"id": "row-1", "description": "x" * 1024})
        async with target_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)

        async with source_engine.connect() as source, target_engine.connect() as target:
            with pytest.raises(MigrationError, match="safe max_allowed_packet budget"):
                await _copy_table(
                    source,
                    target,
                    records,
                    records,
                    resume=False,
                    batch_rows=10,
                    batch_bytes=2048,
                    safe_packet_bytes=128,
                )
            target_count = await target.scalar(select(func.count()).select_from(records))

        assert target_count == 0
    finally:
        await source_engine.dispose()
        await target_engine.dispose()
