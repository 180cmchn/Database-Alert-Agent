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


def test_remove_human_data_migration_round_trip_recreates_empty_tables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "remove-human-data.db"
    database_url = sqlite_url(database)
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    config.set_main_option(
        "script_location", str(Path(__file__).parents[2] / "migrations")
    )
    feedback_columns = [
        "id",
        "alert_id",
        "run_id",
        "idempotency_key",
        "verdict",
        "final_root_cause",
        "actual_resolution",
        "recovered",
        "reviewer",
        "created_at",
        "runbook_match_verdict",
        "correct_runbook_id",
        "correct_runbook_section",
        "missed_runbook_ids_json",
        "supporting_evidence_ids_json",
        "wrong_agent_claims_json",
        "accepted_step_orders_json",
    ]
    knowledge_case_columns = [
        "id",
        "source_alert_id",
        "source_run_id",
        "incident_fingerprint",
        "fingerprint_version",
        "environment",
        "service_name",
        "alert_type",
        "database_engine",
        "final_root_cause",
        "actual_resolution",
        "recommendation_json",
        "confirmed_by",
        "confirmed_at",
        "created_at",
        "correct_runbook_id",
        "correct_runbook_section",
        "supporting_evidence_ids_json",
    ]

    try:
        command.upgrade(config, "0012")
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO alerts "
                "(id, source, external_id, status, alert_json, runbooks_json, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "review-alert",
                    "canonical",
                    "review-required-before-0013",
                    "REVIEW_REQUIRED",
                    "{}",
                    "[]",
                    "2026-08-10 00:00:00",
                    "2026-08-10 00:00:00",
                ),
            )
            connection.execute(
                "INSERT INTO investigation_runs "
                "(id, alert_id, attempt, fencing_token, status, current_stage, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "review-run",
                    "review-alert",
                    1,
                    1,
                    "REVIEW_REQUIRED",
                    "REVIEW_REQUIRED",
                    "2026-08-10 00:00:00",
                    "2026-08-10 00:00:00",
                ),
            )
            connection.execute(
                "INSERT INTO investigation_progress "
                "(id, alert_id, run_id, sequence, stage, message, details_json, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "review-progress",
                    "review-alert",
                    "review-run",
                    1,
                    "REVIEW_REQUIRED",
                    "legacy terminal progress",
                    "{}",
                    "2026-08-10 00:00:00",
                ),
            )
            connection.execute(
                "INSERT INTO alert_feedback "
                "(id, alert_id, run_id, idempotency_key, verdict, "
                "runbook_match_verdict, missed_runbook_ids_json, "
                "supporting_evidence_ids_json, wrong_agent_claims_json, "
                "accepted_step_orders_json, reviewer, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "feedback-1",
                    "review-alert",
                    "review-run",
                    "feedback-key-1",
                    "CONFIRMED",
                    "UNKNOWN",
                    "[]",
                    "[]",
                    "[]",
                    "[]",
                    "operator",
                    "2026-08-10 00:00:00",
                ),
            )
            connection.execute(
                "INSERT INTO knowledge_cases "
                "(id, source_alert_id, source_run_id, incident_fingerprint, "
                "fingerprint_version, environment, service_name, alert_type, "
                "supporting_evidence_ids_json, final_root_cause, actual_resolution, "
                "confirmed_by, confirmed_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "knowledge-case-1",
                    "review-alert",
                    "review-run",
                    "fingerprint-1",
                    "v1",
                    "production",
                    "orders-api",
                    "slow-query",
                    "[]",
                    "historical confirmed cause",
                    "historical resolution",
                    "operator",
                    "2026-08-10 00:00:00",
                    "2026-08-10 00:00:00",
                ),
            )

        command.upgrade(config, "0013")
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0013",
            )
            assert connection.execute(
                "SELECT status FROM alerts WHERE id = 'review-alert'"
            ).fetchone() == ("INCONCLUSIVE",)
            assert connection.execute(
                "SELECT status, current_stage FROM investigation_runs WHERE id = 'review-run'"
            ).fetchone() == ("INCONCLUSIVE", "INCONCLUSIVE")
            assert connection.execute(
                "SELECT stage FROM investigation_progress WHERE id = 'review-progress'"
            ).fetchone() == ("INCONCLUSIVE",)
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            assert "alert_feedback" not in tables
            assert "knowledge_cases" not in tables

        command.downgrade(config, "0012")
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0012",
            )
            assert connection.execute(
                "SELECT status FROM alerts WHERE id = 'review-alert'"
            ).fetchone() == ("REVIEW_REQUIRED",)
            assert connection.execute(
                "SELECT status, current_stage FROM investigation_runs WHERE id = 'review-run'"
            ).fetchone() == ("REVIEW_REQUIRED", "REVIEW_REQUIRED")
            assert connection.execute(
                "SELECT stage FROM investigation_progress WHERE id = 'review-progress'"
            ).fetchone() == ("REVIEW_REQUIRED",)
            assert [
                row[1] for row in connection.execute("PRAGMA table_info('alert_feedback')")
            ] == feedback_columns
            feedback_defaults = {
                row[1]: row[4]
                for row in connection.execute("PRAGMA table_info('alert_feedback')")
            }
            assert feedback_defaults["runbook_match_verdict"] == "'UNKNOWN'"
            assert {
                feedback_defaults[column]
                for column in {
                    "missed_runbook_ids_json",
                    "supporting_evidence_ids_json",
                    "wrong_agent_claims_json",
                    "accepted_step_orders_json",
                }
            } == {"'[]'"}
            assert connection.execute("SELECT COUNT(*) FROM alert_feedback").fetchone() == (0,)
            assert {
                row[1] for row in connection.execute("PRAGMA index_list('alert_feedback')")
            } >= {"ix_alert_feedback_alert_id"}
            foreign_keys = list(connection.execute("PRAGMA foreign_key_list('alert_feedback')"))
            assert {(row[2], row[3], row[4], row[6]) for row in foreign_keys} == {
                ("alerts", "alert_id", "id", "CASCADE"),
                ("investigation_runs", "run_id", "id", "CASCADE"),
            }
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alert_feedback'"
            ).fetchone()[0]
            assert "CONSTRAINT uq_feedback_idempotency UNIQUE" in table_sql
            assert [
                row[1] for row in connection.execute("PRAGMA table_info('knowledge_cases')")
            ] == knowledge_case_columns
            knowledge_defaults = {
                row[1]: row[4]
                for row in connection.execute("PRAGMA table_info('knowledge_cases')")
            }
            assert knowledge_defaults["supporting_evidence_ids_json"] == "'[]'"
            assert connection.execute("SELECT COUNT(*) FROM knowledge_cases").fetchone() == (0,)
            assert {
                row[1] for row in connection.execute("PRAGMA index_list('knowledge_cases')")
            } >= {"ix_knowledge_cases_incident_fingerprint"}
            assert list(connection.execute("PRAGMA foreign_key_list('knowledge_cases')")) == []
            knowledge_table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'knowledge_cases'"
            ).fetchone()[0]
            assert "CONSTRAINT uq_case_source_run UNIQUE" in knowledge_table_sql

        command.upgrade(config, "0013")
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0013",
            )
            assert connection.execute(
                "SELECT status FROM alerts WHERE id = 'review-alert'"
            ).fetchone() == ("INCONCLUSIVE",)
            assert connection.execute(
                "SELECT status, current_stage FROM investigation_runs WHERE id = 'review-run'"
            ).fetchone() == ("INCONCLUSIVE", "INCONCLUSIVE")
            assert connection.execute(
                "SELECT stage FROM investigation_progress WHERE id = 'review-progress'"
            ).fetchone() == ("INCONCLUSIVE",)
            assert connection.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type = 'table' AND name = 'alert_feedback'"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type = 'table' AND name = 'knowledge_cases'"
            ).fetchone() == (0,)
    finally:
        get_settings.cache_clear()
