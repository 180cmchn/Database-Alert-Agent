import asyncio
import json
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
    _recommendation_from_persisted,
)
from app.config import get_settings
from app.domain.models import AlertStatus, StoredAlert


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


def test_legacy_recommendation_steps_remain_readable_without_classification() -> None:
    recommendation, legacy_steps = _recommendation_from_persisted(
        {
            "summary": "Historical analysis",
            "analysis_bases": [{"source": "AI", "statement": "Historical basis"}],
            "steps": [{"order": 1, "action": "Historical action"}],
            "confidence": 0.5,
        }
    )

    assert recommendation is not None
    assert recommendation.temporary_solutions == []
    assert recommendation.long_term_optimizations == []
    assert [step.action for step in legacy_steps] == ["Historical action"]


@pytest.mark.asyncio
async def test_fresh_database_is_created_with_current_revision(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "fresh.db"))

    await repository.initialize()
    async with repository.engine.connect() as connection:
        revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
    await repository.ping()

    assert revision == DATABASE_SCHEMA_REVISION
    await repository.close()


def test_0015_to_0016_keeps_legacy_evidence_as_v1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "evidence-unit-migration.db"
    database_url = sqlite_url(database)
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parents[2] / "migrations"))
    now = "2026-08-24 00:00:00"

    try:
        command.upgrade(config, "0015")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO evidence_records "
                "(id, alert_id, run_id, tool_name, source_system, status, request_json, "
                "summary, data_json, started_at, collected_at, duration_ms, truncated) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-evidence",
                    "legacy-alert",
                    "legacy-run",
                    "legacy-tool",
                    "database_diagnostics",
                    "SUCCESS",
                    "{}",
                    "legacy evidence",
                    "{}",
                    now,
                    now,
                    1,
                    0,
                ),
            )
            connection.commit()

        command.upgrade(config, "0016")
        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT contract_version, source_artifact_id, evidence_units_json "
                "FROM evidence_records WHERE id = 'legacy-evidence'"
            ).fetchone()
            assert row == ("evidence-record/v1", None, "[]")

        command.downgrade(config, "0015")
        with sqlite3.connect(database) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info('evidence_records')")
            }
            assert "contract_version" not in columns
            assert "source_artifact_id" not in columns
            assert "evidence_units_json" not in columns
            assert connection.execute(
                "SELECT summary FROM evidence_records WHERE id = 'legacy-evidence'"
            ).fetchone() == ("legacy evidence",)
    finally:
        get_settings.cache_clear()


def test_fresh_0015_database_can_downgrade_and_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "fresh-round-trip.db"
    database_url = sqlite_url(database)
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    repository = SQLAlchemyAlertRepository(database_url)

    async def initialize() -> None:
        await repository.initialize()
        await repository.close()

    asyncio.run(initialize())
    config = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parents[2] / "migrations"))

    try:
        command.downgrade(config, "0014")
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0014",
            )
            for table in ("alerts", "investigation_runs"):
                columns = {row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")}
                assert "runbooks_json" in columns
                assert "legacy_runbooks_json" not in columns

        command.upgrade(config, "0015")
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0015",
            )
            for table in ("alerts", "investigation_runs"):
                columns = {row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")}
                assert "runbooks_json" not in columns
                assert "legacy_runbooks_json" in columns
    finally:
        get_settings.cache_clear()


def test_0014_to_0015_retires_local_pdf_without_erasing_audit_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "knowledge-contract-migration.db"
    monkeypatch.setenv("DATABASE_URL", sqlite_url(database))
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parents[2] / "migrations"))
    now = "2026-08-20 00:00:00"
    external_match = {
        "knowledge_id": "external-1",
        "title": "External connection guidance",
        "content": "Check current connection consumers.",
        "source_uri": "https://knowledge.example.test/external-1",
        "score": 0.91,
        "raw_score": 91,
        "metadata": {"team": "database"},
    }
    local_match = {
        "source": "local_pdf",
        "knowledge_id": "pdf-1",
        "title": "Legacy local PDF",
        "content": "Removed local content.",
        "source_uri": "file:///legacy.pdf",
        "score": 0.95,
        "raw_score": 0.95,
        "metadata": {"source_type": "local_pdf"},
    }
    recommendation = {
        "summary": "Historical analysis",
        "knowledge_match_summary": "Historical match summary",
        "analysis_bases": [
            {
                "source": "RUNBOOK",
                "statement": "Legacy local manual basis",
                "source_ref": {"runbook_id": "pdf-1", "section": "main"},
            },
            {
                "source": "EXTERNAL_KNOWLEDGE",
                "statement": "External knowledge basis",
                "source_ref": {"knowledge_id": "external-1"},
            },
            {"source": "AI", "statement": "AI basis"},
        ],
        "steps": [
            {
                "order": 1,
                "action": "Check external guidance",
                "source_ref": {"knowledge_id": "external-1"},
            },
            {
                "order": 2,
                "action": "Ignore legacy local guidance",
                "source_ref": {"runbook_id": "pdf-1", "section": "main"},
            },
        ],
        "external_knowledge_matches": [external_match],
        "knowledge_matches": [local_match],
        "manual_matches": [local_match],
        "runbook_excerpts": [local_match],
    }
    config_snapshot = {
        "knowledge_sources": ["local_pdf", "external_knowledge"],
        "runbook_limit": 7,
        "external_knowledge_enabled": True,
    }
    manifest = {
        "run_id": "run-1",
        "agent_name": "database-alert-agent",
        "configuration": config_snapshot,
    }

    try:
        command.upgrade(config, "0014")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO alerts "
                "(id, source, external_id, status, alert_json, recommendation_json, "
                "runbooks_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "alert-1",
                    "canonical",
                    "migration-1",
                    "INCONCLUSIVE",
                    json.dumps({"title": "Migration fixture"}),
                    json.dumps(recommendation),
                    json.dumps([local_match]),
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO investigation_runs "
                "(id, alert_id, attempt, status, current_stage, created_at, updated_at, "
                "config_snapshot_json, recommendation_json, runbooks_json, fencing_token, "
                "manifest_json, manifest_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "run-1",
                    "alert-1",
                    1,
                    "INCONCLUSIVE",
                    "RUNBOOK_MATCHING",
                    now,
                    now,
                    json.dumps(config_snapshot),
                    json.dumps(recommendation),
                    json.dumps([local_match]),
                    1,
                    json.dumps(manifest),
                    "legacy-manifest-hash",
                ),
            )
            connection.execute(
                "INSERT INTO investigation_progress "
                "(id, alert_id, run_id, sequence, stage, message, details_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "progress-1",
                    "alert-1",
                    "run-1",
                    1,
                    "RUNBOOK_MATCHING",
                    "Historical matching",
                    json.dumps(
                        {
                            "stage": "RUNBOOK_MATCHING",
                            "runbooks": [local_match],
                            "external_knowledge_matches": [external_match],
                        }
                    ),
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO agent_events "
                "(id, run_id, sequence, version, kind, payload_json, occurred_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "event-1",
                    "run-1",
                    1,
                    1,
                    "PROGRESS",
                    json.dumps(
                        {
                            "stage": "RUNBOOK_MATCHING",
                            "runbook_references": [local_match],
                            "external_knowledge_matches": [external_match],
                        }
                    ),
                    now,
                ),
            )
            for checkpoint_id, namespace in (
                ("agent-checkpoint", "agent"),
                ("mcp-checkpoint", "mcp:external"),
            ):
                connection.execute(
                    "INSERT INTO agent_checkpoints "
                    "(id, run_id, namespace, version, sequence, payload_json, state_hash, "
                    "manifest_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        checkpoint_id,
                        "run-1",
                        namespace,
                        1,
                        1,
                        json.dumps(
                            {
                                "state": {
                                    "stage": "RUNBOOK_MATCHING",
                                    "runbooks": [local_match],
                                    "external_knowledge_matches": [external_match],
                                },
                                "manifest_hash": "legacy-manifest-hash",
                            }
                        ),
                        "legacy-state-hash",
                        "legacy-manifest-hash",
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO agent_checkpoint_writes "
                    "(run_id, checkpoint_id, task_id, write_index, channel, value_type, "
                    "value_base64, task_path, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "run-1",
                        checkpoint_id,
                        "task-1",
                        0,
                        "state",
                        "json",
                        "e30=",
                        "task",
                        now,
                        now,
                    ),
                )
            connection.commit()

        command.upgrade(config, "0015")

        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0015",
            )
            for table in ("alerts", "investigation_runs"):
                columns = {row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")}
                assert "runbooks_json" not in columns
                assert "legacy_runbooks_json" in columns

            alert_recommendation = json.loads(
                connection.execute(
                    "SELECT recommendation_json FROM alerts WHERE id = 'alert-1'"
                ).fetchone()[0]
            )
            run_row = connection.execute(
                "SELECT current_stage, config_snapshot_json, manifest_json, manifest_hash, "
                "recommendation_json FROM investigation_runs WHERE id = 'run-1'"
            ).fetchone()
            assert run_row is not None
            run_recommendation = json.loads(run_row[4])
            for migrated in (alert_recommendation, run_recommendation):
                assert [item["knowledge_id"] for item in migrated["knowledge_matches"]] == [
                    "external-1"
                ]
                assert migrated["knowledge_matches"][0]["source"] == "external_knowledge"
                assert [item["source"] for item in migrated["analysis_bases"]] == [
                    "KNOWLEDGE",
                    "AI",
                ]
                assert migrated["analysis_bases"][0]["source_ref"] == {
                    "source": "external_knowledge",
                    "knowledge_id": "external-1",
                    "title": "External connection guidance",
                    "source_uri": "https://knowledge.example.test/external-1",
                }
                assert migrated["steps"][0]["source_ref"]["knowledge_id"] == "external-1"
                assert migrated["steps"][1]["source_ref"] is None
                assert (
                    not {
                        "external_knowledge_matches",
                        "manual_matches",
                        "runbook_excerpts",
                    }
                    & migrated.keys()
                )
                assert migrated["legacy_knowledge_contract_v1"] == recommendation

            assert run_row[0] == "KNOWLEDGE_MATCHING"
            migrated_snapshot = json.loads(run_row[1])
            assert migrated_snapshot == config_snapshot
            migrated_manifest = json.loads(run_row[2])
            assert migrated_manifest == manifest
            assert run_row[3] == "legacy-manifest-hash"
            assert json.loads(
                connection.execute(
                    "SELECT legacy_runbooks_json FROM alerts WHERE id = 'alert-1'"
                ).fetchone()[0]
            ) == [local_match]
            assert json.loads(
                connection.execute(
                    "SELECT legacy_runbooks_json FROM investigation_runs WHERE id = 'run-1'"
                ).fetchone()[0]
            ) == [local_match]

            progress_stage, progress_details_json = connection.execute(
                "SELECT stage, details_json FROM investigation_progress WHERE id = 'progress-1'"
            ).fetchone()
            assert progress_stage == "KNOWLEDGE_MATCHING"
            progress_details = json.loads(progress_details_json)
            assert progress_details == {
                "stage": "RUNBOOK_MATCHING",
                "runbooks": [local_match],
                "external_knowledge_matches": [external_match],
            }

            event_payload = json.loads(
                connection.execute(
                    "SELECT payload_json FROM agent_events WHERE id = 'event-1'"
                ).fetchone()[0]
            )
            assert event_payload == {
                "stage": "RUNBOOK_MATCHING",
                "runbook_references": [local_match],
                "external_knowledge_matches": [external_match],
            }

            agent_checkpoint = connection.execute(
                "SELECT namespace, payload_json, manifest_hash FROM agent_checkpoints "
                "WHERE id = 'agent-checkpoint'"
            ).fetchone()
            assert agent_checkpoint is not None
            assert agent_checkpoint[0] == "legacy:0015:agent"
            assert json.loads(agent_checkpoint[1]) == {
                "state": {
                    "stage": "RUNBOOK_MATCHING",
                    "runbooks": [local_match],
                    "external_knowledge_matches": [external_match],
                },
                "manifest_hash": "legacy-manifest-hash",
            }
            assert agent_checkpoint[2] == "legacy-manifest-hash"
            assert connection.execute(
                "SELECT COUNT(*) FROM agent_checkpoint_writes "
                "WHERE checkpoint_id = 'agent-checkpoint'"
            ).fetchone() == (1,)
            mcp_checkpoint = connection.execute(
                "SELECT payload_json, manifest_hash FROM agent_checkpoints "
                "WHERE id = 'mcp-checkpoint'"
            ).fetchone()
            assert mcp_checkpoint is not None
            mcp_payload = json.loads(mcp_checkpoint[0])
            assert mcp_payload["state"]["stage"] == "RUNBOOK_MATCHING"
            assert mcp_payload["state"]["runbooks"] == [local_match]
            assert mcp_checkpoint[1] == run_row[3] == "legacy-manifest-hash"
            assert mcp_payload["manifest_hash"] == "legacy-manifest-hash"
            assert connection.execute(
                "SELECT COUNT(*) FROM agent_checkpoint_writes "
                "WHERE checkpoint_id = 'mcp-checkpoint'"
            ).fetchone() == (1,)

        command.downgrade(config, "0014")

        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0014",
            )
            for table, expected_not_null in (
                ("alerts", True),
                ("investigation_runs", False),
            ):
                columns = {
                    row[1]: bool(row[3])
                    for row in connection.execute(f"PRAGMA table_info('{table}')")
                }
                assert "legacy_runbooks_json" not in columns
                assert columns["runbooks_json"] is expected_not_null

            restored_alert = connection.execute(
                "SELECT recommendation_json, runbooks_json FROM alerts WHERE id = 'alert-1'"
            ).fetchone()
            assert restored_alert is not None
            assert json.loads(restored_alert[0]) == recommendation
            assert json.loads(restored_alert[1]) == [local_match]

            restored_run = connection.execute(
                "SELECT current_stage, config_snapshot_json, manifest_json, manifest_hash, "
                "recommendation_json, runbooks_json FROM investigation_runs WHERE id = 'run-1'"
            ).fetchone()
            assert restored_run is not None
            assert restored_run[0] == "RUNBOOK_MATCHING"
            assert json.loads(restored_run[1]) == config_snapshot
            assert json.loads(restored_run[2]) == manifest
            assert restored_run[3] == "legacy-manifest-hash"
            assert json.loads(restored_run[4]) == recommendation
            assert json.loads(restored_run[5]) == [local_match]
            assert connection.execute(
                "SELECT stage FROM investigation_progress WHERE id = 'progress-1'"
            ).fetchone() == ("RUNBOOK_MATCHING",)
            assert connection.execute(
                "SELECT namespace FROM agent_checkpoints WHERE id = 'agent-checkpoint'"
            ).fetchone() == ("agent",)
            assert connection.execute(
                "SELECT namespace FROM agent_checkpoints WHERE id = 'mcp-checkpoint'"
            ).fetchone() == ("mcp:external",)

        command.upgrade(config, "0015")

        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "0015",
            )
            assert connection.execute(
                "SELECT current_stage FROM investigation_runs WHERE id = 'run-1'"
            ).fetchone() == ("KNOWLEDGE_MATCHING",)
            assert connection.execute(
                "SELECT stage FROM investigation_progress WHERE id = 'progress-1'"
            ).fetchone() == ("KNOWLEDGE_MATCHING",)
            assert connection.execute(
                "SELECT namespace FROM agent_checkpoints WHERE id = 'agent-checkpoint'"
            ).fetchone() == ("legacy:0015:agent",)
            migrated_again = json.loads(
                connection.execute(
                    "SELECT recommendation_json FROM alerts WHERE id = 'alert-1'"
                ).fetchone()[0]
            )
            assert migrated_again["legacy_knowledge_contract_v1"] == recommendation
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_unversioned_partial_database_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "drifted.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE alerts (id TEXT PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
        )

    repository = SQLAlchemyAlertRepository(sqlite_url(database))
    with pytest.raises(RuntimeError, match="Database schema is not current"):
        await repository.initialize()

    await repository.close()


@pytest.mark.asyncio
async def test_current_schema_rejects_blocking_unmapped_required_column(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "blocking-extra.db"))
    try:
        await repository.initialize()
        async with repository.engine.begin() as connection:
            await connection.execute(
                text("ALTER TABLE alerts ADD COLUMN unmapped_required TEXT NOT NULL")
            )

        with pytest.raises(
            RuntimeError,
            match=r"blocking_unmapped_columns=alerts\.unmapped_required",
        ):
            await repository.ping()
    finally:
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
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert tables == {"user_data"}


def test_0018_preserves_legacy_audit_and_allows_new_alerts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "nullable-legacy-runbooks.db"
    database_url = sqlite_url(database)
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "false")
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parents[2] / "migrations"))
    legacy_runbooks = [{"runbook_id": "legacy-1"}]
    now = "2026-08-31 00:00:00"

    try:
        command.upgrade(config, "0017")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO alerts "
                "(id, source, external_id, status, alert_json, legacy_runbooks_json, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-alert",
                    "canonical",
                    "legacy-before-0018",
                    "INCONCLUSIVE",
                    "{}",
                    json.dumps(legacy_runbooks),
                    now,
                    now,
                ),
            )
            connection.commit()

        command.upgrade(config, "head")
        alert = CanonicalAlertSourceAdapter().normalize(
            {
                "external_id": "new-after-0018",
                "severity": "INFO",
                "title": "Migration write contract",
                "reason": "test",
            }
        )

        async def persist_new_alert() -> tuple[StoredAlert, bool]:
            repository = SQLAlchemyAlertRepository(database_url)
            try:
                await repository.initialize()
                return await repository.create_or_get(alert)
            finally:
                await repository.close()

        stored, created = asyncio.run(persist_new_alert())

        with sqlite3.connect(database) as connection:
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            legacy_column = next(
                row
                for row in connection.execute("PRAGMA table_info('alerts')")
                if row[1] == "legacy_runbooks_json"
            )
            legacy_values = {
                external_id: json.loads(value) if value is not None else None
                for external_id, value in connection.execute(
                    "SELECT external_id, legacy_runbooks_json FROM alerts"
                )
            }

        assert revision == (DATABASE_SCHEMA_REVISION,)
        assert bool(legacy_column[3]) is False
        assert legacy_column[4] is None
        assert legacy_values == {
            "legacy-before-0018": legacy_runbooks,
            "new-after-0018": None,
        }
        assert created is True
        assert stored.status == AlertStatus.QUEUED

        command.downgrade(config, "0017")
        with sqlite3.connect(database) as connection:
            downgraded_revision = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchone()
            downgraded_column = next(
                row
                for row in connection.execute("PRAGMA table_info('alerts')")
                if row[1] == "legacy_runbooks_json"
            )
            downgraded_values = {
                external_id: json.loads(value)
                for external_id, value in connection.execute(
                    "SELECT external_id, legacy_runbooks_json FROM alerts"
                )
            }

        assert downgraded_revision == ("0017",)
        assert bool(downgraded_column[3]) is True
        assert downgraded_column[4] is None
        assert downgraded_values == {
            "legacy-before-0018": legacy_runbooks,
            "new-after-0018": [],
        }
    finally:
        get_settings.cache_clear()


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


@pytest.mark.asyncio
async def test_new_alert_can_be_atomically_filtered_and_cannot_auto_claim(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "filtered.db"))
    await repository.initialize()
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "atomic-filtered-1",
            "severity": "INFO",
            "title": "Atomic filtered state",
            "reason": "test",
        }
    )

    stored, created = await repository.create_or_get(
        alert,
        initial_status=AlertStatus.FILTERED,
    )

    assert created is True
    assert stored.status == AlertStatus.FILTERED
    assert await repository.create_run(str(stored.alert.id), "worker-1", 300) is None
    with pytest.raises(ValueError, match="initial alert status"):
        await repository.create_or_get(alert, initial_status=AlertStatus.COMPLETED)
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
    config.set_main_option("script_location", str(Path(__file__).parents[2] / "migrations"))
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
    config.set_main_option("script_location", str(Path(__file__).parents[2] / "migrations"))
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
                row[1]: row[4] for row in connection.execute("PRAGMA table_info('alert_feedback')")
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
                row[1]: row[4] for row in connection.execute("PRAGMA table_info('knowledge_cases')")
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
