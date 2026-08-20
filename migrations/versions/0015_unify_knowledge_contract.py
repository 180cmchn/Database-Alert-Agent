"""Retire active local-PDF persistence without deleting historical audit data.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_LEGACY_ARCHIVE_KEY = "legacy_knowledge_contract_v1"
_LEGACY_CHECKPOINT_PREFIX = "legacy:0015:"
_REMOVED_RESULT_KEYS = {
    "external_knowledge_matches",
    "manual_matched",
    "manual_matches",
    "runbook_excerpts",
    "runbook_references",
    "runbooks",
}


def _knowledge_match(
    value: Any,
    *,
    default_source: str | None = None,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    source = str(value.get("source") or default_source or "").strip()
    if source == "local_pdf" or metadata.get("source_type") == "local_pdf":
        return None
    knowledge_id = str(value.get("knowledge_id") or "").strip()
    title = str(value.get("title") or "").strip()
    content = str(value.get("content") or "").strip()
    source_uri = str(value.get("source_uri") or "").strip()
    if not all((source, knowledge_id, title, content, source_uri)):
        return None
    score = value.get("score", 0.0)
    raw_score = value.get("raw_score", score)
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 <= float(score) <= 1
        or isinstance(raw_score, bool)
        or not isinstance(raw_score, (int, float))
        or float(raw_score) < 0
    ):
        return None
    return {
        "source": source,
        "knowledge_id": knowledge_id,
        "title": title,
        "content": content,
        "source_uri": source_uri,
        "score": float(score),
        "raw_score": float(raw_score),
        "metadata": metadata,
    }


def _knowledge_matches(value: dict[str, Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    candidates = (
        (value.get("knowledge_matches"), None),
        (value.get("external_knowledge_matches"), "external_knowledge"),
        (value.get("external_knowledge"), "external_knowledge"),
        (value.get("knowledge"), None),
    )
    for raw_items, default_source in candidates:
        if not isinstance(raw_items, list):
            continue
        for raw_item in raw_items:
            match = _knowledge_match(raw_item, default_source=default_source)
            if match is None:
                continue
            identity = (match["source"], match["knowledge_id"])
            if identity in seen:
                continue
            seen.add(identity)
            matches.append(match)
    return matches


def _knowledge_reference(
    value: Any,
    matches: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("runbook_id"):
        return None
    knowledge_id = str(value.get("knowledge_id") or "").strip()
    source = str(value.get("source") or "external_knowledge").strip()
    match = matches.get((source, knowledge_id))
    if match is None and knowledge_id:
        candidates = [item for key, item in matches.items() if key[1] == knowledge_id]
        match = candidates[0] if len(candidates) == 1 else None
    if match is None:
        return None
    return {
        "source": match["source"],
        "knowledge_id": match["knowledge_id"],
        "title": match["title"],
        "source_uri": match["source_uri"],
    }


def _normalize_recommendation(value: dict[str, Any]) -> dict[str, Any]:
    if isinstance(value.get(_LEGACY_ARCHIVE_KEY), dict):
        return value

    recommendation = dict(value)
    knowledge = _knowledge_matches(value)
    matches = {(item["source"], item["knowledge_id"]): item for item in knowledge}
    analysis_bases: list[dict[str, Any]] = []
    for raw_basis in value.get("analysis_bases") or []:
        if not isinstance(raw_basis, dict):
            continue
        source = raw_basis.get("source")
        statement = str(raw_basis.get("statement") or "").strip()
        if not statement:
            continue
        if source == "AI":
            analysis_bases.append(
                {"source": "AI", "statement": statement, "source_ref": None}
            )
        elif source in {"KNOWLEDGE", "EXTERNAL_KNOWLEDGE"}:
            analysis_bases.append(
                {
                    "source": "KNOWLEDGE",
                    "statement": statement,
                    "source_ref": _knowledge_reference(
                        raw_basis.get("source_ref"),
                        matches,
                    ),
                }
            )

    steps: list[Any] = []
    for raw_step in value.get("steps") or []:
        if not isinstance(raw_step, dict):
            steps.append(raw_step)
            continue
        step = dict(raw_step)
        step["source_ref"] = _knowledge_reference(step.get("source_ref"), matches)
        steps.append(step)

    for key in _REMOVED_RESULT_KEYS:
        recommendation.pop(key, None)
    recommendation["knowledge_matches"] = knowledge
    recommendation["analysis_bases"] = analysis_bases
    recommendation["steps"] = steps
    recommendation[_LEGACY_ARCHIVE_KEY] = dict(value)
    return recommendation


def _normalize_recommendation_table(
    connection: sa.Connection,
    table: sa.TableClause,
) -> None:
    rows = list(
        connection.execute(sa.select(table.c.id, table.c.recommendation_json)).mappings()
    )
    for row in rows:
        recommendation = row["recommendation_json"]
        if not isinstance(recommendation, dict):
            continue
        connection.execute(
            table.update()
            .where(table.c.id == row["id"])
            .values(recommendation_json=_normalize_recommendation(recommendation))
        )


def upgrade() -> None:
    connection = op.get_bind()
    alerts = sa.table(
        "alerts",
        sa.column("id", sa.String(length=36)),
        sa.column("recommendation_json", sa.JSON()),
    )
    runs = sa.table(
        "investigation_runs",
        sa.column("id", sa.String(length=36)),
        sa.column("current_stage", sa.String(length=40)),
        sa.column("recommendation_json", sa.JSON()),
    )
    progress = sa.table(
        "investigation_progress",
        sa.column("stage", sa.String(length=40)),
    )
    checkpoints = sa.table(
        "agent_checkpoints",
        sa.column("id", sa.String(length=36)),
        sa.column("namespace", sa.String(length=256)),
    )

    _normalize_recommendation_table(connection, alerts)
    _normalize_recommendation_table(connection, runs)

    connection.execute(
        runs.update()
        .where(runs.c.current_stage == "RUNBOOK_MATCHING")
        .values(current_stage="KNOWLEDGE_MATCHING")
    )
    connection.execute(
        progress.update()
        .where(progress.c.stage == "RUNBOOK_MATCHING")
        .values(stage="KNOWLEDGE_MATCHING")
    )

    legacy_checkpoints = list(
        connection.execute(
            sa.select(checkpoints.c.id, checkpoints.c.namespace).where(
                checkpoints.c.namespace.like("agent%")
            )
        ).mappings()
    )
    for checkpoint in legacy_checkpoints:
        archived_namespace = f"{_LEGACY_CHECKPOINT_PREFIX}{checkpoint['namespace']}"
        if len(archived_namespace) > 256:
            raise ValueError("Legacy Agent checkpoint namespace exceeds storage limit")
        connection.execute(
            checkpoints.update()
            .where(checkpoints.c.id == checkpoint["id"])
            .values(namespace=archived_namespace)
        )

    # These columns are retained verbatim for historical audit, but renamed so
    # current application code cannot treat them as an active local-PDF provider.
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.alter_column(
            "runbooks_json",
            new_column_name="legacy_runbooks_json",
            existing_type=sa.JSON(),
            existing_nullable=False,
        )
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.alter_column(
            "runbooks_json",
            new_column_name="legacy_runbooks_json",
            existing_type=sa.JSON(),
            existing_nullable=True,
        )


def _restore_recommendation_table(
    connection: sa.Connection,
    table: sa.TableClause,
) -> None:
    rows = list(
        connection.execute(sa.select(table.c.id, table.c.recommendation_json)).mappings()
    )
    for row in rows:
        recommendation = row["recommendation_json"]
        if not isinstance(recommendation, dict):
            continue
        archived = recommendation.get(_LEGACY_ARCHIVE_KEY)
        if not isinstance(archived, dict):
            continue
        connection.execute(
            table.update()
            .where(table.c.id == row["id"])
            .values(recommendation_json=archived)
        )


def downgrade() -> None:
    connection = op.get_bind()
    alert_columns = {
        str(column["name"])
        for column in sa.inspect(connection).get_columns("alerts")
    }
    if "legacy_runbooks_json" in alert_columns:
        with op.batch_alter_table("alerts") as batch_op:
            batch_op.alter_column(
                "legacy_runbooks_json",
                new_column_name="runbooks_json",
                existing_type=sa.JSON(),
                existing_nullable=False,
            )
    elif "runbooks_json" not in alert_columns:
        json_default: str | sa.TextClause = (
            sa.text("('[]')") if connection.dialect.name == "mysql" else "[]"
        )
        with op.batch_alter_table("alerts") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "runbooks_json",
                    sa.JSON(),
                    nullable=False,
                    server_default=json_default,
                )
            )

    run_columns = {
        str(column["name"])
        for column in sa.inspect(connection).get_columns("investigation_runs")
    }
    if "legacy_runbooks_json" in run_columns:
        with op.batch_alter_table("investigation_runs") as batch_op:
            batch_op.alter_column(
                "legacy_runbooks_json",
                new_column_name="runbooks_json",
                existing_type=sa.JSON(),
                existing_nullable=True,
            )
    elif "runbooks_json" not in run_columns:
        with op.batch_alter_table("investigation_runs") as batch_op:
            batch_op.add_column(sa.Column("runbooks_json", sa.JSON(), nullable=True))

    alerts = sa.table(
        "alerts",
        sa.column("id", sa.String(length=36)),
        sa.column("recommendation_json", sa.JSON()),
    )
    runs = sa.table(
        "investigation_runs",
        sa.column("id", sa.String(length=36)),
        sa.column("current_stage", sa.String(length=40)),
        sa.column("recommendation_json", sa.JSON()),
    )
    progress = sa.table(
        "investigation_progress",
        sa.column("stage", sa.String(length=40)),
    )
    checkpoints = sa.table(
        "agent_checkpoints",
        sa.column("id", sa.String(length=36)),
        sa.column("namespace", sa.String(length=256)),
    )

    _restore_recommendation_table(connection, alerts)
    _restore_recommendation_table(connection, runs)
    connection.execute(
        runs.update()
        .where(runs.c.current_stage == "KNOWLEDGE_MATCHING")
        .values(current_stage="RUNBOOK_MATCHING")
    )
    connection.execute(
        progress.update()
        .where(progress.c.stage == "KNOWLEDGE_MATCHING")
        .values(stage="RUNBOOK_MATCHING")
    )
    legacy_checkpoints = list(
        connection.execute(
            sa.select(checkpoints.c.id, checkpoints.c.namespace).where(
                checkpoints.c.namespace.like(f"{_LEGACY_CHECKPOINT_PREFIX}%")
            )
        ).mappings()
    )
    for checkpoint in legacy_checkpoints:
        connection.execute(
            checkpoints.update()
            .where(checkpoints.c.id == checkpoint["id"])
            .values(
                namespace=checkpoint["namespace"][len(_LEGACY_CHECKPOINT_PREFIX) :]
            )
        )
