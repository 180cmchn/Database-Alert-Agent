"""Remove local runbook persistence and unify historical knowledge results.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_REMOVED_RESULT_KEYS = {
    "external_knowledge_matches",
    "manual_matched",
    "manual_matches",
    "runbook_excerpts",
    "runbook_references",
    "runbooks",
}
_REMOVED_CONFIG_KEYS = {
    "knowledge_local_pdf",
    "local_pdf_enabled",
    "runbook_limit",
    "runbook_match_min_confidence",
    "runbook_match_min_score",
    "runbook_pdf_dir",
    "runbook_pdf_max_file_bytes",
    "runbook_pdf_max_text_chars",
}


def _canonical_json_hash(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _knowledge_match(value: Any, *, default_source: str | None = None) -> dict[str, Any] | None:
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
    sources = (
        (value.get("knowledge_matches"), None),
        (value.get("external_knowledge_matches"), "external_knowledge"),
        (value.get("external_knowledge"), "external_knowledge"),
        (value.get("knowledge"), None),
    )
    for raw_items, default_source in sources:
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
    recommendation = dict(value)
    knowledge = _knowledge_matches(recommendation)
    matches = {(item["source"], item["knowledge_id"]): item for item in knowledge}

    knowledge_bases: list[dict[str, Any]] = []
    ai_bases: list[dict[str, Any]] = []
    for raw_basis in recommendation.get("analysis_bases") or []:
        if not isinstance(raw_basis, dict):
            continue
        source = raw_basis.get("source")
        statement = str(raw_basis.get("statement") or "").strip()
        if not statement:
            continue
        if source in {"KNOWLEDGE", "EXTERNAL_KNOWLEDGE"}:
            reference = _knowledge_reference(raw_basis.get("source_ref"), matches)
            if reference is not None:
                knowledge_bases.append(
                    {"source": "KNOWLEDGE", "statement": statement, "source_ref": reference}
                )
        elif source == "AI":
            ai_bases.append({"source": "AI", "statement": statement, "source_ref": None})

    cited = {
        (basis["source_ref"]["source"], basis["source_ref"]["knowledge_id"])
        for basis in knowledge_bases
    }
    for item in knowledge:
        identity = (item["source"], item["knowledge_id"])
        if identity in cited:
            continue
        knowledge_bases.append(
            {
                "source": "KNOWLEDGE",
                "statement": f"命中历史知识《{item['title']}》，需结合本次实时证据核验。",
                "source_ref": {
                    "source": item["source"],
                    "knowledge_id": item["knowledge_id"],
                    "title": item["title"],
                    "source_uri": item["source_uri"],
                },
            }
        )

    steps: list[Any] = []
    for raw_step in recommendation.get("steps") or []:
        if not isinstance(raw_step, dict):
            steps.append(raw_step)
            continue
        step = dict(raw_step)
        step["source_ref"] = _knowledge_reference(step.get("source_ref"), matches)
        steps.append(step)

    for key in _REMOVED_RESULT_KEYS:
        recommendation.pop(key, None)
    recommendation["knowledge_matches"] = knowledge
    recommendation["analysis_bases"] = [*knowledge_bases, *ai_bases]
    recommendation["steps"] = steps
    return recommendation


def _clean_data(value: Any, *, configuration: bool = False) -> Any:
    if isinstance(value, str):
        return "KNOWLEDGE_MATCHING" if value == "RUNBOOK_MATCHING" else value
    if isinstance(value, list):
        cleaned_items = [
            cleaned
            for item in value
            if (cleaned := _clean_data(item, configuration=configuration)) is not None
        ]
        if configuration:
            return [item for item in cleaned_items if item != "local_pdf"]
        return cleaned_items
    if not isinstance(value, dict):
        return value

    source = str(value.get("source") or "")
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    if (
        value.get("runbook_id")
        or source in {"RUNBOOK", "local_pdf"}
        or metadata.get("source_type") == "local_pdf"
    ):
        return None

    converted_knowledge = _knowledge_matches(value)
    cleaned: dict[str, Any] = {}
    for key, item in value.items():
        lowered = key.casefold()
        if key in _REMOVED_RESULT_KEYS or "runbook" in lowered:
            continue
        if configuration and key in _REMOVED_CONFIG_KEYS:
            continue
        child_configuration = configuration or key in {
            "config_snapshot",
            "config_snapshot_json",
            "configuration",
        }
        if key == "recommendation" and isinstance(item, dict):
            cleaned[key] = _normalize_recommendation(item)
            continue
        child = _clean_data(item, configuration=child_configuration)
        if child is not None:
            cleaned[key] = child

    if converted_knowledge:
        cleaned["knowledge_matches"] = converted_knowledge
    if cleaned.get("source") == "EXTERNAL_KNOWLEDGE":
        cleaned["source"] = "KNOWLEDGE"
    if configuration and isinstance(cleaned.get("knowledge_sources"), list):
        cleaned["knowledge_sources"] = [
            item for item in cleaned["knowledge_sources"] if item != "local_pdf"
        ]
    return cleaned


def _clean_recommendation_table(
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


def _clean_run_manifests(
    connection: sa.Connection,
    runs: sa.TableClause,
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    rows = list(
        connection.execute(
            sa.select(runs.c.id, runs.c.manifest_json, runs.c.manifest_hash)
        ).mappings()
    )
    for row in rows:
        manifest = row["manifest_json"]
        if not isinstance(manifest, dict):
            continue
        cleaned = _clean_data(manifest, configuration=True)
        new_hash = _canonical_json_hash(cleaned)
        hashes[str(row["id"])] = new_hash
        connection.execute(
            runs.update()
            .where(runs.c.id == row["id"])
            .values(manifest_json=cleaned, manifest_hash=new_hash)
        )
    return hashes


def upgrade() -> None:
    connection = op.get_bind()
    alerts = sa.table(
        "alerts",
        sa.column("id", sa.String(length=36)),
        sa.column("recommendation_json", sa.JSON()),
        sa.column("runbooks_json", sa.JSON()),
    )
    runs = sa.table(
        "investigation_runs",
        sa.column("id", sa.String(length=36)),
        sa.column("current_stage", sa.String(length=40)),
        sa.column("config_snapshot_json", sa.JSON()),
        sa.column("manifest_json", sa.JSON()),
        sa.column("manifest_hash", sa.String(length=64)),
        sa.column("recommendation_json", sa.JSON()),
        sa.column("runbooks_json", sa.JSON()),
    )
    progress = sa.table(
        "investigation_progress",
        sa.column("id", sa.String(length=36)),
        sa.column("stage", sa.String(length=40)),
        sa.column("details_json", sa.JSON()),
    )
    checkpoints = sa.table(
        "agent_checkpoints",
        sa.column("id", sa.String(length=36)),
        sa.column("run_id", sa.String(length=36)),
        sa.column("namespace", sa.String(length=256)),
        sa.column("payload_json", sa.JSON()),
        sa.column("state_hash", sa.String(length=64)),
        sa.column("manifest_hash", sa.String(length=64)),
    )
    checkpoint_writes = sa.table(
        "agent_checkpoint_writes",
        sa.column("checkpoint_id", sa.String(length=36)),
    )
    events = sa.table(
        "agent_events",
        sa.column("id", sa.String(length=36)),
        sa.column("payload_json", sa.JSON()),
    )

    _clean_recommendation_table(connection, alerts)
    _clean_recommendation_table(connection, runs)

    run_rows = list(
        connection.execute(
            sa.select(runs.c.id, runs.c.config_snapshot_json)
        ).mappings()
    )
    for row in run_rows:
        snapshot = row["config_snapshot_json"]
        if not isinstance(snapshot, dict):
            continue
        connection.execute(
            runs.update()
            .where(runs.c.id == row["id"])
            .values(config_snapshot_json=_clean_data(snapshot, configuration=True))
        )

    progress_rows = list(
        connection.execute(sa.select(progress.c.id, progress.c.details_json)).mappings()
    )
    for row in progress_rows:
        details = row["details_json"]
        if not isinstance(details, dict):
            continue
        connection.execute(
            progress.update()
            .where(progress.c.id == row["id"])
            .values(details_json=_clean_data(details))
        )

    event_rows = list(
        connection.execute(sa.select(events.c.id, events.c.payload_json)).mappings()
    )
    for row in event_rows:
        payload = row["payload_json"]
        if not isinstance(payload, dict):
            continue
        connection.execute(
            events.update()
            .where(events.c.id == row["id"])
            .values(payload_json=_clean_data(payload))
        )

    manifest_hashes = _clean_run_manifests(connection, runs)

    # Main graph checkpoints serialize the former AgentState class inside a
    # JsonPlus payload. They are execution internals rather than analysis results,
    # and cannot be safely resumed after the state contract changes. Delete them
    # together with pending writes. Provider-specific MCP checkpoints are retained.
    agent_checkpoint_ids = list(
        connection.execute(
            sa.select(checkpoints.c.id).where(checkpoints.c.namespace.like("agent%"))
        ).scalars()
    )
    if agent_checkpoint_ids:
        connection.execute(
            checkpoint_writes.delete().where(
                checkpoint_writes.c.checkpoint_id.in_(agent_checkpoint_ids)
            )
        )
        connection.execute(
            checkpoints.delete().where(checkpoints.c.id.in_(agent_checkpoint_ids))
        )

    checkpoint_rows = list(
        connection.execute(
            sa.select(
                checkpoints.c.id,
                checkpoints.c.run_id,
                checkpoints.c.payload_json,
            )
        ).mappings()
    )
    for row in checkpoint_rows:
        payload = row["payload_json"]
        if not isinstance(payload, dict):
            continue
        cleaned = _clean_data(payload)
        new_manifest_hash = manifest_hashes.get(str(row["run_id"]))
        if new_manifest_hash:
            cleaned["manifest_hash"] = new_manifest_hash
        state = cleaned.get("state") if isinstance(cleaned.get("state"), dict) else {}
        connection.execute(
            checkpoints.update()
            .where(checkpoints.c.id == row["id"])
            .values(
                payload_json=cleaned,
                state_hash=_canonical_json_hash(state),
                manifest_hash=cleaned.get("manifest_hash"),
            )
        )

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

    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_column("runbooks_json")
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.drop_column("runbooks_json")


def downgrade() -> None:
    json_default: str | sa.TextClause = (
        sa.text("('[]')") if op.get_bind().dialect.name == "mysql" else "[]"
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
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.add_column(sa.Column("runbooks_json", sa.JSON(), nullable=True))