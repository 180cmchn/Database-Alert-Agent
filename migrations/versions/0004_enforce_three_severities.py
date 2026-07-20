"""Normalize persisted alert severities to the three-level model.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_VALID_SEVERITIES = {"CRITICAL", "WARNING", "INFO"}


def _normalize_severity(value: object) -> str:
    normalized = str(value or "").upper()
    return normalized if normalized in _VALID_SEVERITIES else "WARNING"


def _normalize_root_cause_confidence(value: object) -> tuple[dict | None, bool]:
    if not isinstance(value, dict):
        return None, False
    recommendation = dict(value)
    root_causes = recommendation.get("root_causes")
    if not isinstance(root_causes, list):
        return recommendation, False
    changed = False
    for root_cause in root_causes:
        if not isinstance(root_cause, dict):
            continue
        confidence = root_cause.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            root_cause["confidence"] = 0.5
            changed = True
    return recommendation, changed


def upgrade() -> None:
    alerts = sa.table(
        "alerts",
        sa.column("id", sa.String(length=36)),
        sa.column("alert_json", sa.JSON()),
        sa.column("runbooks_json", sa.JSON()),
        sa.column("recommendation_json", sa.JSON()),
    )
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(
            alerts.c.id,
            alerts.c.alert_json,
            alerts.c.runbooks_json,
            alerts.c.recommendation_json,
        )
    ).mappings()
    for row in rows:
        alert_json = dict(row["alert_json"] or {})
        runbooks_json = list(row["runbooks_json"] or [])
        recommendation_json, recommendation_changed = _normalize_root_cause_confidence(
            row["recommendation_json"]
        )
        changed = False

        severity = _normalize_severity(alert_json.get("severity"))
        if alert_json.get("severity") != severity:
            alert_json["severity"] = severity
            alert_json["raw_severity"] = severity
            changed = True

        for item in runbooks_json:
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata")
            if not isinstance(metadata, dict) or not isinstance(
                metadata.get("severities"), list
            ):
                continue
            normalized = list(
                dict.fromkeys(
                    _normalize_severity(value) for value in metadata["severities"]
                )
            )
            if metadata["severities"] != normalized:
                metadata["severities"] = normalized
                changed = True

        changed = changed or recommendation_changed

        if changed:
            connection.execute(
                alerts.update()
                .where(alerts.c.id == row["id"])
                .values(
                    alert_json=alert_json,
                    runbooks_json=runbooks_json,
                    recommendation_json=recommendation_json,
                )
            )

    knowledge_cases = sa.table(
        "knowledge_cases",
        sa.column("id", sa.String(length=36)),
        sa.column("recommendation_json", sa.JSON()),
    )
    case_rows = connection.execute(
        sa.select(knowledge_cases.c.id, knowledge_cases.c.recommendation_json)
    ).mappings()
    for row in case_rows:
        recommendation, changed = _normalize_root_cause_confidence(
            row["recommendation_json"]
        )
        if changed:
            connection.execute(
                knowledge_cases.update()
                .where(knowledge_cases.c.id == row["id"])
                .values(recommendation_json=recommendation)
            )


def downgrade() -> None:
    # The previous labels cannot be reconstructed after normalization.
    pass
