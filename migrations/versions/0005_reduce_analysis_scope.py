"""Remove alert routing and notification-delivery state.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


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
        alert_json.pop("signal_state", None)
        alert_json.pop("dedup_key", None)

        recommendation = row["recommendation_json"]
        if isinstance(recommendation, dict):
            recommendation = dict(recommendation)
            legacy_evidence = recommendation.pop("evidence", [])
            if not recommendation.get("analysis_bases"):
                bases: list[dict[str, object]] = []
                for excerpt in row["runbooks_json"] or []:
                    if not isinstance(excerpt, dict):
                        continue
                    runbook_id = excerpt.get("runbook_id")
                    section = excerpt.get("section", "main")
                    if runbook_id:
                        bases.append(
                            {
                                "source": "RUNBOOK",
                                "statement": (
                                    f"历史分析命中手册 {runbook_id}/{section}；"
                                    "请以当前内网页面内容为准。"
                                ),
                                "source_ref": {
                                    "runbook_id": runbook_id,
                                    "section": section,
                                },
                            }
                        )
                for item in legacy_evidence if isinstance(legacy_evidence, list) else []:
                    bases.append(
                        {
                            "source": "AI",
                            "statement": str(item),
                            "source_ref": None,
                        }
                    )
                recommendation["analysis_bases"] = bases

        connection.execute(
            alerts.update()
            .where(alerts.c.id == row["id"])
            .values(
                alert_json=alert_json,
                recommendation_json=recommendation,
            )
        )

    op.drop_table("escalation_deliveries")
    op.drop_table("alert_incidents")
    op.drop_table("notifications")


def downgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("external_delivery_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", "phase", name="uq_notification_phase"),
    )
    op.create_index("ix_notifications_alert_id", "notifications", ["alert_id"])

    op.create_table(
        "alert_incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("active_key", sa.String(length=96), nullable=True),
        sa.Column("dedup_key", sa.String(length=96), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=100), nullable=False),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("policy_json", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("next_action_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=255), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=255), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("active_key", name="uq_alert_incident_active_key"),
    )
    for name, column in (
        ("ix_alert_incidents_active_key", "active_key"),
        ("ix_alert_incidents_dedup_key", "dedup_key"),
        ("ix_alert_incidents_alert_id", "alert_id"),
        ("ix_alert_incidents_state", "state"),
        ("ix_alert_incidents_next_action_at", "next_action_at"),
    ):
        op.create_index(name, "alert_incidents", [column])

    op.create_table(
        "escalation_deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("action_index", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=100), nullable=True),
        sa.Column("recipient", sa.String(length=255), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("external_delivery_id", sa.String(length=255), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["alert_incidents.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "incident_id", "step_index", "action_index", name="uq_escalation_action"
        ),
    )
    op.create_index(
        "ix_escalation_deliveries_incident_id",
        "escalation_deliveries",
        ["incident_id"],
    )
