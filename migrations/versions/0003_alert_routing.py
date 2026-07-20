"""Add durable alert routing incidents and escalation deliveries.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
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
    op.create_index("ix_alert_incidents_active_key", "alert_incidents", ["active_key"])
    op.create_index("ix_alert_incidents_dedup_key", "alert_incidents", ["dedup_key"])
    op.create_index("ix_alert_incidents_alert_id", "alert_incidents", ["alert_id"])
    op.create_index("ix_alert_incidents_state", "alert_incidents", ["state"])
    op.create_index(
        "ix_alert_incidents_next_action_at", "alert_incidents", ["next_action_at"]
    )

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


def downgrade() -> None:
    op.drop_index(
        "ix_escalation_deliveries_incident_id", table_name="escalation_deliveries"
    )
    op.drop_table("escalation_deliveries")
    op.drop_index("ix_alert_incidents_next_action_at", table_name="alert_incidents")
    op.drop_index("ix_alert_incidents_state", table_name="alert_incidents")
    op.drop_index("ix_alert_incidents_alert_id", table_name="alert_incidents")
    op.drop_index("ix_alert_incidents_dedup_key", table_name="alert_incidents")
    op.drop_index("ix_alert_incidents_active_key", table_name="alert_incidents")
    op.drop_table("alert_incidents")
