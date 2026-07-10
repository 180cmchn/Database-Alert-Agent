"""Create alert audit tables.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("alert_json", sa.JSON(), nullable=False),
        sa.Column("recommendation_json", sa.JSON(), nullable=True),
        sa.Column("runbooks_json", sa.JSON(), nullable=False),
        sa.Column("advisor_metadata_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", name="uq_alert_identity"),
    )
    op.create_index(op.f("ix_alerts_source"), "alerts", ["source"], unique=False)
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
    op.create_index(
        op.f("ix_notifications_alert_id"), "notifications", ["alert_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_notifications_alert_id"), table_name="notifications")
    op.drop_table("notifications")
    op.drop_index(op.f("ix_alerts_source"), table_name="alerts")
    op.drop_table("alerts")
