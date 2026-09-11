"""Persist model failures, dispatch control, notification delivery, and poll health.

Revision ID: 0019
Revises: 0018
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.add_column(sa.Column("model_failure_json", sa.JSON(), nullable=True))

    op.create_table(
        "analysis_dispatch_control",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("reason_json", sa.JSON(), nullable=True),
        sa.Column("trigger_run_id", sa.String(length=36), nullable=True),
        sa.Column("paused_settings_revision", sa.String(length=64), nullable=True),
        sa.Column("last_validation_json", sa.JSON(), nullable=True),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resumed_by", sa.String(length=255), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["trigger_run_id"],
            ["investigation_runs.id"],
            name="fk_dispatch_trigger_run",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    dispatch = sa.table(
        "analysis_dispatch_control",
        sa.column("id", sa.String(length=32)),
        sa.column("state", sa.String(length=16)),
        sa.column("version", sa.Integer()),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        dispatch,
        [{"id": "global", "state": "ENABLED", "version": 1, "updated_at": datetime.now(UTC)}],
    )

    op.create_table(
        "analysis_notification_deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("event_json", sa.JSON(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("message_id", sa.String(length=255), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_owner", sa.String(length=255), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "kind", name="uq_notification_run_kind"),
    )
    op.create_index(
        "ix_notification_delivery_status_due",
        "analysis_notification_deliveries",
        ["status", "next_attempt_at", "created_at"],
        unique=False,
    )

    op.create_table(
        "flashduty_poll_state",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("start_time", sa.Integer(), nullable=True),
        sa.Column("end_time", sa.Integer(), nullable=True),
        sa.Column("fetched_count", sa.Integer(), nullable=False),
        sa.Column("created_count", sa.Integer(), nullable=False),
        sa.Column("deduplicated_count", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    poll_state = sa.table(
        "flashduty_poll_state",
        sa.column("id", sa.String(length=32)),
        sa.column("status", sa.String(length=16)),
        sa.column("fetched_count", sa.Integer()),
        sa.column("created_count", sa.Integer()),
        sa.column("deduplicated_count", sa.Integer()),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        poll_state,
        [
            {
                "id": "global",
                "status": "NEVER",
                "fetched_count": 0,
                "created_count": 0,
                "deduplicated_count": 0,
                "updated_at": datetime.now(UTC),
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("flashduty_poll_state")
    op.drop_index(
        "ix_notification_delivery_status_due",
        table_name="analysis_notification_deliveries",
    )
    op.drop_table("analysis_notification_deliveries")
    op.drop_table("analysis_dispatch_control")
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.drop_column("model_failure_json")
