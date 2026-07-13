"""Add asynchronous investigation, evidence, validation, feedback and knowledge tables.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_stage", sa.String(length=40), nullable=False),
        sa.Column("strategy_id", sa.String(length=255), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("lease_owner", sa.String(length=255), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", "attempt", name="uq_run_attempt"),
    )
    op.create_index(
        op.f("ix_investigation_runs_alert_id"),
        "investigation_runs",
        ["alert_id"],
        unique=False,
    )
    op.create_table(
        "investigation_progress",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("stage", sa.String(length=40), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_progress_sequence"),
    )
    op.create_index(
        op.f("ix_investigation_progress_alert_id"),
        "investigation_progress",
        ["alert_id"],
        unique=False,
    )
    op.create_table(
        "evidence_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column("source_system", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("request_json", sa.JSON(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("data_json", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_evidence_records_alert_id"),
        "evidence_records",
        ["alert_id"],
        unique=False,
    )
    op.create_table(
        "validation_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("passed", sa.Integer(), nullable=False),
        sa.Column("issues_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_validation_results_alert_id"),
        "validation_results",
        ["alert_id"],
        unique=False,
    )
    op.create_table(
        "alert_feedback",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("final_root_cause", sa.Text(), nullable=True),
        sa.Column("actual_resolution", sa.Text(), nullable=True),
        sa.Column("recovered", sa.Integer(), nullable=True),
        sa.Column("reviewer", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "alert_id", "idempotency_key", name="uq_feedback_idempotency"
        ),
    )
    op.create_index(
        op.f("ix_alert_feedback_alert_id"),
        "alert_feedback",
        ["alert_id"],
        unique=False,
    )
    op.create_table(
        "knowledge_cases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_alert_id", sa.String(length=36), nullable=False),
        sa.Column("source_run_id", sa.String(length=36), nullable=False),
        sa.Column("incident_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("fingerprint_version", sa.String(length=20), nullable=False),
        sa.Column("environment", sa.String(length=100), nullable=False),
        sa.Column("service_name", sa.String(length=255), nullable=False),
        sa.Column("alert_type", sa.String(length=255), nullable=False),
        sa.Column("database_engine", sa.String(length=100), nullable=True),
        sa.Column("final_root_cause", sa.Text(), nullable=False),
        sa.Column("actual_resolution", sa.Text(), nullable=False),
        sa.Column("recommendation_json", sa.JSON(), nullable=True),
        sa.Column("confirmed_by", sa.String(length=255), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_run_id", name="uq_case_source_run"),
    )
    op.create_index(
        op.f("ix_knowledge_cases_incident_fingerprint"),
        "knowledge_cases",
        ["incident_fingerprint"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_knowledge_cases_incident_fingerprint"),
        table_name="knowledge_cases",
    )
    op.drop_table("knowledge_cases")
    op.drop_index(op.f("ix_alert_feedback_alert_id"), table_name="alert_feedback")
    op.drop_table("alert_feedback")
    op.drop_index(
        op.f("ix_validation_results_alert_id"), table_name="validation_results"
    )
    op.drop_table("validation_results")
    op.drop_index(op.f("ix_evidence_records_alert_id"), table_name="evidence_records")
    op.drop_table("evidence_records")
    op.drop_index(
        op.f("ix_investigation_progress_alert_id"),
        table_name="investigation_progress",
    )
    op.drop_table("investigation_progress")
    op.drop_index(
        op.f("ix_investigation_runs_alert_id"), table_name="investigation_runs"
    )
    op.drop_table("investigation_runs")
