"""Replace the review-required state and remove human-derived data.

Revision ID: 0013
Revises: 0012
"""

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def _json_array_server_default() -> str | sa.TextClause:
    if op.get_bind().dialect.name == "mysql":
        return sa.text("('[]')")
    return "[]"


def _replace_terminal_state(previous: str, replacement: str) -> None:
    op.execute(
        sa.text("UPDATE alerts SET status = :replacement WHERE status = :previous").bindparams(
            previous=previous,
            replacement=replacement,
        )
    )
    op.execute(
        sa.text(
            "UPDATE investigation_runs SET status = :replacement WHERE status = :previous"
        ).bindparams(previous=previous, replacement=replacement)
    )
    op.execute(
        sa.text(
            "UPDATE investigation_runs SET current_stage = :replacement "
            "WHERE current_stage = :previous"
        ).bindparams(previous=previous, replacement=replacement)
    )
    op.execute(
        sa.text(
            "UPDATE investigation_progress SET stage = :replacement WHERE stage = :previous"
        ).bindparams(previous=previous, replacement=replacement)
    )


def upgrade() -> None:
    _replace_terminal_state("REVIEW_REQUIRED", "INCONCLUSIVE")
    op.drop_table("alert_feedback")
    op.drop_table("knowledge_cases")


def downgrade() -> None:
    json_array_default = _json_array_server_default()
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
        sa.Column(
            "runbook_match_verdict",
            sa.String(length=32),
            nullable=False,
            server_default="UNKNOWN",
        ),
        sa.Column("correct_runbook_id", sa.String(length=128), nullable=True),
        sa.Column("correct_runbook_section", sa.String(length=200), nullable=True),
        sa.Column(
            "missed_runbook_ids_json",
            sa.JSON(),
            nullable=False,
            server_default=json_array_default,
        ),
        sa.Column(
            "supporting_evidence_ids_json",
            sa.JSON(),
            nullable=False,
            server_default=json_array_default,
        ),
        sa.Column(
            "wrong_agent_claims_json",
            sa.JSON(),
            nullable=False,
            server_default=json_array_default,
        ),
        sa.Column(
            "accepted_step_orders_json",
            sa.JSON(),
            nullable=False,
            server_default=json_array_default,
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", "idempotency_key", name="uq_feedback_idempotency"),
    )
    op.create_index(
        "ix_alert_feedback_alert_id",
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
        sa.Column("correct_runbook_id", sa.String(length=128), nullable=True),
        sa.Column("correct_runbook_section", sa.String(length=200), nullable=True),
        sa.Column(
            "supporting_evidence_ids_json",
            sa.JSON(),
            nullable=False,
            server_default=json_array_default,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_run_id", name="uq_case_source_run"),
    )
    op.create_index(
        "ix_knowledge_cases_incident_fingerprint",
        "knowledge_cases",
        ["incident_fingerprint"],
        unique=False,
    )

    # Feedback and knowledge-case rows were deliberately deleted during upgrade
    # and cannot be reconstructed. New INCONCLUSIVE records are also
    # indistinguishable from records converted from REVIEW_REQUIRED, so all are
    # mapped to the legacy terminal state for revision 0012 applications.
    _replace_terminal_state("INCONCLUSIVE", "REVIEW_REQUIRED")
