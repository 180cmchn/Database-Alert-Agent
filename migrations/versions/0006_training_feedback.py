"""Add retrieval and evidence labels to feedback knowledge.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_feedback",
        sa.Column(
            "runbook_match_verdict",
            sa.String(length=32),
            nullable=False,
            server_default="UNKNOWN",
        ),
    )
    op.add_column("alert_feedback", sa.Column("correct_runbook_id", sa.String(length=128)))
    op.add_column(
        "alert_feedback", sa.Column("correct_runbook_section", sa.String(length=200))
    )
    op.add_column(
        "alert_feedback",
        sa.Column("missed_runbook_ids_json", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "alert_feedback",
        sa.Column("supporting_evidence_ids_json", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "alert_feedback",
        sa.Column("wrong_agent_claims_json", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "alert_feedback",
        sa.Column("accepted_step_orders_json", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column("knowledge_cases", sa.Column("correct_runbook_id", sa.String(length=128)))
    op.add_column(
        "knowledge_cases", sa.Column("correct_runbook_section", sa.String(length=200))
    )
    op.add_column(
        "knowledge_cases",
        sa.Column("supporting_evidence_ids_json", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("knowledge_cases", "supporting_evidence_ids_json")
    op.drop_column("knowledge_cases", "correct_runbook_section")
    op.drop_column("knowledge_cases", "correct_runbook_id")
    op.drop_column("alert_feedback", "accepted_step_orders_json")
    op.drop_column("alert_feedback", "wrong_agent_claims_json")
    op.drop_column("alert_feedback", "supporting_evidence_ids_json")
    op.drop_column("alert_feedback", "missed_runbook_ids_json")
    op.drop_column("alert_feedback", "correct_runbook_section")
    op.drop_column("alert_feedback", "correct_runbook_id")
    op.drop_column("alert_feedback", "runbook_match_verdict")
