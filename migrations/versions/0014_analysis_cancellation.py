"""Persist analysis cancellation requests and acknowledgement.

Revision ID: 0014
Revises: 0013
"""

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation_runs",
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "investigation_runs",
        sa.Column("cancel_requested_by", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "investigation_runs",
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("investigation_runs", "cancelled_at")
    op.drop_column("investigation_runs", "cancel_requested_by")
    op.drop_column("investigation_runs", "cancel_requested_at")
