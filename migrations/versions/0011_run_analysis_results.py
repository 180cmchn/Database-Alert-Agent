"""Store analysis results on their investigation run.

Revision ID: 0011
Revises: 0010
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation_runs",
        sa.Column("recommendation_json", sa.JSON(), nullable=True),
    )
    op.add_column(
        "investigation_runs",
        sa.Column("runbooks_json", sa.JSON(), nullable=True),
    )
    op.add_column(
        "investigation_runs",
        sa.Column("advisor_metadata_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("investigation_runs", "advisor_metadata_json")
    op.drop_column("investigation_runs", "runbooks_json")
    op.drop_column("investigation_runs", "recommendation_json")
