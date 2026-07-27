"""Add config_snapshot_json to investigation_runs for re-analysis feature.

Revision ID: 0008
Revises: 0007
Create Date: 2024-01-27
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add config_snapshot_json column to investigation_runs table
    op.add_column(
        "investigation_runs",
        sa.Column("config_snapshot_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("investigation_runs", "config_snapshot_json")
