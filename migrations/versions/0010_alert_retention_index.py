"""Add an index supporting safe expired-alert retention cleanup.

Revision ID: 0010
Revises: 0009
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_alerts_status_created_at", "alerts", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_alerts_status_created_at", table_name="alerts")