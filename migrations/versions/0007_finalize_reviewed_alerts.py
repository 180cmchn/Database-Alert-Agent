"""Finalize alerts that already have a human review.

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE alerts
            SET status = 'COMPLETED',
                updated_at = CURRENT_TIMESTAMP
            WHERE status = 'REVIEW_REQUIRED'
              AND EXISTS (
                  SELECT 1
                  FROM alert_feedback
                  WHERE alert_feedback.alert_id = alerts.id
              )
            """
        )
    )


def downgrade() -> None:
    # A completed alert cannot be distinguished from one that was already
    # completed before feedback, so reverting this data transition is unsafe.
    pass
