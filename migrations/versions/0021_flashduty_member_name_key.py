"""Key WeCom mention FlashDuty-member mapping by member_name instead of person_id.

Revision ID: 0021
Revises: 0020
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The table has never carried production rows (person_id was never a usable
    # admin-facing key), so a clean drop/recreate is safe and avoids a data
    # migration that would otherwise need to invent member names for existing rows.
    op.drop_table("wecom_mention_flashduty_members")
    op.create_table(
        "wecom_mention_flashduty_members",
        sa.Column("flashduty_member_name", sa.String(length=255), nullable=False),
        sa.Column("display_label", sa.String(length=100), nullable=False),
        sa.Column("wecom_userid", sa.String(length=128), nullable=True),
        sa.Column("wecom_mobile", sa.String(length=32), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("flashduty_member_name"),
    )


def downgrade() -> None:
    op.drop_table("wecom_mention_flashduty_members")
    op.create_table(
        "wecom_mention_flashduty_members",
        sa.Column("flashduty_person_id", sa.BigInteger(), nullable=False),
        sa.Column("flashduty_member_name", sa.String(length=255), nullable=False),
        sa.Column("display_label", sa.String(length=100), nullable=False),
        sa.Column("wecom_userid", sa.String(length=128), nullable=True),
        sa.Column("wecom_mobile", sa.String(length=32), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("flashduty_person_id"),
    )
