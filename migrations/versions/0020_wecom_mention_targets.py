"""Add WeCom mention engine-owner and FlashDuty-member identity tables.

Revision ID: 0020
Revises: 0019
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wecom_mention_engine_owners",
        sa.Column("engine", sa.String(length=64), nullable=False),
        sa.Column("display_label", sa.String(length=100), nullable=False),
        sa.Column("wecom_userid", sa.String(length=128), nullable=True),
        sa.Column("wecom_mobile", sa.String(length=32), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("engine"),
    )

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


def downgrade() -> None:
    op.drop_table("wecom_mention_flashduty_members")
    op.drop_table("wecom_mention_engine_owners")
