"""Make the retired alert runbook audit payload optional for new rows.

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def _legacy_alert_column(connection: sa.Connection) -> dict[str, object] | None:
    return next(
        (
            dict(column)
            for column in sa.inspect(connection).get_columns("alerts")
            if column["name"] == "legacy_runbooks_json"
        ),
        None,
    )


def upgrade() -> None:
    connection = op.get_bind()
    if _legacy_alert_column(connection) is None:
        # Databases bootstrapped directly from current ORM metadata never had the
        # retired audit column. Only databases that traversed migration 0015 do.
        return

    with op.batch_alter_table("alerts") as batch_op:
        batch_op.alter_column(
            "legacy_runbooks_json",
            existing_type=sa.JSON(),
            existing_nullable=False,
            nullable=True,
        )


def downgrade() -> None:
    connection = op.get_bind()
    if _legacy_alert_column(connection) is None:
        return

    alerts = sa.table(
        "alerts",
        sa.column("legacy_runbooks_json", sa.JSON()),
    )
    connection.execute(
        alerts.update()
        .where(alerts.c.legacy_runbooks_json.is_(None))
        .values(legacy_runbooks_json=[])
    )
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.alter_column(
            "legacy_runbooks_json",
            existing_type=sa.JSON(),
            existing_nullable=True,
            nullable=False,
        )
