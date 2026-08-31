"""Use MySQL LONGTEXT for unbounded persisted Agent payloads.

Revision ID: 0017
Revises: 0016
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_MYSQL_TEXT_MAX_BYTES = 65_535
_LARGE_TEXT_COLUMNS = (
    ("agent_checkpoint_writes", "value_base64"),
    ("agent_artifacts", "sanitized_content"),
)


def upgrade() -> None:
    if op.get_bind().dialect.name != "mysql":
        return

    for table_name, column_name in _LARGE_TEXT_COLUMNS:
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.Text(),
            type_=mysql.LONGTEXT(),
            existing_nullable=False,
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "mysql":
        return

    for table_name, column_name in _LARGE_TEXT_COLUMNS:
        largest_value = connection.scalar(
            sa.text(f"SELECT MAX(OCTET_LENGTH(`{column_name}`)) FROM `{table_name}`")
        )
        if largest_value is not None and int(largest_value) > _MYSQL_TEXT_MAX_BYTES:
            raise RuntimeError(
                f"Cannot downgrade {table_name}.{column_name} to TEXT: "
                f"largest value is {largest_value} bytes"
            )

    for table_name, column_name in reversed(_LARGE_TEXT_COLUMNS):
        op.alter_column(
            table_name,
            column_name,
            existing_type=mysql.LONGTEXT(),
            type_=sa.Text(),
            existing_nullable=False,
        )
