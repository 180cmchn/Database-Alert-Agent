"""Add independently qualified evidence units.

Revision ID: 0016
Revises: 0015
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    json_default: str | sa.TextClause = (
        sa.text("('[]')") if connection.dialect.name == "mysql" else "[]"
    )
    op.add_column(
        "evidence_records",
        sa.Column("source_artifact_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column(
            "contract_version",
            sa.String(length=32),
            nullable=False,
            server_default="evidence-record/v1",
        ),
    )
    op.add_column(
        "evidence_records",
        sa.Column(
            "evidence_units_json",
            sa.JSON(),
            nullable=False,
            server_default=json_default,
        ),
    )


def downgrade() -> None:
    with op.batch_alter_table("evidence_records") as batch_op:
        batch_op.drop_column("evidence_units_json")
        batch_op.drop_column("source_artifact_id")
        batch_op.drop_column("contract_version")
