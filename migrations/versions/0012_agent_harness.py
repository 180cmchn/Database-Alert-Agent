"""Add durable Agent harness events, checkpoints, invocations and artifacts.

Revision ID: 0012
Revises: 0011
"""

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation_runs",
        sa.Column(
            "fencing_token",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.execute(sa.text("UPDATE investigation_runs SET fencing_token = attempt"))
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("investigation_runs") as batch_op:
            batch_op.alter_column(
                "fencing_token",
                existing_type=sa.Integer(),
                nullable=False,
                server_default=None,
            )
    else:
        op.alter_column(
            "investigation_runs",
            "fencing_token",
            existing_type=sa.Integer(),
            nullable=False,
            server_default=None,
        )
    op.add_column(
        "investigation_runs",
        sa.Column("manifest_json", sa.JSON(), nullable=True),
    )
    op.add_column(
        "investigation_runs",
        sa.Column("manifest_hash", sa.String(length=64), nullable=True),
    )
    # Runs created before the harness have neither a frozen manifest nor a
    # checkpoint, so they cannot be resumed without mixing execution contracts.
    op.execute(
        sa.text(
            "UPDATE investigation_runs "
            "SET status = 'FAILED', current_stage = 'FAILED', "
            "error = 'Legacy investigation interrupted by Agent harness migration', "
            "lease_expires_at = NULL "
            "WHERE status = 'RUNNING'"
        )
    )

    op.create_table(
        "agent_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("parent_run_id", sa.String(length=36), nullable=True),
        sa.Column("invocation_id", sa.String(length=36), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("causation_id", sa.String(length=36), nullable=True),
        sa.Column("correlation_id", sa.String(length=36), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_agent_event_sequence"),
    )
    op.create_index(
        "ix_agent_events_run_sequence",
        "agent_events",
        ["run_id", "sequence"],
        unique=False,
    )

    op.create_table(
        "agent_checkpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("namespace", sa.String(length=256), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("stop_reason", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "namespace",
            "version",
            name="uq_agent_checkpoint_namespace_version",
        ),
    )
    op.create_index(
        "ix_agent_checkpoints_run_namespace_version",
        "agent_checkpoints",
        ["run_id", "namespace", "version"],
        unique=False,
    )

    op.create_table(
        "agent_checkpoint_writes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=255), nullable=False),
        sa.Column("write_index", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=255), nullable=False),
        sa.Column("value_type", sa.String(length=255), nullable=False),
        sa.Column("value_base64", sa.Text(), nullable=False),
        sa.Column("task_path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "checkpoint_id",
            "task_id",
            "write_index",
            name="uq_agent_checkpoint_write_task_index",
        ),
    )
    op.create_index(
        "ix_agent_checkpoint_writes_checkpoint",
        "agent_checkpoint_writes",
        ["run_id", "checkpoint_id", "id"],
        unique=False,
    )

    op.create_table(
        "tool_invocations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("parent_run_id", sa.String(length=36), nullable=True),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=255), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("hypothesis_ids_json", sa.JSON(), nullable=False),
        sa.Column("model_arguments_json", sa.JSON(), nullable=False),
        sa.Column("effective_arguments_json", sa.JSON(), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("effective_hash", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error_json", sa.JSON(), nullable=True),
        sa.Column("artifact_ref_json", sa.JSON(), nullable=True),
        sa.Column("invocation_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_tool_invocations_run_status",
        "tool_invocations",
        ["run_id", "status"],
        unique=False,
    )

    op.create_table(
        "agent_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("invocation_id", sa.String(length=36), nullable=True),
        sa.Column("kind", sa.String(length=100), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("uri", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("content_encoding", sa.String(length=16), nullable=False),
        sa.Column("sanitized_content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_artifacts_run_id",
        "agent_artifacts",
        ["run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_agent_artifacts_run_id", table_name="agent_artifacts")
    op.drop_table("agent_artifacts")
    op.drop_index("ix_tool_invocations_run_status", table_name="tool_invocations")
    op.drop_table("tool_invocations")
    op.drop_index(
        "ix_agent_checkpoint_writes_checkpoint",
        table_name="agent_checkpoint_writes",
    )
    op.drop_table("agent_checkpoint_writes")
    op.drop_index(
        "ix_agent_checkpoints_run_namespace_version",
        table_name="agent_checkpoints",
    )
    op.drop_table("agent_checkpoints")
    op.drop_index("ix_agent_events_run_sequence", table_name="agent_events")
    op.drop_table("agent_events")
    op.drop_column("investigation_runs", "manifest_hash")
    op.drop_column("investigation_runs", "manifest_json")
    op.drop_column("investigation_runs", "fencing_token")
