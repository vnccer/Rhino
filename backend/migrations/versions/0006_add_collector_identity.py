"""Add collector identity and audit records.

Revision ID: 0006_collector_identity
Revises: 0005_risk_assessment
Create Date: 2026-08-20
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0006_collector_identity"
down_revision: str | None = "0005_risk_assessment"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("host_id", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("os", sa.String(length=64), nullable=False),
        sa.Column("os_version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("host_id"),
    )
    op.create_index("ix_hosts_last_seen_at", "hosts", ["last_seen_at"])
    op.create_table(
        "collectors",
        sa.Column("collector_id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.host_id"]),
        sa.PrimaryKeyConstraint("collector_id"),
    )
    op.create_index("ix_collectors_host_id", "collectors", ["host_id"])
    op.create_index("ix_collectors_last_seen_at", "collectors", ["last_seen_at"])
    op.create_table(
        "collector_credentials",
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("collector_id", sa.Uuid(), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["collector_id"], ["collectors.collector_id"]),
        sa.PrimaryKeyConstraint("credential_id"),
    )
    op.create_index(
        "ix_collector_credentials_collector_id", "collector_credentials", ["collector_id"]
    )
    op.create_index(
        "ix_collector_credentials_fingerprint",
        "collector_credentials",
        ["fingerprint"],
        unique=True,
    )
    op.create_table(
        "enrollment_tokens",
        sa.Column("token_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("use_count", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("token_id"),
    )
    op.create_index(
        "ix_enrollment_tokens_fingerprint", "enrollment_tokens", ["fingerprint"], unique=True
    )
    op.create_table(
        "audit_logs",
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("audit_id"),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_enrollment_tokens_fingerprint", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")
    op.drop_index("ix_collector_credentials_fingerprint", table_name="collector_credentials")
    op.drop_index("ix_collector_credentials_collector_id", table_name="collector_credentials")
    op.drop_table("collector_credentials")
    op.drop_index("ix_collectors_last_seen_at", table_name="collectors")
    op.drop_index("ix_collectors_host_id", table_name="collectors")
    op.drop_table("collectors")
    op.drop_index("ix_hosts_last_seen_at", table_name="hosts")
    op.drop_table("hosts")
