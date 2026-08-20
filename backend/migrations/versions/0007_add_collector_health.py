"""Add Linux collector health fields.

Revision ID: 0007_collector_health
Revises: 0006_collector_identity
Create Date: 2026-08-20
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0007_collector_health"
down_revision: str | None = "0006_collector_identity"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("collectors", sa.Column("started_at", sa.DateTime(timezone=True)))
    op.add_column("collectors", sa.Column("last_collected_at", sa.DateTime(timezone=True)))
    op.add_column("collectors", sa.Column("last_uploaded_at", sa.DateTime(timezone=True)))
    op.add_column(
        "collectors", sa.Column("queue_depth", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("collectors", sa.Column("last_error", sa.String(length=500)))
    op.add_column(
        "collectors", sa.Column("redaction_count", sa.Integer(), nullable=False, server_default="0")
    )
    op.alter_column("collectors", "queue_depth", server_default=None)
    op.alter_column("collectors", "redaction_count", server_default=None)


def downgrade() -> None:
    op.drop_column("collectors", "redaction_count")
    op.drop_column("collectors", "last_error")
    op.drop_column("collectors", "queue_depth")
    op.drop_column("collectors", "last_uploaded_at")
    op.drop_column("collectors", "last_collected_at")
    op.drop_column("collectors", "started_at")
