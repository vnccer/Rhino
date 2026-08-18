"""Add normalized events.

Revision ID: 0002_add_events
Revises: 0001_stage_0
Create Date: 2026-08-18
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0002_add_events"
down_revision: str | None = "0001_stage_0"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.JSON(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=True),
        sa.Column("object", sa.JSON(), nullable=True),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=True),
        sa.Column("parent_event_id", sa.Uuid(), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_source", "events", ["source"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_trace_id", "events", ["trace_id"])


def downgrade() -> None:
    op.drop_index("ix_events_trace_id", table_name="events")
    op.drop_index("ix_events_event_type", table_name="events")
    op.drop_index("ix_events_source", table_name="events")
    op.drop_index("ix_events_timestamp", table_name="events")
    op.drop_table("events")
