"""Add rule detection alerts.

Revision ID: 0003_add_alerts
Revises: 0002_add_events
Create Date: 2026-08-18
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0003_add_alerts"
down_revision: str | None = "0002_add_events"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("severity_label", sa.String(length=16), nullable=False),
        sa.Column("mitre", sa.JSON(), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_event_ids", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("alert_id"),
    )
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_end_time", "alerts", ["end_time"])


def downgrade() -> None:
    op.drop_index("ix_alerts_end_time", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_rule_id", table_name="alerts")
    op.drop_table("alerts")
