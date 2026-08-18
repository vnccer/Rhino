"""Add correlated attack chains.

Revision ID: 0004_attack_chains
Revises: 0003_add_alerts
Create Date: 2026-08-18
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0004_attack_chains"
down_revision: str | None = "0003_add_alerts"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "attack_chains",
        sa.Column("chain_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stages", sa.JSON(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("alert_ids", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("chain_id"),
    )
    op.create_index("ix_attack_chains_end_time", "attack_chains", ["end_time"])
    op.create_index("ix_attack_chains_confidence", "attack_chains", ["confidence"])
    op.create_table(
        "chain_nodes",
        sa.Column("node_id", sa.Uuid(), nullable=False),
        sa.Column("chain_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["chain_id"], ["attack_chains.chain_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("node_id"),
        sa.UniqueConstraint("chain_id", "entity_type", "entity_id", name="uq_chain_node_entity"),
    )
    op.create_index("ix_chain_nodes_chain_id", "chain_nodes", ["chain_id"])
    op.create_table(
        "chain_edges",
        sa.Column("edge_id", sa.Uuid(), nullable=False),
        sa.Column("chain_id", sa.Uuid(), nullable=False),
        sa.Column("source_node_id", sa.Uuid(), nullable=False),
        sa.Column("target_node_id", sa.Uuid(), nullable=False),
        sa.Column("relationship", sa.String(length=32), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["chain_id"], ["attack_chains.chain_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_node_id"], ["chain_nodes.node_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_node_id"], ["chain_nodes.node_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("edge_id"),
    )
    op.create_index("ix_chain_edges_chain_id", "chain_edges", ["chain_id"])


def downgrade() -> None:
    op.drop_index("ix_chain_edges_chain_id", table_name="chain_edges")
    op.drop_table("chain_edges")
    op.drop_index("ix_chain_nodes_chain_id", table_name="chain_nodes")
    op.drop_table("chain_nodes")
    op.drop_index("ix_attack_chains_confidence", table_name="attack_chains")
    op.drop_index("ix_attack_chains_end_time", table_name="attack_chains")
    op.drop_table("attack_chains")
