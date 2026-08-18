"""Add explainable risk assessments to attack chains.

Revision ID: 0005_risk_assessment
Revises: 0004_attack_chains
Create Date: 2026-08-18
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0005_risk_assessment"
down_revision: str | None = "0004_attack_chains"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "attack_chains",
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "attack_chains",
        sa.Column("risk_level", sa.String(length=16), nullable=False, server_default="low"),
    )
    op.add_column(
        "attack_chains",
        sa.Column("risk_breakdown", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "attack_chains",
        sa.Column("risk_reasons", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "attack_chains",
        sa.Column(
            "risk_evidence_event_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")
        ),
    )
    op.add_column(
        "attack_chains",
        sa.Column("recommendations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("attack_chains", "recommendations")
    op.drop_column("attack_chains", "risk_evidence_event_ids")
    op.drop_column("attack_chains", "risk_reasons")
    op.drop_column("attack_chains", "risk_breakdown")
    op.drop_column("attack_chains", "risk_level")
    op.drop_column("attack_chains", "risk_score")
