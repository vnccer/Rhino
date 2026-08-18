from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AttackChain(Base):
    __tablename__ = "attack_chains"
    __table_args__ = (
        Index("ix_attack_chains_end_time", "end_time"),
        Index("ix_attack_chains_confidence", "confidence"),
    )

    chain_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stages: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    risk_breakdown: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    risk_reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    risk_evidence_event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    @property
    def risk(self) -> dict[str, object]:
        return {
            "score": self.risk_score,
            "level": self.risk_level,
            "breakdown": self.risk_breakdown,
            "reasons": self.risk_reasons,
            "evidence_event_ids": self.risk_evidence_event_ids,
            "recommendations": self.recommendations,
        }


class ChainNode(Base):
    __tablename__ = "chain_nodes"
    __table_args__ = (
        UniqueConstraint("chain_id", "entity_type", "entity_id", name="uq_chain_node_entity"),
        Index("ix_chain_nodes_chain_id", "chain_id"),
    )

    node_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    chain_id: Mapped[UUID] = mapped_column(
        ForeignKey("attack_chains.chain_id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class ChainEdge(Base):
    __tablename__ = "chain_edges"
    __table_args__ = (Index("ix_chain_edges_chain_id", "chain_id"),)

    edge_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    chain_id: Mapped[UUID] = mapped_column(
        ForeignKey("attack_chains.chain_id", ondelete="CASCADE"), nullable=False
    )
    source_node_id: Mapped[UUID] = mapped_column(
        ForeignKey("chain_nodes.node_id", ondelete="CASCADE"), nullable=False
    )
    target_node_id: Mapped[UUID] = mapped_column(
        ForeignKey("chain_nodes.node_id", ondelete="CASCADE"), nullable=False
    )
    relationship: Mapped[str] = mapped_column(String(32), nullable=False)
    event_id: Mapped[UUID | None] = mapped_column(Uuid)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
