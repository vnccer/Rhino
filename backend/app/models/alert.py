from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_end_time", "end_time"),
    )

    alert_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    severity_label: Mapped[str] = mapped_column(String(16), nullable=False)
    mitre: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
