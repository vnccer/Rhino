from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_source", "source"),
        Index("ix_events_event_type", "event_type"),
        Index("ix_events_trace_id", "trace_id"),
    )

    event_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    action: Mapped[str | None] = mapped_column(String(100))
    object: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    trace_id: Mapped[str | None] = mapped_column(String(255))
    parent_event_id: Mapped[UUID | None] = mapped_column(Uuid)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
