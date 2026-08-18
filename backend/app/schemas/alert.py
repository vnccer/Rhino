from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: UUID
    rule_id: str
    rule_name: str
    severity: int
    severity_label: str
    mitre: list[str]
    start_time: datetime
    end_time: datetime
    evidence_event_ids: list[UUID]
    sources: list[str] = Field(default_factory=list)
    evidence: dict[str, Any]
    created_at: datetime
