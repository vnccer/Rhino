from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.event import EventRead


class AttackStage(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    EXTERNAL_COMMUNICATION = "external_communication"


class ChainSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    chain_id: UUID
    title: str
    start_time: datetime
    end_time: datetime
    stages: list[AttackStage]
    event_ids: list[UUID]
    alert_ids: list[UUID]
    confidence: int


class ChainNodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    node_id: UUID
    entity_type: str
    entity_id: str
    label: str
    stage: AttackStage
    event_ids: list[UUID]


class ChainEdgeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    edge_id: UUID
    source_node_id: UUID
    target_node_id: UUID
    relationship: str
    event_id: UUID | None
    reason: str
    priority: int
    confidence: int


class ChainDetail(ChainSummary):
    nodes: list[ChainNodeRead]
    edges: list[ChainEdgeRead]
    events: list[EventRead]
