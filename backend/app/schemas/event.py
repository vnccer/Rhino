from datetime import datetime
from enum import StrEnum
from typing import Any, Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EventSource(StrEnum):
    AGENT = "agent"
    HOST = "host"
    WEB = "web"


class EventType(StrEnum):
    TOOL_CALL = "tool_call"
    PROCESS_START = "process_start"
    FILE_WRITE = "file_write"
    NETWORK_CONNECT = "network_connect"
    HTTP_REQUEST = "http_request"


class ActorType(StrEnum):
    AGENT = "agent"
    USER = "user"
    PROCESS = "process"
    IP = "ip"


class EventResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ActorType
    id: str = Field(min_length=1, max_length=255)


class EventObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=100)
    id: str = Field(min_length=1, max_length=255)
    name: str | None = Field(default=None, max_length=255)


class EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    timestamp: datetime
    source: EventSource
    event_type: EventType
    actor: Actor | None = None
    action: str | None = Field(default=None, max_length=100)
    object: EventObject | None = None
    result: EventResult = EventResult.UNKNOWN
    severity: int = Field(default=0, ge=0, le=100)
    trace_id: str | None = Field(default=None, max_length=255)
    parent_event_id: UUID | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)



class EventCreate(EventBase):
    @model_validator(mode="after")
    def validate_timestamp_timezone(self) -> "EventCreate":
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return self


class EventRead(EventBase):
    model_config = ConfigDict(from_attributes=True)


EventBatch = Annotated[list[EventCreate], Field(min_length=1, max_length=1000)]
