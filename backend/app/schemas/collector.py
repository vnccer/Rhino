from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EnrollmentTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_in_minutes: int = Field(default=30, ge=1, le=1440)
    max_uses: int = Field(default=1, ge=1, le=100)


class EnrollmentTokenCreated(BaseModel):
    token_id: UUID
    enrollment_token: str
    expires_at: datetime
    max_uses: int


class CollectorEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=32, max_length=512)
    host_id: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    os: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=64)
    collector_version: str = Field(min_length=1, max_length=32)


class CollectorEnrollResponse(BaseModel):
    collector_id: UUID
    host_id: str
    api_key: str
    credential_expires_at: datetime


class CollectorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=32)
    queue_depth: int = Field(default=0, ge=0)
    last_error: str | None = Field(default=None, max_length=500)


class CollectorHeartbeatResponse(BaseModel):
    status: str
    received_at: datetime


class CollectorCredentialCreated(BaseModel):
    collector_id: UUID
    api_key: str
    credential_expires_at: datetime


class CollectorStatusResponse(BaseModel):
    collector_id: UUID
    status: str
