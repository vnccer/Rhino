from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.event import EventBatch, EventCreate, EventRead, EventSource, EventType
from app.services.events import create_events, query_events

router = APIRouter(prefix="/api/events", tags=["events"])
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.post(
    "",
    response_model=EventRead | list[EventRead],
    status_code=status.HTTP_201_CREATED,
)
def ingest_events(
    payload: EventCreate | EventBatch,
    db: DatabaseSession,
) -> EventRead | list[EventRead]:
    is_batch = isinstance(payload, list)
    records = create_events(db, payload if is_batch else [payload])
    return records if is_batch else records[0]


@router.get("", response_model=list[EventRead])
def list_events(
    db: DatabaseSession,
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    source: Annotated[EventSource | None, Query()] = None,
    event_type: Annotated[EventType | None, Query()] = None,
    trace_id: Annotated[str | None, Query(max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[EventRead]:
    records = query_events(
        db,
        start_time=start_time,
        end_time=end_time,
        source=source.value if source else None,
        event_type=event_type.value if event_type else None,
        trace_id=trace_id,
        limit=limit,
        offset=offset,
    )
    return [EventRead.model_validate(record) for record in records]
