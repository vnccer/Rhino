from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.event import Event
from app.schemas.event import EventCreate


def create_event(db: Session, event: EventCreate) -> Event:
    existing = db.get(Event, event.event_id)
    if existing is not None:
        return existing

    values = event.model_dump()
    values["source"] = event.source.value
    values["event_type"] = event.event_type.value
    values["result"] = event.result.value
    values["actor"] = event.actor.model_dump(mode="json") if event.actor else None
    values["object"] = event.object.model_dump(mode="json") if event.object else None
    record = Event(**values)

    try:
        with db.begin_nested():
            db.add(record)
            db.flush()
    except IntegrityError:
        duplicate = db.get(Event, event.event_id)
        if duplicate is None:
            raise
        return duplicate
    return record


def create_events(db: Session, events: Sequence[EventCreate]) -> list[Event]:
    records = [create_event(db, event) for event in events]
    db.commit()
    return records


def query_events(
    db: Session,
    *,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source: str | None = None,
    event_type: str | None = None,
    trace_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Event]:
    statement = select(Event)
    if start_time is not None:
        statement = statement.where(Event.timestamp >= start_time)
    if end_time is not None:
        statement = statement.where(Event.timestamp <= end_time)
    if source is not None:
        statement = statement.where(Event.source == source)
    if event_type is not None:
        statement = statement.where(Event.event_type == event_type)
    if trace_id is not None:
        statement = statement.where(Event.trace_id == trace_id)

    statement = statement.order_by(Event.timestamp.desc(), Event.event_id).limit(limit).offset(offset)
    return list(db.scalars(statement))
