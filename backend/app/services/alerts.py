from datetime import datetime

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event


def query_alerts(
    db: Session,
    *,
    rule_id: str | None = None,
    severity: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    statement = select(Alert)
    if rule_id is not None:
        statement = statement.where(Alert.rule_id == rule_id)
    if severity is not None:
        statement = statement.where(Alert.severity_label == severity)
    if start_time is not None:
        statement = statement.where(Alert.end_time >= start_time)
    if end_time is not None:
        statement = statement.where(Alert.start_time <= end_time)
    statement = statement.order_by(Alert.end_time.desc(), Alert.alert_id)
    records = list(db.scalars(statement))
    if source is not None:
        source_event_ids = {
            str(event_id)
            for event_id in db.scalars(select(Event.event_id).where(Event.source == source))
        }
        records = [
            alert
            for alert in records
            if source_event_ids.intersection(alert.evidence_event_ids)
        ]
    return records[offset : offset + limit]


def alert_sources(db: Session, alerts: list[Alert]) -> dict[UUID, list[str]]:
    event_ids = {
        UUID(event_id)
        for alert in alerts
        for event_id in alert.evidence_event_ids
    }
    if not event_ids:
        return {alert.alert_id: [] for alert in alerts}
    event_source = dict(
        db.execute(select(Event.event_id, Event.source).where(Event.event_id.in_(event_ids))).all()
    )
    return {
        alert.alert_id: sorted(
            {event_source[UUID(event_id)] for event_id in alert.evidence_event_ids if UUID(event_id) in event_source}
        )
        for alert in alerts
    }
