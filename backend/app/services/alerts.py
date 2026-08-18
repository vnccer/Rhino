from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert


def query_alerts(
    db: Session,
    *,
    rule_id: str | None = None,
    severity: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
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
    statement = statement.order_by(Alert.end_time.desc(), Alert.alert_id).limit(limit).offset(offset)
    return list(db.scalars(statement))
