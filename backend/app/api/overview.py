from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin
from app.models.alert import Alert
from app.models.chain import AttackChain
from app.models.event import Event
from app.schemas.overview import OverviewRead, TrendPoint

router = APIRouter(
    prefix="/api/overview", tags=["overview"], dependencies=[Depends(require_admin)]
)
DatabaseSession = Annotated[Session, Depends(get_db)]


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.get("", response_model=OverviewRead)
def read_overview(
    db: DatabaseSession,
    days: Annotated[int, Query(ge=1, le=30)] = 7,
) -> OverviewRead:
    event_count = db.scalar(select(func.count()).select_from(Event)) or 0
    alert_count = db.scalar(select(func.count()).select_from(Alert)) or 0
    chain_count = db.scalar(select(func.count()).select_from(AttackChain)) or 0
    critical_alert_count = db.scalar(
        select(func.count()).select_from(Alert).where(Alert.severity_label == "critical")
    ) or 0
    high_risk_chain_count = db.scalar(
        select(func.count()).select_from(AttackChain).where(
            AttackChain.risk_level.in_(["high", "critical"])
        )
    ) or 0
    source_counts = {source: count for source, count in db.execute(
        select(Event.source, func.count()).group_by(Event.source)
    ).all()}

    event_times = [_utc(value) for value in db.scalars(select(Event.timestamp))]
    alert_times = [_utc(value) for value in db.scalars(select(Alert.end_time))]
    timestamps = [*event_times, *alert_times]
    latest = max(timestamps, default=datetime.now(UTC))
    end_day = latest.date()
    start_day = end_day - timedelta(days=days - 1)
    event_buckets = Counter(value.date() for value in event_times)
    alert_buckets = Counter(value.date() for value in alert_times)
    trend = [
        TrendPoint(
            bucket=(start_day + timedelta(days=index)).isoformat(),
            events=event_buckets[start_day + timedelta(days=index)],
            alerts=alert_buckets[start_day + timedelta(days=index)],
        )
        for index in range(days)
    ]
    return OverviewRead(
        event_count=event_count,
        alert_count=alert_count,
        critical_alert_count=critical_alert_count,
        high_risk_chain_count=high_risk_chain_count,
        chain_count=chain_count,
        source_counts={
            source: source_counts.get(source, 0) for source in ("agent", "host", "web")
        },
        trend=trend,
    )
