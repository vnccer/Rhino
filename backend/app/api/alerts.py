from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.alert import AlertRead
from app.schemas.rule import RuleSeverity
from app.services.alerts import query_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[AlertRead])
def list_alerts(
    db: DatabaseSession,
    rule_id: Annotated[str | None, Query(max_length=100)] = None,
    severity: Annotated[RuleSeverity | None, Query()] = None,
    start_time: Annotated[datetime | None, Query()] = None,
    end_time: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AlertRead]:
    records = query_alerts(
        db,
        rule_id=rule_id,
        severity=severity.value if severity else None,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return [AlertRead.model_validate(record) for record in records]
