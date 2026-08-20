import hmac
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    CollectorPrincipal,
    as_utc,
    collector_rate_limiter,
    create_opaque_secret,
    fingerprint,
    require_collector,
    secret_hash,
)
from app.models.identity import Collector, CollectorCredential, EnrollmentToken, Host
from app.schemas.collector import (
    CollectorEnrollRequest,
    CollectorEnrollResponse,
    CollectorHeartbeat,
    CollectorHeartbeatResponse,
)
from app.schemas.event import EventBatch, EventRead, EventSource
from app.services.audit import write_audit
from app.services.events import create_events

router = APIRouter(prefix="/api/collectors", tags=["collectors"])
collector_router = APIRouter(prefix="/api/collector", tags=["collector ingestion"])
DatabaseSession = Annotated[Session, Depends(get_db)]
AuthenticatedCollector = Annotated[CollectorPrincipal, Depends(require_collector)]


@router.post("/enroll", response_model=CollectorEnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll_collector(
    payload: CollectorEnrollRequest, request: Request, db: DatabaseSession
) -> CollectorEnrollResponse:
    now = datetime.now(timezone.utc)
    token = db.scalar(
        select(EnrollmentToken).where(
            EnrollmentToken.fingerprint == fingerprint(payload.enrollment_token)
        ).with_for_update()
    )
    if (
        token is None
        or not hmac.compare_digest(token.token_hash, secret_hash(payload.enrollment_token))
        or token.status != "active"
        or as_utc(token.expires_at) <= now
        or token.use_count >= token.max_uses
    ):
        write_audit(
            db,
            request,
            action="collector.enroll",
            outcome="rejected",
            actor_type="collector",
            actor_id=payload.host_id,
            details={"reason": "invalid_or_expired_token"},
        )
        raise HTTPException(status_code=401, detail="Enrollment token is invalid or expired")

    host = db.get(Host, payload.host_id)
    if host is None:
        host = Host(
            host_id=payload.host_id,
            hostname=payload.hostname,
            os=payload.os,
            os_version=payload.os_version,
            last_seen_at=now,
        )
        db.add(host)
        db.flush()
    else:
        host.hostname = payload.hostname
        host.os = payload.os
        host.os_version = payload.os_version
        host.last_seen_at = now

    collector = Collector(
        host_id=payload.host_id,
        version=payload.collector_version,
        last_seen_at=now,
    )
    db.add(collector)
    db.flush()
    api_key = create_opaque_secret("aasm_collector")
    expires_at = now + timedelta(days=get_settings().collector_credential_ttl_days)
    db.add(
        CollectorCredential(
            collector_id=collector.collector_id,
            secret_hash=secret_hash(api_key),
            fingerprint=fingerprint(api_key),
            expires_at=expires_at,
        )
    )
    token.use_count += 1
    if token.use_count >= token.max_uses:
        token.status = "consumed"
    write_audit(
        db,
        request,
        action="collector.enroll",
        outcome="success",
        actor_type="collector",
        actor_id=str(collector.collector_id),
        details={"host_id": payload.host_id, "token_id": str(token.token_id)},
    )
    return CollectorEnrollResponse(
        collector_id=collector.collector_id,
        host_id=payload.host_id,
        api_key=api_key,
        credential_expires_at=expires_at,
    )


def _check_rate_limit(
    principal: CollectorPrincipal, request: Request, db: Session
) -> None:
    settings = get_settings()
    if collector_rate_limiter.allow(
        principal.credential_id, settings.collector_rate_limit_per_minute
    ):
        return
    write_audit(
        db,
        request,
        action="collector.rate_limit",
        outcome="rejected",
        actor_type="collector",
        actor_id=principal.collector_id,
        details={"credential_id": principal.credential_id},
    )
    raise HTTPException(
        status_code=429,
        detail="Collector rate limit exceeded; retry after 60 seconds",
        headers={"Retry-After": "60"},
    )


@collector_router.post("/events", response_model=list[EventRead], status_code=status.HTTP_201_CREATED)
def ingest_collector_events(
    payload: EventBatch,
    request: Request,
    db: DatabaseSession,
    principal: AuthenticatedCollector,
) -> list[EventRead]:
    settings = get_settings()
    _check_rate_limit(principal, request, db)
    if len(payload) > settings.collector_max_batch_size:
        raise HTTPException(
            status_code=413,
            detail=f"Batch exceeds {settings.collector_max_batch_size} events",
        )
    now = datetime.now(timezone.utc)
    normalized = []
    for event in payload:
        if event.source != EventSource.HOST:
            raise HTTPException(status_code=422, detail="Collector events must use source=host")
        if abs((as_utc(event.timestamp) - now).total_seconds()) > settings.collector_max_clock_skew_seconds:
            raise HTTPException(
                status_code=422,
                detail="Event timestamp is outside the allowed clock skew",
            )
        attributes = dict(event.attributes)
        attributes["host_id"] = principal.host_id
        attributes["collector_id"] = principal.collector_id
        normalized.append(event.model_copy(update={"attributes": attributes}))
    records = create_events(db, normalized)
    collector = db.get(Collector, UUID(principal.collector_id))
    host = db.get(Host, principal.host_id)
    if collector:
        collector.last_seen_at = now
    if host:
        host.last_seen_at = now
    db.commit()
    return [EventRead.model_validate(record) for record in records]


@collector_router.post("/heartbeat", response_model=CollectorHeartbeatResponse)
def collector_heartbeat(
    payload: CollectorHeartbeat,
    request: Request,
    db: DatabaseSession,
    principal: AuthenticatedCollector,
) -> CollectorHeartbeatResponse:
    _check_rate_limit(principal, request, db)
    now = datetime.now(timezone.utc)
    collector = db.get(Collector, UUID(principal.collector_id))
    host = db.get(Host, principal.host_id)
    if collector:
        collector.version = payload.version
        collector.last_seen_at = now
    if host:
        host.last_seen_at = now
    db.commit()
    return CollectorHeartbeatResponse(status="ok", received_at=now)
