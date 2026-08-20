from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    AdminPrincipal,
    as_utc,
    create_opaque_secret,
    fingerprint,
    require_admin_strict,
    secret_hash,
)
from app.models.identity import (
    AuditLog,
    Collector,
    CollectorCredential,
    EnrollmentToken,
    Host,
)
from app.schemas.auth import AuditLogRead
from app.schemas.collector import (
    CollectorCredentialCreated,
    CollectorHealthRead,
    CollectorStatusResponse,
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
)
from app.services.audit import write_audit

router = APIRouter(prefix="/api/admin", tags=["administration"])
DatabaseSession = Annotated[Session, Depends(get_db)]
Administrator = Annotated[AdminPrincipal, Depends(require_admin_strict)]


@router.get("/collectors", response_model=list[CollectorHealthRead])
def list_collectors(
    db: DatabaseSession,
    _: Administrator,
) -> list[CollectorHealthRead]:
    now = datetime.now(timezone.utc)
    offline_after = timedelta(seconds=get_settings().collector_offline_after_seconds)
    records = db.execute(
        select(Collector, Host)
        .join(Host, Host.host_id == Collector.host_id)
        .order_by(Collector.last_seen_at.desc(), Collector.created_at.desc())
    ).all()
    return [
        CollectorHealthRead(
            collector_id=collector.collector_id,
            host_id=host.host_id,
            hostname=host.hostname,
            os=host.os,
            os_version=host.os_version,
            version=collector.version,
            status=collector.status,
            online=collector.status == "active"
            and collector.last_seen_at is not None
            and now - as_utc(collector.last_seen_at) <= offline_after,
            created_at=collector.created_at,
            last_seen_at=collector.last_seen_at,
            started_at=collector.started_at,
            last_collected_at=collector.last_collected_at,
            last_uploaded_at=collector.last_uploaded_at,
            queue_depth=collector.queue_depth,
            last_error=collector.last_error,
            redaction_count=collector.redaction_count,
        )
        for collector, host in records
    ]


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    db: DatabaseSession,
    _: Administrator,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)))


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    request: Request,
    db: DatabaseSession,
    admin: Administrator,
) -> EnrollmentTokenCreated:
    value = create_opaque_secret("aasm_enroll")
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=payload.expires_in_minutes)
    record = EnrollmentToken(
        token_hash=secret_hash(value),
        fingerprint=fingerprint(value),
        expires_at=expires_at,
        max_uses=payload.max_uses,
        created_by=admin.username,
    )
    db.add(record)
    db.flush()
    write_audit(
        db,
        request,
        action="enrollment_token.create",
        outcome="success",
        actor_type="admin",
        actor_id=admin.username,
        details={"token_id": str(record.token_id), "max_uses": payload.max_uses},
    )
    return EnrollmentTokenCreated(
        token_id=record.token_id,
        enrollment_token=value,
        expires_at=record.expires_at,
        max_uses=record.max_uses,
    )


@router.post(
    "/collectors/{collector_id}/credentials/rotate",
    response_model=CollectorCredentialCreated,
)
def rotate_collector_credential(
    collector_id: UUID,
    request: Request,
    db: DatabaseSession,
    admin: Administrator,
) -> CollectorCredentialCreated:
    collector = db.get(Collector, collector_id)
    if collector is None:
        raise HTTPException(status_code=404, detail="Collector not found")
    now = datetime.now(timezone.utc)
    for credential in db.scalars(
        select(CollectorCredential).where(
            CollectorCredential.collector_id == collector_id,
            CollectorCredential.status == "active",
        )
    ):
        credential.status = "rotated"
        credential.rotated_at = now
    value = create_opaque_secret("aasm_collector")
    expires_at = now + timedelta(days=get_settings().collector_credential_ttl_days)
    db.add(
        CollectorCredential(
            collector_id=collector_id,
            secret_hash=secret_hash(value),
            fingerprint=fingerprint(value),
            expires_at=expires_at,
        )
    )
    write_audit(
        db,
        request,
        action="collector.credential.rotate",
        outcome="success",
        actor_type="admin",
        actor_id=admin.username,
        details={"collector_id": str(collector_id)},
    )
    return CollectorCredentialCreated(
        collector_id=collector_id,
        api_key=value,
        credential_expires_at=expires_at,
    )


@router.post("/collectors/{collector_id}/disable", response_model=CollectorStatusResponse)
def disable_collector(
    collector_id: UUID,
    request: Request,
    db: DatabaseSession,
    admin: Administrator,
) -> CollectorStatusResponse:
    collector = db.get(Collector, collector_id)
    if collector is None:
        raise HTTPException(status_code=404, detail="Collector not found")
    collector.status = "disabled"
    write_audit(
        db,
        request,
        action="collector.disable",
        outcome="success",
        actor_type="admin",
        actor_id=admin.username,
        details={"collector_id": str(collector_id)},
    )
    return CollectorStatusResponse(collector_id=collector_id, status=collector.status)
