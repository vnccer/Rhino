from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.identity import AuditLog


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()[:64]
    return request.client.host[:64] if request.client else None


def write_audit(
    db: Session,
    request: Request,
    *,
    action: str,
    outcome: str,
    actor_type: str,
    actor_id: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> None:
    db.add(
        AuditLog(
            action=action,
            outcome=outcome,
            actor_type=actor_type,
            actor_id=actor_id,
            source_ip=client_ip(request),
            details=details or {},
        )
    )
    if commit:
        db.commit()
