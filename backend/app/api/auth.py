import hmac
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import admin_login_rate_limiter, create_admin_token, verify_password
from app.schemas.auth import LoginRequest, LoginResponse
from app.services.audit import client_ip, write_audit

router = APIRouter(prefix="/api/auth", tags=["authentication"])
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: DatabaseSession) -> LoginResponse:
    settings = get_settings()
    rate_limit_key = client_ip(request) or "unknown"
    if not admin_login_rate_limiter.allow(
        rate_limit_key, settings.admin_login_rate_limit_per_minute
    ):
        write_audit(
            db,
            request,
            action="admin.login_rate_limit",
            outcome="rejected",
            actor_type="admin",
            actor_id=payload.username,
            details={"reason": "rate_limit_exceeded"},
        )
        raise HTTPException(
            status_code=429,
            detail="Administrator login rate limit exceeded; retry after 60 seconds",
            headers={"Retry-After": "60"},
        )
    username_matches = hmac.compare_digest(payload.username, settings.admin_username)
    password_matches = verify_password(payload.password, settings.admin_password_hash)
    if not username_matches or not password_matches:
        write_audit(
            db,
            request,
            action="admin.login",
            outcome="rejected",
            actor_type="admin",
            actor_id=payload.username,
            details={"reason": "invalid_credentials"},
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, expires_at = create_admin_token(payload.username)
    write_audit(
        db,
        request,
        action="admin.login",
        outcome="success",
        actor_type="admin",
        actor_id=payload.username,
    )
    return LoginResponse(
        access_token=token,
        expires_at=datetime.fromtimestamp(expires_at, timezone.utc),
    )
