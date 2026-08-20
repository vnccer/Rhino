import hmac
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import create_admin_token, verify_password
from app.schemas.auth import LoginRequest, LoginResponse
from app.services.audit import write_audit

router = APIRouter(prefix="/api/auth", tags=["authentication"])
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: DatabaseSession) -> LoginResponse:
    settings = get_settings()
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
