import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.identity import Collector, CollectorCredential

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AdminPrincipal:
    username: str


@dataclass(frozen=True)
class CollectorPrincipal:
    collector_id: str
    host_id: str
    credential_id: str


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint(value: str) -> str:
    return secret_hash(value)[:16]


def create_opaque_secret(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_password(password: str, *, iterations: int = 600_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "$".join(
        (
            "pbkdf2_sha256",
            str(iterations),
            base64.urlsafe_b64encode(salt).decode().rstrip("="),
            base64.urlsafe_b64encode(digest).decode().rstrip("="),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, int(iterations_text)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def create_admin_token(username: str) -> tuple[str, int]:
    settings = get_settings()
    expires_at = int(time.time()) + settings.admin_session_ttl_minutes * 60
    payload = _encode(
        json.dumps({"sub": username, "exp": expires_at}, separators=(",", ":")).encode()
    )
    signature = _encode(
        hmac.new(settings.admin_session_secret.encode(), payload.encode(), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}", expires_at


def verify_admin_token(token: str) -> AdminPrincipal | None:
    settings = get_settings()
    try:
        payload, signature = token.split(".", 1)
        expected = _encode(
            hmac.new(
                settings.admin_session_secret.encode(), payload.encode(), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(signature, expected):
            return None
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
        if claims.get("sub") != settings.admin_username or int(claims["exp"]) < int(time.time()):
            return None
        return AdminPrincipal(username=claims["sub"])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def require_admin(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> AdminPrincipal:
    settings = get_settings()
    if not settings.auth_required:
        return AdminPrincipal(username=settings.admin_username)
    return _authenticate_admin(credentials, request, db)


def require_admin_strict(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> AdminPrincipal:
    return _authenticate_admin(credentials, request, db)


def _authenticate_admin(
    credentials: HTTPAuthorizationCredentials | None,
    request: Request,
    db: Session,
) -> AdminPrincipal:
    principal = (
        verify_admin_token(credentials.credentials)
        if credentials and credentials.scheme.lower() == "bearer"
        else None
    )
    if principal is None:
        from app.services.audit import write_audit

        collector, _ = _resolve_collector(
            db, request.headers.get("X-Collector-API-Key", "")
        )
        if collector is not None:
            write_audit(
                db,
                request,
                action="admin.authorization",
                outcome="rejected",
                actor_type="collector",
                actor_id=collector.collector_id,
                details={"reason": "collector_not_allowed"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Collector credentials cannot access administrator APIs",
            )

        write_audit(
            db,
            request,
            action="admin.authentication",
            outcome="rejected",
            actor_type="admin",
            details={"reason": "missing_or_invalid_token"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid administrator authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_collector(request: Request, db: Annotated[Session, Depends(get_db)]) -> CollectorPrincipal:
    api_key = request.headers.get("X-Collector-API-Key", "")
    if not api_key:
        admin = _admin_from_request(request)
        if admin is not None:
            from app.services.audit import write_audit

            write_audit(
                db,
                request,
                action="collector.authorization",
                outcome="rejected",
                actor_type="admin",
                actor_id=admin.username,
                details={"reason": "admin_not_allowed"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator credentials cannot access collector APIs",
            )
        _audit_collector_rejection(db, request, "missing_credential")
        raise HTTPException(status_code=401, detail="Collector API key is required")
    principal, rejection = _resolve_collector(db, api_key)
    if principal is None:
        admin = _admin_from_request(request)
        if admin is not None:
            from app.services.audit import write_audit

            write_audit(
                db,
                request,
                action="collector.authorization",
                outcome="rejected",
                actor_type="admin",
                actor_id=admin.username,
                details={"reason": "admin_not_allowed"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator credentials cannot access collector APIs",
            )
        _audit_collector_rejection(db, request, "invalid_or_expired_credential")
        raise HTTPException(status_code=401, detail="Collector credential is invalid or expired")
    if rejection == "collector_disabled":
        _audit_collector_rejection(db, request, rejection)
        raise HTTPException(status_code=403, detail="Collector is disabled")
    return principal


def _admin_from_request(request: Request) -> AdminPrincipal | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    return verify_admin_token(token) if scheme.lower() == "bearer" else None


def _resolve_collector(
    db: Session, api_key: str
) -> tuple[CollectorPrincipal | None, str | None]:
    if not api_key:
        return None, "missing_credential"
    credential = db.scalar(
        select(CollectorCredential).where(
            CollectorCredential.fingerprint == fingerprint(api_key)
        )
    )
    now = datetime.now(timezone.utc)
    if (
        credential is None
        or credential.status != "active"
        or not hmac.compare_digest(credential.secret_hash, secret_hash(api_key))
        or (credential.expires_at is not None and as_utc(credential.expires_at) <= now)
    ):
        return None, "invalid_or_expired_credential"
    collector = db.get(Collector, credential.collector_id)
    if collector is None:
        return None, "invalid_or_expired_credential"
    principal = CollectorPrincipal(
        collector_id=str(collector.collector_id),
        host_id=collector.host_id,
        credential_id=str(credential.credential_id),
    )
    return principal, None if collector.status == "active" else "collector_disabled"


def _audit_collector_rejection(db: Session, request: Request, reason: str) -> None:
    from app.services.audit import write_audit

    write_audit(
        db,
        request,
        action="collector.authentication",
        outcome="rejected",
        actor_type="collector",
        details={"reason": reason},
    )


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            requests = self._requests[key]
            while requests and requests[0] <= now - window_seconds:
                requests.popleft()
            if len(requests) >= limit:
                return False
            requests.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()


collector_rate_limiter = SlidingWindowRateLimiter()
admin_login_rate_limiter = SlidingWindowRateLimiter()
