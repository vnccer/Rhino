from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.admin import router as admin_router
from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.chains import router as chains_router
from app.api.collectors import collector_router, router as collectors_router
from app.api.events import router as events_router
from app.api.health import router as health_router
from app.api.overview import router as overview_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.middleware import CollectorBodyLimitMiddleware


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings = get_settings()
    if settings.auth_required:
        missing = [
            name
            for name, value in (
                ("ADMIN_PASSWORD_HASH", settings.admin_password_hash),
                ("ADMIN_SESSION_SECRET", settings.admin_session_secret),
                ("CORS_ORIGINS", settings.cors_origins),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
        if len(settings.admin_session_secret) < 32:
            raise RuntimeError("ADMIN_SESSION_SECRET must contain at least 32 characters")
        if not settings.admin_password_hash.startswith("pbkdf2_sha256$"):
            raise RuntimeError("ADMIN_PASSWORD_HASH must be a PBKDF2 hash")
        if "*" in settings.cors_origins:
            raise RuntimeError("CORS_ORIGINS cannot contain a wildcard in production")
    yield


app = FastAPI(
    title="AI-Agent Security Monitor",
    version="0.1.1",
    lifespan=lifespan,
)
app.add_middleware(CollectorBodyLimitMiddleware)
if get_settings().cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Collector-API-Key"],
    )
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(collectors_router)
app.include_router(collector_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(chains_router)
app.include_router(overview_router)
