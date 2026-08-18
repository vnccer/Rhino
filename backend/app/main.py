from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.chains import router as chains_router
from app.api.events import router as events_router
from app.api.health import router as health_router
from app.api.overview import router as overview_router
from app.core.logging import configure_logging


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    yield


app = FastAPI(
    title="AI-Agent Security Monitor",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(health_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(chains_router)
app.include_router(overview_router)
