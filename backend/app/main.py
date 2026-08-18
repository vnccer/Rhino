from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI

from app.api.health import router as health_router
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

