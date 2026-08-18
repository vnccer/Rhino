import asyncio

import httpx

from app.main import app


async def request(method: str, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path)


def test_health_returns_ok() -> None:
    response = asyncio.run(request("GET", "/health"))

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_rejects_unsupported_method() -> None:
    response = asyncio.run(request("POST", "/health"))

    assert response.status_code == 405
