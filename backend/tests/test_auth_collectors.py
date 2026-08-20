from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.security import admin_login_rate_limiter, hash_password
from app.main import create_app


def configure_auth() -> tuple[object, dict[str, object]]:
    settings = get_settings()
    original = {
        "auth_required": settings.auth_required,
        "admin_username": settings.admin_username,
        "admin_password_hash": settings.admin_password_hash,
        "admin_session_secret": settings.admin_session_secret,
        "admin_login_rate_limit_per_minute": settings.admin_login_rate_limit_per_minute,
        "collector_max_batch_size": settings.collector_max_batch_size,
        "collector_max_body_bytes": settings.collector_max_body_bytes,
        "collector_rate_limit_per_minute": settings.collector_rate_limit_per_minute,
    }
    settings.auth_required = True
    settings.admin_username = "security-admin"
    settings.admin_password_hash = hash_password("correct-horse-battery-staple")
    settings.admin_session_secret = "test-session-secret-that-is-at-least-32-bytes"
    return settings, original


def restore(settings: object, original: dict[str, object]) -> None:
    for key, value in original.items():
        setattr(settings, key, value)


def admin_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": "security-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def enroll(
    client: TestClient, headers: dict[str, str], *, host_id: str = "stable-host-id"
) -> dict[str, str]:
    created = client.post(
        "/api/admin/enrollment-tokens",
        headers=headers,
        json={"expires_in_minutes": 10, "max_uses": 1},
    )
    assert created.status_code == 201
    token = created.json()["enrollment_token"]
    enrolled = client.post(
        "/api/collectors/enroll",
        json={
            "enrollment_token": token,
            "host_id": host_id,
            "hostname": "vm-security-monitor-01",
            "os": "ubuntu",
            "os_version": "22.04",
            "collector_version": "0.1.1",
        },
    )
    assert enrolled.status_code == 201
    assert client.post(
        "/api/collectors/enroll",
        json={
            "enrollment_token": token,
            "host_id": "other-host",
            "hostname": "other",
            "os": "ubuntu",
            "os_version": "22.04",
            "collector_version": "0.1.1",
        },
    ).status_code == 401
    return {
        "X-Collector-API-Key": enrolled.json()["api_key"],
        "collector_id": enrolled.json()["collector_id"],
        "host_id": host_id,
    }


def event_payload(*, timestamp: datetime | None = None) -> dict[str, object]:
    return {
        "event_id": str(uuid4()),
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "source": "host",
        "event_type": "process_start",
        "actor": {"type": "process", "id": "1234"},
        "action": "start",
        "object": {"type": "process", "id": "/usr/bin/true"},
        "result": "success",
        "attributes": {"host_id": "forged-host", "collector_id": "forged-collector"},
    }


def test_admin_authentication_and_protected_reads(client: TestClient) -> None:
    settings, original = configure_auth()
    try:
        rejected = client.post(
            "/api/auth/login", json={"username": "security-admin", "password": "wrong"}
        )
        assert rejected.status_code == 401
        assert client.get("/api/events").status_code == 401
        assert client.post("/api/events", json=event_payload()).status_code == 401
        headers = admin_headers(client)
        assert client.get("/api/events", headers=headers).status_code == 200
        assert client.get("/api/admin/audit-logs", headers=headers).status_code == 200
    finally:
        restore(settings, original)


def test_cors_only_allows_configured_console_origin() -> None:
    settings = get_settings()
    original = settings.cors_origins
    settings.cors_origins = ["https://monitor.example.com"]
    try:
        with TestClient(create_app()) as cors_client:
            allowed = cors_client.options(
                "/api/events",
                headers={
                    "Origin": "https://monitor.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
            rejected = cors_client.options(
                "/api/events",
                headers={
                    "Origin": "https://attacker.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
        assert allowed.status_code == 200
        assert allowed.headers["access-control-allow-origin"] == "https://monitor.example.com"
        assert rejected.status_code == 400
        assert "access-control-allow-origin" not in rejected.headers
    finally:
        settings.cors_origins = original


def test_enrollment_and_collector_identity_are_enforced(client: TestClient) -> None:
    settings, original = configure_auth()
    try:
        headers = admin_headers(client)
        collector = enroll(client, headers)
        api_headers = {"X-Collector-API-Key": collector["X-Collector-API-Key"]}
        payload = event_payload()
        first = client.post("/api/collector/events", headers=api_headers, json=[payload])
        retry_payload = {**payload, "timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}
        duplicate = client.post(
            "/api/collector/events", headers=api_headers, json=[retry_payload]
        )
        assert first.status_code == duplicate.status_code == 201
        assert first.json()[0]["attributes"]["host_id"] == "stable-host-id"
        assert first.json()[0]["attributes"]["collector_id"] == collector["collector_id"]
        queried = client.get("/api/events", headers=headers)
        assert queried.status_code == 200
        assert len(queried.json()) == 1
        assert client.get("/api/events", headers=api_headers).status_code == 403
        assert client.post(
            "/api/collector/heartbeat",
            headers=headers,
            json={"version": "0.1.1", "queue_depth": 0},
        ).status_code == 403

        other_collector = enroll(client, headers, host_id="second-stable-host-id")
        ownership_rejection = client.post(
            "/api/collector/events",
            headers={"X-Collector-API-Key": other_collector["X-Collector-API-Key"]},
            json=[payload],
        )
        assert ownership_rejection.status_code == 403
        assert len(client.get("/api/events", headers=headers).json()) == 1
        assert client.post("/api/collector/events", json=[event_payload()]).status_code == 401
        assert client.post(
            "/api/collector/events",
            headers={"X-Collector-API-Key": "aasm_collector_invalid"},
            json=[event_payload()],
        ).status_code == 401
        actions = [item["action"] for item in client.get("/api/admin/audit-logs", headers=headers).json()]
        assert "collector.enroll" in actions
        assert "collector.authentication" in actions
        assert "collector.authorization" in actions
        assert "admin.authorization" in actions
        assert "collector.event_ingest" in actions
        assert "enrollment_token.create" in actions

        rotated = client.post(
            f"/api/admin/collectors/{collector['collector_id']}/credentials/rotate",
            headers=headers,
        )
        assert rotated.status_code == 200, rotated.text
        assert client.post(
            "/api/collector/heartbeat",
            headers=api_headers,
            json={"version": "0.1.1", "queue_depth": 0},
        ).status_code == 401
        rotated_headers = {"X-Collector-API-Key": rotated.json()["api_key"]}
        assert client.post(
            "/api/collector/heartbeat",
            headers=rotated_headers,
            json={"version": "0.1.1", "queue_depth": 0},
        ).status_code == 200
        assert client.post(
            f"/api/admin/collectors/{collector['collector_id']}/disable", headers=headers
        ).status_code == 200
        assert client.post(
            "/api/collector/heartbeat",
            headers=rotated_headers,
            json={"version": "0.1.1", "queue_depth": 0},
        ).status_code == 403
    finally:
        restore(settings, original)


def test_admin_login_rate_limit_is_audited(client: TestClient) -> None:
    settings, original = configure_auth()
    try:
        admin_login_rate_limiter.reset()
        settings.admin_login_rate_limit_per_minute = 1
        rejected = client.post(
            "/api/auth/login", json={"username": "security-admin", "password": "wrong"}
        )
        limited = client.post(
            "/api/auth/login", json={"username": "security-admin", "password": "wrong"}
        )
        assert rejected.status_code == 401
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "60"

        admin_login_rate_limiter.reset()
        actions = [
            item["action"]
            for item in client.get(
                "/api/admin/audit-logs", headers=admin_headers(client)
            ).json()
        ]
        assert "admin.login_rate_limit" in actions
    finally:
        restore(settings, original)


def test_collector_limits_and_retry_guidance(client: TestClient) -> None:
    settings, original = configure_auth()
    try:
        headers = admin_headers(client)
        collector = enroll(client, headers)
        api_headers = {"X-Collector-API-Key": collector["X-Collector-API-Key"]}
        settings.collector_max_body_bytes = 10
        oversized = client.post("/api/collector/events", headers=api_headers, json=[event_payload()])
        assert oversized.status_code == 413
        settings.collector_max_body_bytes = original["collector_max_body_bytes"]
        settings.collector_max_batch_size = 1
        too_many = client.post(
            "/api/collector/events", headers=api_headers, json=[event_payload(), event_payload()]
        )
        assert too_many.status_code == 413
        stale = client.post(
            "/api/collector/events",
            headers=api_headers,
            json=[event_payload(timestamp=datetime.now(timezone.utc) - timedelta(hours=1))],
        )
        assert stale.status_code == 422
        settings.collector_rate_limit_per_minute = 3
        first = client.post(
            "/api/collector/heartbeat",
            headers=api_headers,
            json={"version": "0.1.1", "queue_depth": 0},
        )
        limited = client.post(
            "/api/collector/heartbeat",
            headers=api_headers,
            json={"version": "0.1.1", "queue_depth": 0},
        )
        assert first.status_code == 200
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "60"
    finally:
        restore(settings, original)
