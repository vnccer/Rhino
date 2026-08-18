from copy import deepcopy
from typing import Any

from fastapi.testclient import TestClient


def event_payload(**overrides: Any) -> dict[str, Any]:
    payload = {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "timestamp": "2026-08-18T12:00:00Z",
        "source": "agent",
        "event_type": "tool_call",
        "actor": {"type": "agent", "id": "agent-01"},
        "action": "execute",
        "object": {"type": "command", "id": "cmd-01", "name": "curl"},
        "result": "success",
        "severity": 10,
        "trace_id": "session-01",
        "parent_event_id": None,
        "attributes": {"command": "curl https://example.test"},
    }
    payload.update(overrides)
    return payload


def test_ingests_and_queries_single_event(client: TestClient) -> None:
    payload = event_payload()

    created = client.post("/api/events", json=payload)
    queried = client.get("/api/events")

    assert created.status_code == 201
    assert created.json()["event_id"] == payload["event_id"]
    assert queried.status_code == 200
    assert [event["event_id"] for event in queried.json()] == [payload["event_id"]]


def test_ingests_batch_and_filters_events(client: TestClient) -> None:
    first = event_payload()
    second = event_payload(
        event_id="22222222-2222-4222-8222-222222222222",
        timestamp="2026-08-18T12:10:00Z",
        source="web",
        event_type="http_request",
        actor={"type": "ip", "id": "192.0.2.10"},
        trace_id="request-02",
    )
    response = client.post("/api/events", json=[first, second])

    assert response.status_code == 201
    assert len(response.json()) == 2

    filters = {
        "source": "web",
        "event_type": "http_request",
        "trace_id": "request-02",
        "start_time": "2026-08-18T12:05:00Z",
        "end_time": "2026-08-18T12:15:00Z",
    }
    queried = client.get("/api/events", params=filters)

    assert queried.status_code == 200
    assert [event["event_id"] for event in queried.json()] == [second["event_id"]]


def test_duplicate_event_id_is_idempotent(client: TestClient) -> None:
    original = event_payload()
    changed_duplicate = deepcopy(original)
    changed_duplicate["severity"] = 99

    first = client.post("/api/events", json=original)
    duplicate = client.post("/api/events", json=changed_duplicate)
    queried = client.get("/api/events")

    assert first.status_code == 201
    assert duplicate.status_code == 201
    assert duplicate.json()["severity"] == original["severity"]
    assert len(queried.json()) == 1


def test_batch_deduplicates_repeated_event_ids(client: TestClient) -> None:
    payload = event_payload()

    response = client.post("/api/events", json=[payload, payload])
    queried = client.get("/api/events")

    assert response.status_code == 201
    assert len(response.json()) == 2
    assert len(queried.json()) == 1


def test_rejects_invalid_or_incomplete_events(client: TestClient) -> None:
    invalid_source = client.post("/api/events", json=event_payload(source="email"))
    missing_required = client.post(
        "/api/events",
        json={"event_id": "11111111-1111-4111-8111-111111111111"},
    )
    naive_timestamp = client.post(
        "/api/events",
        json=event_payload(timestamp="2026-08-18T12:00:00"),
    )

    assert invalid_source.status_code == 422
    assert missing_required.status_code == 422
    assert naive_timestamp.status_code == 422


def test_rejects_invalid_query_filters(client: TestClient) -> None:
    invalid_source = client.get("/api/events", params={"source": "email"})
    invalid_limit = client.get("/api/events", params={"limit": 0})

    assert invalid_source.status_code == 422
    assert invalid_limit.status_code == 422
