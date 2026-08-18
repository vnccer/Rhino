import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = next(
    root for root in (TEST_FILE.parents[2], TEST_FILE.parents[1]) if (root / "demo").is_dir()
)


def load_jsonl(filename: str) -> list[dict[str, Any]]:
    path = PROJECT_ROOT / "demo" / filename
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_stage2_demo_triggers_all_expected_rules(client: TestClient) -> None:
    events = load_jsonl("events-stage2.jsonl")

    ingested = client.post("/api/events", json=events)
    response = client.get("/api/alerts")

    assert ingested.status_code == 201
    assert response.status_code == 200
    alerts = response.json()
    assert {alert["rule_id"] for alert in alerts} == {
        "agent-tool-call-burst",
        "web-multi-path-probe",
        "auth-failures-then-success",
        "shell-launches-downloader",
        "file-write-then-process",
    }
    for alert in alerts:
        assert alert["severity"] in {75, 100}
        assert alert["evidence_event_ids"]
        assert alert["start_time"] <= alert["end_time"]
        assert all(technique.startswith("T") for technique in alert["mitre"])
        assert alert["evidence"]["event_count"] == len(alert["evidence_event_ids"])


def test_normal_events_do_not_create_alerts(client: TestClient) -> None:
    response = client.post("/api/events", json=load_jsonl("events-stage2-normal.jsonl"))

    assert response.status_code == 201
    assert client.get("/api/alerts").json() == []


def test_window_grouping_and_threshold_prevent_false_positive(client: TestClient) -> None:
    events = load_jsonl("events-stage2.jsonl")[:8]
    for index, event in enumerate(events):
        event["timestamp"] = f"2026-08-18T12:{index * 2:02d}:00Z"
        if index >= 4:
            event["trace_id"] = "another-session"

    response = client.post("/api/events", json=events)

    assert response.status_code == 201
    assert client.get("/api/alerts").json() == []


def test_detection_across_separate_ingestion_requests_and_event_deduplication(
    client: TestClient,
) -> None:
    auth_events = load_jsonl("events-stage2.jsonl")[14:18]
    for event in auth_events:
        assert client.post("/api/events", json=event).status_code == 201

    duplicate = client.post("/api/events", json=auth_events[-1])
    alerts = client.get("/api/alerts", params={"rule_id": "auth-failures-then-success"})

    assert duplicate.status_code == 201
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1
    assert len(alerts.json()[0]["evidence_event_ids"]) == 4


def test_alert_filters_and_validation(client: TestClient) -> None:
    client.post("/api/events", json=load_jsonl("events-stage2.jsonl"))

    critical = client.get("/api/alerts", params={"severity": "critical"})
    invalid_severity = client.get("/api/alerts", params={"severity": "urgent"})
    invalid_limit = client.get("/api/alerts", params={"limit": 0})

    assert critical.status_code == 200
    assert {alert["rule_id"] for alert in critical.json()} == {
        "auth-failures-then-success",
        "shell-launches-downloader",
    }
    assert invalid_severity.status_code == 422
    assert invalid_limit.status_code == 422
