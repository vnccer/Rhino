import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = next(
    root for root in (TEST_FILE.parents[2], TEST_FILE.parents[1]) if (root / "demo").is_dir()
)


def load_stage3_events() -> list[dict[str, Any]]:
    path = PROJECT_ROOT / "demo" / "events-stage3.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_stage3_demo_builds_one_traceable_attack_chain(client: TestClient) -> None:
    events = load_stage3_events()

    ingested = client.post("/api/events", json=events)
    listed = client.get("/api/chains")

    assert ingested.status_code == 201
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    summary = listed.json()[0]
    assert summary["stages"] == [
        "reconnaissance",
        "credential_access",
        "execution",
        "persistence",
        "lateral_movement",
        "external_communication",
    ]
    assert len(summary["event_ids"]) == 16
    assert events[-1]["event_id"] not in summary["event_ids"]
    assert summary["alert_ids"]

    detail_response = client.get(f"/api/chains/{summary['chain_id']}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert {event["event_id"] for event in detail["events"]} == set(summary["event_ids"])
    assert {node["entity_type"] for node in detail["nodes"]} >= {
        "agent", "user", "process", "file", "ip", "domain", "session"
    }
    for node in detail["nodes"]:
        assert node["event_ids"]
        assert set(node["event_ids"]) <= set(summary["event_ids"])
    assert {edge["relationship"] for edge in detail["edges"]} >= {
        "calls", "creates", "writes", "executes", "connects", "derived_from"
    }
    assert any(edge["reason"] == "parent_event_id" for edge in detail["edges"])

    replayed = client.post("/api/events", json=events)
    assert replayed.status_code == 201
    assert len(client.get("/api/chains").json()) == 1


def test_different_traces_do_not_merge_on_temporal_actor_proximity(client: TestClient) -> None:
    first, second = load_stage3_events()[-1].copy(), load_stage3_events()[-1].copy()
    first["event_id"] = "40000000-0000-4000-8000-000000000001"
    first["trace_id"] = "session-a"
    second["event_id"] = "40000000-0000-4000-8000-000000000002"
    second["trace_id"] = "session-b"
    second["timestamp"] = "2026-08-18T14:03:30Z"

    assert client.post("/api/events", json=[first, second]).status_code == 201
    assert client.get("/api/chains").json() == []


def test_agent_session_correlates_events_without_trace_id(client: TestClient) -> None:
    first, second = load_stage3_events()[-1].copy(), load_stage3_events()[-1].copy()
    first["event_id"] = "50000000-0000-4000-8000-000000000001"
    first["trace_id"] = None
    first["actor"] = {"type": "agent", "id": "agent-a"}
    first["attributes"] = {"agent_session": "shared-agent-session"}
    second["event_id"] = "50000000-0000-4000-8000-000000000002"
    second["trace_id"] = None
    second["actor"] = {"type": "agent", "id": "agent-b"}
    second["attributes"] = {"agent_session": "shared-agent-session"}

    assert client.post("/api/events", json=[first, second]).status_code == 201
    chains = client.get("/api/chains").json()
    assert len(chains) == 1
    detail = client.get(f"/api/chains/{chains[0]['chain_id']}").json()
    assert any(
        edge["reason"] == "same agent_session: shared-agent-session"
        for edge in detail["edges"]
    )


def test_chain_filters_validation_and_missing_detail(client: TestClient) -> None:
    client.post("/api/events", json=load_stage3_events())

    external = client.get("/api/chains", params={"stage": "external_communication"})
    absent = client.get("/api/chains", params={"stage": "lateral_movement", "min_confidence": 100})
    invalid_stage = client.get("/api/chains", params={"stage": "initial_access"})
    invalid_confidence = client.get("/api/chains", params={"min_confidence": 101})
    missing = client.get("/api/chains/ffffffff-ffff-4fff-8fff-ffffffffffff")

    assert len(external.json()) == 1
    assert absent.json() == []
    assert invalid_stage.status_code == 422
    assert invalid_confidence.status_code == 422
    assert missing.status_code == 404
