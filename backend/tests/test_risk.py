import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.models.event import Event
from app.schemas.chain import AttackStage, RiskLevel
from app.services.risk import AssetCatalog, _level, calculate_risk

TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = next(
    root for root in (TEST_FILE.parents[2], TEST_FILE.parents[1]) if (root / "demo").is_dir()
)


def load_stage3_events() -> list[dict[str, Any]]:
    path = PROJECT_ROOT / "demo" / "events-stage3.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_chain_api_returns_deterministic_explainable_risk(client: TestClient) -> None:
    events = load_stage3_events()
    assert client.post("/api/events", json=events).status_code == 201

    first = client.get("/api/chains").json()[0]["risk"]
    assert client.post("/api/events", json=events).status_code == 201
    second = client.get("/api/chains").json()[0]["risk"]

    assert second == first
    assert 0 <= first["score"] <= 100
    assert first["level"] == "critical"
    assert set(first["breakdown"]) == {
        "alert_severity",
        "chain_completeness",
        "asset_importance",
        "automation_intensity",
        "correlation_confidence",
    }
    assert sum(item["contribution"] for item in first["breakdown"].values()) == pytest.approx(
        first["score"], abs=0.5
    )
    assert first["breakdown"]["chain_completeness"]["score"] == 100
    assert first["breakdown"]["asset_importance"]["score"] == 90
    assert set(first["evidence_event_ids"]) == {
        event["event_id"] for event in events if event["trace_id"] == "attack-chain-01"
    }
    assert first["reasons"]
    assert first["recommendations"]

    chain_id = client.get("/api/chains").json()[0]["chain_id"]
    assert client.get(f"/api/chains/{chain_id}").json()["risk"] == first


def _events(values: list[dict[str, Any]]) -> list[Event]:
    return [
        Event(
            event_id=UUID(value["event_id"]),
            timestamp=datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00")),
            source=value["source"],
            event_type=value["event_type"],
            actor=value.get("actor"),
            action=value.get("action"),
            object=value.get("object"),
            result=value.get("result", "unknown"),
            severity=value.get("severity", 0),
            trace_id=value.get("trace_id"),
            parent_event_id=value.get("parent_event_id"),
            attributes=value.get("attributes", {}),
        )
        for value in values
    ]


def test_removing_key_stages_reduces_completeness_and_total_score() -> None:
    values = load_stage3_events()[:-1]
    events = _events(values)
    alert = SimpleNamespace(
        severity=100,
        rule_name="Critical demo alert",
        evidence_event_ids=[value["event_id"] for value in values[:4]],
    )
    complete_stages = list(AttackStage)
    reduced_stages = [
        AttackStage.RECONNAISSANCE,
        AttackStage.CREDENTIAL_ACCESS,
        AttackStage.EXECUTION,
    ]

    complete = calculate_risk(events, [alert], complete_stages, 90)
    reduced = calculate_risk(events, [alert], reduced_stages, 90)

    assert complete["breakdown"]["chain_completeness"]["score"] == 100
    assert reduced["breakdown"]["chain_completeness"]["score"] == 50
    assert reduced["score"] < complete["score"]


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, RiskLevel.LOW), (29, RiskLevel.LOW), (30, RiskLevel.MEDIUM),
     (59, RiskLevel.MEDIUM), (60, RiskLevel.HIGH), (79, RiskLevel.HIGH),
     (80, RiskLevel.CRITICAL), (100, RiskLevel.CRITICAL)],
)
def test_risk_level_boundaries(score: int, expected: RiskLevel) -> None:
    assert _level(score) == expected


def test_asset_catalog_rejects_out_of_range_importance() -> None:
    with pytest.raises(ValidationError):
        AssetCatalog.model_validate(
            {"default_importance": 40, "assets": [
                {"entity_type": "host", "entity_id": "server-1", "importance": 101}
            ]}
        )
