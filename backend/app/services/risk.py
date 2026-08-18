from collections import Counter
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.event import Event
from app.schemas.chain import AttackStage, RiskLevel

WEIGHTS = {
    "alert_severity": 0.30,
    "chain_completeness": 0.25,
    "asset_importance": 0.20,
    "automation_intensity": 0.15,
    "correlation_confidence": 0.10,
}


class AssetEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    importance: int = Field(ge=0, le=100)
    name: str | None = None


class AssetCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_importance: int = Field(default=40, ge=0, le=100)
    assets: list[AssetEntry] = Field(default_factory=list)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def resolve_assets_path() -> Path:
    configured = get_settings().assets_path
    if configured:
        return Path(configured).expanduser().resolve()
    candidates = (
        Path.cwd() / "assets.yaml",
        Path.cwd().parent / "assets.yaml",
        Path(__file__).resolve().parents[3] / "assets.yaml",
        Path("/app/assets.yaml"),
    )
    return next((path for path in candidates if path.is_file()), candidates[0])


@lru_cache(maxsize=8)
def _load_asset_catalog(path_string: str) -> AssetCatalog:
    path = Path(path_string)
    if not path.is_file():
        raise RuntimeError(f"asset importance configuration does not exist: {path}")
    with path.open(encoding="utf-8") as stream:
        return AssetCatalog.model_validate(yaml.safe_load(stream) or {})


def load_asset_catalog() -> AssetCatalog:
    return _load_asset_catalog(str(resolve_assets_path()))


def _event_entity_keys(event: Event) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if event.actor and event.actor.get("id"):
        keys.add((str(event.actor.get("type", "resource")), str(event.actor["id"])))
    if event.object and event.object.get("id"):
        keys.add((str(event.object.get("type", "resource")), str(event.object["id"])))
    attributes = event.attributes or {}
    for field, entity_type in {
        "agent_id": "agent", "user_id": "user", "pid": "process",
        "process_id": "process", "destination_ip": "ip", "dst_ip": "ip",
        "destination_domain": "domain", "domain": "domain",
    }.items():
        if attributes.get(field) is not None:
            keys.add((entity_type, str(attributes[field])))
    return keys


def _alert_factor(alerts: list[Alert]) -> tuple[int, list[str]]:
    if not alerts:
        return 0, ["No detection alert is linked to this chain"]
    highest = max(alert.severity for alert in alerts)
    names = sorted(alert.rule_name for alert in alerts if alert.severity == highest)
    return highest, [f"Highest linked alert severity is {highest}: {', '.join(names)}"]


def _completeness_factor(stages: list[AttackStage]) -> tuple[int, list[str]]:
    unique_stages = sorted({stage.value for stage in stages})
    score = round(len(unique_stages) / len(AttackStage) * 100)
    return score, [f"Observed {len(unique_stages)} of {len(AttackStage)} attack stages: {', '.join(unique_stages)}"]


def _asset_factor(events: list[Event]) -> tuple[int, list[str]]:
    catalog = load_asset_catalog()
    configured = {(asset.entity_type, asset.entity_id): asset for asset in catalog.assets}
    matched = [configured[key] for event in events for key in _event_entity_keys(event) if key in configured]
    if not matched:
        return catalog.default_importance, [f"No configured asset matched; default importance is {catalog.default_importance}"]
    asset = max(matched, key=lambda item: (item.importance, item.entity_type, item.entity_id))
    label = asset.name or f"{asset.entity_type}:{asset.entity_id}"
    return asset.importance, [f"Highest-impact asset is {label} with importance {asset.importance}"]


def _automation_factor(events: list[Event]) -> tuple[int, list[str]]:
    ordered = sorted(events, key=lambda event: (_utc(event.timestamp), str(event.event_id)))
    duration_seconds = max((_utc(ordered[-1].timestamp) - _utc(ordered[0].timestamp)).total_seconds(), 1)
    events_per_minute = len(ordered) * 60 / duration_seconds
    frequency = 100 if events_per_minute >= 12 else 75 if events_per_minute >= 6 else 50 if events_per_minute >= 3 else 25 if events_per_minute >= 1 else 0

    timestamp_counts = Counter(_utc(event.timestamp) for event in ordered)
    max_concurrency = max(timestamp_counts.values(), default=1)
    concurrency = 100 if max_concurrency >= 4 else 75 if max_concurrency == 3 else 50 if max_concurrency == 2 else 0

    switch_delays = [
        (_utc(current.timestamp) - _utc(previous.timestamp)).total_seconds()
        for previous, current in zip(ordered, ordered[1:], strict=False)
        if previous.result == "failure" and (
            current.result == "success" or current.event_type != previous.event_type
        )
    ]
    fastest_switch = min(switch_delays, default=None)
    failure_switch = 100 if fastest_switch is not None and fastest_switch <= 5 else 75 if fastest_switch is not None and fastest_switch <= 15 else 50 if fastest_switch is not None and fastest_switch <= 30 else 0

    tool_count = len({event.event_type for event in ordered})
    cross_tool = min(100, max(0, tool_count - 1) * 25)
    score = round((frequency + concurrency + failure_switch + cross_tool) / 4)
    switch_text = "not observed" if fastest_switch is None else f"{fastest_switch:g}s"
    reasons = [
        f"Frequency: {events_per_minute:.2f} events/minute (score {frequency})",
        f"Concurrency: {max_concurrency} event(s) at the busiest timestamp (score {concurrency})",
        f"Fastest failure-to-switch interval: {switch_text} (score {failure_switch})",
        f"Cross-tool continuity: {tool_count} event types (score {cross_tool})",
    ]
    return score, reasons


def _level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _recommendations(level: RiskLevel, stages: list[AttackStage]) -> list[str]:
    recommendations = {
        RiskLevel.LOW: ["Continue monitoring and retain the linked evidence"],
        RiskLevel.MEDIUM: ["Review the affected identities and assets within the current response cycle"],
        RiskLevel.HIGH: ["Triage immediately and isolate confirmed affected endpoints"],
        RiskLevel.CRITICAL: ["Activate incident response and contain affected identities, hosts, and network paths"],
    }[level]
    stage_set = set(stages)
    if AttackStage.CREDENTIAL_ACCESS in stage_set:
        recommendations.append("Reset exposed credentials and revoke active sessions")
    if AttackStage.PERSISTENCE in stage_set:
        recommendations.append("Remove persistence artifacts and verify system integrity")
    if AttackStage.EXTERNAL_COMMUNICATION in stage_set:
        recommendations.append("Block identified command-and-control destinations and inspect related traffic")
    return recommendations


def calculate_risk(
    events: list[Event], alerts: list[Alert], stages: list[AttackStage], confidence: int
) -> dict[str, Any]:
    factors = {
        "alert_severity": _alert_factor(alerts),
        "chain_completeness": _completeness_factor(stages),
        "asset_importance": _asset_factor(events),
        "automation_intensity": _automation_factor(events),
        "correlation_confidence": (confidence, [f"Attack-chain correlation confidence is {confidence}"]),
    }
    breakdown: dict[str, dict[str, Any]] = {}
    for name, (score, reasons) in factors.items():
        weight = WEIGHTS[name]
        breakdown[name] = {
            "score": score,
            "weight": weight,
            "contribution": round(score * weight, 2),
            "reasons": reasons,
        }
    total = round(sum(item["contribution"] for item in breakdown.values()))
    level = _level(total)
    reasons = [reason for item in breakdown.values() for reason in item["reasons"]]
    evidence_ids = sorted(
        {str(event.event_id) for event in events}
        | {value for alert in alerts for value in alert.evidence_event_ids}
    )
    return {
        "score": total,
        "level": level.value,
        "breakdown": breakdown,
        "reasons": reasons,
        "evidence_event_ids": evidence_ids,
        "recommendations": _recommendations(level, stages),
    }
