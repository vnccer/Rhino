import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.schemas.rule import (
    SEVERITY_SCORES,
    CountConditions,
    DetectionRule,
    SequenceConditions,
)
from app.services.rules import load_rules

ALERT_NAMESPACE = UUID("769b2248-99ef-4f0d-9942-39cecf81984d")
MISSING = object()


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _field_value(event: Event, path: str) -> Any:
    value: Any = event
    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part, MISSING)
        else:
            value = getattr(value, part, MISSING)
        if value is MISSING:
            break
    if isinstance(value, UUID):
        return str(value)
    return value


def _compare(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, dict):
        return actual is not MISSING and actual == expected

    for operator, operand in expected.items():
        if operator == "exists":
            matched = (actual is not MISSING) is bool(operand)
        elif actual is MISSING:
            matched = False
        elif operator == "eq":
            matched = actual == operand
        elif operator == "ne":
            matched = actual != operand
        elif operator == "in":
            matched = actual in operand
        elif operator == "not_in":
            matched = actual not in operand
        elif operator == "contains":
            matched = isinstance(actual, (str, list, dict)) and operand in actual
        elif operator == "starts_with":
            matched = isinstance(actual, str) and actual.startswith(str(operand))
        elif operator == "regex":
            matched = isinstance(actual, str) and re.search(str(operand), actual) is not None
        else:
            raise ValueError(f"unsupported rule operator: {operator}")
        if not matched:
            return False
    return True


def event_matches(event: Event, match: dict[str, Any]) -> bool:
    return all(_compare(_field_value(event, field), expected) for field, expected in match.items())


def _group_key(event: Event, fields: list[str]) -> tuple[Any, ...]:
    return tuple(_field_value(event, field) for field in fields)


def _window_events(db: Session, trigger: Event, rule: DetectionRule) -> list[Event]:
    start_time = trigger.timestamp - rule.window
    statement = (
        select(Event)
        .where(Event.timestamp >= start_time, Event.timestamp <= trigger.timestamp)
        .order_by(Event.timestamp, Event.event_id)
    )
    return list(db.scalars(statement))


def _count_evidence(
    candidates: list[Event], trigger: Event, rule: DetectionRule, conditions: CountConditions
) -> list[Event] | None:
    if not event_matches(trigger, conditions.match):
        return None
    trigger_group = _group_key(trigger, conditions.group_by)
    matched = [
        event
        for event in candidates
        if _group_key(event, conditions.group_by) == trigger_group
        and event_matches(event, conditions.match)
    ]

    if conditions.distinct_by:
        distinct: dict[Any, Event] = {}
        for event in matched:
            distinct[_field_value(event, conditions.distinct_by)] = event
        evidence = list(distinct.values())
        count = len(distinct)
    else:
        evidence = matched
        count = len(matched)

    # Fire when the threshold is crossed. This avoids one alert per subsequent event.
    return evidence if count == rule.threshold else None


def _sequence_evidence(
    candidates: list[Event], trigger: Event, conditions: SequenceConditions
) -> list[Event] | None:
    if not event_matches(trigger, conditions.ordered[-1].match):
        return None
    trigger_group = _group_key(trigger, conditions.group_by)
    grouped = [
        event for event in candidates if _group_key(event, conditions.group_by) == trigger_group
    ]
    try:
        boundary = next(index for index, event in enumerate(grouped) if event.event_id == trigger.event_id)
    except StopIteration:
        return None

    selected: list[Event] = []
    for reverse_index, step in enumerate(reversed(conditions.ordered)):
        needed = step.min_count
        if reverse_index == 0:
            selected.append(trigger)
            needed -= 1
            boundary -= 1
        while needed:
            while boundary >= 0 and not event_matches(grouped[boundary], step.match):
                boundary -= 1
            if boundary < 0:
                return None
            selected.append(grouped[boundary])
            boundary -= 1
            needed -= 1
    return sorted(selected, key=lambda event: (_utc_timestamp(event.timestamp), str(event.event_id)))


def _build_alert(rule: DetectionRule, evidence: list[Event]) -> Alert:
    event_ids = [str(event.event_id) for event in evidence]
    signature = f"{rule.id}:{','.join(event_ids)}"
    return Alert(
        alert_id=uuid5(ALERT_NAMESPACE, signature),
        rule_id=rule.id,
        rule_name=rule.name,
        severity=SEVERITY_SCORES[rule.severity],
        severity_label=rule.severity.value,
        mitre=rule.mitre,
        start_time=min(_utc_timestamp(event.timestamp) for event in evidence),
        end_time=max(_utc_timestamp(event.timestamp) for event in evidence),
        evidence_event_ids=event_ids,
        evidence={
            "event_count": len(evidence),
            "trigger_event_id": event_ids[-1],
            "explanation": f"Rule '{rule.name}' matched {len(evidence)} event(s)",
        },
        created_at=datetime.now(UTC),
    )


def detect_events(db: Session, events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    rules = load_rules()
    for trigger in sorted(
        events, key=lambda event: (_utc_timestamp(event.timestamp), str(event.event_id))
    ):
        for rule in rules:
            candidates = _window_events(db, trigger, rule)
            if isinstance(rule.conditions, CountConditions):
                evidence = _count_evidence(candidates, trigger, rule, rule.conditions)
            else:
                evidence = _sequence_evidence(candidates, trigger, rule.conditions)
            if not evidence:
                continue
            alert = _build_alert(rule, evidence)
            if db.get(Alert, alert.alert_id) is None:
                try:
                    with db.begin_nested():
                        db.add(alert)
                        db.flush()
                except IntegrityError:
                    if db.get(Alert, alert.alert_id) is None:
                        raise
                else:
                    alerts.append(alert)
    return alerts
