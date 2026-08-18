from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.chain import AttackChain, ChainEdge, ChainNode
from app.models.event import Event
from app.schemas.chain import AttackStage
from app.services.risk import calculate_risk

CHAIN_NAMESPACE = UUID("cebe0d0c-2678-4a5b-89ee-d5dd8976fab3")
NODE_NAMESPACE = UUID("b9278d82-5806-401a-a150-e9de4f6c8d7a")
EDGE_NAMESPACE = UUID("38115002-68d4-4af7-ab26-b68551d71902")
TEMPORAL_WINDOW = timedelta(minutes=5)
STAGE_ORDER = list(AttackStage)


class _DisjointSet:
    def __init__(self, values: list[UUID]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: UUID) -> UUID:
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            value, self.parent[value] = self.parent[value], root
        return root

    def union(self, left: UUID, right: UUID) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _stage(event: Event) -> AttackStage:
    attributes = event.attributes or {}
    action = (event.action or "").lower()
    if attributes.get("lateral_movement") or action in {"remote_execute", "move_laterally"}:
        return AttackStage.LATERAL_MOVEMENT
    if attributes.get("persistence") or action in {
        "persist",
        "create_service",
        "schedule_task",
    }:
        return AttackStage.PERSISTENCE
    if event.event_type == "network_connect" or attributes.get("destination_domain"):
        return AttackStage.EXTERNAL_COMMUNICATION
    if action == "authenticate" or attributes.get("credential_access"):
        return AttackStage.CREDENTIAL_ACCESS
    if event.event_type == "http_request" and action in {"request", "scan", "probe"}:
        return AttackStage.RECONNAISSANCE
    return AttackStage.EXECUTION


def _entity_key(entity_type: str, entity_id: Any) -> tuple[str, str] | None:
    if entity_id is None or str(entity_id).strip() == "":
        return None
    return entity_type, str(entity_id)


def _event_entities(event: Event) -> list[tuple[str, str, str]]:
    entities: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(entity_type: str, entity_id: Any, label: Any = None) -> None:
        key = _entity_key(entity_type, entity_id)
        if key is None or key in seen:
            return
        seen.add(key)
        entities.append((key[0], key[1], str(label or key[1])))

    if event.actor:
        add(str(event.actor.get("type", "resource")), event.actor.get("id"))
    if event.object:
        object_type = str(event.object.get("type", "resource"))
        add(object_type, event.object.get("id"), event.object.get("name"))
    if event.trace_id:
        add("session", event.trace_id)

    attributes = event.attributes or {}
    attribute_entities = {
        "agent_id": "agent",
        "user_id": "user",
        "pid": "process",
        "process_id": "process",
        "ppid": "process",
        "parent_pid": "process",
        "sha256": "file",
        "file_hash": "file",
        "source_ip": "ip",
        "src_ip": "ip",
        "destination_ip": "ip",
        "dst_ip": "ip",
        "domain": "domain",
        "destination_domain": "domain",
        "session_id": "session",
        "agent_session": "session",
    }
    for field, entity_type in attribute_entities.items():
        add(entity_type, attributes.get(field))
    return entities


def _strong_keys(event: Event) -> set[tuple[str, str]]:
    allowed = {"process", "file", "ip", "domain"}
    return {(kind, value) for kind, value, _ in _event_entities(event) if kind in allowed}


def _session_keys(event: Event) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if event.trace_id:
        keys.add(("trace_id", event.trace_id))
    attributes = event.attributes or {}
    for field in ("agent_session", "session_id"):
        if attributes.get(field):
            keys.add((field, str(attributes[field])))
    return keys


def _actor_key(event: Event) -> tuple[str, str] | None:
    actor = event.actor or {}
    return _entity_key(str(actor.get("type", "")), actor.get("id"))


def _semantic_relationship(event: Event) -> str:
    if event.event_type != "tool_call" and (event.action or "").lower() in {
        "execute",
        "remote_execute",
    }:
        return "executes"
    return {
        "tool_call": "calls",
        "process_start": "creates",
        "file_write": "writes",
        "network_connect": "connects",
        "http_request": "connects",
    }.get(event.event_type, "executes")


def rebuild_attack_chains(db: Session) -> list[AttackChain]:
    events = list(db.scalars(select(Event).order_by(Event.timestamp, Event.event_id)))
    alerts = list(db.scalars(select(Alert).order_by(Alert.start_time, Alert.alert_id)))
    db.execute(delete(ChainEdge))
    db.execute(delete(ChainNode))
    db.execute(delete(AttackChain))
    if len(events) < 2:
        return []

    by_id = {event.event_id: event for event in events}
    disjoint = _DisjointSet(list(by_id))
    links: list[tuple[UUID, UUID, str, int, int]] = []

    def link(left: UUID, right: UUID, reason: str, priority: int, confidence: int) -> None:
        if left == right or left not in by_id or right not in by_id:
            return
        disjoint.union(left, right)
        links.append((left, right, reason, priority, confidence))

    for event in events:
        if event.parent_event_id:
            link(event.parent_event_id, event.event_id, "parent_event_id", 1, 100)

    session_groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    strong_groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    actor_groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        for key in _session_keys(event):
            session_groups[key].append(event)
        for key in _strong_keys(event):
            strong_groups[key].append(event)
        actor = _actor_key(event)
        if actor:
            actor_groups[actor].append(event)

    for (field, value), grouped in session_groups.items():
        for event in grouped[1:]:
            link(grouped[0].event_id, event.event_id, f"same {field}: {value}", 2, 90)
    for (kind, value), grouped in strong_groups.items():
        for event in grouped[1:]:
            link(grouped[0].event_id, event.event_id, f"shared {kind}: {value}", 3, 75)
    for actor, grouped in actor_groups.items():
        grouped.sort(key=lambda item: (_utc(item.timestamp), str(item.event_id)))
        for previous, current in zip(grouped, grouped[1:], strict=False):
            conflicting_traces = (
                previous.trace_id
                and current.trace_id
                and previous.trace_id != current.trace_id
            )
            if not conflicting_traces and _utc(current.timestamp) - _utc(previous.timestamp) <= TEMPORAL_WINDOW:
                link(previous.event_id, current.event_id, f"same actor near in time: {actor[1]}", 4, 50)

    for alert in alerts:
        evidence = [UUID(value) for value in alert.evidence_event_ids if UUID(value) in by_id]
        for event_id in evidence[1:]:
            link(evidence[0], event_id, f"same alert: {alert.rule_id}", 2, 95)

    components: dict[UUID, list[Event]] = defaultdict(list)
    for event in events:
        components[disjoint.find(event.event_id)].append(event)

    now = datetime.now(UTC)
    chains: list[AttackChain] = []
    for component in components.values():
        if len(component) < 2:
            continue
        component.sort(key=lambda item: (_utc(item.timestamp), str(item.event_id)))
        event_ids = {event.event_id for event in component}
        component_links = [item for item in links if item[0] in event_ids and item[1] in event_ids]
        signature = ",".join(sorted(str(value) for value in event_ids))
        chain_id = uuid5(CHAIN_NAMESPACE, signature)
        stages = [stage for stage in STAGE_ORDER if any(_stage(event) == stage for event in component)]
        related_alerts = [
            alert
            for alert in alerts
            if any(UUID(value) in event_ids for value in alert.evidence_event_ids)
        ]
        confidence = round(sum(link_item[4] for link_item in component_links) / len(component_links))
        risk = calculate_risk(component, related_alerts, stages, confidence)
        chain = AttackChain(
            chain_id=chain_id,
            title=f"Attack chain: {' -> '.join(stage.value for stage in stages)}",
            start_time=_utc(component[0].timestamp),
            end_time=_utc(component[-1].timestamp),
            stages=[stage.value for stage in stages],
            event_ids=[str(event.event_id) for event in component],
            alert_ids=[str(alert.alert_id) for alert in related_alerts],
            confidence=confidence,
            risk_score=risk["score"],
            risk_level=risk["level"],
            risk_breakdown=risk["breakdown"],
            risk_reasons=risk["reasons"],
            risk_evidence_event_ids=risk["evidence_event_ids"],
            recommendations=risk["recommendations"],
            created_at=now,
            updated_at=now,
        )
        db.add(chain)
        db.flush()
        chains.append(chain)

        nodes: dict[tuple[str, str], ChainNode] = {}
        event_node_keys: dict[UUID, list[tuple[str, str]]] = {}
        for event in component:
            event_node_keys[event.event_id] = []
            for entity_type, entity_id, label in _event_entities(event):
                key = (entity_type, entity_id)
                event_node_keys[event.event_id].append(key)
                if key not in nodes:
                    nodes[key] = ChainNode(
                        node_id=uuid5(NODE_NAMESPACE, f"{chain_id}:{entity_type}:{entity_id}"),
                        chain_id=chain_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        label=label,
                        stage=_stage(event).value,
                        event_ids=[str(event.event_id)],
                    )
                elif str(event.event_id) not in nodes[key].event_ids:
                    nodes[key].event_ids.append(str(event.event_id))
        db.add_all(nodes.values())
        db.flush()

        edge_signatures: set[str] = set()

        def add_edge(
            source_key: tuple[str, str],
            target_key: tuple[str, str],
            relationship: str,
            event_id: UUID | None,
            reason: str,
            priority: int,
            edge_confidence: int,
        ) -> None:
            if source_key == target_key:
                return
            signature = f"{nodes[source_key].node_id}:{nodes[target_key].node_id}:{relationship}:{event_id}:{reason}"
            if signature in edge_signatures:
                return
            edge_signatures.add(signature)
            db.add(
                ChainEdge(
                    edge_id=uuid5(EDGE_NAMESPACE, signature),
                    chain_id=chain_id,
                    source_node_id=nodes[source_key].node_id,
                    target_node_id=nodes[target_key].node_id,
                    relationship=relationship,
                    event_id=event_id,
                    reason=reason,
                    priority=priority,
                    confidence=edge_confidence,
                )
            )

        for event in component:
            keys = event_node_keys[event.event_id]
            if len(keys) >= 2:
                add_edge(
                    keys[0], keys[1], _semantic_relationship(event), event.event_id,
                    f"observed in event {event.event_id}", 0, 100,
                )
        for left, right, reason, priority, edge_confidence in component_links:
            pair = next(
                (
                    (left_key, right_key)
                    for left_key in event_node_keys[left]
                    for right_key in event_node_keys[right]
                    if left_key != right_key
                ),
                None,
            )
            if pair:
                relationship = "derived_from" if priority == 1 else "associated_with"
                add_edge(pair[0], pair[1], relationship, right, reason, priority, edge_confidence)
    db.flush()
    return chains


def query_chains(
    db: Session,
    *,
    stage: str | None = None,
    min_confidence: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AttackChain]:
    statement = select(AttackChain)
    if min_confidence is not None:
        statement = statement.where(AttackChain.confidence >= min_confidence)
    statement = statement.order_by(AttackChain.end_time.desc(), AttackChain.chain_id)
    records = list(db.scalars(statement))
    if stage is not None:
        records = [record for record in records if stage in record.stages]
    return records[offset : offset + limit]


def get_chain(db: Session, chain_id: UUID) -> tuple[AttackChain, list[ChainNode], list[ChainEdge], list[Event]] | None:
    chain = db.get(AttackChain, chain_id)
    if chain is None:
        return None
    nodes = list(db.scalars(select(ChainNode).where(ChainNode.chain_id == chain_id).order_by(ChainNode.entity_type, ChainNode.entity_id)))
    edges = list(db.scalars(select(ChainEdge).where(ChainEdge.chain_id == chain_id).order_by(ChainEdge.priority, ChainEdge.edge_id)))
    event_ids = [UUID(value) for value in chain.event_ids]
    events_by_id = {event.event_id: event for event in db.scalars(select(Event).where(Event.event_id.in_(event_ids)))}
    events = [events_by_id[event_id] for event_id in event_ids]
    return chain, nodes, edges, events
