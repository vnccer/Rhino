from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aasm_linux_collector.queue import EventQueue, QueueFullError


def event(event_id: str, padding: int = 0) -> dict[str, object]:
    return {"event_id": event_id, "value": "x" * padding}


def test_queue_recovers_order_and_acknowledges_only_confirmed_events(tmp_path: Path) -> None:
    path = tmp_path / "queue.db"
    first = EventQueue(path, max_bytes=10_000, retention_hours=24)
    assert first.enqueue(event("first"))
    assert first.enqueue(event("second"))
    assert not first.enqueue(event("first"))
    first.close()

    recovered = EventQueue(path, max_bytes=10_000, retention_hours=24)
    assert [item["event_id"] for item in recovered.peek(10, 10_000)] == ["first", "second"]
    assert recovered.acknowledge(["first"]) == 1
    assert [item["event_id"] for item in recovered.peek(10, 10_000)] == ["second"]
    recovered.close()


def test_queue_enforces_capacity_and_retention(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "queue.db", max_bytes=100, retention_hours=1)
    with pytest.raises(QueueFullError):
        queue.enqueue(event("oversized", 200))

    old = datetime.now(timezone.utc) - timedelta(hours=2)
    queue.enqueue(event("expired"), now=old)
    queue.enqueue(event("current"))
    assert queue.purge_expired() == 0  # enqueue already applies the retention policy
    assert [item["event_id"] for item in queue.peek(10, 100)] == ["current"]
    queue.close()

