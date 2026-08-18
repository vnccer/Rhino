"""Replay normalized JSONL events into the monitor API."""

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
    if not events:
        raise ValueError("event file is empty")
    return events


def request_json(url: str, *, payload: object | None = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event_file", type=Path)
    parser.add_argument(
        "--api-url",
        default=os.getenv("MONITOR_API_URL", "http://localhost:8000"),
    )
    args = parser.parse_args()

    base_url = args.api_url.rstrip("/")
    events = read_events(args.event_file)
    replayed_event_ids = {event["event_id"] for event in events}
    request_json(f"{base_url}/api/events", payload=events)
    alerts = [
        alert
        for alert in request_json(f"{base_url}/api/alerts?limit=1000")
        if replayed_event_ids.intersection(alert["evidence_event_ids"])
    ]
    chains = [
        chain
        for chain in request_json(f"{base_url}/api/chains?limit=1000")
        if replayed_event_ids.intersection(chain["event_ids"])
    ]
    print(
        f"Replayed {len(events)} events; matched "
        f"{len(alerts)} alert(s) and {len(chains)} attack chain(s)."
    )
    for alert in alerts:
        print(f"- [{alert['severity_label']}] {alert['rule_id']}: {alert['rule_name']}")
    for chain in chains:
        stages = " -> ".join(chain["stages"])
        print(f"- [chain {chain['confidence']}%] {chain['chain_id']}: {stages}")


if __name__ == "__main__":
    main()
