"""Replay normalized JSONL events into the monitor API."""

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"event on line {line_number} must be a JSON object")
            for field in ("event_id", "timestamp"):
                if field not in event:
                    raise ValueError(f"event on line {line_number} is missing {field}")
            try:
                timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"invalid timestamp on line {line_number}") from exc
            if timestamp.tzinfo is None:
                raise ValueError(f"timestamp on line {line_number} must include a timezone")
            events.append(event)
    if not events:
        raise ValueError("event file is empty")
    return sorted(
        events,
        key=lambda event: (
            datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00")),
            str(event["event_id"]),
        ),
    )


def request_json(url: str, *, payload: object | None = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"API request failed ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"cannot reach monitor API at {url}: {exc.reason}") from exc


def replay_events(base_url: str, events: list[dict[str, Any]], delay: float = 0) -> None:
    for index, event in enumerate(events, start=1):
        request_json(f"{base_url}/api/events", payload=event)
        print(
            f"[{index:02d}/{len(events):02d}] {event['timestamp']} "
            f"{event.get('source', '?')}/{event.get('event_type', '?')}"
        )
        if delay and index < len(events):
            time.sleep(delay)


def collect_results(base_url: str, event_ids: set[str]) -> tuple[list[Any], list[Any]]:
    alerts = [
        alert
        for alert in request_json(f"{base_url}/api/alerts?limit=1000")
        if event_ids.intersection(alert["evidence_event_ids"])
    ]
    summaries = [
        chain
        for chain in request_json(f"{base_url}/api/chains?limit=1000")
        if event_ids.intersection(chain["event_ids"])
    ]
    chains = [request_json(f"{base_url}/api/chains/{chain['chain_id']}") for chain in summaries]
    return alerts, chains


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event_file", type=Path)
    parser.add_argument(
        "--api-url",
        default=os.getenv("MONITOR_API_URL", "http://localhost:3000"),
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="wall-clock delay between events in seconds (default: 0)",
    )
    parser.add_argument("--output", type=Path, help="write matched chain details as JSON")
    args = parser.parse_args()
    if args.delay < 0:
        parser.error("--delay must be zero or greater")

    base_url = args.api_url.rstrip("/")
    events = read_events(args.event_file)
    replayed_event_ids = {event["event_id"] for event in events}
    replay_events(base_url, events, args.delay)
    alerts, chains = collect_results(base_url, replayed_event_ids)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(chains, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(
        f"Replayed {len(events)} events; matched "
        f"{len(alerts)} alert(s) and {len(chains)} attack chain(s)."
    )
    for alert in alerts:
        print(f"- [{alert['severity_label']}] {alert['rule_id']}: {alert['rule_name']}")
    for chain in chains:
        stages = " -> ".join(chain["stages"])
        risk = chain["risk"]
        print(
            f"- [chain {chain['confidence']}% / risk {risk['score']} {risk['level']}] "
            f"{chain['chain_id']}: {stages}"
        )


if __name__ == "__main__":
    main()
