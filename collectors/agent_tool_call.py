"""Submit an example AI Agent tool-call event to the monitor API."""

import argparse
import json
import os
from datetime import UTC, datetime
from urllib.request import Request, urlopen
from uuid import uuid4


def build_event(agent_id: str, tool: str, trace_id: str) -> dict[str, object]:
    return {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "agent",
        "event_type": "tool_call",
        "actor": {"type": "agent", "id": agent_id},
        "action": "execute",
        "object": {"type": "tool", "id": tool, "name": tool},
        "result": "success",
        "severity": 0,
        "trace_id": trace_id,
        "parent_event_id": None,
        "attributes": {"example": True},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", default="agent-01")
    parser.add_argument("--tool", default="shell")
    parser.add_argument("--trace-id", default="demo-session-01")
    parser.add_argument(
        "--api-url",
        default=os.getenv("MONITOR_API_URL", "http://localhost:8000"),
    )
    args = parser.parse_args()

    payload = json.dumps(build_event(args.agent_id, args.tool, args.trace_id)).encode()
    request = Request(
        f"{args.api_url.rstrip('/')}/api/events",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        print(response.read().decode())


if __name__ == "__main__":
    main()
