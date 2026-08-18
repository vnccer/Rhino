"""Start the stack and replay a reproducible demo scenario."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from replay import collect_results, read_events, replay_events

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = {
    "ai_attack": Path(__file__).with_name("ai_attack.jsonl"),
    "normal_ops": Path(__file__).with_name("normal_ops.jsonl"),
}


def wait_for_api(url: str, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{url}/api/overview", timeout=3) as response:
                if response.status == 200:
                    return
        except URLError:
            time.sleep(2)
    raise RuntimeError(f"monitor API did not become healthy within {timeout:g} seconds")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS, nargs="?", default="ai_attack")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if args.delay < 0:
        parser.error("--delay must be zero or greater")

    compose_command = ["docker", "compose", "up", "-d"]
    if not args.skip_build:
        compose_command.append("--build")
    subprocess.run(compose_command, cwd=REPOSITORY_ROOT, check=True)

    api_url = "http://localhost:3000"
    wait_for_api(api_url)
    events = read_events(SCENARIOS[args.scenario])
    replay_events(api_url, events, args.delay)
    alerts, chains = collect_results(api_url, {event["event_id"] for event in events})

    output = Path(__file__).with_name("output") / f"{args.scenario}_chains.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(chains, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    high_risk = [chain for chain in chains if chain["risk"]["level"] in {"high", "critical"}]
    print(
        f"Scenario complete: {len(events)} events, {len(alerts)} alerts, "
        f"{len(chains)} chains, {len(high_risk)} high-risk chains."
    )
    print(f"Chain details: {output}")
    print("Console: http://localhost:3000")

    if args.scenario == "normal_ops" and high_risk:
        raise RuntimeError("normal operations scenario unexpectedly produced a high-risk chain")
    if args.scenario == "ai_attack" and not high_risk:
        raise RuntimeError("AI attack scenario did not produce a high-risk chain")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Demo failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
