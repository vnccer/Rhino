import importlib.util
from pathlib import Path

import pytest

TEST_FILE = Path(__file__).resolve()
REPLAY_PATH = next(
    path
    for path in (
        TEST_FILE.parents[1] / "demo" / "replay.py",
        TEST_FILE.parents[2] / "demo" / "replay.py",
    )
    if path.is_file()
)
SPEC = importlib.util.spec_from_file_location("demo_replay", REPLAY_PATH)
assert SPEC and SPEC.loader
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


def test_read_events_orders_by_timestamp(tmp_path: Path) -> None:
    event_file = tmp_path / "events.jsonl"
    event_file.write_text(
        '{"event_id":"second","timestamp":"2026-08-18T00:00:02Z"}\n'
        '{"event_id":"first","timestamp":"2026-08-18T00:00:01Z"}\n',
        encoding="utf-8",
    )

    events = replay.read_events(event_file)

    assert [event["event_id"] for event in events] == ["first", "second"]


def test_read_events_rejects_timestamp_without_timezone(tmp_path: Path) -> None:
    event_file = tmp_path / "events.jsonl"
    event_file.write_text(
        '{"event_id":"invalid","timestamp":"2026-08-18T00:00:00"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must include a timezone"):
        replay.read_events(event_file)
