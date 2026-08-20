from pathlib import Path

from aasm_linux_collector.queue import EventQueue
from aasm_linux_collector.tailer import FileTailer


def test_tailer_starts_at_end_then_persists_new_line_cursor(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("historical\n", encoding="utf-8")
    queue = EventQueue(tmp_path / "queue.db", max_bytes=10_000, retention_hours=24)
    tailer = FileTailer(log, "auth", queue)

    assert tailer.read()[0] == []
    with log.open("a", encoding="utf-8") as handle:
        handle.write("new-event\n")
    records, state = tailer.read()
    assert [line.rstrip("\r\n") for _, line in records] == ["new-event"]
    tailer.commit(state, records[-1][0])

    recovered = FileTailer(log, "auth", queue)
    assert recovered.read()[0] == []
    queue.close()
