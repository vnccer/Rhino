from __future__ import annotations

import json
import os
from pathlib import Path

from .queue import EventQueue


class FileTailer:
    def __init__(self, path: Path, state_key: str, queue: EventQueue) -> None:
        self.path = path
        self.state_key = f"cursor:{state_key}"
        self.queue = queue

    def _state(self) -> tuple[int | None, int | None, int]:
        raw = self.queue.get_metadata(self.state_key)
        if not raw:
            try:
                stat = self.path.stat()
            except OSError:
                return None, None, 0
            initial = {"device": stat.st_dev, "inode": stat.st_ino, "offset": stat.st_size}
            self.queue.set_metadata(
                self.state_key, json.dumps(initial, separators=(",", ":"))
            )
            return stat.st_dev, stat.st_ino, stat.st_size
        try:
            value = json.loads(raw)
            return int(value["device"]), int(value["inode"]), int(value["offset"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None, None, 0

    def _candidate(self, device: int | None, inode: int | None) -> tuple[Path, os.stat_result] | None:
        candidates = [self.path]
        try:
            candidates.extend(
                item for item in self.path.parent.glob(f"{self.path.name}.*") if item.suffix != ".gz"
            )
        except OSError:
            pass
        existing: list[tuple[Path, os.stat_result]] = []
        for candidate in candidates:
            try:
                existing.append((candidate, candidate.stat()))
            except OSError:
                continue
        if device is not None and inode is not None:
            previous = next(
                (item for item in existing if item[1].st_dev == device and item[1].st_ino == inode),
                None,
            )
            if previous:
                return previous
        return next((item for item in existing if item[0] == self.path), None)

    def read(self, max_lines: int = 5000) -> tuple[list[tuple[int, str]], dict[str, int]]:
        device, inode, offset = self._state()
        selected = self._candidate(device, inode)
        if selected is None:
            return [], {"device": 0, "inode": 0, "offset": 0}
        path, stat = selected
        if stat.st_dev != device or stat.st_ino != inode or stat.st_size < offset:
            offset = 0
        records: list[tuple[int, str]] = []
        with path.open("rb") as handle:
            handle.seek(offset)
            while len(records) < max_lines:
                line = handle.readline()
                if not line or not line.endswith(b"\n"):
                    break
                records.append((handle.tell(), line.decode("utf-8", "replace")))
        if not records and path != self.path:
            try:
                current = self.path.stat()
            except OSError:
                pass
            else:
                self.queue.set_metadata(
                    self.state_key,
                    json.dumps(
                        {"device": current.st_dev, "inode": current.st_ino, "offset": 0},
                        separators=(",", ":"),
                    ),
                )
                return self.read(max_lines)
        return records, {"device": stat.st_dev, "inode": stat.st_ino, "offset": offset}

    def commit(self, state: dict[str, int], offset: int) -> None:
        state = {**state, "offset": offset}
        self.queue.set_metadata(self.state_key, json.dumps(state, separators=(",", ":")))
