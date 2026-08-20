from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class QueueFullError(RuntimeError):
    pass


class EventQueue:
    def __init__(self, path: Path, max_bytes: int, retention_hours: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.retention = timedelta(hours=retention_hours)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def _purge_expired_locked(self, now: datetime) -> int:
        cutoff = (now - self.retention).isoformat()
        cursor = self._db.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
        self._db.commit()
        return cursor.rowcount

    def purge_expired(self, now: datetime | None = None) -> int:
        with self._lock:
            return self._purge_expired_locked(now or datetime.now(timezone.utc))

    def enqueue(self, event: dict[str, Any], now: datetime | None = None) -> bool:
        payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        payload_bytes = len(payload.encode("utf-8"))
        if payload_bytes > self.max_bytes:
            raise QueueFullError("one event exceeds the configured queue size")
        created_at = (now or datetime.now(timezone.utc)).isoformat()
        with self._lock:
            self._purge_expired_locked(now or datetime.now(timezone.utc))
            if self._db.execute(
                "SELECT 1 FROM events WHERE event_id = ?", (str(event["event_id"]),)
            ).fetchone():
                return False
            current_bytes = self._db.execute(
                "SELECT COALESCE(SUM(payload_bytes), 0) FROM events"
            ).fetchone()[0]
            if current_bytes + payload_bytes > self.max_bytes:
                raise QueueFullError(
                    f"queue is full ({current_bytes} of {self.max_bytes} payload bytes used)"
                )
            cursor = self._db.execute(
                "INSERT INTO events(event_id, payload, payload_bytes, created_at) VALUES (?, ?, ?, ?)",
                (str(event["event_id"]), payload, payload_bytes, created_at),
            )
            self._db.commit()
            return cursor.rowcount == 1

    def peek(self, limit: int, max_bytes: int) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT payload, payload_bytes FROM events ORDER BY sequence LIMIT ?", (limit,)
        ).fetchall()
        output: list[dict[str, Any]] = []
        total = 2
        for payload, payload_bytes in rows:
            next_total = total + payload_bytes + (1 if output else 0)
            if output and next_total > max_bytes:
                break
            if not output and next_total > max_bytes:
                raise QueueFullError("oldest queued event exceeds maximum upload body size")
            output.append(json.loads(payload))
            total = next_total
        return output

    def acknowledge(self, event_ids: list[str]) -> int:
        if not event_ids:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            cursor = self._db.execute(
                f"DELETE FROM events WHERE event_id IN ({placeholders})", event_ids
            )
            self._db.commit()
            return cursor.rowcount

    def depth(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def set_metadata(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._db.commit()

    def get_metadata(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else None
