from __future__ import annotations

import json
import logging
import random
import time
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .config import CollectorConfig
from .events import host_context, utc_iso
from .http_client import ApiClient
from .parsers import parse_audit_lines, parse_auth_line
from .queue import EventQueue, QueueFullError
from .tailer import FileTailer

LOG = logging.getLogger("aasm_collector")


class Collector:
    def __init__(self, config: CollectorConfig, *, random_source: random.Random | None = None) -> None:
        self.config = config
        self.queue = EventQueue(
            config.queue_path, config.queue_max_bytes, config.queue_retention_hours
        )
        credential = json.loads(config.credential_file.read_text(encoding="utf-8"))
        self.context = host_context(__version__)
        self.context["host_id"] = credential["host_id"]
        self.context["collector_id"] = credential["collector_id"]
        self.api = ApiClient(
            config.api_url,
            credential["api_key"],
            config.request_timeout_seconds,
            config.ca_cert,
        )
        self.audit = FileTailer(config.audit_log, "audit", self.queue)
        self.auth = FileTailer(config.auth_log, "auth", self.queue)
        self.started_at = datetime.now(timezone.utc)
        self.last_collected_at: datetime | None = None
        self.last_uploaded_at: datetime | None = None
        self._errors: dict[str, str] = {}
        self.redaction_count = 0
        self._random = random_source or random.Random()
        self._backoff = config.backoff_initial_seconds
        self._next_upload = 0.0
        self._next_heartbeat = 0.0

    def close(self) -> None:
        self.queue.close()

    @property
    def last_error(self) -> str | None:
        if not self._errors:
            return None
        return "; ".join(self._errors.values())[:500]

    def _set_error(self, category: str, message: str | None) -> None:
        if message is None:
            self._errors.pop(category, None)
        else:
            self._errors[category] = message[:500]

    def _enqueue(self, events: list[dict[str, Any]]) -> bool:
        try:
            for event in events:
                self.queue.enqueue(event)
        except QueueFullError as error:
            self._set_error("queue", str(error))
            LOG.error("persistent queue full; source cursor retained: %s", error)
            return False
        self._set_error("queue", None)
        if events:
            self.last_collected_at = datetime.now(timezone.utc)
        return True

    def collect_audit(self) -> int:
        if not self.config.audit_log.is_file():
            message = f"audit source is unavailable: {self.config.audit_log}"
            if self._errors.get("audit") != message:
                LOG.error(message)
            self._set_error("audit", message)
            return 0
        self._set_error("audit", None)
        try:
            records, state = self.audit.read()
        except OSError as error:
            message = f"cannot read audit source: {error}"
            self._set_error("audit", message)
            LOG.error(message)
            return 0
        if not records:
            return 0
        safe_index = max(
            (index for index, (_, line) in enumerate(records) if line.startswith("type=EOE ")),
            default=-1,
        )
        if safe_index < 0:
            serials = []
            for _, line in records:
                marker = line.find("msg=audit(")
                serial = line[line.find(":", marker) + 1 : line.find(")", marker)] if marker >= 0 else ""
                serials.append(serial)
            if len(set(filter(None, serials))) > 1:
                newest = next(value for value in reversed(serials) if value)
                safe_index = max(index for index, value in enumerate(serials) if value != newest)
        if safe_index < 0:
            return 0
        selected = records[: safe_index + 1]
        events, redactions = parse_audit_lines(
            [line for _, line in selected], self.context, self.config.command_line_max_length
        )
        if not self._enqueue(events):
            return 0
        self.redaction_count += redactions
        self.audit.commit(state, selected[-1][0])
        return len(events)

    def collect_auth(self) -> int:
        if not self.config.auth_log.is_file():
            message = f"authentication source is unavailable: {self.config.auth_log}"
            if self._errors.get("auth") != message:
                LOG.error(message)
            self._set_error("auth", message)
            return 0
        self._set_error("auth", None)
        try:
            records, state = self.auth.read()
        except OSError as error:
            message = f"cannot read authentication source: {error}"
            self._set_error("auth", message)
            LOG.error(message)
            return 0
        collected = 0
        for offset, line in records:
            event, redactions = parse_auth_line(
                line,
                self.context,
                self.config.command_line_max_length,
                source_id=f"auth:{state['device']}:{state['inode']}:{offset}",
            )
            if event is not None and not self._enqueue([event]):
                return collected
            self.redaction_count += redactions
            self.auth.commit(state, offset)
            collected += int(event is not None)
        return collected

    def _retry_later(self, retry_after: float | None = None) -> None:
        delay = retry_after or self._backoff * self._random.uniform(0.8, 1.2)
        self._next_upload = time.monotonic() + min(delay, self.config.backoff_max_seconds)
        self._backoff = min(self._backoff * 2, self.config.backoff_max_seconds)

    def upload_once(self) -> bool:
        if time.monotonic() < self._next_upload:
            return False
        try:
            batch = self.queue.peek(self.config.batch_size, self.config.max_batch_bytes)
        except QueueFullError as error:
            self._set_error("upload", str(error))
            LOG.error("cannot upload queue head: %s", error)
            return False
        if not batch:
            return False
        reported_at = utc_iso(datetime.now(timezone.utc))
        upload_batch = [
            {
                **event,
                "attributes": {**event.get("attributes", {}), "reported_at": reported_at},
            }
            for event in batch
        ]
        result = self.api.send_events(upload_batch)
        if result.success:
            self.queue.acknowledge([event["event_id"] for event in batch])
            self.last_uploaded_at = datetime.now(timezone.utc)
            self._set_error("upload", None)
            self._backoff = self.config.backoff_initial_seconds
            self._next_upload = time.monotonic() + self.config.upload_interval_seconds
            return True
        message = f"event upload failed ({result.status}): {result.error}"[:500]
        self._set_error("upload", message)
        LOG.warning(message)
        if result.retryable:
            self._retry_later(result.retry_after)
        else:
            self._next_upload = time.monotonic() + self.config.backoff_max_seconds
        return False

    def heartbeat_once(self, force: bool = False) -> bool:
        now_monotonic = time.monotonic()
        if not force and now_monotonic < self._next_heartbeat:
            return False
        payload = {
            "version": __version__,
            "started_at": utc_iso(self.started_at),
            "queue_depth": self.queue.depth(),
            "last_collected_at": utc_iso(self.last_collected_at) if self.last_collected_at else None,
            "last_uploaded_at": utc_iso(self.last_uploaded_at) if self.last_uploaded_at else None,
            "last_error": self.last_error,
            "redaction_count": self.redaction_count,
        }
        result = self.api.send_heartbeat(payload)
        self._next_heartbeat = now_monotonic + self.config.heartbeat_interval_seconds
        if not result.success:
            message = f"heartbeat failed ({result.status}): {result.error}"[:500]
            self._set_error("heartbeat", message)
            LOG.warning(message)
            return False
        self._set_error("heartbeat", None)
        return True

    def run(self) -> None:
        LOG.info("collector started for host %s", self.context["host_id"])
        try:
            while True:
                expired = self.queue.purge_expired()
                if expired:
                    message = f"retention policy expired {expired} queued event(s)"
                    self._set_error("retention", message)
                    LOG.warning(message)
                self.collect_audit()
                self.collect_auth()
                self.upload_once()
                self.heartbeat_once()
                time.sleep(self.config.poll_interval_seconds)
        finally:
            self.close()
