import json
import random
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aasm_linux_collector.collector import Collector
from aasm_linux_collector.config import CollectorConfig
from aasm_linux_collector.http_client import ApiClient
from aasm_linux_collector.http_client import UploadResult


class MockCollectorApi(BaseHTTPRequestHandler):
    attempts = 0
    received: list[dict[str, object]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        type(self).attempts += 1
        if type(self).attempts == 1:
            self.send_response(503)
            self.end_headers()
            return
        type(self).received.extend(payload)
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, format: str, *args: object) -> None:
        pass


def test_local_mock_api_classifies_retry_and_accepts_idempotent_batch() -> None:
    MockCollectorApi.attempts = 0
    MockCollectorApi.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockCollectorApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = ApiClient(f"http://127.0.0.1:{server.server_port}", "test-key", timeout=2)
        payload = [{"event_id": "stable-id", "source": "host"}]

        first = client.send_events(payload)
        second = client.send_events(payload)

        assert not first.success and first.retryable and first.status == 503
        assert second.success and not second.retryable and second.status == 201
        assert MockCollectorApi.received == payload
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class FailingThenSuccessfulApi:
    def __init__(self) -> None:
        self.attempts = 0
        self.last_batch: list[dict[str, object]] = []

    def send_events(self, events: list[dict[str, object]]) -> UploadResult:
        self.attempts += 1
        self.last_batch = events
        if self.attempts == 1:
            return UploadResult(False, True, 503, "unavailable")
        return UploadResult(True, False, 201)

    def send_heartbeat(self, _: dict[str, object]) -> UploadResult:
        return UploadResult(True, False, 200)


def test_collector_keeps_queue_on_retryable_failure_then_acknowledges(tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text(
        json.dumps(
            {"host_id": "linux-test", "collector_id": "collector-test", "api_key": "test-key"}
        ),
        encoding="utf-8",
    )
    config = CollectorConfig(
        api_url="https://monitor.example.com",
        credential_file=credential,
        queue_path=tmp_path / "queue.db",
        audit_log=tmp_path / "audit.log",
        auth_log=tmp_path / "auth.log",
        ca_cert=None,
        poll_interval_seconds=1,
        upload_interval_seconds=1,
        heartbeat_interval_seconds=30,
        request_timeout_seconds=1,
        batch_size=10,
        max_batch_bytes=10_000,
        queue_max_bytes=10_000,
        queue_retention_hours=24,
        command_line_max_length=512,
        backoff_initial_seconds=1,
        backoff_max_seconds=10,
    )
    collector = Collector(config, random_source=random.Random(1))
    fake_api = FailingThenSuccessfulApi()
    collector.api = fake_api  # type: ignore[assignment]
    collector.queue.enqueue(
        {
            "event_id": "stable-id",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "host",
        }
    )
    try:
        assert not collector.upload_once()
        assert collector.queue.depth() == 1
        assert collector._next_upload > 0
        collector._next_upload = 0
        assert collector.upload_once()
        assert collector.queue.depth() == 0
        assert fake_api.attempts == 2
        assert "reported_at" in fake_api.last_batch[0]["attributes"]
    finally:
        collector.close()
