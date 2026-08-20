from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CollectorConfig:
    api_url: str
    credential_file: Path
    queue_path: Path
    audit_log: Path
    auth_log: Path
    ca_cert: Path | None
    poll_interval_seconds: float
    upload_interval_seconds: float
    heartbeat_interval_seconds: float
    request_timeout_seconds: float
    batch_size: int
    max_batch_bytes: int
    queue_max_bytes: int
    queue_retention_hours: int
    command_line_max_length: int
    backoff_initial_seconds: float
    backoff_max_seconds: float

    @classmethod
    def load(cls, path: Path) -> "CollectorConfig":
        parser = configparser.ConfigParser(interpolation=None)
        if not parser.read(path, encoding="utf-8"):
            raise ValueError(f"configuration file does not exist or is unreadable: {path}")
        values = parser["collector"]

        def positive_int(name: str, default: int) -> int:
            value = values.getint(name, fallback=default)
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
            return value

        def positive_float(name: str, default: float) -> float:
            value = values.getfloat(name, fallback=default)
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
            return value

        api_url = values.get("api_url", "").strip().rstrip("/")
        if not api_url.startswith("https://"):
            raise ValueError("api_url must use HTTPS")
        ca_cert_value = values.get("ca_cert", "").strip()
        return cls(
            api_url=api_url,
            credential_file=Path(values.get("credential_file", "/etc/aasm-collector/credential.json")),
            queue_path=Path(values.get("queue_path", "/var/lib/aasm-collector/queue.db")),
            audit_log=Path(values.get("audit_log", "/var/log/audit/audit.log")),
            auth_log=Path(values.get("auth_log", "/var/log/auth.log")),
            ca_cert=Path(ca_cert_value) if ca_cert_value else None,
            poll_interval_seconds=positive_float("poll_interval_seconds", 1.0),
            upload_interval_seconds=positive_float("upload_interval_seconds", 2.0),
            heartbeat_interval_seconds=positive_float("heartbeat_interval_seconds", 30.0),
            request_timeout_seconds=positive_float("request_timeout_seconds", 10.0),
            batch_size=positive_int("batch_size", 200),
            max_batch_bytes=positive_int("max_batch_bytes", 1_500_000),
            queue_max_bytes=positive_int("queue_max_bytes", 268_435_456),
            queue_retention_hours=positive_int("queue_retention_hours", 168),
            command_line_max_length=positive_int("command_line_max_length", 512),
            backoff_initial_seconds=positive_float("backoff_initial_seconds", 1.0),
            backoff_max_seconds=positive_float("backoff_max_seconds", 300.0),
        )

