from __future__ import annotations

import hashlib
import os
import platform
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redaction import redact_mapping


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_host_id(machine_id_path: Path = Path("/etc/machine-id")) -> str:
    try:
        machine_id = machine_id_path.read_text(encoding="ascii").strip()
    except OSError:
        machine_id = str(uuid.getnode())
    digest = hashlib.sha256(f"aasm-linux:{machine_id}".encode()).hexdigest()
    return f"linux-{digest[:32]}"


def os_release(path: Path = Path("/etc/os-release")) -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values.get("ID", platform.system().lower()), values.get(
        "VERSION_ID", platform.release()
    )


def host_context(collector_version: str) -> dict[str, Any]:
    os_name, version = os_release()
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        boot_id = "unknown"
    return {
        "host_id": stable_host_id(),
        "hostname": socket.gethostname(),
        "os": os_name,
        "os_version": version,
        "collector_version": collector_version,
        "boot_id": boot_id,
    }


def build_event(
    *,
    timestamp: datetime,
    event_type: str,
    actor: dict[str, str] | None,
    action: str,
    object_value: dict[str, str] | None,
    result: str,
    severity: int,
    attributes: dict[str, Any],
    context: dict[str, Any],
    redaction_limit: int,
    event_id_seed: str | None = None,
) -> tuple[dict[str, Any], int]:
    merged = {**context, **attributes, "collected_at": utc_iso(datetime.now(timezone.utc))}
    cleaned, redaction_count = redact_mapping(merged, redaction_limit)
    if redaction_count:
        cleaned["redaction_count"] = redaction_count
    event_id = (
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"aasm:{context.get('host_id', '')}:{context.get('boot_id', '')}:{event_id_seed}",
        )
        if event_id_seed
        else uuid.uuid4()
    )
    return {
        "event_id": str(event_id),
        "timestamp": utc_iso(timestamp),
        "source": "host",
        "event_type": event_type,
        "actor": actor,
        "action": action,
        "object": object_value,
        "result": result,
        "severity": severity,
        "attributes": cleaned,
    }, redaction_count
