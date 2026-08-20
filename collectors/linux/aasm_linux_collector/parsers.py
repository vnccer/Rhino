from __future__ import annotations

import binascii
import os
import re
import shlex
import socket
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .events import build_event

try:
    import pwd
except ImportError:  # pragma: no cover - enables parser tests on non-Linux development hosts
    pwd = None  # type: ignore[assignment]

_AUDIT_ID = re.compile(r"msg=audit\((?P<seconds>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
_AUDIT_TYPE = re.compile(r"\btype=(?P<type>[A-Z0-9_]+)")
_AUTH_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
)
_SSH_AUTH = re.compile(
    r"sshd\[\d+\]: (?P<result>Accepted|Failed) (?P<method>\S+) for "
    r"(?:(?:invalid user)\s+)?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
_PAM_FAILURE = re.compile(
    r"pam_unix\((?P<service>[^)]+)\): authentication failure;(?P<details>.*)$"
)
_FIELD = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"(?:\\.|[^\"])*\"|'[^']*'|\S+)")


def _fields(line: str) -> dict[str, str]:
    output: dict[str, str] = {}
    for match in _FIELD.finditer(line):
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        output[match.group("key")] = value
    return output


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _username(uid: int | None) -> str | None:
    if uid is None:
        return None
    if pwd is None:
        return str(uid)


def _process_name(pid: int | None) -> str | None:
    if pid is None:
        return None
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()[:255] or None
    except OSError:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _decode_proctitle(value: str | None) -> str:
    if not value:
        return ""
    try:
        raw = bytes.fromhex(value)
        return " ".join(part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part)
    except (ValueError, binascii.Error):
        return value


def _decode_sockaddr(value: str | None) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    try:
        raw = bytes.fromhex(value)
        family = int.from_bytes(raw[:2], "little")
        port = int.from_bytes(raw[2:4], "big")
        if family == socket.AF_INET and len(raw) >= 8:
            return socket.inet_ntop(socket.AF_INET, raw[4:8]), port
        if family == socket.AF_INET6 and len(raw) >= 24:
            return socket.inet_ntop(socket.AF_INET6, raw[8:24]), port
    except (ValueError, OSError):
        pass
    return None, None


def group_audit_records(lines: Iterable[str]) -> list[tuple[str, float, list[str]]]:
    groups: dict[str, tuple[float, list[str]]] = {}
    order: list[str] = []
    for line in lines:
        identifier = _AUDIT_ID.search(line)
        if not identifier:
            continue
        serial = identifier.group("serial")
        if serial not in groups:
            groups[serial] = (float(identifier.group("seconds")), [])
            order.append(serial)
        groups[serial][1].append(line.rstrip("\n"))
    return [(serial, groups[serial][0], groups[serial][1]) for serial in order]


def parse_audit_lines(
    lines: Iterable[str], context: dict[str, Any], redaction_limit: int
) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    total_redactions = 0
    groups = group_audit_records(lines)
    process_names: dict[int, str] = {}
    for _, _, records in groups:
        syscall_line = next(
            (record for record in records if _AUDIT_TYPE.search(record) and "type=SYSCALL" in record),
            None,
        )
        if syscall_line:
            fields = _fields(syscall_line)
            pid = _int(fields.get("pid"))
            executable = fields.get("exe") or fields.get("comm")
            if pid is not None and executable:
                process_names[pid] = os.path.basename(executable)

    for serial, seconds, records in groups:
        typed: dict[str, list[dict[str, str]]] = {}
        for record in records:
            type_match = _AUDIT_TYPE.search(record)
            if type_match:
                typed.setdefault(type_match.group("type"), []).append(_fields(record))
        syscall = (typed.get("SYSCALL") or [{}])[0]
        keys = {item.get("key") for values in typed.values() for item in values}
        key = syscall.get("key")
        if key:
            keys.add(key)
        timestamp = datetime.fromtimestamp(seconds, timezone.utc)
        pid = _int(syscall.get("pid"))
        ppid = _int(syscall.get("ppid"))
        common = {
            "pid": pid,
            "ppid": ppid,
            "parent_process_name": (
                process_names.get(ppid) or _process_name(ppid) if ppid is not None else None
            ),
            "uid": _int(syscall.get("uid")),
            "username": _username(_int(syscall.get("uid"))),
            "audit_serial": serial,
            "audit_key": key,
        }
        success = syscall.get("success", "yes") in {"yes", "1"}

        if "aasm_process" in keys:
            proctitle = _decode_proctitle((typed.get("PROCTITLE") or [{}])[0].get("proctitle"))
            execve = (typed.get("EXECVE") or [{}])[0]
            if not proctitle and execve:
                args = [execve[name] for name in sorted(execve) if re.fullmatch(r"a\d+", name)]
                proctitle = shlex.join(args)
            executable = syscall.get("exe") or execve.get("a0") or syscall.get("comm") or "unknown"
            event, count = build_event(
                timestamp=timestamp,
                event_type="process_start",
                actor={"type": "process", "id": str(common["pid"] or "unknown")},
                action="start",
                object_value={"type": "process", "id": executable, "name": os.path.basename(executable)},
                result="success" if success else "failure",
                severity=20 if success else 40,
                attributes={**common, "executable_path": executable, "command_line": proctitle},
                context=context,
                redaction_limit=redaction_limit,
                event_id_seed=f"audit:{serial}:process_start",
            )
            events.append(event)
            total_redactions += count

        if "aasm_file" in keys:
            paths = typed.get("PATH") or []
            path_types = {item.get("nametype") for item in paths}
            is_rename = "CREATE" in path_types and "DELETE" in path_types
            target = next(
                (
                    item
                    for item in reversed(paths)
                    if item.get("name") and (not is_rename or item.get("nametype") == "CREATE")
                ),
                {},
            )
            path = target.get("name", "unknown")
            name_type = target.get("nametype", "NORMAL")
            action = (
                "rename"
                if is_rename
                else {"CREATE": "create", "DELETE": "delete"}.get(name_type, "write")
            )
            source_path = next(
                (item.get("name") for item in paths if item.get("nametype") == "DELETE"), None
            )
            event, count = build_event(
                timestamp=timestamp,
                event_type="file_write",
                actor={"type": "process", "id": str(common["pid"] or "unknown")},
                action=action,
                object_value={"type": "file", "id": path, "name": os.path.basename(path)},
                result="success" if success else "failure",
                severity=35,
                attributes={
                    **common,
                    "path": path,
                    "source_path": source_path if is_rename else None,
                    "operation": action,
                    "nametype": name_type,
                },
                context=context,
                redaction_limit=redaction_limit,
                event_id_seed=f"audit:{serial}:file_write:{path}",
            )
            events.append(event)
            total_redactions += count

        if "aasm_network" in keys:
            sockaddr = (typed.get("SOCKADDR") or [{}])[0].get("saddr")
            destination_ip, destination_port = _decode_sockaddr(sockaddr)
            if destination_ip:
                event, count = build_event(
                    timestamp=timestamp,
                    event_type="network_connect",
                    actor={"type": "process", "id": str(common["pid"] or "unknown")},
                    action="connect",
                    object_value={
                        "type": "network_endpoint",
                        "id": f"{destination_ip}:{destination_port or 0}",
                        "name": destination_ip,
                    },
                    result="success" if success else "failure",
                    severity=25,
                    attributes={
                        **common,
                        "executable_path": syscall.get("exe"),
                        "destination_ip": destination_ip,
                        "destination_port": destination_port,
                        "protocol": "unknown",
                    },
                    context=context,
                    redaction_limit=redaction_limit,
                    event_id_seed=f"audit:{serial}:network_connect",
                )
                events.append(event)
                total_redactions += count
    return events, total_redactions


def _auth_timestamp(line: str, now: datetime) -> datetime:
    prefix = _AUTH_PREFIX.match(line)
    if not prefix:
        return now.astimezone(timezone.utc)
    parsed = datetime.strptime(
        f"{now.year} {prefix.group('month')} {prefix.group('day')} {prefix.group('time')}",
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=now.astimezone().tzinfo)
    if parsed - now > timedelta(days=180):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed.astimezone(timezone.utc)


def parse_auth_line(
    line: str,
    context: dict[str, Any],
    redaction_limit: int,
    now: datetime | None = None,
    source_id: str | None = None,
) -> tuple[dict[str, Any] | None, int]:
    current = now or datetime.now().astimezone()
    match = _SSH_AUTH.search(line)
    service = "ssh"
    if match:
        values = match.groupdict()
        result = "success" if values["result"] == "Accepted" else "failure"
        username = values["user"]
        source_ip = values["ip"]
        method = values["method"]
    else:
        pam = _PAM_FAILURE.search(line)
        if not pam:
            return None, 0
        values = pam.groupdict()
        result = "failure"
        details = values.get("details") or ""
        user_match = re.search(r"(?:^|\s)user=(\S+)", details)
        ip_match = re.search(r"(?:^|\s)rhost=(\S+)", details)
        username = user_match.group(1) if user_match else "unknown"
        source_ip = ip_match.group(1) if ip_match else None
        service = (values.get("service") or "pam").split(":", 1)[0]
        method = "pam"
    timestamp = _auth_timestamp(line, current)
    seed = source_id or f"auth:{hash(line)}"
    return build_event(
        timestamp=timestamp,
        event_type="http_request",
        actor={"type": "user", "id": username},
        action="authenticate",
        object_value={"type": "account", "id": username, "name": username},
        result=result,
        severity=15 if result == "success" else 45,
        attributes={
            "username": username,
            "source_ip": source_ip,
            "authentication_method": method,
            "service": service,
        },
        context=context,
        redaction_limit=redaction_limit,
        event_id_seed=seed,
    )
