from datetime import datetime, timezone

from aasm_linux_collector.parsers import parse_audit_lines, parse_auth_line

CONTEXT = {
    "host_id": "linux-test",
    "hostname": "vm-security-monitor-01",
    "os": "ubuntu",
    "os_version": "22.04",
    "collector_id": "collector-test",
    "collector_version": "0.1.1",
}


def test_maps_process_file_and_network_audit_records() -> None:
    lines = [
        'type=SYSCALL msg=audit(1787187599.100:100): success=yes ppid=1 pid=10 uid=1000 exe="/usr/bin/sh" key="aasm_process"',
        "type=PROCTITLE msg=audit(1787187599.100:100): proctitle=7368002D630074727565",
        "type=EOE msg=audit(1787187599.100:100):",
        'type=SYSCALL msg=audit(1787187600.100:101): success=yes ppid=10 pid=20 uid=1000 exe="/usr/bin/curl" key="aasm_process"',
        "type=PROCTITLE msg=audit(1787187600.100:101): proctitle=6375726C0068747470733A2F2F6578616D706C652E636F6D",
        "type=EOE msg=audit(1787187600.100:101):",
        'type=SYSCALL msg=audit(1787187601.100:102): success=yes ppid=20 pid=21 uid=1000 exe="/usr/bin/sh" key="aasm_file"',
        'type=PATH msg=audit(1787187601.100:102): name="/tmp/aasm-test/event.txt" nametype=CREATE',
        "type=EOE msg=audit(1787187601.100:102):",
        'type=SYSCALL msg=audit(1787187602.100:103): success=yes ppid=20 pid=22 uid=1000 exe="/usr/bin/curl" key="aasm_network"',
        "type=SOCKADDR msg=audit(1787187602.100:103): saddr=020001BBC633640A0000000000000000",
        "type=EOE msg=audit(1787187602.100:103):",
    ]

    events, redactions = parse_audit_lines(lines, CONTEXT, 512)

    assert redactions == 0
    assert [event["event_type"] for event in events] == [
        "process_start",
        "process_start",
        "file_write",
        "network_connect",
    ]
    assert events[1]["object"]["name"] == "curl"
    assert events[1]["attributes"]["command_line"] == "curl https://example.com"
    assert events[1]["attributes"]["parent_process_name"] == "sh"
    assert events[2]["action"] == "create"
    assert events[2]["attributes"]["path"] == "/tmp/aasm-test/event.txt"
    assert events[3]["attributes"]["destination_ip"] == "198.51.100.10"
    assert events[3]["attributes"]["destination_port"] == 443
    assert all(event["attributes"]["host_id"] == "linux-test" for event in events)


def test_maps_ssh_success_and_failure_to_authentication_events() -> None:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    failed, _ = parse_auth_line(
        "Aug 20 11:59:58 host sshd[123]: Failed password for invalid user test-user from 203.0.113.9 port 4444 ssh2",
        CONTEXT,
        512,
        now=now,
        source_id="auth-failed",
    )
    success, _ = parse_auth_line(
        "Aug 20 12:00:00 host sshd[124]: Accepted publickey for test-user from 203.0.113.9 port 4444 ssh2",
        CONTEXT,
        512,
        now=now,
        source_id="auth-success",
    )

    assert failed is not None and success is not None
    assert failed["event_type"] == success["event_type"] == "http_request"
    assert failed["action"] == success["action"] == "authenticate"
    assert failed["result"] == "failure"
    assert success["result"] == "success"
    assert success["attributes"]["authentication_method"] == "publickey"
    assert success["attributes"]["source_ip"] == "203.0.113.9"

    pam, _ = parse_auth_line(
        "Aug 20 12:00:01 host login[125]: pam_unix(login:auth): authentication failure; logname= uid=0 rhost=203.0.113.10 user=test-user",
        CONTEXT,
        512,
        now=now,
        source_id="pam-failed",
    )
    assert pam is not None
    assert pam["actor"]["id"] == "test-user"
    assert pam["attributes"]["source_ip"] == "203.0.113.10"
    assert pam["attributes"]["authentication_method"] == "pam"
