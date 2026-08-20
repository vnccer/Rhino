# AASM Linux Host Collector v0.1.1

The first supported target is Ubuntu 22.04 LTS on x86_64. The collector is a Python
standard-library service: it tails `auditd` and `/var/log/auth.log`, persists normalized
events in SQLite, and sends authenticated HTTPS batches to the platform. It never executes,
injects into, or captures payloads from monitored processes.

## Install

Create a one-time enrollment token using the administrator API described in the repository
README, then run from a checked-out repository on the monitored host:

```bash
cd collectors/linux
sudo env \
  AASM_API_URL=https://monitor.example.com \
  AASM_ENROLLMENT_TOKEN='<one-time-token>' \
  bash ./install.sh
```

For a private CA, add `AASM_CA_CERT=/path/to/ca.crt`. Certificate verification cannot be
disabled. `install.sh` installs `auditd` and Python 3, creates a locked service account,
loads `/etc/audit/rules.d/50-aasm.rules`, enrolls once, and starts the systemd service.
The token is not written to disk. The returned per-host API key is stored as mode `0600` in
`/etc/aasm-collector/credential.json`.

Rerun the same installer without `AASM_ENROLLMENT_TOKEN` to upgrade an existing installation;
it retains the current credential and restarts the service.

The default audit policy observes user-launched processes and successful outbound `connect`
syscalls, plus writes under `/tmp/aasm-test/`. Add only explicitly approved directories as
separate audit `-w` rules. Broad watches can create high audit volume.

## Permissions and data handling

The daemon runs as `aasm-collector`, with no root or Linux capabilities. Membership in the
Ubuntu `adm` group is required only to read the audit and authentication log files. The
installer needs root to install files, create that account, and load audit rules. The systemd
unit uses filesystem and kernel hardening and grants write access only to
`/var/lib/aasm-collector`.

File contents, network payloads, passwords, cookies, authorization values, tokens, and private
keys are never intentionally collected. Command summaries are redacted and truncated before
entering the durable queue. The queue defaults to 256 MiB and seven-day retention. When full,
the collector logs an explicit error, retains its input cursor, and reports the error in its
heartbeat rather than silently skipping input.

Authentication records use the existing normalized `http_request` event type with
`action=authenticate`; this preserves compatibility with the current detection rule while the
attributes identify the actual SSH/PAM service and method.

## Operations

```bash
sudo systemctl status aasm-collector
sudo journalctl -u aasm-collector --since today
sudo -u aasm-collector env PYTHONPATH=/opt/aasm-collector \
  python3 -m aasm_linux_collector --config /etc/aasm-collector/config.ini check-config
sudo auditctl -l | grep aasm
```

Only HTTP `200/201` acknowledgements remove events. Network failures, `429`, and `5xx` use
bounded exponential backoff with jitter; `429` honors `Retry-After`. Credential, authorization,
payload-size, and validation errors retain the queue and back off for operator action. Queue and
file cursors survive service and host restarts, and a rotated uncompressed log is drained before
the new log is read.

To rotate a credential, use the administrator API, stop the service, replace only `api_key` in
the credential file, restore ownership/mode, and restart. Never paste credentials into logs.

## Controlled validation

Use only the approved test account and directory:

```bash
sudo install -d -m 1777 /tmp/aasm-test
sh -c 'echo test > /tmp/aasm-test/event.txt'
curl --fail https://monitor.example.com/health >/dev/null
```

Run an ordinary harmless command such as `/usr/bin/true`. Separately, from an approved source,
perform three known-bad SSH password attempts followed by one successful test-account login to
exercise `auth-failures-then-success`. Do not automate password guessing or test production
accounts. In the administrator event query, verify the same `host_id` and server-bound
`collector_id` on `process_start`, `file_write`, `network_connect`, and authentication events.
The authentication sequence should create an alert with four original evidence event IDs.

To test recovery, block only outbound access from the collector host to the platform for a short
window, generate test events, confirm `queue_depth` increases in logs/heartbeat, restore access,
and verify the queue returns to zero without duplicate `event_id` values.

Run the collector tests from this directory with a development-only `pytest` installation:

```bash
PYTHONPATH=. python3 -m pytest
```

The suite covers audit/auth mapping, recursive redaction, queue restart/capacity behavior, log
cursor recovery, retryable HTTP failures, and a local mock ingestion API.

## Uninstall

```bash
sudo bash ./uninstall.sh
```

This stops the service and removes code and audit rules, but retains the credential and SQLite
queue for recovery. After disabling the collector in the platform, permanently remove retained
state with `sudo bash ./uninstall.sh --purge`.
