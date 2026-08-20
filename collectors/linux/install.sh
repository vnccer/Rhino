#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_URL="${AASM_API_URL:-}"
ENROLLMENT_TOKEN="${AASM_ENROLLMENT_TOKEN:-}"
CA_CERT="${AASM_CA_CERT:-}"
SKIP_PACKAGES=false

usage() {
  echo "Usage: sudo env AASM_API_URL=https://host AASM_ENROLLMENT_TOKEN=token bash ./install.sh [--ca-cert PATH] [--skip-packages]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
    --skip-packages) SKIP_PACKAGES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$EUID" -eq 0 ]] || { echo "Run this installer through sudo." >&2; exit 1; }
[[ "$API_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] || {
  echo "AASM_API_URL must be a valid HTTPS base URL." >&2
  exit 1
}
[[ -e /etc/aasm-collector/credential.json || -n "$ENROLLMENT_TOKEN" ]] || {
  echo "AASM_ENROLLMENT_TOKEN is required and should be a fresh one-time token." >&2
  exit 1
}
[[ -z "$CA_CERT" || -r "$CA_CERT" ]] || { echo "CA certificate is unreadable: $CA_CERT" >&2; exit 1; }

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] || {
    echo "This release supports Ubuntu 22.04 LTS; detected ${ID:-unknown} ${VERSION_ID:-unknown}." >&2
    exit 1
  }
fi

if ! $SKIP_PACKAGES; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y auditd python3
fi
command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
command -v augenrules >/dev/null || { echo "auditd/augenrules is required." >&2; exit 1; }

getent group aasm-collector >/dev/null || groupadd --system aasm-collector
id aasm-collector >/dev/null 2>&1 || useradd \
  --system --gid aasm-collector --groups adm --home-dir /var/lib/aasm-collector \
  --shell /usr/sbin/nologin aasm-collector
usermod -a -G adm aasm-collector

install -d -o root -g root -m 0755 /opt/aasm-collector /opt/aasm-collector/aasm_linux_collector
install -m 0644 "$SCRIPT_DIR"/aasm_linux_collector/*.py /opt/aasm-collector/aasm_linux_collector/
install -m 0644 "$SCRIPT_DIR/README.md" /opt/aasm-collector/README.md
install -d -o root -g aasm-collector -m 0750 /etc/aasm-collector
install -d -o aasm-collector -g aasm-collector -m 0700 /var/lib/aasm-collector
install -d -o root -g root -m 1777 /tmp/aasm-test

CA_DEST=""
if [[ -n "$CA_CERT" ]]; then
  install -m 0644 "$CA_CERT" /etc/aasm-collector/ca.crt
  CA_DEST="/etc/aasm-collector/ca.crt"
fi

CONFIG_TMP="$(mktemp)"
trap 'rm -f "$CONFIG_TMP"' EXIT
sed \
  -e "s|^api_url = .*|api_url = $API_URL|" \
  -e "s|^ca_cert =.*|ca_cert = $CA_DEST|" \
  "$SCRIPT_DIR/config.example.ini" > "$CONFIG_TMP"
install -o root -g aasm-collector -m 0640 "$CONFIG_TMP" /etc/aasm-collector/config.ini

install -o root -g root -m 0640 "$SCRIPT_DIR/systemd/aasm.rules" /etc/audit/rules.d/50-aasm.rules
install -o root -g root -m 0644 "$SCRIPT_DIR/systemd/aasm-collector.service" /etc/systemd/system/aasm-collector.service
systemctl enable --now auditd
augenrules --load
systemctl daemon-reload

if [[ -e /etc/aasm-collector/credential.json ]]; then
  echo "Existing collector credential retained for this upgrade."
else
  AASM_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" PYTHONPATH=/opt/aasm-collector \
    python3 -m aasm_linux_collector --config /etc/aasm-collector/config.ini enroll
fi
chown aasm-collector:aasm-collector /etc/aasm-collector/credential.json
chmod 0600 /etc/aasm-collector/credential.json
unset ENROLLMENT_TOKEN AASM_ENROLLMENT_TOKEN

systemctl enable aasm-collector
systemctl restart aasm-collector
systemctl --no-pager --full status aasm-collector
echo "AASM Linux collector installed and started."
