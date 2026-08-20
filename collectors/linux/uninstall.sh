#!/usr/bin/env bash
set -Eeuo pipefail

PURGE=false
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--purge" ) ]]; then
  echo "Usage: sudo bash ./uninstall.sh [--purge]" >&2
  exit 2
fi
[[ "${1:-}" == "--purge" ]] && PURGE=true
[[ "$EUID" -eq 0 ]] || { echo "Run this uninstaller through sudo." >&2; exit 1; }

systemctl disable --now aasm-collector 2>/dev/null || true
rm -f /etc/systemd/system/aasm-collector.service
rm -f /etc/audit/rules.d/50-aasm.rules
systemctl daemon-reload
command -v augenrules >/dev/null && augenrules --load || true
rm -rf /opt/aasm-collector

if $PURGE; then
  echo "Purging credential, configuration, and queued telemetry."
  rm -rf /etc/aasm-collector /var/lib/aasm-collector
  userdel aasm-collector 2>/dev/null || true
  groupdel aasm-collector 2>/dev/null || true
else
  echo "Configuration, credential, queue, and service account were retained."
  echo "Run uninstall.sh --purge only after disabling the collector credential in the platform."
fi
