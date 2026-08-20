#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-compose.production.yaml}"
ENV_FILE="${ENV_FILE:-.env.production}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
AGE_RECIPIENT="${AGE_RECIPIENT:-}"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

cd "$ROOT_DIR"
[[ -n "$AGE_RECIPIENT" ]] || { echo "AGE_RECIPIENT is required; backups must be encrypted." >&2; exit 1; }
command -v age >/dev/null || { echo "age is required to encrypt backups: https://age-encryption.org" >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Missing $ENV_FILE" >&2; exit 1; }
db_name="$(grep -E '^POSTGRES_DB=' "$ENV_FILE" | tail -n 1 | cut -d= -f2-)"
[[ -n "$db_name" ]] || { echo "POSTGRES_DB is missing from $ENV_FILE" >&2; exit 1; }
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="$BACKUP_DIR/security-monitor-${timestamp}.dump.age"

"${COMPOSE[@]}" exec -T db pg_dump --format=custom --no-owner --no-privileges --dbname="$db_name" \
  | age --encrypt --recipient "$AGE_RECIPIENT" --output "$output"
chmod 600 "$output"
find "$BACKUP_DIR" -type f -name 'security-monitor-*.dump.age' -mtime "+$RETENTION_DAYS" -delete
echo "Encrypted PostgreSQL backup written to $output"
