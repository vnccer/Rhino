#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-compose.production.yaml}"
ENV_FILE="${ENV_FILE:-.env.production}"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

cd "$ROOT_DIR"
[[ -f "$ENV_FILE" ]] || { echo "Missing $ENV_FILE; copy .env.production.example and fill secrets." >&2; exit 1; }
[[ -f "$COMPOSE_FILE" ]] || { echo "Missing $COMPOSE_FILE" >&2; exit 1; }

required=(POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD DATABASE_URL DOMAIN TLS_CERT_FILE TLS_KEY_FILE)
for name in "${required[@]}"; do
  value="$(grep -E "^${name}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true)"
  [[ -n "$value" && "$value" != replace-* && "$value" != change-me ]] || {
    echo "$name is missing or still uses a placeholder in $ENV_FILE" >&2
    exit 1
  }
done

cert="$(grep -E '^TLS_CERT_FILE=' "$ENV_FILE" | tail -n 1 | cut -d= -f2-)"
key="$(grep -E '^TLS_KEY_FILE=' "$ENV_FILE" | tail -n 1 | cut -d= -f2-)"
[[ -r "$cert" ]] || { echo "TLS certificate is not readable: $cert" >&2; exit 1; }
[[ -r "$key" ]] || { echo "TLS private key is not readable: $key" >&2; exit 1; }

"${COMPOSE[@]}" config >/dev/null
"${COMPOSE[@]}" build --pull
"${COMPOSE[@]}" up -d db
"${COMPOSE[@]}" run --rm backend alembic upgrade head
"${COMPOSE[@]}" up -d backend frontend proxy

for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error --insecure "https://127.0.0.1:${HTTPS_PORT:-443}/health" >/dev/null; then
    echo "Deployment is healthy."
    exit 0
  fi
  sleep 2
done

echo "Deployment did not become healthy; recent service status:" >&2
"${COMPOSE[@]}" ps >&2
exit 1
