#!/usr/bin/env bash
# Starts the whole system inside a GitHub Codespace (step 19d, ADR-62). Run by
# .devcontainer/devcontainer.json every time the codespace starts; safe to run again.
#
# The codespace belongs to whoever opened it: their own copy, their own fresh secrets, private to
# them. The containers are the ones a server runs (deploy/compose.yaml); only Caddy's settings and the
# Origins the gateway accepts differ (deploy/compose.codespaces.yaml), because of GitHub's forwarding.
set -euo pipefail
cd "$(dirname "$0")/.."

compose() { docker compose -f deploy/compose.yaml -f deploy/compose.codespaces.yaml "$@"; }

: "${CODESPACE_NAME:?this script is for GitHub Codespaces}"
: "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:?this script is for GitHub Codespaces}"
# The address GitHub gives Caddy's port 80; the gateway accepts changes only from this origin.
site="$CODESPACE_NAME-80.$GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN"

# Fresh random secrets for this codespace, made once and never changed (the audit key must not).
[ -e deploy/.env ] || sh deploy/make-secrets.sh "$site"

echo "Waiting for Docker..."
for _ in $(seq 60); do
    docker info >/dev/null 2>&1 && break
    sleep 2
done
docker info >/dev/null 2>&1 || { echo "Docker did not start." >&2; exit 1; }

echo "Building the containers (about 10 minutes the first time, seconds after that)..."
compose build

# Everything but the front door first, so the site only opens once there is something behind it.
compose up --detach db gateway-certificate gateway agent
echo "Waiting for the gateway..."
for _ in $(seq 150); do
    compose logs gateway 2>/dev/null | grep -q "Started GatewayApplication" && break
    sleep 2
done
compose logs gateway 2>/dev/null | grep -q "Started GatewayApplication" \
    || { echo "The gateway did not start; see: docker compose -f deploy/compose.yaml logs gateway" >&2; exit 1; }

compose up --detach caddy
for _ in $(seq 60); do
    curl --silent --fail http://localhost/api/health 2>/dev/null | grep -q '"UP"' && break
    sleep 2
done
curl --silent --fail http://localhost/api/health | grep -q '"UP"' \
    || { echo "The site did not answer; see: docker compose -f deploy/compose.yaml logs caddy" >&2; exit 1; }

cat <<EOF

  Casewright is ready: https://$site

  Open it from the Ports tab (port 80, "Casewright", the globe icon) and press "Try the demo".
  It is private to you. Delete the codespace when you are done, so it stops using your free hours.

EOF
