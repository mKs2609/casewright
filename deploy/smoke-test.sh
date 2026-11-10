#!/usr/bin/env bash
# Uses the running containers the way a visitor would, and checks the walls between them
# (step 19a, ADR-54). Run by CI after:
#   sh deploy/make-secrets.sh localhost
#   docker compose -f deploy/compose.yaml up -d --build
# For "localhost", Caddy makes its own small certificate authority instead of asking Let's Encrypt;
# this script trusts exactly that authority (never "--insecure").
set -euo pipefail

compose() { docker compose -f deploy/compose.yaml "$@"; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
site="https://localhost"
pass=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

echo "Waiting for Caddy's local certificate authority..."
for _ in $(seq 60); do
    compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" >/dev/null 2>&1 && break
    sleep 2
done
[ -s "$work/root.crt" ] || fail "Caddy never created its certificate authority"
web() { curl --silent --show-error --cacert "$work/root.crt" "$@"; }

echo "Waiting for the gateway, through Caddy..."
for _ in $(seq 90); do
    [ "$(web -o /dev/null -w '%{http_code}' "$site/api/health" || true)" = 200 ] && break
    sleep 2
done
[ "$(web "$site/api/health" | json "['status']")" = UP ] || fail "the gateway never became healthy"
ok "the gateway answers through Caddy, over a verified HTTPS connection"

# ---- The dashboard and its headers
headers="$(web -o "$work/index.html" -D - "$site/")"
grep -qi '^content-security-policy: default-src '"'"'none'"'"'; script-src '"'"'self'"'"';' <<<"$headers" \
    || fail "the dashboard is served without its security policy"
grep -qi '^strict-transport-security: max-age=31536000' <<<"$headers" || fail "no HSTS on the dashboard"
grep -qi '^server:' <<<"$headers" && fail "the Server header is still sent"
grep -q '<div id="root">' "$work/index.html" || fail "the dashboard page was not served"
ok "the dashboard is served with its security policy and HSTS, and no Server header"

location="$(curl --silent -o /dev/null -w '%{http_code} %{redirect_url}' "http://localhost/api/health")"
[ "$location" = "301 https://localhost/api/health" ] || fail "plain HTTP is not redirected to HTTPS: $location"
ok "plain HTTP is redirected to HTTPS on the standard port"

# ---- A visitor's whole journey: sign up, log in, run a demo scenario, check the audit chain
user="smoke.tester"
password="$(openssl rand -hex 16)"
post() { web -o "$work/body" -w '%{http_code}' -b "$work/cookies" -c "$work/cookies" -H "Origin: $site" \
    -H 'Content-Type: application/json' -X POST "$site$1" ${2:+--data "$2"}; }

[ "$(post /api/auth/signup "{\"username\":\"$user\",\"password\":\"$password\"}")" = 201 ] || fail "signup failed"
# New accounts are viewers; an administrator promotes them. Here, directly in the database.
compose exec -T db psql --quiet --username postgres --dbname secanalyst \
    -c "UPDATE app_users SET role = 'ANALYST' WHERE username = '$user'" >/dev/null
[ "$(post /api/auth/login "{\"username\":\"$user\",\"password\":\"$password\"}")" = 200 ] || fail "login failed"
ok "a new account can sign up and log in (cookies over HTTPS)"

[ "$(post /api/demo/phishing_email)" = 202 ] || fail "the demo scenario was refused: $(cat "$work/body")"
incident="$(json "['id']" <"$work/body")"
status=queued
for _ in $(seq 60); do
    status="$(web -b "$work/cookies" "$site/api/incidents/$incident" | json "['status']")"
    case "$status" in queued|investigating) sleep 2 ;; *) break ;; esac
done
case "$status" in
    needs_review|awaiting_approval) ok "the phishing demo was investigated by the agent: $status" ;;
    *) fail "the phishing demo ended as '$status'" ;;
esac

[ "$(web -b "$work/cookies" "$site/api/audit/verify" | json "['valid']")" = True ] || fail "the audit chain does not verify"
ok "the audit chain verifies"

[ "$(web -o /dev/null -w '%{http_code}' -X POST -H 'Origin: https://attacker.example' -b "$work/cookies" \
    "$site/api/demo/phishing_email")" = 403 ] || fail "a request from another site was not refused"
ok "a request from another website is refused (cross-site check, with the public origin)"

# ---- The walls between the containers
# Each "cannot reach" has a matching "can reach" with the same tool (nc only opens a connection),
# so a refusal can only mean the wall is there, not that the tool or the name is broken.
can() { compose exec -T "$1" nc -z -w 3 "$2" "$3" >/dev/null 2>&1; }
can caddy gateway 8443 || fail "control: Caddy cannot reach the gateway at all"
can caddy gateway 8001 && fail "the agent can be reached from Caddy"
ok "the agent cannot be reached from Caddy, which can reach the gateway (the agent is on its loopback only)"
can caddy db 5432 && fail "the database can be reached from Caddy"
ok "the database cannot be reached from Caddy"
can gateway db 5432 || fail "control: the gateway cannot reach the database"
can gateway 127.0.0.1 8001 || fail "control: the gateway cannot reach the agent"
can gateway example.com 443 && fail "the gateway can reach the internet"
ok "the gateway reaches the database and the agent, but not the internet (nor does the agent, on its network)"
can caddy example.com 443 || fail "control: Caddy cannot reach the internet (it needs to, for Let's Encrypt)"
ok "Caddy can reach the internet, for its certificates"

for service in caddy gateway agent; do
    [ "$(compose exec -T "$service" id -u)" != 0 ] || fail "$service runs as root"
done
ok "Caddy, the gateway and the agent run as ordinary users"
for service in caddy gateway agent; do
    found="$(compose exec -T "$service" sh -c 'find / -xdev \( -name ".env" -o -name "*.p12" \) 2>/dev/null' | grep -v '^/certs/' || true)"
    [ -z "$found" ] || fail "$service contains a secrets file: $found"
done
ok "no .env file or stray keystore inside any image"

echo "All $pass checks passed."
