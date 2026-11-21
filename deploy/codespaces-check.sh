#!/usr/bin/env bash
# Checks the GitHub Codespaces setup (step 19d, ADR-62) the way GitHub's port forwarding uses it:
# plain HTTP to Caddy's port 80, with the same site, headers and checks as on a server. Run by CI
# after deploy/smoke-test.sh and deploy/codespaces-start.sh (whose names for the codespace CI makes up).
set -euo pipefail

compose() { docker compose -f deploy/compose.yaml -f deploy/compose.codespaces.yaml "$@"; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
site="http://localhost"
pass=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

curl --silent "$site/api/health" | grep -q '"status":"UP"' || fail "the gateway does not answer through Caddy over HTTP"
ok "the gateway answers through Caddy over plain HTTP, as GitHub's forwarding reaches it"

headers="$(curl --silent -o "$work/index.html" -D - "$site/")"
grep -qi '^content-security-policy: default-src '"'"'none'"'"'; script-src '"'"'self'"'"';' <<<"$headers" \
    || fail "the dashboard is served without its security policy"
grep -qi '^strict-transport-security: max-age=31536000' <<<"$headers" || fail "no HSTS on the dashboard"
grep -qi '^server:' <<<"$headers" && fail "the Server header is still sent"
grep -q '<div id="root">' "$work/index.html" || fail "the dashboard page was not served"
ok "the dashboard is served with the same security policy and HSTS, and no Server header"

[ "$(curl --silent "$site/api/auth/options")" = '{"signupOpen":false,"demoLogin":true}' ] \
    || fail "the codespace is not in the public demo mode"
ok "sign-up is closed and Try the demo is offered, as on the public site"

origin="$(grep '^PUBLIC_ORIGIN=' deploy/.env | cut -d= -f2-)"
code() { curl --silent -o /dev/null -w '%{http_code}' -H "Origin: $1" -X POST "$site/api/auth/demo-login"; }
[ "$(code https://attacker.example)" = 403 ] || fail "a request from another website is accepted"
[ "$(code "$origin")" = 200 ] || fail "control: a request from the codespace's own address is refused"
ok "the cross-site check still refuses other websites, and accepts the codespace's own address"

[ "$(compose exec -T caddy id -u)" != 0 ] || fail "Caddy runs as root"
# Caddy is process 1 in its container; its command line names the settings file it was started with.
compose exec -T caddy cat /proc/1/cmdline | tr '\000' ' ' | grep -q 'Caddyfile.codespaces' || fail "Caddy is not using the Codespaces settings"
ok "Caddy runs as an ordinary user, with the Codespaces settings"

echo "All $pass Codespaces checks passed."
