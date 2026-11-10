#!/bin/sh
# Creates deploy/.env on the server, with a fresh random value for every secret (step 19a, ADR-54).
# The Linux counterpart of scripts/setup-secrets.ps1. Run once, from the repository root:
#   sh deploy/make-secrets.sh casewright.duckdns.org
#
# It never overwrites an existing deploy/.env (the audit key, for one, must never change once
# entries are signed with it) and never prints a secret.
set -eu

site="${1:?usage: sh deploy/make-secrets.sh <site address, e.g. casewright.duckdns.org>}"
case "$site" in
    *[!A-Za-z0-9.-]*) echo "The site address may only contain letters, digits, dots and hyphens." >&2; exit 1 ;;
esac
out="$(dirname "$0")/.env"
if [ -e "$out" ]; then
    echo "$out already exists; nothing changed." >&2
    exit 1
fi

random() { openssl rand -base64 "$1" | tr -d '\n'; }

umask 077   # readable by this user only
{
    echo "# Made by deploy/make-secrets.sh. Never commit, copy or print this file."
    echo "SITE_ADDRESS=$site"
    echo "PUBLIC_ORIGIN=https://$site"
    echo "POSTGRES_PASSWORD=$(random 24)"
    echo "DB_PASSWORD=$(random 24)"
    echo "JWT_SIGNING_KEY=$(random 48)"
    echo "SSL_KEYSTORE_PASSWORD=$(random 24)"
    echo "BASELINE_ENCRYPTION_KEY=$(random 32)"
    echo "AGENT_SERVICE_TOKEN=$(random 32)"
    echo "AUDIT_HMAC_KEY=$(random 32)"
} > "$out"
echo "Wrote $out (readable by you only)."
