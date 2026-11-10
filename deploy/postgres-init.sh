#!/bin/sh
# Runs once, when the database volume is first created: the postgres image runs every script in
# /docker-entrypoint-initdb.d at that moment, and never again (step 19a, ADR-54).
#
# Creates the application's limited role (no superuser, cannot create databases or roles) and its
# database, with exactly the SQL a development machine uses (scripts/setup-db.sql). psql reads the
# password from the environment itself (\getenv), so it never appears in the process list.
set -e
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -c '\getenv pw APP_DB_PASSWORD' -f /setup-db.sql
