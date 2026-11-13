# Deployment

How Casewright runs on a server (step 19a, [ADR-54](DECISIONS.md)). The public demo is not online yet: step 19d puts it on a server.

## The public demo mode

With the production settings ([ADR-55](DECISIONS.md)): no sign-up; a **Try the demo** button that logs visitors in as a shared analyst account whose password nobody knows; that account fires the demo scenarios and decides the (simulated) actions but cannot submit text of its own; demo runs are limited to 5 a minute per visitor and 300 a day for the site.

## What runs where

```
                    internet
                       │  80, 443
                 ┌─────▼──────┐
                 │   caddy    │  the only container with open ports; HTTPS from Let's Encrypt;
                 └─────┬──────┘  serves the dashboard; passes /api on
          "edge" network (internal; Caddy has the fixed address 172.30.0.10)
                 ┌─────▼──────┐
                 │  gateway   │  HTTPS only, with its own certificate, which Caddy trusts by name
                 │  + agent   │  the agent shares the gateway's network, on 127.0.0.1 only
                 └─────┬──────┘
          "data" network (internal)
                 ┌─────▼──────┐
                 │     db     │  PostgreSQL 16; the application's limited role
                 └────────────┘
```

| Container | Image | Runs as | Can reach the internet |
|---|---|---|---|
| `caddy` | `deploy/caddy.Dockerfile`: Caddy 2.11 and the built dashboard | an ordinary user | yes (for its certificates) |
| `gateway` | `gateway/Dockerfile`: Java 25 runtime and the gateway | an ordinary user | no |
| `agent` | `agent/Dockerfile`: Python 3.14 and the agent, no AI model | an ordinary user | no |
| `db` | the official PostgreSQL 16 image | `postgres` (after setting up its folder) | no |
| `gateway-certificate` | the gateway's image, run once at first start | an ordinary user | no network at all |

Every container drops all special Linux rights and cannot gain new ones; Caddy, the gateway and the agent cannot change their own files while running.

## The files

| File | What it is |
|---|---|
| `deploy/compose.yaml` | The whole system: containers, networks, volumes |
| `deploy/Caddyfile` | Caddy's settings |
| `deploy/caddy.Dockerfile`, `gateway/Dockerfile`, `agent/Dockerfile` | How each image is built (base images pinned by digest) |
| `deploy/make-secrets.sh` | Creates `deploy/.env` with fresh random secrets, once |
| `deploy/make-gateway-certificate.sh` | Makes the gateway's internal certificate at first start |
| `deploy/postgres-init.sh` | Creates the application's database role at first start, with `scripts/setup-db.sql` |
| `deploy/smoke-test.sh` | What CI runs against the started containers |
| `deploy/.env.example` | The names of the settings; the real `deploy/.env` is never committed |
| `gateway/src/main/resources/application-production.properties` | The gateway's production settings |
| `.dockerignore` | What builds may never see: `.env`, certificates, personal files |

## Running it

On a Linux machine with Docker and the Compose plugin, from the repository root:

```bash
sh deploy/make-secrets.sh casewright.duckdns.org
docker compose -f deploy/compose.yaml up -d --build
```

The first command runs once and refuses to overwrite an existing `deploy/.env`: the audit key in it must never change, or every audit entry stops verifying. The site name must already point at the server (DNS) and ports 80 and 443 must be open, or Let's Encrypt cannot check that the site is yours.

| Task | Command |
|---|---|
| See what is running | `docker compose -f deploy/compose.yaml ps` |
| Follow the logs | `docker compose -f deploy/compose.yaml logs -f` |
| Update after a `git pull` | `docker compose -f deploy/compose.yaml up -d --build` |
| Stop everything (data is kept) | `docker compose -f deploy/compose.yaml down` |

`down --volumes` also deletes the database, the certificates and the audit log, for good.

## Checked on every pull request

CI's "Containers" job, twice (on GitHub's usual x86 machine and, as "Containers (ARM)", on an ARM machine like the server's, ADR-56), builds the images, starts everything with throwaway secrets (Caddy makes its own certificate authority for `localhost`), and runs `deploy/smoke-test.sh`: a verified HTTPS connection, the page's security headers and HSTS, the HTTP-to-HTTPS redirect, sign-up closed and the "Try the demo" button, the demo account unable to submit text of its own, a demo investigation from start to finish, the audit chain, the cross-site check, and the walls between the containers. Then it checks that every container runs on that machine's own kind of processor.
