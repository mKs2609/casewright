# Deployment

How Casewright runs on a server (step 19a, [ADR-54](DECISIONS.md)), and in GitHub Codespaces (step 19d, [ADR-62](DECISIONS.md)). There is no public server yet: anyone can start their own copy in a codespace instead ([below](#github-codespaces)).

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
| `deploy/Caddyfile` | Caddy's settings on a server |
| `deploy/site.caddy` | The site's rules (the API route, the page's headers), imported by both Caddy settings files |
| `deploy/Caddyfile.codespaces`, `deploy/compose.codespaces.yaml` | Caddy's settings in a codespace, and the Compose layer that chooses them |
| `.devcontainer/devcontainer.json`, `deploy/codespaces-start.sh` | What a codespace is made of, and how it starts everything |
| `deploy/codespaces-check.sh` | What CI runs against the codespace-style start |
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

## GitHub Codespaces

The README's **Open in GitHub Codespaces** button gives anyone with a GitHub account their own private copy of the whole system, on their own free Codespaces hours:

1. GitHub makes the codespace from `.devcontainer/devcontainer.json`: Ubuntu with Docker inside it (both pinned by digest), on the smallest machine (2 cores, 8 GB).
2. Every time the codespace starts, it runs `deploy/codespaces-start.sh`: fresh secrets for this codespace (once, with `make-secrets.sh`), then the same containers as a server, built and started with `deploy/compose.codespaces.yaml` layered on `compose.yaml`. The front door (Caddy) starts last, once the gateway is up, and the script prints **Casewright is ready** with the address.
3. GitHub forwards Caddy's port 80 as `https://<codespace>-80.app.github.dev`. GitHub provides the HTTPS and lets only the codespace's owner in, so Caddy serves the site over plain HTTP behind it (`Caddyfile.codespaces`) with the same rules as a server (`site.caddy`). The gateway's cross-site check accepts that address only.

The first start takes about 10 minutes (it builds everything); later starts take seconds. A free GitHub account has 120 core-hours a month (60 hours on this machine) and 15 GB of storage; delete the codespace afterwards so it stops using them.

## Checked on every pull request

CI's "Containers" job, twice (on GitHub's usual x86 machine and, as "Containers (ARM)", on an ARM machine like the server's, ADR-56), builds the images, starts everything with throwaway secrets (Caddy makes its own certificate authority for `localhost`), and runs `deploy/smoke-test.sh`: a verified HTTPS connection, the page's security headers and HSTS, the HTTP-to-HTTPS redirect, sign-up closed and the "Try the demo" button, the demo account unable to submit text of its own, a demo investigation from start to finish, the audit chain, the cross-site check, and the walls between the containers. Then it checks that every container runs on that machine's own kind of processor, and starts the system once more the way a codespace does (`codespaces-start.sh`), checking it with `deploy/codespaces-check.sh`: the page and its headers over plain HTTP, the public demo mode, the cross-site check, and Caddy as an ordinary user with the Codespaces settings.
