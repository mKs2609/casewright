# The web server's image (step 19a, ADR-54): Caddy, with the built dashboard inside it. Built from
# the repository root:
#   docker build -f deploy/caddy.Dockerfile .
# Pinned by digest, like every base image here.

# ---- Stage 1: build the dashboard (Node is needed only for this, and is thrown away afterwards)
FROM node:24.22.0-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4 AS dashboard
WORKDIR /src
# Exact versions from the lock file; packages may not run install scripts (.npmrc).
COPY dashboard/package.json dashboard/package-lock.json dashboard/.npmrc ./
RUN npm ci --no-audit --no-fund
COPY dashboard/ ./
# The page's security headers, generated from the same file the dev server uses (pagePolicy.ts).
RUN npm run build && node scripts/page-headers.ts > /page-headers.caddy

# ---- Stage 2: Caddy, the files and its settings
FROM caddy:2.11.6-alpine@sha256:d44355d3c2149dc580ce2cac735955d1c08d3d00882c30489c241aa51a5c10d9
# An ordinary user, as in the other images. Caddy keeps its certificates in /data and /config.
# It listens on high ports (Caddyfile), so the binary's built-in right to open low ports is removed:
# with every right dropped (compose.yaml), Linux would refuse to start a binary that asks for one.
RUN addgroup -S web && adduser -S -G web -H web && chown -R web:web /data /config \
    && setcap -r /usr/bin/caddy
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=dashboard /page-headers.caddy /etc/caddy/page-headers.caddy
COPY --from=dashboard /src/dist /srv
USER web
