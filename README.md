# Casewright

[![CI](https://github.com/mKs2609/casewright/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mKs2609/casewright/actions/workflows/ci.yml)

**An AI security analyst that builds its case from evidence.**

> An AI security analyst that investigates threats like a human would, explains itself to experts and non-experts at the same time, and never acts alone on anything risky.

Given a suspicious email, a burst of login attempts or a phone-call transcript, the system investigates step by step with tools, produces an evidence-backed verdict, explains it twice (a technical report and a plain-language one), and waits for a human before any high-risk action.

**Status:** early development. See the [roadmap](docs/ROADMAP.md).

## Project structure

```
.
├── gateway/     Java Spring Boot: public API, auth, rate limiting, WebSocket
├── agent/       Python: the AI reasoning agent and its tools        (not built yet)
├── dashboard/   React + D3: live investigation dashboard             (not built yet)
├── docs/        Project documents
├── AGENTS.md    Instructions for AI coding assistants
└── SECURITY.md  Security checklist and status
```

## Documents

| Document | What it answers |
|---|---|
| [PRD](docs/PRD.md) | What are we building, for whom, and what is out of scope? |
| [Architecture](docs/ARCHITECTURE.md) | How do the parts fit together? Data model, APIs, request flow. |
| [Agent design](docs/AGENT_DESIGN.md) | How does the AI agent investigate, and what stops it being manipulated? |
| [Design system](docs/DESIGN_SYSTEM.md) | Colours, type, components and writing style for the dashboard. |
| [Threat model](docs/THREAT_MODEL.md) | What could go wrong, and which control prevents it? |
| [Roadmap](docs/ROADMAP.md) | The 18 build steps and when each is "done". |
| [Tasks](docs/TASKS.md) | What is being worked on right now. |
| [Rules](docs/RULES.md) | How we work, security rules, definition of done. |
| [Git workflow](docs/GIT_WORKFLOW.md) | Branches, commits, pull requests: how a change reaches `main`. |
| [Decisions](docs/DECISIONS.md) | Why each significant choice was made. |
| [Glossary](docs/GLOSSARY.md) | Plain-language meanings of the terms used. |
| [Security](SECURITY.md) | Status of every hardening item. |

## Running the gateway

Requirements: Java 25 or newer and PostgreSQL 16. Maven comes bundled as `mvnw`.

One-time database setup (creates the database, a limited database user, and your local `.env` file; it asks for your PostgreSQL `postgres` password):

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1
```

Generate the application's secrets, then the development certificate the gateway uses for HTTPS (both are safe to re-run, and nothing they create is committed):

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-secrets.ps1
```

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1
```

Optionally, trust that certificate for your Windows account so browsers stop warning about it (Windows asks you to confirm; `-Untrust` removes it again):

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1 -Trust
```

Then start the gateway:

```bash
cd gateway
./mvnw spring-boot:run
```

Then open https://localhost:8443/api/health. The gateway only speaks HTTPS. You should see `{"status":"UP","database":"UP", ...}`.

Run the tests (they start their own throwaway PostgreSQL, so they need no setup). GitHub also runs them on every pull request:

```bash
cd gateway
./mvnw test
```

## Running the agent

The agent is a separate Python service (3.14) that the gateway calls to investigate each incident. It listens on this machine only and accepts calls only from the gateway, which proves itself with `AGENT_SERVICE_TOKEN` from `.env` (created by `setup-secrets.ps1`).

One-time setup, from the `agent` folder:

```bash
python -m venv .venv
```

```bash
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Start it (keep it running alongside the gateway):

```bash
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --no-server-header
```

Run its tests:

```bash
.\.venv\Scripts\python.exe -m pytest
```
