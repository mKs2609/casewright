# Casewright

[![CI](https://github.com/mKs2609/casewright/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mKs2609/casewright/actions/workflows/ci.yml)

**An AI security analyst that builds its case from evidence.**

> An AI security analyst that investigates threats like a human would, explains itself to experts and non-experts at the same time, and never acts alone on anything risky.

Given a suspicious email, a burst of login attempts or a phone-call transcript, the system investigates step by step with tools, produces an evidence-backed verdict, explains it twice (a technical report and a plain-language one), and waits for a human before any high-risk action.

**Status:** the backend works end to end through its API: investigation, verdicts, both reports, human approval and the audit log. The dashboard, demo scenarios and evaluation are next. See the [roadmap](docs/ROADMAP.md).

## What it does today

| Stage | What happens | What keeps it honest |
|---|---|---|
| **Report** | Someone submits a suspicious email, a batch of logins or a call transcript | Strict validation; only analysts and admins can submit |
| **Investigate** | A local AI model chooses which read-only tools to run. Without one, a fixed plan does | Every call passes one guardrail; incident text is fenced as data; the model can add checks but never skip the standard ones |
| **Decide** | A risk score from the evidence gives the verdict and attack type | Computed by code, not the AI; the gateway recomputes it and never lets a verdict fall below the evidence |
| **Explain** | One report for the security team, one in plain language for the employee | Both built from recorded findings, and checked word for word against the stored evidence |
| **Act** | Actions are proposed from the findings. Low-risk ones run at once; high-risk ones wait for a person | The gateway's policy checks every proposal; proposals expire after 24 hours; nobody decides an action on their own account |
| **Record** | Every step goes into an append-only audit log | Each entry is signed together with the one before it, using a key outside the database |

**What is simulated:** the threat data is a small built-in list using reserved example names, and approved actions are recorded instead of carried out ([ADR-13](docs/DECISIONS.md)). Nothing real gets blocked.

### Human approval

A high-risk action (blocking an address, domain or number, quarantining an email, locking an account or forcing a password reset) starts as `pending`, and its incident shows `awaiting_approval`. Analysts and admins decide it:

| Request | What it does |
|---|---|
| `GET /api/actions` | What is waiting (or `?status=executed`, `rejected`, `expired`) |
| `GET /api/incidents/{id}` | The incident with its evidence, verdict, reports and actions |
| `POST /api/actions/{id}/decision` | Body `{"decision": "approve"}` or `{"decision": "reject"}` |
| `GET /api/audit` | Recent audit entries |
| `GET /api/audit/verify` | Checks the chain, and says where it broke if it did |

Internal addresses and your own domains can never be blocked, whatever an incident says. So a hidden "block 10.0.0.5" note in an email goes nowhere.

To try the whole path, with the gateway and agent running (see below):

```bash
powershell -ExecutionPolicy Bypass -File scripts\try-incident.ps1 -Username <you> -Decide approve
```

Your account needs the `ANALYST` or `ADMIN` role, which `scripts\set-role.ps1` can grant.

## Project structure

```
.
├── gateway/     Java Spring Boot: public API, auth, rate limiting, approvals, audit log
├── agent/       Python: the investigation, its tools, the verdict and both reports
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

If you already have a `.env` from before the audit log, run `setup-secrets.ps1` again to add its key. Keep that key: changing it makes every existing audit entry fail verification. The gateway also writes `gateway/logs/gateway.log`, which is a record of the audit chain's latest position outside the database.

Settings such as how long approvals stay open (`actions.approval-lifetime`, 24 hours) and which domains can never be blocked (`actions.protected-domains`) are in `gateway/src/main/resources/application.properties`.

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

Optional: let a free local AI model choose the investigation steps. Install [Ollama](https://ollama.com/download) (use "Download manually"), download the model once, then add `LLM_PROVIDER=ollama` to `.env` and restart the agent. Without it, the agent uses its fixed plan.

```bash
ollama pull qwen3:8b
```
