# Architecture

**Status:** Draft v1 · **Last updated:** 2026-10-02
Decisions referenced as ADR-n are recorded in [`DECISIONS.md`](DECISIONS.md).

---

## 1. System overview

```mermaid
flowchart LR
    U[Browser<br/>React dashboard] -- HTTPS + WebSocket --> G[Gateway<br/>Java Spring Boot]
    G -- SQL --> DB[(PostgreSQL)]
    G -- internal HTTP<br/>service token --> A[Agent service<br/>Python FastAPI]
    A -- local HTTP --> L[Local AI model<br/>Ollama, same machine]
```

There are three services and one database. Only the **gateway** is reachable from the browser.

| Component | Tech | Responsibility | Never does |
|---|---|---|---|
| **Dashboard** | React, TypeScript, Vite, D3 | Shows incidents, the live investigation, both reports, the approval screen. | Hold secrets; decide anything about security. |
| **Gateway** | Java 25, Spring Boot 4, Spring Security | The only public entry point. Authentication, authorisation, rate limiting, validation, incident storage, approvals, audit log, WebSocket. **Owns the database.** | Call the LLM. |
| **Agent** | Python 3, FastAPI | Runs one investigation: tools, LLM loop, guardrails, risk score, both reports. **Stateless.** | Touch the database; accept traffic from browsers; execute actions. |
| **PostgreSQL** | v16 | All persistent data. | |

### Why split it this way

- **The gateway owns all data and all authority (ADR-3).** The agent receives everything it needs in the request and returns results. It has no database credentials. If the LLM is manipulated, the worst it can do is return a bad answer, which the gateway validates before storing.
- **The agent is the only part that sees attacker-controlled text next to an LLM.** Keeping it small, stateless and isolated limits what a successful attack can reach.
- **Java for the perimeter, Python for the AI (ADR-1).** Spring Security is mature for auth and hardening; Python has the best LLM tooling.

## 2. Request flow: one investigation

```mermaid
sequenceDiagram
    participant B as Browser
    participant G as Gateway
    participant DB as PostgreSQL
    participant A as Agent
    participant L as LLM

    B->>G: POST /api/incidents (cookie auth)
    G->>G: validate, authorise, rate-limit
    G->>DB: insert incident (status=queued)
    G-->>B: 202 Accepted {incidentId}
    G->>A: POST /internal/investigate (incident + baselines + recent indicators)
    loop each investigation step
        A->>L: messages + tool definitions
        L-->>A: tool call
        A->>A: validate arguments, run tool
        A-->>G: stream event: step
        G->>DB: insert evidence + audit entry
        G-->>B: WebSocket: agent.step
    end
    A-->>G: stream event: verdict (reports, proposed actions)
    G->>G: validate schema, re-check action policy
    G->>DB: insert verdict, actions (high-risk = pending), audit
    G-->>B: WebSocket: verdict
    B->>G: POST /api/actions/{id}/decision
    G->>DB: update action, audit entry
```

The gateway never trusts the agent's output: it parses it against a schema and re-applies the action allow-list before anything is saved (ADR-5).

## 3. Repository layout

```
.
├── gateway/        Spring Boot app (Maven)
│   └── src/main/java/com/securityanalyst/gateway/
│       ├── health/       health endpoint
│       ├── auth/         signup, login, tokens, roles
│       ├── incident/     ingestion, listing, detail
│       ├── agent/        client that calls the agent service
│       ├── action/       proposed actions, approvals
│       ├── audit/        hash-chained audit log
│       ├── realtime/     WebSocket
│       └── common/       error handling, validation, rate limiting, security config
├── agent/          Python FastAPI service
│   └── app/
│       ├── main.py          internal API
│       ├── investigation.py one investigation: the AI first, the fixed plan as fallback
│       ├── reasoning.py     the AI-led loop: prompt, fence, submit_verdict
│       ├── llm.py           talks to the local model (Ollama)
│       ├── budget.py        daily cap on model use
│       ├── tools.py         the allow-listed tools and the guardrail (+ one module per tool)
│       ├── verdict.py       risk score, verdict, attack type
│       ├── report.py        the SOC and plain reports, from the evidence
│       └── summary.py       the one checked AI summary line
├── dashboard/      React app
├── docs/           this folder
├── AGENTS.md       instructions for AI coding assistants
├── README.md
└── SECURITY.md
```

Packages are organised **by feature**, not by layer, so everything about one feature lives together.

## 4. Data model

All tables live in PostgreSQL and are created by Flyway migrations in `gateway/src/main/resources/db/migration`.

```mermaid
erDiagram
    app_users ||--o{ refresh_tokens : has
    app_users ||--o{ incidents : submits
    monitored_identities ||--o{ incidents : "is subject of"
    incidents ||--o{ evidence : has
    incidents ||--|| verdicts : has
    incidents ||--o{ actions : has
    app_users ||--o{ actions : decides
```

| Table | Purpose | Key columns |
|---|---|---|
| `app_users` | People who log in to the product (analysts). | `id`, `username` (unique), `password_hash`, `role`, `created_at` |
| `refresh_tokens` | Rotating refresh tokens. Only a hash is stored. | `token_hash`, `user_id`, `expires_at`, `revoked_at`, `replaced_by` |
| `monitored_identities` | Employees the product protects, with their baseline. **Not** the same as `app_users`. | `identity` (e.g. `priya.sharma`), `display_name`, `baseline` (AES-256-GCM encrypted bytes, ADR-37), `created_at` |
| `incidents` | One suspicious event. | `id`, `kind`, `subject_identity`, `payload` (JSONB, the validated request), `status`, `source`, `created_by`, `created_at` |
| `incident_indicators` | The indicators found in each incident, for correlation across incidents (ADR-42). | `incident_id`, `type` (`ip`/`domain`/`email`/`phone`), `value`; indexed on (`type`, `value`) |
| `evidence` | One row per agent tool call, accepted (E1, E2, …) or refused (R1, R2, …). | `id`, `incident_id`, `label`, `tool`, `args` (JSONB), `status` (`ok`/`rejected`), `summary`, `result` (JSONB), `signals` (JSONB list of findings), `reason` (refused calls), `created_at`. One label per incident. |
| `verdicts` | Final outcome of an investigation (ADR-43). | `incident_id`, `verdict`, `attack_type`, `risk_score` (recomputed by the gateway), `agent_verdict`, `agent_risk_score`, `disagreement`, `engine`, `cited_evidence`, `counterfactual`, `soc_report`, `plain_report` (JSONB, step 13, checked against the stored evidence), `created_at` |
| `actions` | Proposed response actions and their lifecycle. | `id`, `incident_id`, `action`, `target`, `risk`, `status` (`pending`/`executed`/`rejected`/`expired`), `proposed_by`, `decided_by`, `decided_at`, `reason` |
| `enforcement` | What the (simulated) enforcement layer has done. | `id`, `action_id`, `action`, `target`, `created_at` |
| `audit_log` | Tamper-evident, append-only history (ADR-46). | `seq` (no gaps), `ts`, `actor`, `event`, `incident_id` (no foreign key), `data`, `prev_hash`, `hash` |

Incident status: `queued → investigating → awaiting_approval | needs_review | closed | error`. Since step 11: benign verdicts close the incident; suspicious, malicious and disagreements go to `needs_review`; `awaiting_approval` arrives with human approval (step 15).

## 5. API surface

### 5.1 Public API (gateway, HTTPS on port 8443)

All responses are JSON. Errors use one shape: `{"error": "...", "fields": {...}, "traceId": "..."}` (`fields` only for validation errors). Every response carries an `X-Trace-Id` header that matches the `traceId` and the server log lines for that request.

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/health` | none | Liveness check |
| POST | `/api/auth/signup` | none | Create account |
| POST | `/api/auth/login` | none | Log in, set cookies |
| POST | `/api/auth/refresh` | cookie | Rotate tokens |
| POST | `/api/auth/logout` | any | Revoke refresh token |
| GET | `/api/me` | any | Current user |
| GET | `/api/admin/users` | ADMIN | List users |
| PUT | `/api/admin/users/{id}/role` | ADMIN | Change a user's role (never one's own) |
| POST | `/api/incidents` | ANALYST+ | Submit an incident (`202 Accepted`, investigation queued) |
| GET | `/api/incidents` | any | List incidents |
| GET | `/api/incidents/{id}` | any | Incident + evidence (since step 9) + verdict + actions |
| POST | `/api/actions/{id}/decision` | ANALYST+ | Approve or reject |
| GET | `/api/audit?limit=100` | any | Recent audit entries, newest first (at most 500) |
| GET | `/api/audit/verify` | any | Walk the hash chain: valid or not, entries, head entry and hash, where it broke |
| POST | `/api/demo/{scenario}` | ANALYST+ | Fire a simulated incident |
| WS | `/ws` | any | Live event stream |

### 5.2 Internal API (agent, port 8001, bound to localhost)

| Method | Path | Purpose |
|---|---|---|
| GET | `/internal/health` | Liveness |
| POST | `/internal/investigate` | Run one investigation; response is a stream of newline-delimited JSON events |

Every internal request carries `Authorization: Bearer <AGENT_SERVICE_TOKEN>`. The agent rejects anything without it.

### 5.3 Event types (agent → gateway → browser)

| Event | Meaning |
|---|---|
| `incident.created` / `incident.status` | Lifecycle changes |
| `incident.indicators` | (agent → gateway) The indicators found in the incident, reported once, checked and stored (step 10b) |
| `agent.thought` | Short narration of what the agent is about to do |
| `agent.step` | A completed tool call (an evidence item: label, tool, args, summary, result, signals); the running risk score is added in step 11 |
| `agent.guardrail` | A tool call or action that was **blocked** (label R1, R2, …), with the reason |
| `verdict` | Final verdict available (agent → gateway: verdict, attack type, risk score, cited evidence, counterfactual; the gateway recomputes the score and applies the floor) |
| `report` | (agent → gateway, after the verdict) The SOC and plain reports as structured data; every finding and reason must match the stored evidence (ADR-45) |
| `investigation.complete` | (agent → gateway) Last line of every investigation: the status the agent suggests (`needs_review` or `closed`; the gateway decides) and the engine, `llm` or `rules` (ADR-44). |
| `action.decided` | A human approved or rejected an action |

## 6. Security architecture (summary)

Full detail in [`THREAT_MODEL.md`](THREAT_MODEL.md) and `SECURITY.md`.

| Layer | Controls |
|---|---|
| Browser → Gateway | TLS, HttpOnly/Secure/SameSite cookies, CSRF protection, CSP and security headers, rate limiting, strict validation |
| Gateway | Role checks on every endpoint, object-level checks, generic errors with trace IDs, audit log |
| Gateway → Agent | Localhost-only binding, service token, schema validation of everything returned |
| Agent | Incident text fenced as data, read-only tool allow-list, arguments limited to values extracted from the incident, action policy, turn and time limits |
| Data | Argon2 password hashes, hashed tokens, encrypted baselines, HMAC-chained audit log |

## 7. Configuration and secrets

Nothing secret is committed. Each service reads environment variables; a `.env.example` documents the names.

| Variable | Used by | Purpose |
|---|---|---|
| `DB_URL`, `DB_USER`, `DB_PASSWORD` | gateway | PostgreSQL connection |
| `JWT_SIGNING_KEY` | gateway | Signs access tokens (32+ random bytes, Base64; created by `scripts\setup-secrets.ps1`) |
| `AUDIT_HMAC_KEY` | gateway | Signs the audit chain (32+ random bytes, Base64; created by `scripts\setup-secrets.ps1`; never change it, or existing entries fail verification) |
| `BASELINE_ENCRYPTION_KEY` | gateway | Encrypts baselines at rest (exactly 32 random bytes, Base64; created by `scripts\setup-secrets.ps1`) |
| `AGENT_SERVICE_TOKEN` | gateway, agent | Authenticates gateway → agent calls (32+ random bytes, Base64; created by `scripts\setup-secrets.ps1`; both read it from `.env`) |
| `LLM_PROVIDER`, `LLM_MODEL`, `OLLAMA_URL` (not secret) | agent | The local AI model: `off` (default, rule engine only) or `ollama`; the model name; its address, which must be on this machine (ADR-15) |
| `SECURITY_RATELIMIT_*` (optional) | gateway | Override the rate-limit thresholds set in `application.properties`, e.g. `SECURITY_RATELIMIT_REQUESTSPERMINUTE` |

## 8. Local development

| Service | Port | Start command |
|---|---|---|
| Gateway | 8443 (HTTPS only) | `cd gateway && ./mvnw spring-boot:run`. Needs the certificate from `scripts\setup-https.ps1` |
| Agent | 8001 (127.0.0.1 only) | `cd agent; .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --no-server-header` |
| Ollama (AI model) | 11434 (127.0.0.1 only) | Installed app, runs in the background. Once: `ollama pull qwen3:8b`; then `LLM_PROVIDER=ollama` in `.env` |
| Dashboard | 5173 | `cd dashboard && npm run dev` |
| PostgreSQL | 5432 | Windows service `postgresql-x64-16`. Database `secanalyst`, role `secanalyst_app`, created once by `scripts\setup-db.ps1` |

## 9. Testing strategy

| Level | Tool | What it covers |
|---|---|---|
| Gateway unit / slice | JUnit 6, MockMvc | Controllers, validation, security rules |
| Gateway integration | Spring Boot test + embedded PostgreSQL 16 (started by the tests, ADR-16) | Migrations, repositories, auth flows |
| Agent unit | pytest | Tools, guardrails, scoring, reports |
| Agent scenarios | pytest | Each demo scenario reaches the expected verdict with the rule engine, and with a scripted model making the same calls (same evidence, same score) |
| Red-team suite | pytest | A scripted hijacked model (tools off the allow-list, values not in the incident, odd arguments, invented evidence, skipped checks, a benign claim) never gets an unauthorised call through and never lowers a verdict (`test_reasoning.py`) |
| Dashboard | Vitest + Testing Library | Components render untrusted text safely |
| End to end | Script against running services | Submit → investigate → approve → audit verifies |
| CI | GitHub Actions (`.github/workflows/ci.yml`) | Gateway tests on every pull request and push to `main` (since step 5a); more suites, dependency audit and static analysis added as they arrive |
