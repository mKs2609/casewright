# Roadmap

**Last updated:** 2026-10-02

One feature at a time. A step is finished only when it is **built, explained, tested, and committed by Mohit**.
Pushing to GitHub waits until the project is demo-ready and named (around step 16–17).
The checklist for the step currently in progress lives in [`TASKS.md`](TASKS.md).

Status: ✅ committed · 🟡 built, waiting for review/commit · ⬜ not started

| # | Step | You will learn | Done when | Status |
|---|---|---|---|---|
| 0 | **Project documents** | How a project is specified before code | PRD, architecture, design system and the other docs are committed | 🟡 |
| 1 | **Gateway skeleton + health endpoint** | Spring Boot basics, controllers, tests, Maven | `GET /api/health` returns `UP`; 3 tests pass | 🟡 |
| 2 | **PostgreSQL + migrations** | Connecting to a database, Flyway, a least-privilege DB user | Gateway starts against Postgres; first migration creates `app_users`; integration test passes | 🟡 (run and checked by Mohit; not committed) |
| 3 | **Signup and login** | Password hashing with Argon2, DTO validation | A user can sign up and log in; the stored password is a hash; wrong password gives a generic error | 🟡 (run and checked by Mohit; not committed) |
| 4 | **Tokens and roles** | JWT, refresh rotation, secure cookies, Spring Security filters | Protected endpoints need a valid token; `VIEWER` is refused where `ANALYST` is required; refresh rotates; logout revokes | 🟡 |
| 5 | **Validation, errors, headers** | Global exception handling, CSP and security headers, CSRF | Bad input is rejected without echoing it; errors return a trace ID and no stack trace; headers present on every response | ⬜ |
| 6 | **Rate limiting** | Token buckets, backoff, config-driven limits | Login is limited per IP and per account with backoff; limits come from config; tests prove it | ⬜ |
| 7 | **Incident ingestion** | Polymorphic request validation, JSON columns, baselines | The three incident kinds can be submitted, listed and fetched; baselines seeded and encrypted | ⬜ |
| 8 | **Agent service + secure connection** | FastAPI, service-to-service auth, streaming responses | Gateway calls the Python agent with a service token; calls without the token are refused; agent returns a stub result | ⬜ |
| 9 | **Tool 1: reputation lookup + evidence chain** | Tool design, argument guardrails, evidence records | An incident produces evidence `E1`; lookups outside the incident are rejected and logged | ⬜ |
| 10 | **Tools 2–4** | Baseline comparison, pattern matching, correlation | Each tool has tests; credential stuffing and impossible travel are detected | ⬜ |
| 11 | **Risk score, verdict, rule engine** | Combining evidence, deterministic verdicts | All six scenarios reach the expected verdict with no LLM | ⬜ |
| 12 | **LLM reasoning agent** | Tool calling with an LLM, prompt-injection defence, schema-validated output | The LLM drives the tools; red-team suite passes; fallback works when the LLM is off | ⬜ |
| 13 | **Dual explanation** | Generating two views from one source | SOC and plain reports are produced; every finding cites existing evidence | ⬜ |
| 14 | **Audit log** | Hash chains, HMAC | Every event is logged; editing a row makes verification fail | ⬜ |
| 15 | **Human approval** | State machines, separation of duties | High-risk actions wait as `pending`; approve/reject is audited; expiry and self-approval rules hold | ⬜ |
| 16 | **Dashboard + live stream** | React, WebSocket auth, safe rendering, the design system | Investigation appears live; steps are clickable; both reports render; approval works from the UI | ⬜ |
| 17 | **Demo scenarios + red-team probe** | Building a reliable demo | "Attempt breach" and the other scenarios run from the UI; the probe shows every hijack attempt blocked | ⬜ |
| 18 | **CI security gate + evaluation** | GitHub Actions, dependency audit, static analysis, measuring accuracy | Every push runs tests and scans; evaluation numbers are in the README; `SECURITY.md` fully ticked | ⬜ |

## Suggested pace (8 weeks)

| Week | Steps |
|---|---|
| 1 | 0–2 |
| 2 | 3–6 |
| 3 | 7–9 |
| 4 | 10–11 |
| 5 | 12–13 |
| 6 | 14–16 |
| 7 | 16–17 |
| 8 | 18, polish, demo video, rehearsal |

## After the roadmap (stretch)

Uploading `.eml` files · a real threat-intel feed behind a flag · analyst feedback on verdicts · grouping related incidents into campaigns · investigation replay · anchoring the audit chain externally.
