# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-21

---

## Now

### Step 8: Agent service and secure connection (on `feature/agent-service`)
- [x] `agent/`: Python 3.14 FastAPI service, exact-pinned packages, `GET /internal/health`, `POST /internal/investigate` (stub, streams NDJSON events)
- [x] Agent listens on 127.0.0.1 only; every request needs `AGENT_SERVICE_TOKEN` (constant-time check); docs pages off; 1 MB body limit
- [x] Gateway calls the agent in the background after an incident is committed; status `queued → investigating → needs_review` or `error`
- [x] Gateway re-validates every event (ADR-5): known types and fields only, allow-listed status, line/event/time limits
- [x] New secret `AGENT_SERVICE_TOKEN`; trace ID carried onto the background thread
- [x] Tests: `agent/tests` (25), `InvestigationTest` (13, with a fake agent); CI job "Agent tests"
- [ ] "Agent tests" added as a required check in the `Protect main` ruleset (Mohit, on GitHub)
- [ ] Merged

## Next

### Step 9: Tool 1, reputation lookup, and the evidence chain
See `ROADMAP.md`.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-15 before step 12) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

- **2026-10-21:** Step 7 (incident ingestion, encrypted baselines) merged: PR #5.
- **2026-10-19:** Step 6 (rate limiting) merged: PR #4.
- **2026-10-18:** Step 5b (local HTTPS) merged: PR #3.
- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
