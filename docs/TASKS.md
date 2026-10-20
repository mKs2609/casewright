# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-19

---

## Now

### Step 7: Incident ingestion (on `feature/incident-ingestion`)
- [x] Migration V3: `monitored_identities` (encrypted baseline) and `incidents` (JSONB payload)
- [x] Baselines encrypted with AES-256-GCM (`BaselineCipher`, ADR-37); new secret `BASELINE_ENCRYPTION_KEY`
- [x] Three fictional demo employees added at startup (`demo.seed-identities`)
- [x] `POST /api/incidents` (ANALYST/ADMIN, `202`), `GET /api/incidents`, `GET /api/incidents/{id}`
- [x] `email` and `login` kinds with strict validation; unknown kinds and fields refused; strict IP parsing
- [x] `call_transcript` kind: validation rules and tests
- [x] Tests: `IncidentApiTest`, `BaselineCipherTest`, `MonitoredIdentitiesTest`
- [ ] Merged

## Next

### Step 8: Agent service and secure connection
Needs ADR-3, ADR-4 and ADR-5 confirmed.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-3/4/5 for the agent service, ADR-15) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

- **2026-10-19:** Step 6 (rate limiting) merged: PR #4.
- **2026-10-18:** Step 5b (local HTTPS) merged: PR #3.
- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
