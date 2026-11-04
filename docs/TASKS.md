# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-04

---

## Now

### Step 16b: Live stream (on `feature/live-stream`)
- [x] `GET /api/incidents/events`: incident numbers only, announced from the audit log after each commit (ADR-49)
- [x] The feed closes when its access token expires; access tokens no longer get a 60-second grace period
- [x] Limits: 3 feeds per user, 200 in total; keep-alive; a slow or vanished browser is dropped without holding anything up
- [x] Errors stay JSON for a request that asked for the stream; a browser leaving is not logged as an error
- [x] Dashboard follows the feed through `src/api.ts`, reconnects with backoff, merges reloads; live badge; Refresh still works
- [x] Tests: gateway 311 (both test orders), dashboard 87, agent unchanged (302, left to CI); 28 mutation checks with controls (15 dashboard, 13 gateway)
- [x] Checked through the dashboard's forwarding: messages arrive as sent, nothing held back; a browser leaving reaches the server
- [x] Live: two AI-led incidents investigated on screen as they ran (Live badge, no Refresh); a block approved in the browser; no gateway errors; audit chain valid
- [ ] Merged

## Next

### Step 17: Demo scenarios and red-team probe
See `ROADMAP.md`.

## Later

See `ROADMAP.md` step 18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

- **2026-11-03:** Step 16a (dashboard) merged: PR #16. "Dashboard tests" is now a required check on `main`.
- **2026-11-02:** Step 15 (human approval) merged: PR #15.
- **2026-10-31:** Step 14 (audit log) merged: PR #14.
- **2026-10-30:** Step 13 (dual explanation) merged: PR #13.
- **2026-10-29:** Step 12 (LLM reasoning agent, local model) merged: PR #12.
- **2026-10-27:** Step 11 (risk score, verdict, rule engine) merged: PR #11.
- **2026-10-25:** Step 10b (related incidents) merged: PR #10.
- **2026-10-24:** Step 10 (baseline check, pattern match, correlation) merged: PR #9.
- **2026-10-23:** Step 9 (reputation lookup, evidence chain) merged: PR #8.
- **2026-10-22:** Fixed a flaky test: "not echoed" checks were sometimes fooled by the random trace ID (a short value like `ab` appears in one in about 17 trace IDs). Checks now blank the trace ID first (`NoEcho`).
- **2026-10-22:** Step 8 (agent service, secure connection) merged: PR #6. "Agent tests" is now a required check on `main`.
- **2026-10-21:** Step 7 (incident ingestion, encrypted baselines) merged: PR #5.
- **2026-10-19:** Step 6 (rate limiting) merged: PR #4.
- **2026-10-18:** Step 5b (local HTTPS) merged: PR #3.
- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
