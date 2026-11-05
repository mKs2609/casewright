# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-05

---

## Now

### Step 17a: Demo scenarios (on `feature/demo-scenarios`)
- [x] `GET /api/demo/scenarios` and `POST /api/demo/{scenario}`: the browser names a scenario, the gateway submits its own copy (ADR-50)
- [x] The six tested scenarios, generated from the agent's (`scripts/make-demo-scenarios.py`) and checked to match; validated at startup
- [x] Demo incidents stored as `source = demo`, audited as such, shown as "Simulated"; `demo.enabled` switch
- [x] Dashboard: demo buttons under the app bar, "Attempt breach" first; viewers see them disabled; the new incident opens and fills in live
- [x] Fixed on the way: a submit that ran without a transaction (Spring proxy); the stale "Refresh to see new steps" notice; the API table's old WebSocket row
- [x] Tests: gateway 325 (both orders), dashboard 95, agent 315; mutation checks with controls: 22 of 23 caught by the named test (the other cannot change a demo's verdict)
- [x] Live: all six fired from the dashboard (AI-led) reached their expected verdicts; stored and audited as demo; the injected note's target never proposed; no gateway errors; audit chain valid
- [ ] Merged

## Next

### Step 17b: Red-team probe
A hijacked model's attempts replayed against the real guardrails, each shown blocked (FR-27).

## Later

See `ROADMAP.md` step 18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

- **2026-11-05:** Step 16b (live stream) merged: PR #17.
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
