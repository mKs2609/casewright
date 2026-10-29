# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-29

---

## Now

### Step 13: Dual explanation (on `feature/dual-explanation`)
- [x] SOC and plain reports built by code from the evidence chain; sent as a `report` event after the verdict
- [x] Gateway checks every finding and reason against the stored evidence; reports stored with the verdict (migration V7)
- [x] One AI summary line (SOC report only): written from masked findings, kept only if it passes every check (Mohit's choice, ADR-45)
- [x] Plain report: no jargon, reading grade 8 or below; three plain sentences reworded
- [x] Tests: agent 291, gateway 192 (both test orders); 12 new mutation checks, step 12's 16 still caught
- [x] Live: six scenarios with both reports accepted; 4 of 5 AI lines kept (one too long)
- [ ] Merged

## Next

### Step 14: Audit log
Every event logged in a hash chain with an HMAC key kept outside the database; editing a row makes verification fail.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

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
