# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-24

---

## Now

### Step 10b: Related incidents (on `feature/related-incidents`)
- [x] The agent reports each incident's indicators once; the gateway checks each value against its type and stores them (migration V5, `incident_indicators`)
- [x] Each investigation gets the indicators of incidents from the last 7 days (setting), values and incident numbers only, bounded
- [x] `correlate_events` reports `RELATED-INCIDENTS`, ignoring known-good entries and internal addresses; emails and calls now end with correlation
- [x] Tests: agent 119, gateway 160; two mutation checks
- [ ] Merged

## Next

### Step 11: Risk score, verdict and rule engine
Combine the evidence into a risk score and a verdict, without an LLM; the six demo scenarios must reach their expected verdicts.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-15 before step 12) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

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
