# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-25

---

## Now

### Step 11: Risk score, verdict and rule engine (on `feature/risk-score-and-verdict`)
- [x] Rule engine in the agent: noisy-OR risk score, bands, attack type, cited evidence, counterfactual; `verdict` event
- [x] Gateway recomputes the score from stored evidence and enforces the floor; disagreements go to a human; cited evidence must exist (migration V6, `verdicts`)
- [x] Benign incidents close automatically; the incident detail shows the verdict
- [x] The six demo scenarios reach their expected verdicts with no AI (tests, and live through the API)
- [x] Shared golden file of risk-score cases checked by both test suites
- [x] Related incidents: known-harmless entries (score below 10) no longer link incidents
- [x] Tests: agent 153, gateway 183 (both check the golden file); mutation checks
- [ ] Merged

## Next

### Step 12: LLM reasoning agent
Needs ADR-15 confirmed (which LLM, and the budget).

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-15 before step 12) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

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
