# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-01

---

## Now

### Step 15: Human approval (on `feature/human-approval`)
- [x] Code proposes actions from the findings (Mohit's choice); a new `actions.proposed` event
- [x] The gateway's policy decides the risk and checks every target against what it stored
- [x] Low-risk actions run at once; high-risk ones wait as `pending`, and the incident shows `awaiting_approval`
- [x] `POST /api/actions/{id}/decision`: analysts and admins, one winner, no deciding your own account; the submitter may decide (Mohit's choice)
- [x] Approvals expire after 24 hours, as a setting (Mohit's choice)
- [x] Simulated enforcement table; every step in the audit log
- [x] Incidents cut off by a stopped gateway become `error` at startup
- [x] README brought up to date
- [x] Tests: agent 302, gateway 287 (both test orders); 22 mutation checks with controls
- [x] Live: AI-led run, awaiting approval, approved by a person, simulated enforcement recorded, chain valid
- [ ] Merged

## Next

### Step 16: Dashboard and live stream
The investigation appears live; steps are clickable; both reports render; approval works from the screen.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

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
