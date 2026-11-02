# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-02

---

## Now

### Step 16a: Dashboard (on `feature/dashboard`)
- [x] React and TypeScript app in `dashboard/`, with design tokens from the design system
- [x] Login, session renewal (one refresh at a time, across tabs) and logout
- [x] Incident list with verdict, status and risk score (the gateway's list gained the last two)
- [x] Investigation view: steps, blocked calls, risk meter, clickable evidence chips
- [x] Both reports, side by side with the evidence
- [x] Approval card: evidence above the buttons; the gateway has the last word
- [x] Page security policy; incident text is only ever text
- [x] Tests: dashboard 73, gateway 288 (both test orders), agent 302; 26 mutation checks with controls
- [x] "Dashboard tests" job in CI
- [x] Checked in a real browser against a fake gateway, and the HTTPS forwarding against the real one (no login)
- [x] Live: logged in on the real gateway, opened an AI-led incident and approved its block; simulated enforcement recorded, chain valid
- [ ] Merged, and "Dashboard tests" added to the required checks

## Next

### Step 16b: Live stream
Steps appear as they happen, over Server-Sent Events (ADR-48).

## Later

See `ROADMAP.md` steps 17–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

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
