# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-06

---

## Now

### Step 17b: Red-team probe (on `feature/red-team-probe`)
- [x] Agent: a scripted, hijacked model (`app/redteam.py`) used only for requests marked `redTeam`, with its own budget
- [x] Gateway: `POST /api/red-team` submits the trick email as a `red_team` incident; only those ask the agent for the script
- [x] Gateway: `GET /api/red-team/{id}`, a scorecard judged from the stored record; anything not shown blocked is reported (ADR-51)
- [x] Dashboard: "Red-team the agent" button, "Red team" badge, the scorecard following the live feed
- [x] README: the probe added to the evidence and the limitations
- [x] Tests: gateway 345 (both orders), dashboard 102, agent 324; 28 of 28 mutation checks caught with controls (14 gateway, 10 dashboard, 4 agent)
- [x] Live: two runs from the dashboard, 10 of 10 attempts blocked each; stored record agrees; no gateway errors; audit chain valid
- [ ] Merged

## Next

### Step 18: CI security gate and evaluation
See `ROADMAP.md`.

## Later

Step 19: the final handbook.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

- **2026-11-06:** Step 17a (demo scenarios) merged: PR #18. The README now covers the safety approach, evidence and limitations.
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
