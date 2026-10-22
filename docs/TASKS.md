# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-23

---

## Now

### Step 9: Tool 1 (reputation lookup) and the evidence chain (on `feature/reputation-and-evidence`)
- [x] Indicator extraction in the agent (IPs, domains, email addresses, phone numbers; strict IPv4; capped)
- [x] Reputation lookup with look-alike and new-domain checks; mock data uses only reserved example names
- [x] One guardrail for every tool call: unknown tools and arguments not in the incident are refused and recorded as R1, R2, ...
- [x] Gateway stores evidence as it arrives (migration V4, `evidence` table), enforces E1, E2, ... order; the incident detail API lists it
- [x] Tests: agent 54, gateway 154; two mutation checks
- [ ] Merged

## Next

### Step 10: Tools 2-4 (baseline check, pattern match, correlation)
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

- **2026-10-22:** Fixed a flaky test: "not echoed" checks were sometimes fooled by the random trace ID (a short value like `ab` appears in one in about 17 trace IDs). Checks now blank the trace ID first (`NoEcho`).
- **2026-10-22:** Step 8 (agent service, secure connection) merged: PR #6. "Agent tests" is now a required check on `main`.
- **2026-10-21:** Step 7 (incident ingestion, encrypted baselines) merged: PR #5.
- **2026-10-19:** Step 6 (rate limiting) merged: PR #4.
- **2026-10-18:** Step 5b (local HTTPS) merged: PR #3.
- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
