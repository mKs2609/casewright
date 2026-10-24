# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-23

---

## Now

### Step 10: Tools 2-4 (on `feature/tools-baseline-pattern-correlation`)
- [x] `baseline_check`: unusual country, hours, device, impossible travel; new sender, reply-to mismatch, unknown caller. Records differences only, never baseline values
- [x] `pattern_match`: urgency, credential and one-time-code requests, payment pressure, impersonation, remote-access tools, prompt injection; text normalised first; invisible characters reported
- [x] `correlate_events`: credential stuffing, brute force, success after failures, automation; bounded results
- [x] Fixed plan per incident kind; gateway accepts the four tool names
- [x] Tests: agent 110, gateway 155; two mutation checks. A real run showed the one-time-code check missing "read me the six-digit code"; widened and tested
- [ ] Merged

## Next

### Step 10b: Related incidents
Store each incident's indicators; tell the agent which recent incidents share them.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-15 before step 12) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

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
