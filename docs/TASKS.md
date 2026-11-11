# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-11

---

## Now

### Step 19b: Public demo mode (on `feature/public-demo`)
- [x] Sign-up switch (`security.signup-enabled`), off on the server
- [x] "Try the demo": the shared `demo` analyst with a password nobody knows, reset at every start; `POST /api/auth/demo-login`; `GET /api/auth/options` for the login page (ADR-55)
- [x] Incidents of one's own for admins only on the server (`security.incident-submitter-roles`)
- [x] Demo runs limited per address (5 a minute) and per day for the site (300)
- [x] The live feed's per-user limit counts each visitor address separately
- [x] Login page: the "Try the demo" button where it exists
- [x] Smoke test follows the public demo's path (no sign-up, the demo button)
- [x] Fixed a timing-dependent dashboard test from step 16b (it compared with a measured delay)
- [x] Tests: gateway 364 (both orders), dashboard 107, agent 656; 12 mutation checks, all caught
- [x] Dashboard screenshot for the README and profile: `docs/images/dashboard.png` (incident #70, a phishing email with its evidence and two actions waiting for approval)
- [ ] All checks pass on GitHub, including Containers
- [ ] Merged

## Later

Step 19c (going live), then design and UI/UX polish, then step 20: the final handbook.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |

## Done

- **2026-11-11:** Step 19a (containers) merged. "Containers" is the 11th required check on `main`.
- **2026-11-10:** Step 18b (evaluation) merged: PR #21.
- **2026-11-09:** Step 18a (CI security gate) merged: PR #20. All 10 checks are required on `main`.
- **2026-11-08:** Step 17b (red-team probe) merged: PR #19.
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
