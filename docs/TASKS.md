# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-26

---

## Now

### Step 23: How evidence adds up (on `feature/evidence-scoring`, ADR-63)
Step 22 showed that more keyword rules did not help on fresh incidents. Calls are the weak spot: an unknown caller starts at 5 risk, so one clear finding (a fee before a job, a request for bank details) stays under the line of 30. This step changes how evidence combines instead, measured the same way as step 22.
- [x] A third held-out set (40: 20 attacks, 20 harmless; half of it phone calls), written before any change and checked for form only; the agent has not been run on it
- [x] Committed and pushed before any scoring change (Mohit)
- [ ] Optional: hand-written examples from Mohit (can still be added; they would be run once, as a further fresh set)
- [x] The design, from the seen sets only (all 164), approved by Mohit before it was built: agent only, no formula change. A new finding for a request to send money (`SIG-SEND-MONEY`), and a combination finding when an unknown caller's own lines ask for something (`BASELINE-STRANGER-ASKS`, ADR-64)
- [x] Built, with tests that must fire and must not; 14 of 14 mutation checks caught; 1038 agent tests pass
- [x] The third held-out set run once: 8 of 20 attacks caught (3 before), 2 of 20 false alarms (2 before); phone scams 3 of 10 (0 before), no false alarm on calls. The seven missed calls ask in words no rule knows
- [x] `docs/EVALUATION.md` regenerated (before numbers recorded), README, ADR-64, `AGENTS.md`
- [x] A real run through the dashboard's session (gateway, agent and database): the "wrong transfer" scam scored 50 and went to review (5 before); a harmless "we'll pay by wire transfer" call scored 24 and was closed; the evidence records only which kinds of request, not the caller's words
- [ ] All checks pass on GitHub
- [ ] Merged

## Next

### Optional
- A short demo video or GIF at the top of the README (Mohit decided it is not needed for now)

## Waiting

### Going live on a server (when a hosting account works)
Oracle Cloud's free ARM server (ADR-56), or Azure for Students if its support lifts the block. Everything for it is built and checked in CI.
- [ ] A hosting account
- [ ] The server (Ubuntu, ARM), with an SSH key made on the laptop; ports 80 and 443 open
- [ ] The DuckDNS name `casewright` points at the server (Mohit)
- [ ] Docker installed; the system started with `deploy/make-secrets.sh` and `docker compose up`
- [ ] Checked from outside: HTTPS, the demo button, a demo run, the audit chain
- [ ] `docs/DEPLOYMENT.md`: how it was set up and how to look after it; the live link in the README

## Open questions

| # | Question | Needed by |
|---|---|---|
| - | None open: every decision in `DECISIONS.md` is Accepted | - |

## Done

- **2026-11-26:** Step 22 (better detection, measured honestly) merged: PR #32, with every check passing (the dependency audit without the picomatch exception). On the fresh sets: 13 of 32 attacks caught, 6 of 32 false alarms.
- **2026-11-24:** Step 21 (code cleanup) merged: PR #31.
- **2026-11-23:** Step 19e (finishing touches, filters, the README, MIT) merged: PR #30.
- **2026-11-22:** Step 19d (Try it yourself in GitHub Codespaces) merged: PR #29, after a real codespace run (the login fix for GitHub's rewritten Origin).
- **2026-11-19:** Step 20d (design motion, with the React Bits branched menu and lattice loader) merged: PR #28. The final handbook (step 21) is dropped: the handbook stays Mohit's own notes.
- **2026-11-18:** Step 20c (dashboard pages) merged: PR #27, with the picomatch exception (ADR-60, until 2026-12-18) and the LiveUpdatesTest race fix.
- **2026-11-17:** Step 20b (front page) merged.
- **2026-11-16:** Step 20a (the new look) merged: PR #25. The first Containers run on `main` failed once: Maven's download server briefly answered 404 for a file it has (checked: the file is there); the failed job is re-run.
- **2026-11-15:** Step 19c (containers on ARM) merged: PR #24, with the opentelemetry-api upgrade. "Containers (ARM)" is the 12th required check on `main`.
- **2026-11-13:** Step 19b (public demo mode) merged: PR #23, with the dashboard screenshot. Its first checks were stuck for a day by a GitHub Actions outage; an empty commit started fresh ones, which all passed (15 smoke checks).
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
