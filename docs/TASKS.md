# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-17

---

## Now

### Step 20c: Dashboard layout (on `feature/dashboard-layout`)
Mohit found the dashboard too crowded on one screen. Mohit chose: a left sidebar; pages Overview and Scenarios; the colours stay (near-black and indigo). Incidents open on their own page with tabs.
- [x] Sidebar with Overview and Scenarios (the current page marked); the live badge, Refresh, the audit badge, the user and Log out at its foot, on every page; a bar across the top on small screens
- [x] Overview: four figures (incidents, attacks found, waiting for a decision, audit log entries), then the incidents as a grid of cards
- [x] Scenarios page: each demo as a card with what it is and its button; a note when demos are switched off
- [x] Incident page: All incidents, the header and risk, a "decisions waiting" note, then Evidence / Reports / Actions tabs (WAI-ARIA tabs: arrow keys, Home, End); an evidence chip opens the Evidence tab at that step
- [x] Addresses: #/ (Overview), #/scenarios, #/incidents/57 (unchanged); anything else is the Overview
- [x] Tests: dashboard 119 (6 new for the sidebar, figures, tabs and the way back; the existing ones now move through pages and tabs like a person; the hostile-text test checks each view on its own)
- [x] New README screenshot (incident #72, two decisions waiting, live)
- [x] README brought up to date: the status, the pages, where the demo buttons are, test counts, containers on ARM, mutation-check results, the folder list and how to use the dashboard
- [x] The PR's first run failed twice for reasons outside this change: (1) the dependency audit found GHSA-fc5q-39xc-vjpf in picomatch 4.0.7 (through Vite and Vitest; published that week, no fixed release), accepted for 30 days with Mohit's approval (ADR-60, `.github/osv-scanner.toml`); (2) a timing race in the gateway test `LiveUpdatesTest.aFeedThatFallsTooFarBehindIsClosedSoTheDashboardReloadsInstead`: the feed's writer could start late and take some changes with it. The test now waits until the writer is stuck before sending changes; the race was reproduced on purpose, then fixed; gateway 364 in both orders
- [ ] All checks pass on GitHub
- [ ] Merged

## Waiting

### Step 19d: Going live (paused: the Oracle Cloud sign-up needs a card that works)
Decided: Oracle Cloud's free ARM server in India South (Hyderabad), staying on the free tier (ADR-56), the DuckDNS name `casewright`.
- [ ] Oracle Cloud account (Mohit; the sign-up stopped at the card check)
- [ ] The free ARM server (Ubuntu, Ampere A1), with an SSH key made on the laptop
- [ ] Ports 80 and 443 open (Oracle's network rules and the server's own firewall)
- [ ] The DuckDNS name `casewright` points at the server (Mohit)
- [ ] Docker installed; the system started with `deploy/make-secrets.sh` and `docker compose up`
- [ ] Checked from outside: HTTPS, the demo button, a demo run, the audit chain
- [ ] `docs/DEPLOYMENT.md`: how it was set up and how to look after it; the live link in the README

## Later

Step 20d (live motion in the dashboard), then step 21: the final handbook.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |

## Done

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
