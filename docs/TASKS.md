# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-23

---

## Now

### Step 19e: Finishing touches, filters and the README (on `feature/polish-and-readme`)
Mohit's notes from the Codespaces run and the local dashboard; he chose to include the filters in this PR, and an MIT licence.
- [x] The sidebar's foot in two groups: the system's state (Live and Audit badges, Refresh at full width) and who is logged in (name and role, Log out at full width), each under a hairline; one wrapping row on small screens
- [x] Every button centres its text (Log in sat on the left on the public demo); Log in is the white main button, or outlined under Try the demo on the public site (Mohit's choice, after trying white fields); the fields stay black, even when a browser autofills them; the card's fields and buttons share one height
- [x] Refresh says what it did: its icon turns while it works, then "Updated <time>" (with the live feed on there was often nothing new, so a click looked like nothing happened)
- [x] The Overview's figures filter the incidents: Incidents (all), Attacks found, Waiting for a decision (with exactly one waiting, it opens that incident on its Actions tab; otherwise it lists them, and each opens on its Actions tab); plus a Type row (All, Email, Sign-ins, Phone calls, with counts); "Showing n of m" and Show all; the filters live in the address (`#/?show=attacks&kind=email`, read strictly) and All incidents goes back to the list as it was filtered
- [x] This step's own code simplified (the audit check loaded in one place; the type labels a plain list); no behaviour change
- [x] Tests: dashboard 142 (13 new); 9 mutation checks, all caught (one test was found checking the public demo before the page knew it was one, and fixed); a real run in the browser on desktop and phone sizes
- [x] MIT licence (`LICENSE`); `THIRD_PARTY_NOTICES.md` says the React Bits files keep their own
- [x] README rewritten for someone deciding about Mohit: what it is, highlights, try it, how it works (a Mermaid diagram), safety by design, tech stack, quality and evidence (every number re-run: gateway 364, agent 656, dashboard 142; every link checked), limitations; the setup steps moved, unchanged, to `docs/DEVELOPMENT.md`
- [x] A fresh README screenshot: a Scam phone call demo (#79, risk 85, led by the AI model, one decision waiting) with the new sidebar foot
- [ ] All checks pass on GitHub
- [ ] Merged

## Next

### Simplify the code (Mohit's request)
- [ ] A pass over the gateway, agent and dashboard to reduce complexity without changing behaviour: every suite and the mutation checks after each change, in its own pull request

### The demo video
- [ ] A short video at the top of the README (Mohit records it, from a shot list)

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
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |

## Done

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
