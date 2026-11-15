# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-15

---

## Now

### Step 20a: The new look (on `feature/design-polish`)
Mohit's references: Ameba, AWE and Auros first, then zkPass and Dovetail for the final look. Mohit chose: one look throughout, a simple centred login, no brackets on labels, a soft indigo signal colour, icons with the labels, and three parts (20a look, 20b front page, 20c live dashboard), each its own PR (ADR-57).
- [x] New tokens: one monochrome system on a blueprint grid with one soft indigo signal colour; every text colour measured against WCAG contrast; a test that every token used exists and every token is used
- [x] Fonts bundled from Fontsource (Source Serif 4, Inter Tight, IBM Plex Mono; OFL), served by our own server under the strict page policy
- [x] Every screen restyled, every section label with an icon: app bar (indigo bar, logo tile), scenario strip, incident list, risk meter, evidence timeline, reports, approval cards, red-team card
- [x] The login: centred and simple, an icon tile in the headline, over a turning dotted globe (canvas) with a dark pool behind the text
- [x] Simplified on the way: one look instead of two (the separate navy/teal tokens, the aurora button and the live feed card removed), repeated styles merged
- [x] Reduced motion respected; nothing scrolls sideways at 390px
- [x] `DESIGN_SYSTEM.md` v2
- [x] New README screenshot `docs/images/dashboard.png` (incident #71, live updates on); the login's image waits until the front page, 20b
- [x] Found and fixed: in development, Vite's proxy kept a page's live-updates request to the gateway open after the page was reloaded or closed, so a few reloads used up the 3-per-person limit and paused live updates until a restart. The proxy now closes it (`vite.config.ts`); the gateway frees the slot at its next keep-alive. Production (Caddy) was not affected
- [x] Tests: dashboard 109 (the live feed card and its tests removed; new: every token used exists and every token is used); 6 mutation checks, all caught
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

Step 20b (front page), step 20c (live dashboard), then step 21: the final handbook.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |

## Done

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
