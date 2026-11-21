# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-11-22

---

## Now

### Step 19d: Try it yourself (on `feature/try-it-yourself`)
Going live is blocked from outside the project: Oracle Cloud's card check refused every card tried (the bank never saw the attempts), and Azure for Students blocked the sign-up at its automatic check. Mohit chose instead: an "Open in GitHub Codespaces" button and a demo video (ADR-62). The server setup stays ready.
- [x] Plan agreed with Mohit
- [x] `.devcontainer/devcontainer.json`: Ubuntu (pinned by digest) and Docker inside the codespace (an exact version, its digest in `devcontainer-lock.json`, the editor's accepted form); starts `deploy/codespaces-start.sh` every time the codespace starts
- [x] `deploy/codespaces-start.sh`: fresh secrets for that codespace, builds the same containers as a server, starts the front door only once the gateway is up, says where to open it
- [x] Caddy's site rules moved into `deploy/site.caddy`, shared by the server's `Caddyfile` and the new `Caddyfile.codespaces` (plain HTTP behind GitHub's private, HTTPS port forwarding; chosen by `deploy/compose.codespaces.yaml`)
- [x] CI: both Containers jobs also start the system the codespace way and run `deploy/codespaces-check.sh`
- [x] A real run, first try (codespace on this branch): it built and started by itself ("Casewright is ready", gateway and database UP), but the login was refused as cross-site. A header check in the codespace showed why: GitHub rewrites every request's Origin and Host to `http://localhost:80`, while the browser's `Sec-Fetch-Site` and `Referer` pass through untouched
- [x] Fix: in a codespace the gateway also accepts that Origin; CI proves a login as GitHub delivers it is accepted and `Sec-Fetch-Site: cross-site` is still refused. Also: only port 80 published (443 had shown up as a broken second address); the Docker feature pinned by exact version with its digest in `devcontainer-lock.json` (the editor flagged the digest form)
- [x] A real run after the fix (the same codespace, after `git pull` and the start script): Try the demo, four scenarios investigated (live feed on), an action approved ("Block this number": done, simulated, by demo; the incident moved to needs review), the audit chain intact. Logging in with a laptop account is refused as it should be: the codespace has its own empty database and sign-up is closed
- [x] README: the button and how to use it
- [x] All checks pass on GitHub (the first commit, and the fix)
- [ ] Merged

## Next

### Step 19e: Finishing touches (after this step merges)
- [ ] Mohit's note: the sidebar's foot (the user chip and Log out) and the login page's Log in button look out of place: make them match the rest
- [ ] The demo video at the top of the README (Mohit records it, from a shot list)

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
