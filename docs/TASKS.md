# Tasks

The working board. `ROADMAP.md` is the long-term plan; this file tracks what is happening **now**.
Update it at the start and end of every work session.

**Last updated:** 2026-10-14

---

## Now

### Step 4: Tokens and roles (built and checked by Mohit; not committed)
- [x] Spring Security added; every URL needs a login except health, signup, login, refresh, logout
- [x] Login sets a 15-minute access token (JWT) and a 7-day refresh token in `HttpOnly`, `Secure`, `SameSite=Strict` cookies
- [x] `refresh_tokens` table (migration V2, fingerprints only); single-use rotation; reuse revokes the whole session; logout revokes
- [x] `GET /api/me`
- [x] Admin only: `GET /api/admin/users`, `PUT /api/admin/users/{id}/role`
- [x] Cross-site request check (`OriginCheckFilter`)
- [x] `JWT_SIGNING_KEY` is a required secret; `scripts\setup-secrets.ps1` generated it into `.env`
- [x] `scripts\set-role.ps1` (first admin) and `scripts\try-auth.ps1` (session walkthrough)
- [x] 20 new tests (53 in total, all passing); one protection deliberately broken to prove its test fails
- [x] Run for real against the development database; throwaway accounts removed afterwards
- [x] Docs and handbook chapter updated
- [x] Mohit restarted the gateway, made `mohit` an `ADMIN` with `set-role.ps1`, and ran `try-auth.ps1`: all seven steps behaved as expected (2026-10-14)
- [ ] Mohit can explain: access token vs refresh token, what the three cookie flags do, 401 vs 403, why refresh tokens rotate
- [ ] Included in the initial commit (see below)

### First push to GitHub (in progress)
- [x] Git workflow written (`docs/GIT_WORKFLOW.md`); study notes in the handbook
- [x] Name chosen: **Casewright**; repository **public** from the first push (2026-10-14)
- [x] `docs/MEMORY.md` made local-only (git-ignored) so the working diary is not published
- [ ] Mohit switches git to GitHub's noreply email
- [ ] `git init -b main`, `git add .` (assistant checks the staged files for secrets), initial commit
- [ ] Publish to GitHub; from then on, every step on its own branch

### Still open from earlier steps
- [ ] Mohit runs `.\mvnw.cmd test` in `gateway\` and sees the tests pass
- [ ] Mohit reads the docs and flags anything to change
- [ ] Mohit confirms or changes the **Proposed** decisions in `DECISIONS.md` (ADR-3, 4, 5, 12, 15)

## Next

### Step 5: Validation, errors, security headers
- [ ] Catch-all handler: unexpected errors return a generic message and a trace ID; details stay in the server log
- [ ] Trace ID on every response and in every log line
- [ ] Security headers on every response: CSP, `nosniff`, `X-Frame-Options: DENY`, HSTS, Referrer-Policy
- [ ] Request size limit
- [ ] HTTPS for local development (self-signed certificate)
- [ ] Tests for each; update `SECURITY.md` sections A and D

## Later

See `ROADMAP.md` steps 6–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | ~~Final product name~~ Casewright (decided 2026-10-14) | Done |
| 2 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-12 rate limiting, then ADR-3/4/5 for the agent service) |
| 3 | LLM model and budget | Step 12 |
| 4 | Evaluation data source | Step 18 |

## Done

Nothing committed yet. Steps 0 to 4 are built and waiting for review.
