# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-17

---

## Now

### Step 5b: Local HTTPS (on `feature/local-https`)
- [x] Gateway serves HTTPS only on port 8443, TLS 1.3 and 1.2 only
- [x] `scripts/setup-https.ps1`: creates a self-signed, `localhost`-only certificate in `certs/` (git-ignored); `-Trust` / `-Untrust` for the current Windows user
- [x] Keystore password as a new secret, `SSL_KEYSTORE_PASSWORD` (properties, startup check, `.env.example`, `setup-secrets.ps1`)
- [x] Clear startup error when the certificate file is missing
- [x] `try-auth.ps1` uses HTTPS and normal cookie handling; accepts only the development certificate if Windows does not trust it
- [x] Allowed origins updated to `https://localhost:8443` and `https://localhost:5173`
- [x] `HttpsServerTest`: real server over HTTPS, TLS 1.3, HSTS, untrusted certificate refused, plain HTTP refused
- [ ] Merged

## Next

### Step 6: Rate limiting
Needs ADR-12 confirmed (in-memory Bucket4j).

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-12 rate limiting, then ADR-3/4/5 for the agent service) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
