# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-18

---

## Now

### Step 6: Rate limiting (on `feature/rate-limiting`)
- [x] Every request: 120 a minute per client IP address
- [x] Login and signup: 10 a minute per client IP address
- [x] Login per username: 5 free attempts, then waits doubling from 1 s to 15 minutes; checked before the password; unknown usernames treated the same; a correct password resets it
- [x] `429` with `Retry-After`, in the usual error shape, with the security headers
- [x] Thresholds in `application.properties` (`security.rate-limit.*`), checked at startup
- [x] Counters in a bounded in-memory cache; `X-Forwarded-For` not trusted
- [x] Tests: `RateLimitTest`, `LoginThrottleTest`, `KeyedRateLimiterTest`
- [ ] Merged

## Next

### Step 7: Incident ingestion
See `ROADMAP.md`.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-3/4/5 for the agent service, ADR-15) |
| 2 | LLM model and budget | Step 12 |
| 3 | Evaluation data source | Step 18 |

## Done

- **2026-10-18:** Step 5b (local HTTPS) merged: PR #3.
- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
