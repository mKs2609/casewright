# Tasks

The working board. `ROADMAP.md` is the long-term plan; this file tracks what is happening **now**.
Update it at the start and end of every work session.

**Last updated:** 2026-10-14

---

## Now

### Step 5: Errors, trace IDs, security headers (in progress on `feature/error-handling-and-headers`)
- [x] Catch-all error handler: unexpected errors return a generic message and a trace ID; details stay in the server log
- [x] Framework errors (404, 405, wrong parameter type...) keep their real status, not 500
- [x] Trace ID on every response (`X-Trace-Id` header and in error bodies) and in every log line
- [x] Security headers on every response: CSP, `nosniff`, `X-Frame-Options: DENY`, HSTS (over HTTPS), Referrer-Policy, Permissions-Policy, cross-origin policies
- [x] Request size limit (413), chunked bodies refused (411)
- [x] 14 new tests (67 in total, all passing); a deliberate leak was caught by a test; run for real on port 8081
- [x] `SECURITY.md`, `DECISIONS.md` (ADR-31 to 34), `ARCHITECTURE.md`, `AGENTS.md` updated
- [x] Handbook chapter
- [ ] Mohit commits, pushes the branch, opens and merges the first pull request

## Next

### Step 5a: Automated checks (CI)
Brought forward at Mohit's request, so every pull request from now on is tested automatically.
- [ ] GitHub Actions workflow: on every push and pull request, set up Java and run `.\mvnw test` (Linux runner)
- [ ] Status check visible on the pull request
- [ ] Branch protection on `main`: merging requires the check to pass
- [ ] Badge in the README

### Step 5b: Local HTTPS
Split out of step 5: it needs a development certificate and a decision by Mohit about trusting it on this machine.

### Step 6: Rate limiting
Needs ADR-12 confirmed (in-memory Bucket4j).

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | ~~Final product name~~ Casewright (decided 2026-10-14) | Done |
| 2 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects (ADR-12 rate limiting, then ADR-3/4/5 for the agent service) |
| 3 | LLM model and budget | Step 12 |
| 4 | Evaluation data source | Step 18 |

## Done

- **2026-10-15:** Steps 0 to 4 committed (`b9c2883`) and published to https://github.com/mKs2609/casewright.
