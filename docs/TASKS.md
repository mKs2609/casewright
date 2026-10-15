# Tasks

The working board. `ROADMAP.md` is the long-term plan; this file tracks what is happening **now**.
Update it at the start and end of every work session.

**Last updated:** 2026-10-14

---

## Now

### Step 5a: Automated checks (CI) (in progress on `chore/ci-workflow`)
Brought forward at Mohit's request, so every pull request from now on is tested automatically.
- [x] GitHub Actions workflow (`.github/workflows/ci.yml`): on every pull request and push to `main`, set up Java 25 and run the tests on Linux; read-only token; actions pinned to commit SHAs
- [x] `mvnw` marked executable in git (needed on Linux)
- [ ] Status check visible on the pull request
- [ ] Branch protection on `main`: merging requires the check to pass
- [x] Badge in the README

## Next

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

- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed (`b9c2883`) and published to https://github.com/mKs2609/casewright.
