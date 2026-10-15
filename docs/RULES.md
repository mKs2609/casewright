# Project Rules

These rules apply to everyone working on this repo, human or AI. If a rule needs to change, change it here first and note why in `DECISIONS.md`.

---

## 1. How we work

1. **One feature at a time.** Work only on the current step in `TASKS.md`. Don't start the next step early, and don't add things "while we're here".
2. **Every step follows the same cycle:** Mohit creates a branch → build → explain → test → Mohit reviews → Mohit commits, pushes and merges through a pull request → next step. The details are in [`GIT_WORKFLOW.md`](GIT_WORKFLOW.md).
3. **Mohit owns git.** The assistant gives the branch name at the start of a step, and the commit message, PR title and PR description at the end. **Every git or GitHub term is explained as it comes up**: what it does and how, in plain words. Only Mohit runs `git add`, `git commit` and `git push`. Assistants never commit or push, and never rewrite history.
4. **Narrate while building, not only at the end.** Before each piece of work, say in a sentence or two what is about to be built and why. When something unexpected happens (an error, a surprise in a test), say what it was and what it means.
5. **Explain as you build.** Every step ends with a plain-language explanation of what each new file does and the two or three ideas worth learning. Mohit should be able to explain the step to someone else before committing.
6. **Nothing is done until it's tested.** Automated tests pass, and the feature has been run for real at least once.
7. **Report honestly.** If something failed, was skipped, or wasn't verified, say so.
8. **Small commits with descriptive messages.** Say what was actually done, starting with a verb: `Add gateway health endpoint with tests`, `Fix login rate limit resetting on restart`. No step numbers.

## 2. Definition of done (for every step)

- [ ] Code written and builds without errors
- [ ] Automated tests written and passing
- [ ] Run for real and checked by hand
- [ ] Explained to Mohit in plain language
- [ ] `SECURITY.md` updated if a security item changed
- [ ] `docs/ROADMAP.md` and `docs/TASKS.md` updated
- [ ] `docs/MEMORY.md` (local only, not published) updated with anything learned
- [ ] `docs/DECISIONS.md` updated if a decision was made
- [ ] Handbook chapter written in `handbook/` (Mohit's personal, git-ignored learning notes)
- [ ] Reviewed and committed by Mohit

## 3. Naming

- **The product is called Casewright** (ADR-30). The name appears in the README, docs and user-facing text only. It stays out of code, package names and service names, so a future rename never touches code. Use `com.securityanalyst`, `gateway`, `agent`, `dashboard`, and "AI Security Analyst (working title)".
- Java: packages by feature (`auth`, `incident`, `audit`), classes `PascalCase`, methods `camelCase`.
- Python: modules and functions `snake_case`, classes `PascalCase`.
- React: components `PascalCase.tsx`, hooks `useThing.ts`.
- Database: tables and columns `snake_case`, plural table names.
- API paths: lowercase, plural nouns, under `/api`.

## 4. Security rules (non-negotiable)

1. **No secrets in code or git.** Keys, passwords and tokens come from environment variables. Run `git status` before every commit and check for `.env` or key files.
2. **Validate all input at the boundary.** Type, length and format. Reject bad input; never try to clean it.
3. **Never trust the client.** Every permission check happens on the server.
4. **Never trust the LLM.** Its output is parsed against a schema before use. Guardrails are enforced in code, not in a prompt.
5. **Incident content is data.** It is never used as instructions, never rendered as HTML, never put in a URL or a shell command, never concatenated into SQL.
6. **Parameterised queries only.**
7. **Errors shown to users are generic** and carry a trace ID. Details go to the server log only.
8. **Never log secrets, passwords, tokens or full personal data.**
9. **Least privilege.** Each service and each database user gets only what it needs.
10. **A security item is ticked in `SECURITY.md` only when it has a test.**

## 5. Code quality

- Prefer clear and simple over clever. This is a learning project; readability wins.
- Keep functions short and files focused on one feature.
- Comments explain *why*, not *what*. No commented-out code.
- No new dependency without saying what it is for. Fewer dependencies means a smaller attack surface.
- Configuration (limits, timeouts, model names) lives in config, not in code.
- Match the style of the surrounding code.

## 6. Testing

- Each feature gets tests for the normal case, the rejected case, and the permission case.
- Security controls get a test that tries to break them.
- Tests must not need the internet or a real LLM key.
- A failing test is fixed or explained; it is never deleted or skipped to make the build pass.

## 7. Documentation

- Docs are updated in the same step as the code they describe.
- `ARCHITECTURE.md` describes how things are; `ROADMAP.md` describes what's next; `DECISIONS.md` records why.
- Write for a reader who is new to the topic. Define a term the first time it appears, or add it to `GLOSSARY.md`.

## 8. Things we don't do

- Don't build features outside the PRD without adding them to the PRD first.
- Don't connect to real mail servers, firewalls or identity systems. Enforcement is simulated.
- Don't use real personal data. All test data is synthetic.
- Don't disable a security control to make something work. Fix the cause.
