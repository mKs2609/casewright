# AGENTS.md

Instructions for AI coding assistants working in this repository.
(The design of the product's own AI agent is in [`docs/AGENT_DESIGN.md`](docs/AGENT_DESIGN.md).)

## Read first, every session

1. `docs/MEMORY.md`: current state, machine setup, known gotchas. **Local only** (git-ignored, never published): it exists on Mohit's machine but not in the GitHub repository. Never copy machine details or personal notes from it into a committed file.
2. [`docs/TASKS.md`](docs/TASKS.md): what is in progress right now
3. [`docs/RULES.md`](docs/RULES.md): how we work, security rules, definition of done

Then, as needed: [`PRD`](docs/PRD.md) · [`ARCHITECTURE`](docs/ARCHITECTURE.md) · [`DESIGN_SYSTEM`](docs/DESIGN_SYSTEM.md) · [`THREAT_MODEL`](docs/THREAT_MODEL.md) · [`ROADMAP`](docs/ROADMAP.md) · [`DECISIONS`](docs/DECISIONS.md) · [`GLOSSARY`](docs/GLOSSARY.md)

## What this project is

An agentic AI security analyst: it investigates a suspicious event with tools, explains its verdict for experts and for non-experts from one evidence chain, and requires human approval for risky actions. Java Spring Boot gateway, Python agent service, React dashboard, PostgreSQL.

## The rules that matter most

- **One step at a time.** Work only on the current step in `docs/TASKS.md`.
- **Never run `git add`, `git commit`, `git push`, `git merge` or anything that changes history.** Mohit does all git operations. Read-only commands (`git status`, `git diff`, `git log`) are fine for checking.
- **Follow [`docs/GIT_WORKFLOW.md`](docs/GIT_WORKFLOW.md).** At the start of a step, give Mohit the branch name and the commands to create it from an up-to-date `main`. At the end, give the commit message(s), PR title and PR description. Before Mohit's first commit of a step, check the staged files for secrets. Explain every git/GitHub term and command as it is used (what it does and how); Mohit is learning git alongside the project.
- **Commit messages and PR descriptions are written in Mohit's own voice**: plain, short, saying what changed and why. No AI attribution of any kind (no `Co-Authored-By` lines for an AI, no "Generated with" footers, no mention of an assistant).
- **Narrate as you go.** Before each piece of work, tell Mohit what is about to be built and why; flag surprises when they happen.
- **Explain what you built** in plain language at the end of every step. Mohit is learning; assume terms need defining.
- **Test before calling it done**: automated tests and a real run. Report failures honestly.
- **The product is called Casewright, but the name stays out of code.** Code uses `com.securityanalyst`, `gateway`, `agent`, `dashboard`; the name appears only in docs, the README and user-facing text (ADR-30).
- **No secrets in code.** Environment variables only.
- **Never weaken a security control to make something pass.**
- **Update the docs in the same step**: `TASKS.md`, `ROADMAP.md`, `MEMORY.md`, `SECURITY.md`, and `DECISIONS.md` when a decision is made.
- **Write a handbook chapter for every finished step** in `handbook/` (format in `handbook/README.md`). The handbook is Mohit's personal learning material: it is git-ignored, never committed, and product docs must not link to it. Study notes on a single technology go in `handbook/notes/`.

## Commands

| Task | Command (from repo root, Windows) |
|---|---|
| One-time database setup | `powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1` (Mohit runs this; it asks for the `postgres` password) |
| Add missing application secrets to `.env` | `powershell -ExecutionPolicy Bypass -File scripts\setup-secrets.ps1` (safe to re-run; never prints values) |
| Create the local HTTPS certificate | `powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1` (once; `-Trust` / `-Untrust` change the Windows trust list, so only Mohit runs those) |
| Make a user an admin | `powershell -ExecutionPolicy Bypass -File scripts\set-role.ps1 -Username <name> -Role ADMIN` |
| Walk through a login session | `powershell -ExecutionPolicy Bypass -File scripts\try-auth.ps1 -Username <name>` |
| Submit a sample incident and watch its status | `powershell -ExecutionPolicy Bypass -File scripts\try-incident.ps1 -Username <name>` (needs the gateway and the agent running) |
| Gateway tests | `cd gateway; .\mvnw.cmd test` (uses its own embedded PostgreSQL; needs no setup) |
| Run gateway | `cd gateway; .\mvnw.cmd spring-boot:run` (https://localhost:8443/api/health) |
| Agent: one-time setup | `cd agent; python -m venv .venv; .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt` |
| Agent tests | `cd agent; .\.venv\Scripts\python.exe -m pytest` (never uses a real model) |
| Run agent | `cd agent; .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --no-server-header` |
| Use the local AI model | Install Ollama (ollama.com, "Download manually"), then `ollama pull qwen3:8b` once, and set `LLM_PROVIDER=ollama` in `.env` (ADR-15). Without it the agent uses the fixed plan |
| Dashboard: one-time setup | `cd dashboard; npm ci` (needs Node 24 and the certificate from `setup-https.ps1`) |
| Dashboard tests | `cd dashboard; npm test` (no gateway or certificate needed); `npm run typecheck` for types |
| Run dashboard | `cd dashboard; npm run dev` (https://localhost:5173; needs the gateway running) |
| Run the built dashboard under the strict page policy | `cd dashboard; npm run build; npm run preview` |
| Add hashes after changing a Python package version | `agent\.venv\Scripts\python.exe scripts\hash-requirements.py` |
| Rewrite the demo scenarios file after changing `agent/tests/scenarios.py` | `agent\.venv\Scripts\python.exe scripts\make-demo-scenarios.py` |
| Measure accuracy and rewrite `docs/EVALUATION.md` (after any change to detection) | `agent\.venv\Scripts\python.exe scripts\evaluate.py` (`--model` also runs the local AI model; Ollama must be running) |

Maven is not installed globally; always use the wrapper `mvnw.cmd`.

## Layout

```
gateway/     Spring Boot 4.1 (Java 25). Package root: com.securityanalyst.gateway, organised by feature.
agent/       Python 3.14 FastAPI service (app/, tests/). Called only by the gateway; no database access.
dashboard/   React + TypeScript with Vite (src/api.ts, src/components/, src/styles/). Talks only to the gateway, through its own server.
docs/        All project documents
```

## Conventions

- Spring Boot **4**: test annotations live in `org.springframework.boot.webmvc.test.autoconfigure`; the web starter is `spring-boot-starter-webmvc`. Check the installed jars rather than relying on Boot 2/3 examples.
- Java: constructor injection, records for DTOs, Bean Validation on every request body. Request records that hold a secret override `toString()` to hide it.
- Errors shown to callers are thrown as `ApiException(status, message)`; `ApiExceptionHandler` turns them into `{"error": ...}`. Never echo a rejected value back.
- Security is deny-by-default: a new URL needs a login unless it is added to the public list in `SecurityConfig`. Security filters are created inside `SecurityConfig`; filters that must run before security (the trace ID) are registered in `WebFilterConfig`. Never make a filter a `@Component` (that registers it twice).
- Every error body is built with `ApiError.of(...)` / `SecurityErrors.write(...)`, which add the trace ID. Unexpected errors are logged once, in `ApiExceptionHandler`; do not catch-and-log elsewhere.
- The gateway serves HTTPS only (port 8443). Tests that need the real server use `@SpringBootTest(webEnvironment = RANDOM_PORT)` and make a throwaway certificate, as `HttpsServerTest` does; MockMvc tests need no certificate.
- Rate limits come from `security.rate-limit.*`. `PostgresIntegrationTest` sets limits ordinary tests can never reach (via `@TestPropertySource`); a test that needs real limits sets them with `@DynamicPropertySource`, as `RateLimitTest` does, and uses its own fake client IPs.
- Baselines are only ever encrypted and decrypted by `MonitoredIdentityService` (AES-256-GCM, ADR-37). Changing `BASELINE_ENCRYPTION_KEY` makes stored baselines unreadable.
- A new incident kind needs: a record implementing `IncidentRequest`, an entry in its `permits` list and in `@JsonSubTypes`, a case in `IncidentService.submit`'s switch (the compiler insists), and the kind in the `incidents.kind` check constraint (new migration).
- A new required secret goes in four places: `application.properties`, `RequiredSettingsCheck`, `.env.example`, and `scripts/setup-secrets.ps1`; tests get their own value in `PostgresIntegrationTest`.
- Anything worth a permanent record calls `AuditLog.record` in the same transaction as the action (ADR-46). Entries hold short facts only: never incident text, tool arguments or anything the agent wrote. `audit_log` cannot be changed or cleaned up, by tests or live runs alike: tests that tamper with it must run inside a transaction that rolls back, and live runs must use the real `AUDIT_HMAC_KEY`, because entries signed with another key break the chain for good.
- A service method that writes something and then throws to refuse the request needs `@Transactional(noRollbackFor = ApiException.class)`, or the write is undone.
- JPA entities must match the Flyway schema exactly (`ddl-auto=validate`). Change the migration first, then the entity.
- Database changes only through Flyway migrations (`gateway/src/main/resources/db/migration`). Never edit a migration that has already run; add a new one.
- Tests that need a database extend `PostgresIntegrationTest`. All test classes share one database and run in an order that differs between machines: a class that commits data cleans it up before and after each test, and no test assumes a table is empty (compare counts before and after; use usernames no other class uses). Check with `.\mvnw.cmd test "-Dsurefire.runOrder=reversealphabetical"`.
- To check that an error response does not repeat a rejected value, use `NoEcho.doesNotEcho(value)`, never a plain "body does not contain": every error carries a random hex trace ID, which short values can appear in by chance.
- Python: type hints, Pydantic models with `extra="forbid"` for all input and all LLM output (the `Strict` base class in `agent/app/models.py`; JSON names are camelCase). Packages are pinned to exact versions, including indirect ones, in `agent/requirements*.txt`, with the hashes of their files (`scripts/hash-requirements.py` after any change); choose releases at least two weeks old.
- A new agent event type needs: an entry in `AgentEvent`'s `@JsonSubTypes` (the gateway refuses unknown types), a Pydantic model in `agent/app/models.py`, a record in the gateway's `AgentEvent` (with its own validation rules), and handling in `InvestigationRunner`. The gateway never trusts the agent's output (ADR-5).
- A new tool needs: a function in `agent/app/tools.py` registered in `TOOLS` (read-only; arguments checked against the incident's indicators, raising `ToolRejected` otherwise), its argument names in `TOOL_ARGUMENTS`, a definition in `reasoning.tool_definitions` (what the AI model is offered), its name in `StepEvent.tool` and in the gateway's `AgentEvent.KNOWN_TOOLS`. Every call goes through `ToolBox.call`, never around it.
- The AI model (ADR-15, ADR-44) is untrusted like the incident: everything it asks for goes through `ToolBox.call` or `reasoning.check_submission`; its own words never go into events or logs; any failure returns `None` from `investigate_with_llm` so the fixed plan finishes. Its address must stay a loopback one. Tests never reach a real model (`conftest.py` switches it off); use `tests/fake_model.ScriptedModel`.
- Reports (ADR-45) are built by code in `agent/app/report.py` from recorded findings only; the gateway's `ReportCheck` compares every finding and reason with the stored evidence. Changing a signal's `label` or `plain` wording changes the reports: plain wording must stay jargon-free and at reading grade 8 or below (`test_report.py`). The only model-written text is the summary line in `agent/app/summary.py`; any change to its checks is made in the agent and in `ReportCheck` together.
- Actions (ADR-47) are proposed by code in `agent/app/actions.py`, never by the AI, and `ActionPolicy` in the gateway decides their risk and checks every target against what the gateway stored. A new action needs: its name in `ProposedAction` (agent), `AgentEvent.ProposedAction`'s pattern, `ActionPolicy`, and the `actions.action` check constraint (new migration). High-risk actions always start `pending`. Running one only writes to `enforcement` (ADR-13).
- Tool results never copy baseline values into evidence (baselines are encrypted at rest; evidence is not): record only the difference. Attacker-written text is matched only after `patterns.normalise`, and is quoted only inside a result, never in summaries or signal labels.
- Related incidents (ADR-42): the agent reports indicators once per investigation (`incident.indicators`); the gateway validates each value against its type, stores it in `incident_indicators`, and sends recent ones (`agent.related-incident-window`, `agent.max-recent-indicators`) as values and incident numbers only. Known-good entries and internal addresses (`threat_intel.is_noise`) never link incidents; use `is_internal_address`, not Python's `is_private`, which also covers the documentation ranges.
- The risk score exists twice, `agent/app/verdict.py` and the gateway's `RiskScore` (ADR-43): change both together, and both must still match `testdata/risk-score-cases.json`. The gateway, never the agent, sets an incident's final status.
- Mock threat-intel and test data use only reserved example names: `.example` domains, IPs from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, and 555-01xx phone numbers. Never label a real site, network or number as malicious.
- Tests that need the agent use a fake one (see `InvestigationTest`); `PostgresIntegrationTest` points `agent.base-url` at port 1 so no test reaches a real agent by accident.
- React: no `dangerouslySetInnerHTML`; colours, sizes and durations only from design tokens; no links built from incident data; nothing in browser storage (`src/test/rules.test.ts` checks these). Every call to the gateway goes through `src/api.ts`, which shares one session refresh (ADR-48). Hiding a control from a role is a convenience: the gateway's check is the control. npm packages are pinned to exact versions, at least two weeks old, with install scripts off (`.npmrc`). No setting reaches the page: product code never reads `import.meta.env`.
- Demo scenarios (ADR-50) live in `gateway/src/main/resources/demo/scenarios.json`, generated from `agent/tests/scenarios.py` by `scripts/make-demo-scenarios.py`; never edit the JSON by hand (`test_demo_scenarios.py` checks they match). Demo incidents are stored with `source = demo`; the browser only ever sends a scenario's name.
- The red-team probe (ADR-51): the hijacked model's script is in `agent/app/redteam.py` and the values it uses are repeated in `RedTeamScorecard`: change both. `redTeam` reaches the agent only for incidents with `source = red_team`, which only `POST /api/red-team` creates. Scorecard outcomes are read from the stored record, never from the agent's words.
- The evaluation (ADR-53): `agent/tests/evaluation_set.py` (development) and `evaluation_heldout.py` (held-out) are frozen: add a new example, never edit or delete one, and never change one to improve a number. `docs/EVALUATION.md` is generated by `scripts/evaluate.py`; `test_evaluation.py` fails when it no longer matches, so any change to the tools, signals, weights or verdict rules comes with a regenerated report in the same pull request. Detection changes are general rules about what an attack does, never keyed to an example's words.
- `@Transactional` works only on calls from outside the class (Spring's proxy). Never have one method of a service call another `@Transactional` method of the same class; give callers the one method instead. Tests marked `@Transactional` hide this mistake, so a change to how something is saved also needs a test that commits (like `DemoInvestigationTest`).
- The live feed (ADR-49) learns of changes from `AuditLog.record`: a change to an incident that is not audited with its incident id never reaches the dashboard. The feed sends incident numbers only; never put incident data in it. It closes when the access token it opened with expires.
- CI (`.github/workflows/ci.yml`) runs on every pull request and must stay green; a new test suite (agent, dashboard) gets its own job there. Actions are pinned to full commit SHAs with the version in a comment, and the workflow token stays `contents: read`; the one exception is `security-events: write` on the CodeQL job (ADR-52). A tool downloaded in CI is checked against its SHA-256 before it runs. The dependency audit, secret scan and CodeQL fail on any finding: fix the cause (usually a version upgrade), never switch the check off. A CodeQL finding may be accepted only by adding it to `.github/codeql-reviewed.json` (one rule in one file, with the reason and a decision record) and only with Mohit's approval.
- A reference prototype exists outside this repo (see the local `docs/MEMORY.md`). Port ideas from it deliberately, one step at a time.
