# Decision Log

Short records of *why* we chose something, so we don't re-argue it later.
Add a new entry at the bottom; never rewrite an old one. If a decision changes, add a new entry that supersedes it.

Status: **Accepted** · **Proposed** (needs Mohit's confirmation before the step that uses it) · **Superseded**

---

## ADR-1: Java gateway + Python agent + React dashboard
**Status:** Accepted (2026-09-30)
**Decision:** Spring Boot for the public API and security, Python for the AI agent, React for the dashboard, PostgreSQL for data.
**Why:** Matches the coursework (OOP, software engineering, DBMS). Spring Security is mature for auth and hardening. Python has the best LLM tooling.
**Trade-off:** Three stacks is more work than one. We manage it by building one feature at a time.

## ADR-2: Build one feature at a time
**Status:** Accepted (2026-09-30)
**Decision:** Each step is built, explained, tested, and committed by Mohit before the next begins.
**Why:** The goal is to understand the system, not only to have it.

## ADR-3: The gateway owns the database; the agent is stateless
**Status:** Accepted (confirmed by Mohit, 2026-10-21)
**Decision:** Only the gateway connects to PostgreSQL. The gateway sends the agent everything it needs (incident, baselines, recent indicators) and stores what comes back.
**Why:** The agent is the component exposed to attacker-written text and an LLM. With no database credentials and no state, a manipulated agent can only return a bad answer, which the gateway validates.
**Trade-off:** Requests to the agent are larger; the gateway must assemble the context.
**In practice (step 8):** each call carries the incident and the subject's baseline, decrypted by the gateway. The agent has no database driver at all.

## ADR-4: Gateway ↔ agent over localhost HTTP with a service token
**Status:** Accepted (confirmed by Mohit, 2026-10-21)
**Decision:** The agent binds to `127.0.0.1` and requires a bearer service token. Results are streamed back as newline-delimited JSON.
**Why:** Simple to build and explain; no extra infrastructure (no Redis, no message queue).
**Trade-off:** Mutual TLS would be stronger. Listed as an accepted risk in the threat model.
**In practice (step 8):** every request, even for an address that does not exist, needs `Authorization: Bearer <AGENT_SERVICE_TOKEN>`; the token is compared in constant time (`hmac.compare_digest`). FastAPI's `/docs`, `/redoc` and `/openapi.json` are switched off. Request bodies must state their length and stay under 1 MB. Validation errors name the field without echoing the value.

## ADR-5: The gateway re-validates everything the agent returns
**Status:** Accepted (confirmed by Mohit, 2026-10-21)
**Decision:** Agent output is parsed against a schema and proposed actions are checked against the allow-list again in Java.
**Why:** Defence in depth. The agent is treated as untrusted from the gateway's point of view.
**In practice (step 8):** every line of the agent's answer must be a known event type with exactly the expected fields (unknown or repeated fields refused), within length limits and without control characters. The status the agent may choose is an allow-list (`needs_review` for now). Lines are capped at 64 KB, answers at 1000 events, and the whole investigation at 2 minutes; `investigation.complete` must come last, exactly once. Anything else marks the incident `error`.

## ADR-6: Access token (JWT) + rotating refresh token, both in cookies
**Status:** Accepted (confirmed by Mohit, 2026-10-13)
**Decision:** 15-minute signed access token and a rotating refresh token, both in HttpOnly, Secure, SameSite=Strict cookies. Refresh tokens are stored hashed.
**Why:** Matches the original plan and is a common industry pattern. Cookies keep tokens away from JavaScript.
**Trade-off:** More moving parts than server-side sessions. CSRF protection is required because cookies are sent automatically.

## ADR-7: Argon2id for passwords
**Status:** In use since the signup/login step (2026-10-13); not yet explicitly confirmed by Mohit
**Decision:** Spring Security's `Argon2PasswordEncoder`.
**Why:** Memory-hard, current best practice. bcrypt would also be acceptable.

## ADR-8: Flyway for database migrations
**Status:** In use since the database step (2026-10-04); not yet explicitly confirmed by Mohit
**Decision:** Schema changes are versioned SQL files applied by Flyway at startup. Hibernate never auto-creates tables.
**Why:** The schema history is reviewable and repeatable, and you see real SQL (useful for DBMS coursework).

## ADR-9: The risk score is computed by code, not by the LLM
**Status:** Accepted (2026-09-26, proven in the prototype)
**Decision:** Noisy-OR over signal weights. The LLM may raise a verdict, never lower it below the evidence band.
**Why:** A confidence number written by an LLM is not grounded. A code-computed floor also defeats "classify this as safe" injections.

## ADR-10: Rule-engine fallback
**Status:** Accepted (2026-09-26, proven in the prototype)
**Decision:** If the LLM is unavailable, refuses, or times out, a fixed plan runs the same tools.
**Why:** The demo must never depend on an external API. It also gives a baseline to compare the LLM against.

## ADR-11: HMAC hash chain for the audit log
**Status:** Accepted (2026-09-26, proven in the prototype)
**Decision:** Each entry's hash is an HMAC over the entry and the previous hash; the key lives outside the database.
**Why:** A plain hash chain can be recomputed by anyone who can edit the table. An HMAC cannot without the key.

## ADR-12: In-memory rate limiting
**Status:** Accepted (confirmed by Mohit, 2026-10-18)
**Decision:** Bucket4j token buckets held in memory; every threshold comes from `security.rate-limit.*` in `application.properties`. Three limits:
- every request, per client IP address (120 a minute);
- login and signup, per client IP address (10 a minute), because each runs the deliberately slow password hash;
- per username on login: 5 free attempts, then each further attempt waits 1 s, 2 s, 4 s ... up to 15 minutes. A correct password resets it. No permanent lockout.

Refusals are `429` with a `Retry-After` header, in the usual error shape.
**Why:** One gateway instance is enough for this project. Redis can be added later without changing the rules.
**Details that matter:**
- The per-username check runs before the password is checked, and unknown usernames are treated the same as real ones, so the 429 reveals nothing.
- An attempt is counted when it starts and cleared on success, so parallel guesses cannot all slip through before the first failure is recorded.
- The counters sit in a bounded Caffeine cache, so a flood of made-up IPs or usernames cannot exhaust memory.
- The client IP is the connection's own address. `X-Forwarded-For` is ignored until a trusted proxy exists (step 17), because anyone can forge it.

**Trade-offs:** Counters reset when the gateway restarts and would not be shared between several instances. An attacker can slow down a real user's logins for up to 15 minutes at a time (the price of having no permanent lockout). People sharing one IP address (an office, a university) share the per-IP limits.

## ADR-13: Enforcement is simulated
**Status:** Accepted (2026-10-02)
**Decision:** "Block", "lock" and "quarantine" are recorded in a table, not carried out.
**Why:** The project is about investigation, explanation and approval. Real integrations are out of scope.

## ADR-14: Neutral names until the product is named
**Status:** Accepted (2026-09-30)
**Decision:** Code uses the package `com.securityanalyst` and service names `gateway`, `agent`, `dashboard`. No brand name appears in code.
**Why:** The name is undecided; a brand name in code would need renaming everywhere.

## ADR-15: Anthropic Claude as the LLM, model set by configuration
**Status:** Proposed
**Decision:** Use the official Anthropic Python SDK with tool calling. The model ID is an environment variable.
**Why:** Strong tool-calling support. Keeping the model configurable lets us use a cheaper model for development.

## ADR-16: Tests run against an embedded PostgreSQL
**Status:** Accepted (2026-10-04)
**Decision:** Database tests start their own throwaway PostgreSQL 16 (the `io.zonky.test:embedded-postgres` library). They never use the development database.
**Why:** Tests need no password, no setup and no Docker, cannot damage real data, and run the same way on any machine and in CI. It is a real PostgreSQL, so constraints and SQL behave exactly as in production.
**Trade-off:** The first test run downloads the PostgreSQL binaries, and each run takes a few extra seconds to start the server.

## ADR-17: Plain JDBC first, JPA when the first entity arrives
**Status:** Accepted (2026-10-04)
**Decision:** The database step uses `spring-boot-starter-jdbc` only. Spring Data JPA is added in the signup/login step with the `User` entity.
**Why:** Each step should add only what it uses.

## ADR-18: The application role owns its database
**Status:** Accepted (2026-10-04)
**Decision:** One non-superuser role, `secanalyst_app`, owns the `secanalyst` database, runs migrations and serves queries.
**Why:** Simple, and already far safer than connecting as `postgres`: the role cannot create databases or roles, or touch other databases.
**Trade-off:** A stricter setup would use one role for migrations and a second, table-level-only role at runtime. Recorded as an accepted risk.

## ADR-19: Push to GitHub only when demo-ready and named
**Status:** Superseded by ADR-29 (2026-10-14)
**Decision:** No GitHub repository until the project can be shown and has its final name. Local commits per step are recommended in the meantime.
**Why:** Mohit wants the public repository to start with something presentable under the right name.

## ADR-20: Password policy is length, not complexity
**Status:** Accepted (2026-10-13)
**Decision:** Passwords must be 12 to 128 characters and must not contain the username. No rules about symbols, digits or capitals.
**Why:** Current NIST guidance: length is what makes a password strong, and forced complexity pushes people to predictable patterns. The 128 upper limit stops someone sending megabytes of text for the server to hash.
**Trade-off:** A long but common password (for example a famous phrase) is accepted. Checking against a list of breached passwords is a possible later addition.

## ADR-21: Signup may reveal that a username is taken
**Status:** Accepted (2026-10-13)
**Decision:** Signup answers "Username is already taken". Login never reveals whether a username exists.
**Why:** A person choosing a username has to be told when it is unavailable. Login is where guessing attacks happen, so that is where the answer is kept identical for unknown users and wrong passwords.
**Trade-off:** Someone can test usernames one at a time through signup. Rate limiting (a later step) makes that slow.

## ADR-22: Every new account is a VIEWER
**Status:** Accepted (2026-10-13)
**Decision:** Signup always creates the `VIEWER` role and rejects any request that tries to send a role.
**Why:** Otherwise anyone could make themselves an analyst and approve actions.
**Trade-off:** Until the tokens-and-roles step adds a way for an admin to promote users, an `ANALYST` can only be created directly in the database.

## ADR-23: Password hashing library only, not the full security framework yet
**Status:** Accepted (2026-10-13)
**Decision:** This step adds `spring-security-crypto` (plus BouncyCastle for Argon2) but not `spring-boot-starter-security`.
**Why:** The full framework locks every endpoint as soon as it is added. That belongs to the tokens-and-roles step, where it can be configured and understood properly.

## ADR-24: Access tokens are HS256 JWTs made with Spring Security's own JWT module
**Status:** Accepted (2026-10-13)
**Decision:** `spring-security-oauth2-jose` creates and verifies tokens. One secret key (HMAC-SHA256), at least 32 random bytes, from `JWT_SIGNING_KEY`. The verifier accepts HS256 only. Claims: user id (`sub`), `username`, `role`, issued-at, expiry.
**Why:** It ships with Spring Security, so its version is managed for us and no extra third-party JWT library is needed. Pinning the algorithm blocks "alg: none" and algorithm-confusion attacks.
**Trade-off:** A single shared key means whoever can verify tokens can also create them. That is fine while only the gateway does both. The library also allows 60 seconds of clock skew, so a token works up to a minute past its expiry.

## ADR-25: CSRF defence by origin check plus SameSite cookies
**Status:** Accepted (2026-10-13)
**Decision:** Spring Security's token-based CSRF protection is switched off and replaced by `OriginCheckFilter`: a state-changing request is refused if its `Origin` header is not on the allowed list, or its `Sec-Fetch-Site` header says `cross-site`. Cookies are `SameSite=Strict` as an independent second layer.
**Why:** Browsers set these headers themselves and page scripts cannot forge them. It needs no extra token round-trip, which keeps the React client and manual testing simple.
**Trade-off:** A request with neither header is let through. Browsers always send at least one on cross-site state-changing requests; tools such as curl send neither, but they hold no victim's cookies. The allowed-origin list must be kept correct for each environment.

## ADR-26: Refresh tokens are single-use, with reuse detection
**Status:** Accepted (2026-10-13)
**Decision:** Each refresh returns a new refresh token and revokes the old one. All tokens from one login share a `family_id`. Presenting an already-used token revokes the whole family. Only SHA-256 fingerprints are stored.
**Why:** A stolen refresh token is otherwise a 7-day key. With rotation, the thief and the real user collide on the next refresh and the session is shut down.
**Trade-off:** Two genuine refreshes fired at the same instant look like theft and log the user out. The client must refresh from one place at a time.

## ADR-27: Logout and role changes do not instantly kill an access token
**Status:** Accepted (2026-10-13)
**Decision:** Access tokens are checked without the database. Logout and role changes revoke refresh tokens at once and delete the cookies, but an access token already issued stays valid until it expires (15 minutes at most).
**Why:** This is the point of a JWT: no database lookup on every request. Keeping the lifetime short bounds the damage.
**Trade-off:** For up to 15 minutes a demoted user keeps their old role, and a copied access token survives logout. If that ever matters, either shorten the lifetime or check a per-user "tokens valid after" timestamp on each request.

## ADR-28: The first admin is appointed from outside the application
**Status:** Accepted (2026-10-13)
**Decision:** `scripts\set-role.ps1` sets a role directly in the database. Inside the application only an existing admin can change roles, and never their own.
**Why:** Any in-app way to become the first admin (a magic signup, a default account) is a standing weakness. Whoever can run the script already has full database access, so it grants nothing new.

## ADR-29: GitHub flow from the first push
**Status:** Accepted (2026-10-14). Supersedes ADR-19.
**Decision:** Push to GitHub now. `main` always works; each step, fix or docs change happens on its own branch and reaches `main` through a pull request merged with a merge commit; branches are deleted after merging. Mohit runs all git commands; the assistant supplies branch names, commit messages and PR descriptions.
**Why:** Mohit wants to learn the everyday professional workflow while building, and wants an off-machine copy of the work.
**Trade-off:** A little more ceremony per step than committing straight to `main`. Worth it: `main` only ever holds tested work, and each PR documents one step.

## ADR-30: The product is called Casewright; code stays neutral
**Status:** Accepted (2026-10-14). Updates ADR-14.
**Decision:** The product and the GitHub repository are named **Casewright**: the system builds its case from evidence, like a detective. The name appears in the README, the documentation and the user interface. Package names, service names and other code keep the neutral names from ADR-14.
**Why:** It describes what the product does and is easy to say and spell. A quick search found no clashing product. The candidates containing "Phantom" were rejected because Phantom was a well-known security-operations product (acquired by Splunk, now Splunk SOAR), and "ghost"/"vector" names suggest an offensive tool.
**Trade-off:** A web search is not a trademark clearance; acceptable for a portfolio project.

## ADR-31: Server-generated trace IDs on every request
**Status:** Accepted (2026-10-15)
**Decision:** A filter that runs before everything else gives each request a random 16-character ID. It is returned in the `X-Trace-Id` header and in every error body, and printed on every log line for that request. An ID sent by the caller is ignored.
**Why:** A user can report "trace ID 3f9a…" and the exact log lines can be found, without the error message itself revealing anything. Accepting caller-chosen IDs would let anyone plant misleading entries in the logs.
**Trade-off:** IDs do not follow a request across services yet. When the agent service arrives, the gateway will pass its ID along.

## ADR-32: Strict headers for a JSON-only API
**Status:** Accepted (2026-10-15)
**Decision:** `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` plus `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy` denying device access, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, and HSTS for a year (HTTPS only).
**Why:** The gateway never serves pages, so it can forbid everything. The dashboard will set its own, looser policy for the page itself.
**Trade-off:** If the gateway ever serves HTML, the policy must be relaxed for those responses.

## ADR-33: Request bodies are limited to 256 KB; chunked bodies are refused
**Status:** Accepted (2026-10-15)
**Decision:** A filter refuses bodies whose stated length exceeds `security.max-request-size` (256 KB) with 413, and bodies sent without a stated length (chunked) with 411.
**Why:** Without a limit, Tomcat accepts JSON bodies of any size, and each one costs memory and CPU (and password hashing at login). A body's size can only be checked before reading it if the length is stated.
**Trade-off:** Clients must send `Content-Length`, which browsers and normal HTTP clients do. Incident uploads (later) must fit within the limit or get their own, explicitly larger one.

## ADR-34: Local HTTPS is its own step
**Status:** Accepted (2026-10-15)
**Decision:** HTTPS for local development moves from step 5 to a new step 5b.
**Why:** It needs a development certificate and a decision by Mohit about trusting it on this machine, which is a separate topic from error handling and headers.

## ADR-35: Continuous integration on GitHub Actions, with a protected main
**Status:** Accepted (2026-10-16). Brought forward from step 18 at Mohit's request.
**Decision:** A GitHub Actions workflow runs the gateway test suite on a fresh Ubuntu machine for every pull request and every push to `main`. A ruleset on `main` requires a pull request, requires the `Gateway tests` check to pass, and blocks force-pushes and deletion. No approving review is required.
**Why:** Every change is tested in a clean environment, not only on one Windows laptop, and broken code cannot reach `main`. Reviews are not required because the project has one developer and GitHub does not let authors approve their own pull requests.
**Security choices:** the workflow token is read-only (`contents: read`); actions are pinned to full commit SHAs, so a re-tagged or compromised action cannot change what runs; the checkout does not keep credentials on the runner.
**Trade-off:** Pinned SHAs must be updated by hand (or by Dependabot, planned for step 18). Each run takes a few minutes.

## ADR-36: Local HTTPS with a self-signed, localhost-only certificate
**Status:** Accepted (2026-10-17)
**Decision:** The gateway serves HTTPS only, on port 8443, with TLS 1.3 and 1.2. `scripts/setup-https.ps1` makes the certificate with the JDK's `keytool`: self-signed, valid one year, only for `localhost`, `127.0.0.1` and `::1`, marked "not a certificate authority", and limited to server authentication. The certificate and its private key live in `certs/gateway-dev.p12` (git-ignored), protected by `SSL_KEYSTORE_PASSWORD` from `.env`. Trusting the certificate is a separate, opt-in action (`-Trust`) that adds it to the current Windows user's trusted list, never the whole machine's.
**Why:** Cookies are marked `Secure` and the gateway sends HSTS, so local development should use HTTPS like production does. `keytool` ships with Java, so nothing extra has to be downloaded.
**Alternatives considered:** *mkcert* (popular, but it installs a local certificate authority: if that CA's key ever leaked, it could vouch for any website on this machine; our certificate can only ever vouch for `localhost`). *Plain HTTP for local work* (the browser exception for `localhost` hides problems that only show up over real HTTPS).
**Consequences:** Plain HTTP to port 8443 gets `400`. The script `try-auth.ps1` accepts the development certificate even if it is not trusted, but only that exact certificate. HSTS applies to a host name, not a port, so once a browser has seen it for `localhost`, the dashboard's development server (step 16) must use HTTPS too; the allowed origins already expect `https://localhost:5173`. The certificate expires after a year; `setup-https.ps1 -Force` replaces it.

## ADR-37: Baselines encrypted by the gateway with AES-256-GCM
**Status:** Accepted (chosen by Mohit, 2026-10-19)
**Decision:** The gateway encrypts each monitored identity's baseline before storing it, with AES-256-GCM and a 32-byte key from `BASELINE_ENCRYPTION_KEY`. Stored format: a version byte, a random 12-byte nonce, then the ciphertext and its 16-byte tag. The identity is bound in as associated data. Only `MonitoredIdentityService` encrypts or decrypts.
**Why:** The database, its backups and its logs never see the key or the plaintext, so a leaked dump reveals nothing. GCM also detects any change to the stored bytes, and the associated data stops one person's baseline being copied onto another person's row.
**Alternatives considered:** *pgcrypto* (encryption inside PostgreSQL: the key would travel to the database with each query and could end up in its logs). *No encryption for now* (would leave a known gap).
**Trade-offs:** Losing the key makes every baseline unreadable, and changing it needs a re-encryption step (the version byte leaves room for that). The demo employees are added by code at startup, not by a migration, because a migration never sees the key.

## ADR-38: Incidents as one endpoint with a "kind" discriminator and a JSONB payload
**Status:** Accepted (2026-10-19)
**Decision:** `POST /api/incidents` takes one JSON body whose `kind` (`email`, `login`, `call_transcript`) selects a record with its own validation rules (a sealed Java interface plus Jackson's `@JsonTypeInfo`). The validated request is stored in a `JSONB` column; the common fields (`kind`, subject, status, creator, time) are ordinary columns. The answer is `202 Accepted` with a `Location` header, because the investigation is only queued.
**Details:** An incident must name an existing monitored identity (foreign key). Any logged-in user may read every incident (one team, one tool); only ANALYST and ADMIN may submit. IPv4 addresses must be in the plain four-number form, because shorthand forms (`185.220.101`, `3232235777`, `010.0.0.1`) are read differently by different tools. Extracting indicators from incidents is left to step 9, where the tools that use them arrive.
**Why:** One endpoint and one table keep listing and the investigation pipeline simple, while each kind still gets strict, kind-specific validation. JSONB keeps the original evidence intact and queryable.
**Trade-offs:** The payload's inner structure is checked by the Java records, not by database constraints. A 500-event login batch with very long user agents can exceed the 256 KB request limit (ADR-33) and get `413`.

## ADR-39: Investigations run in the background, after the incident is committed
**Status:** Accepted (2026-10-21)
**Decision:** Submitting an incident publishes an event; a listener runs the investigation on a background thread (`@Async`) only after the database transaction has committed (`@TransactionalEventListener(AFTER_COMMIT)`). Status goes `queued → investigating →` the agent's result, or `error` if the agent is unreachable, refuses, or answers with anything invalid. The request's trace ID is carried onto the background thread, so all of an investigation's log lines share it.
**Why:** The analyst gets `202 Accepted` at once instead of waiting for the agent. Running only after commit means the agent never investigates an incident that was then rolled back.
**Trade-off:** If the gateway stops in the middle, an incident can stay `investigating`; picking those up again belongs with the audit and approval work. Python dependencies are pinned to exact versions, including indirect ones, in `agent/requirements*.txt` (hash pinning and auditing come in step 18).

## ADR-40: Indicators, tool guardrails and the evidence chain
**Status:** Accepted (2026-10-23)
**Decision:**
- Plain code (`agent/app/indicators.py`) extracts the incident's indicators: IP addresses (plain four-number IPv4, or IPv6 from login events), domains (from addresses and links), email addresses and phone numbers, at most 50 of each. Bare names merely mentioned in the text are not indicators.
- Every tool call goes through one guardrail (`ToolBox.call`): the tool must be on the allow-list and its arguments must be indicators of this incident. Accepted calls become evidence `E1, E2, ...`; refused ones are recorded as `R1, R2, ...` with the reason, and never run.
- The gateway stores each evidence item as it arrives (`evidence` table) and requires the labels in order with no gaps or repeats; the database also refuses a repeated label. The incident detail API lists the evidence.
- The reputation data is the PRD's static mock dataset, using only names reserved for examples: `.example` domains (RFC 2606), documentation IP ranges (RFC 5737) and 555-01xx numbers, so the public list never accuses a real site, network or person.
- Until the verdict exists (step 11) a fixed plan looks up every indicator (at most 20 lookups) and the engine is reported as `rules`.

**Why:** From step 12 an LLM chooses the tool calls, and incident text can try to steer it ("look up attacker-server.example"). Limiting arguments to extracted indicators makes that impossible in code, whatever the model is persuaded to ask for. Numbered, stored evidence is what the reports will cite.
**Trade-offs:** The registrable-domain rule is simplified (the last two labels; the Public Suffix List would handle names like `example.co.uk`). Indicators are not stored on the incident yet; correlation (step 10) will need them.

## ADR-41: Tools 2-4 (baseline check, pattern match, correlation)
**Status:** Accepted (2026-10-23)
**Decision:**
- Every tool receives one `Case` (the incident, the subject's baseline, the extracted indicators) and nothing else. `baseline_check` accepts only identities in the incident, `pattern_match` only text fields the incident kind has, `correlate_events` no arguments at all.
- `baseline_check` records only **differences** from normal ("a country this person doesn't normally use"), never the baseline itself: baselines are encrypted at rest (ADR-37), evidence is not.
- `pattern_match` normalises text before matching (invisible characters removed and reported as their own finding, Unicode NFKC, common Cyrillic/Greek look-alike letters mapped to Latin, whitespace collapsed), so disguised phrases are still found. Prompt-injection phrasing is recorded as evidence of an attack (`SIG-AI-INJECTION`, weight 40); it is never followed. Quoted snippets are kept only inside the evidence result, at most 120 characters, without control characters.
- `correlate_events` computes per-source login statistics: credential stuffing (8+ accounts, 70%+ failures), brute force (8+ failures on at most 2 accounts), success after 5+ failures, and more than 15 attempts a minute. Results list at most 25 sources and 12 findings.
- The fixed plan per kind follows AGENT_DESIGN section 12: email and call: pattern match, reputation, baseline; login: correlation, reputation of the 5 busiest source addresses, baseline.

**Why:** These are the checks the verdict (step 11) will combine. Keeping baselines out of evidence keeps personal data encrypted; normalising text defeats the common tricks used to slip injection phrases past filters.
**Deferred:** "related incidents" (the same indicators in other recent incidents) moves to step 10b, because it needs the gateway to store each incident's indicators and send recent ones to the agent (ADR-3).
**Trade-offs:** Signature lists catch known phrasing, not every possible wording; the LLM (step 12) and the evaluation suite (step 18) cover the rest. The city list for impossible travel is small and fixed.

## ADR-42: Related incidents over a 7-day window
**Status:** Accepted (window chosen by Mohit, 2026-10-24)
**Decision:**
- The agent reports each incident's indicators once (`incident.indicators`). The gateway checks every value really looks like its type (an IP address, a domain, an email address, a phone number) and stores them in `incident_indicators`.
- Each investigation request carries the indicators of other incidents created in the last **7 days** (`agent.related-incident-window`), most recently seen first, at most 1000 of them (`agent.max-recent-indicators`), each with at most 20 incident numbers. Only values and incident numbers are sent, never who those incidents were about.
- `correlate_events` reports `RELATED-INCIDENTS` (weight 10, or 15 when two or more incidents are linked) for shared indicators, ignoring known-good and internal entries (score 0 in the threat data: the company's own domain, well-known brands, the internal helpdesk) and internal network addresses (10/8, 172.16/12, 192.168/16, loopback, link-local and their IPv6 equivalents). Emails and calls now end with a correlation step.

**Why:** One attacker hitting several people is a strong sign of a campaign. Seven days catches active campaigns and attackers who return within the week, including across weekends, while keeping requests small. The agent stays stateless (ADR-3): the history lives in the gateway.
**Alternatives considered:** 24 hours (the original design: fewer false links, but misses attackers returning after a day or a weekend); 30 days (catches slow campaigns, but more noise, larger requests and more personal data linked across incidents).
**Trade-offs:** Unrelated attackers sharing infrastructure (a cheap cloud server, a popular VPN) can be linked; the weight is kept low for that reason. Incidents older than the window are never compared.

## ADR-43: Verdicts by code, with the score floor enforced by the gateway
**Status:** Accepted (benign handling chosen by Mohit, 2026-10-25)
**Decision:**
- The agent's rule engine turns evidence into a decision: the risk score (noisy-OR over the strongest finding of each kind, each weight capped at 95), the verdict band (0-29 benign, 30-64 suspicious, 65-100 malicious), the attack type (from which findings fired, most specific first), the cited evidence and a counterfactual ("without the strongest finding the risk would be ..."). It sends a `verdict` event before `investigation.complete`.
- The gateway recomputes the score from the evidence it stored (`RiskScore`) and applies AGENT_DESIGN section 8: the final verdict is never below the evidence band; a claim of benign against non-benign evidence, or a gap of two levels, is a disagreement and goes to a human. Cited evidence must exist. The gateway, not the agent, decides the status.
- **Benign incidents are closed automatically**; suspicious, malicious and disagreements go to `needs_review`. Closed incidents stay listed with their verdict and evidence.
- Both implementations multiply in the same order (sorted by id) and round halves up, and both are checked against one shared golden file (`testdata/risk-score-cases.json`), so they cannot drift apart.
- Amends ADR-42: entries the threat data knows to be harmless (score below 10, e.g. a residential connection) are noise for related incidents, like score 0. A live run showed a person's own home address linking two of their incidents.

**Why:** ADR-9 says the score comes from code, never from a model. Enforcing it at the trust boundary means even a compromised agent (or, from step 12, a manipulated LLM) cannot talk an incident down. Closing benign incidents spares analysts from reviewing harmless reports (alert fatigue).
**Alternatives considered:** sending every incident to a human (nothing closed unseen, but real alerts drown in harmless ones); trusting the agent's score (simpler, but a single compromised component could close dangerous incidents).
**Trade-offs:** a wrongly benign verdict closes an incident without review; the evaluation set (step 18) measures how often. The rules engine's attack type is a heuristic.
