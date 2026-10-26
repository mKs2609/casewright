# Security

Status: ✅ done & tested · 🟡 partial · ⬜ not started

Each item is ticked only when it is implemented **and** covered by a test.

## A. Perimeter / API
| Item | Status | Notes |
|---|---|---|
| Rate limiting: strict on `/auth/*` (per-IP + per-account, exponential backoff, no hard lockout), moderate elsewhere; thresholds in config | ✅ | Every request: 120/min per IP. Login and signup: 10/min per IP. Login per username: 5 free attempts, then waits doubling from 1 s to 15 min, checked before the password and identical for unknown usernames; a correct password resets it. `429` with `Retry-After`. Bounded in-memory counters (ADR-12); `X-Forwarded-For` not trusted. Tests: `RateLimitTest`, `LoginThrottleTest`, `KeyedRateLimiterTest`. |
| Strict input validation (type, length, format); reject, never "clean" | 🟡 | Done for signup, login and incidents: format and length rules, unknown JSON fields rejected (including fields that belong to another incident kind), rejected values never echoed back. Incident text is kept exactly as sent and only ever returned as JSON data. IPs: plain four-number IPv4 or IPv6 only, parsed without any DNS lookup. To be repeated for every new endpoint. Tests: `IncidentApiTest`. |
| Security headers: CSP, `nosniff`, `X-Frame-Options: DENY`, HSTS | ✅ | Every response, including refusals: `Content-Security-Policy` (nothing may load or run), `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, cross-origin opener/resource policies, `Cache-Control: no-store`; HSTS on HTTPS responses only (as the standard requires). No `Server` header. Tests: `ErrorHandlingAndHeadersTest`. |
| Request size limit | ✅ | Bodies over 256 KB refused with 413 before being read; chunked bodies without a length refused with 411; limit in config (`aBodyOverTheLimitIsRefusedBeforeItIsRead`). |
| HTTPS/TLS everywhere, including local demo | 🟡 | The gateway serves HTTPS only (port 8443), TLS 1.3 and 1.2 only; plain HTTP to the port is refused. Development certificate: self-signed, `localhost` only, marked not-a-CA, private key in a git-ignored, password-protected keystore. Trusting it is a separate, opt-in step for the current Windows user. Tests: `HttpsServerTest`. Production certificates come with deployment (step 17); agent-service traffic gets TLS when that service exists. |
| WebSocket hardening: authenticated handshake, message schema, per-connection rate limit | ⬜ | |

## B. Authentication & authorization
| Item | Status | Notes |
|---|---|---|
| Passwords hashed with Argon2/bcrypt | ✅ | Argon2id, 19 MiB / 2 passes / 1 thread (OWASP minimum), settings in config. Random salt per password. Tests: stored value is an `$argon2id$` hash, same password gives different hashes, password never returned or logged (`AuthControllerTest`, `RequestRecordsTest`). |
| Login reveals nothing about which usernames exist | ✅ | Same message and same work for a wrong password and an unknown user (`wrongPasswordAndUnknownUserGetTheExactSameAnswer`). Signup does reveal a taken username; accepted, see ADR-21. |
| No self-assigned roles | ✅ | Every signup becomes `VIEWER`; a request containing `role` is rejected (`nobodyCanGiveThemselvesARoleAtSignup`). |
| Short-lived tokens + refresh rotation | ✅ | 15-minute signed access token (JWT, HS256 only). 7-day refresh token, random 256 bits, stored only as a SHA-256 fingerprint, single-use. Reusing an old one revokes the whole session. Tests: altered, wrong-key, expired and unsigned tokens are all refused; rotation; reuse detection; logout (`SessionAndRolesTest`). |
| HttpOnly + Secure + SameSite cookies | ✅ | Both cookies are `HttpOnly`, `Secure`, `SameSite=Strict`; the refresh cookie is limited to `Path=/api/auth`; tokens never appear in a response body (`loginSetsTwoLockedDownCookiesAndPutsNoTokenInTheBody`). |
| Cross-site request forgery (CSRF) protection | ✅ | State-changing requests from an unknown `Origin`, or marked `Sec-Fetch-Site: cross-site`, are refused; `SameSite=Strict` is a second layer (`requestsFromAnotherWebsiteAreRefused`). See ADR-25. |
| Role-based access (deny by default) | ✅ | Every URL needs a login unless explicitly listed as public; `/api/admin/**` needs `ADMIN`. Tests cover viewer, analyst and admin, self-promotion, and changing one's own role. |
| Object-level authorization on every endpoint | ⬜ | Incidents are deliberately readable by every logged-in user (one team, ADR-38); submitting needs ANALYST or ADMIN. Per-object checks arrive with approvals (an analyst cannot decide their own proposals, step 14). |

## C. Secrets & dependencies
| Item | Status | Notes |
|---|---|---|
| All secrets in env vars, never in code | 🟡 | `.gitignore` blocks `.env`, keys and certs. Database credentials and the token-signing key come from `.env` / environment only; the gateway refuses to start if any is missing, or if the signing key is shorter than 32 bytes. Tests use their own random key. More secrets arrive in later steps. |
| Pre-commit secret scanning | ⬜ | |
| Nothing sensitive in the frontend bundle | ⬜ | |
| Dependency audit (Maven, pip, npm) with findings table | ⬜ | Python packages are pinned to exact versions, including indirect ones (`agent/requirements*.txt`). Audit and hash pinning in step 18. |

## D. Error handling & data protection
| Item | Status | Notes |
|---|---|---|
| Generic errors + trace ID to client; stack traces server-side only | ✅ | One error shape `{"error", "fields", "traceId"}` everywhere, including security refusals. Unexpected errors: generic message, full stack trace in the server log on a line tagged with the same trace ID. Framework errors keep their real status (404, 405, 400). Trace IDs are generated by the server, never taken from the caller. Tests: `ErrorHandlingAndHeadersTest`, including a check that a leaked message is caught. |
| Application uses a non-superuser database role | 🟡 | `scripts/setup-db.sql` creates `secanalyst_app` with no superuser, create-database or create-role rights. Checked by hand against a throwaway instance; no automated test. |
| Parameterised queries only | 🟡 | All queries so far use bound parameters. Database constraints reject malformed usernames (`AppUsersMigrationTest`). |
| Sensitive fields encrypted at rest | 🟡 | Employee baselines: AES-256-GCM in the gateway, key from `BASELINE_ENCRYPTION_KEY`, random nonce per write, identity bound as associated data, tampering detected (ADR-37). Evidence never copies baseline values, only differences from them (ADR-41). Tests: `BaselineCipherTest`, `MonitoredIdentitiesTest`, `agent/tests/test_baseline_check.py`. Incident payloads are not encrypted (they are what analysts read); revisit before real data. |
| Tamper-evident (hash-chained) audit log | ⬜ | |

## E. File uploads
| Item | Status | Notes |
|---|---|---|
| Magic-byte validation, size limits, isolated storage, never executable | ⬜ | Only if we accept `.eml` uploads |

## F. AI-specific hardening
| Item | Status | Notes |
|---|---|---|
| Incident text passed to the LLM as fenced data, never instructions | ⬜ | |
| Prompt-injection text detected and treated as evidence of an attack | 🟡 | `pattern_match` finds injection phrasing after normalising the text (invisible characters, full-width and Cyrillic/Greek look-alike letters), and records it as `SIG-AI-INJECTION`; invisible characters are a finding of their own. The text is never followed. The red-team suite comes in step 12. Tests: `agent/tests/test_patterns.py`. |
| Fixed tool allow-list; arguments validated against the incident | 🟡 | Every tool call passes one guardrail: unknown tools, and arguments that are not indicators extracted from this incident, are refused and recorded as `R1, R2, ...` (ADR-40). Done for tool 1; it will apply unchanged when an LLM picks the calls (step 12). Tests: `agent/tests/test_tools.py`. |
| Every agent tool call logged | ✅ | Accepted and refused calls are both stored in the `evidence` table (label, tool, arguments, result or reason) and logged with the incident's trace ID. The gateway enforces the numbering and the database refuses repeated labels. Tests: `InvestigationTest`. |
| Data sent to the agent kept to what it needs | 🟡 | Each request carries the incident, the subject's baseline, and other recent incidents' indicators as values and incident numbers only, never who those incidents were about (ADR-42); bounded to 1000 indicators. Pseudonymising personal identifiers before the LLM sees them comes with step 12. |
| Agent service isolated and treated as untrusted | ✅ | Listens on `127.0.0.1` only; every request needs the service token (constant-time comparison); no database access and no state (ADR-3, ADR-4); API docs pages off; 1 MB body limit. The gateway re-validates every event it returns: known types and fields only, allow-listed statuses, size and time limits (ADR-5). Tests: `agent/tests`, `InvestigationTest`. |
| LLM output validated against a schema before use | ⬜ | |
| A verdict can never be lowered below the evidence | ✅ | The gateway recomputes the risk score from the evidence it stored and never lets the verdict fall below its band; claiming benign against the evidence is flagged as a disagreement and sent to a human; cited evidence must exist; the gateway, not the agent, sets the status (ADR-43). Tests: `InvestigationTest`, `RiskScoreTest`, the shared golden file. |

## G. Operational
| Item | Status | Notes |
|---|---|---|
| CI: tests + dependency audit + static analysis on every push | 🟡 | GitHub Actions runs the full test suite on every pull request and every push to `main`; `main` is protected so a pull request cannot merge while it fails. Least-privilege token (`contents: read`), actions pinned to exact commits. Dependency audit and static analysis come in step 18. |
| This file kept current | 🟡 | |
