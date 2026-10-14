# Security

Status: ✅ done & tested · 🟡 partial · ⬜ not started

Each item is ticked only when it is implemented **and** covered by a test.

## A. Perimeter / API
| Item | Status | Notes |
|---|---|---|
| Rate limiting: strict on `/auth/*` (per-IP + per-account, exponential backoff, no hard lockout), moderate elsewhere; thresholds in config | ⬜ | |
| Strict input validation (type, length, format); reject, never "clean" | 🟡 | Done for signup and login: format and length rules, unknown JSON fields rejected, rejected values never echoed back. To be repeated for every new endpoint. |
| Security headers: CSP, `nosniff`, `X-Frame-Options: DENY`, HSTS | ⬜ | |
| HTTPS/TLS everywhere, including local demo | ⬜ | |
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
| Object-level authorization on every endpoint | ⬜ | Nothing user-owned exists yet; arrives with incidents. |

## C. Secrets & dependencies
| Item | Status | Notes |
|---|---|---|
| All secrets in env vars, never in code | 🟡 | `.gitignore` blocks `.env`, keys and certs. Database credentials and the token-signing key come from `.env` / environment only; the gateway refuses to start if any is missing, or if the signing key is shorter than 32 bytes. Tests use their own random key. More secrets arrive in later steps. |
| Pre-commit secret scanning | ⬜ | |
| Nothing sensitive in the frontend bundle | ⬜ | |
| Dependency audit (Maven, pip, npm) with findings table | ⬜ | |

## D. Error handling & data protection
| Item | Status | Notes |
|---|---|---|
| Generic errors + trace ID to client; stack traces server-side only | 🟡 | One error shape (`{"error": ..., "fields": ...}`) for validation, conflicts and failed logins; health reports `DOWN` without the database error text. Catch-all handler and trace IDs still to come. |
| Application uses a non-superuser database role | 🟡 | `scripts/setup-db.sql` creates `secanalyst_app` with no superuser, create-database or create-role rights. Checked by hand against a throwaway instance; no automated test. |
| Parameterised queries only | 🟡 | All queries so far use bound parameters. Database constraints reject malformed usernames (`AppUsersMigrationTest`). |
| Sensitive fields encrypted at rest | ⬜ | |
| Tamper-evident (hash-chained) audit log | ⬜ | |

## E. File uploads
| Item | Status | Notes |
|---|---|---|
| Magic-byte validation, size limits, isolated storage, never executable | ⬜ | Only if we accept `.eml` uploads |

## F. AI-specific hardening
| Item | Status | Notes |
|---|---|---|
| Incident text passed to the LLM as fenced data, never instructions | ⬜ | |
| Fixed tool allow-list; arguments validated against the incident | ⬜ | |
| Every agent tool call logged | ⬜ | |
| LLM output validated against a schema before use | ⬜ | |

## G. Operational
| Item | Status | Notes |
|---|---|---|
| CI: tests + dependency audit + static analysis on every push | ⬜ | |
| This file kept current | 🟡 | |
