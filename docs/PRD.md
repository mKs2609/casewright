# Product Requirements Document

**Product:** Casewright
**Owner:** Mohit Kumar · **Status:** Draft v1 · **Last updated:** 2026-10-02

---

## 1. Summary

An agentic AI security analyst. Given a suspicious event (an email, a set of login attempts, or a phone-call transcript), it **investigates step by step** using tools, reaches an **evidence-backed verdict**, explains that verdict **twice** (once for a security expert, once for anyone), and **asks a human** before any high-risk action is taken.

**One-line pitch:** An AI security analyst that investigates threats like a human would, explains itself to experts and non-experts at the same time, and never acts alone on anything risky.

## 2. Problem

| Problem | Who feels it |
|---|---|
| Security tools output a label ("malicious: 0.93") with no reasoning, so analysts can't trust or verify it. | SOC analysts |
| Alerts are written for experts. The employee who received the phishing email can't understand what happened or what to do. | Employees |
| Fully automated response is dangerous: a wrong or manipulated decision can lock out real users or block real systems. | Security leads |
| AI-based tools are themselves attackable: text inside an email can instruct the AI to misbehave (prompt injection). | Everyone |

## 3. Goals and non-goals

### Goals
1. **Explainable investigation.** Every verdict comes with the chain of evidence that produced it.
2. **Dual-audience explanation.** A technical report and a plain-language report, both generated from the *same* evidence chain so they can never contradict each other.
3. **Human-in-the-loop.** High-risk actions (block, lock, quarantine) never execute without explicit approval by an authorised human.
4. **Auditable.** Every tool call, verdict, approval and rejection is recorded in a tamper-evident log.
5. **Secure by construction.** The system protecting people is itself hardened, including against attacks on its own AI. Tracked in `SECURITY.md`.
6. **Demo-ready.** A live dashboard shows the investigation as it happens, and works even if the LLM API is unavailable.

### Non-goals (explicitly out of scope)
- Real enforcement. Actions like "block IP" are **simulated** and recorded; no firewall, mail server or identity provider is touched.
- Real threat-intelligence feeds. Reputation data is a static mock dataset (a real feed may be added behind a flag later).
- Multi-tenancy. One organisation only.
- Mobile app, email/Slack integrations, SSO.
- Training or fine-tuning a model.

## 4. Users

| Persona | Role in system | What they need |
|---|---|---|
| **Asha, SOC analyst** (primary) | `ANALYST` | See what the agent found and why, check the evidence, approve or reject actions quickly and confidently. |
| **Ravi, employee** | No login; receives the plain-language report | Understand in 20 seconds whether something is dangerous and what to do. No jargon. |
| **Meera, security lead** | `ADMIN` | Trust that nothing risky happens without a human, and that the history can't be quietly edited. |
| **Viewer / auditor** | `VIEWER` | Read incidents and the audit log. Cannot approve anything. |
| **Faculty / interviewer** | Demo audience | See the investigation live and understand the security design. |

## 5. User stories

- As an **analyst**, I can submit an incident and watch the agent's investigation steps appear live.
- As an **analyst**, I can click any step to see exactly what was checked and what came back.
- As an **analyst**, I see the technical report and the plain-language report side by side.
- As an **analyst**, I must approve or reject each high-risk action, after seeing the evidence, and can give a reason.
- As a **viewer**, I can read everything but cannot approve or submit.
- As a **security lead**, I can verify that the audit log has not been tampered with.
- As a **demo presenter**, I can press one button to fire a simulated attack.
- As an **employee**, I get a short explanation with clear next steps, in plain words.

## 6. Functional requirements

Priority: **P0** = must have for the demo · **P1** = should have · **P2** = stretch.

### 6.1 Accounts and access
| ID | Requirement | Pri |
|---|---|---|
| FR-1 | Sign up and log in with username + password; passwords stored only as Argon2 hashes. | P0 |
| FR-2 | Roles: `ADMIN`, `ANALYST`, `VIEWER`. Only `ANALYST`/`ADMIN` can submit incidents and decide actions. | P0 |
| FR-3 | Short-lived access token + rotating refresh token, delivered in HttpOnly, Secure, SameSite cookies. | P0 |
| FR-4 | Log out invalidates the refresh token. | P0 |

### 6.2 Incidents
| ID | Requirement | Pri |
|---|---|---|
| FR-5 | Ingest three incident kinds: `email`, `login` (a batch of login events), `call_transcript`. | P0 |
| FR-6 | Strict schema validation on every field (type, length, format); invalid input is rejected, never cleaned. | P0 |
| FR-7 | Each monitored identity (employee) has a behavioural baseline: usual countries, hours, devices, contacts. | P0 |
| FR-8 | List incidents and view one incident with its evidence, verdict and actions. | P0 |
| FR-9 | Upload an `.eml` file as an incident. | P2 |

### 6.3 Reasoning agent
| ID | Requirement | Pri |
|---|---|---|
| FR-10 | The agent investigates using a fixed allow-list of read-only tools: reputation lookup, baseline check, pattern match, event correlation. | P0 |
| FR-11 | Every tool call is recorded as an evidence item with ID, arguments, result and timestamp. | P0 |
| FR-12 | The agent produces a structured verdict: `benign` / `suspicious` / `malicious`, attack type, cited evidence, proposed actions. | P0 |
| FR-13 | A deterministic risk score (0–100) is computed from the evidence. The LLM may raise the verdict but can never lower it below what the evidence supports. | P0 |
| FR-14 | If the LLM is unavailable, refuses or times out, a rule engine completes the investigation with the same tools. | P0 |
| FR-15 | Findings are mapped to MITRE ATT&CK / ATLAS technique IDs. | P1 |
| FR-16 | Each verdict states a counterfactual: what evidence would have changed it. | P1 |

### 6.4 Explanations
| ID | Requirement | Pri |
|---|---|---|
| FR-17 | SOC report: verdict, risk, indicators, findings with evidence IDs, techniques, recommended actions. | P0 |
| FR-18 | Plain-language report: what happened, why we think so, what to do. No acronyms or jargon. | P0 |
| FR-19 | Both reports are rendered from the same evidence chain; every claim traces to an evidence ID. | P0 |

### 6.5 Human approval and audit
| ID | Requirement | Pri |
|---|---|---|
| FR-20 | High-risk actions are created as `pending` and execute only after an analyst approves. | P0 |
| FR-21 | The approval screen shows the supporting evidence before the decision. | P0 |
| FR-22 | Approvals expire; a user cannot decide an action targeting their own account. | P1 |
| FR-23 | Hash-chained audit log of tool calls, verdicts, approvals, rejections and logins, with a verify function. | P0 |

### 6.6 Dashboard and demo
| ID | Requirement | Pri |
|---|---|---|
| FR-24 | Live stream of investigation steps over an authenticated WebSocket. | P0 |
| FR-25 | Animated investigation view; click any step for full detail. | P0 |
| FR-26 | "Attempt breach" button and other simulated scenarios (phishing, vishing, impossible travel, prompt-injection email). | P0 |
| FR-27 | "Red-team the agent" action that replays what a hijacked model would attempt and shows every attempt blocked. | P1 |
| FR-28 | Replay a finished investigation step by step. | P2 |

## 7. Non-functional requirements

| Area | Requirement |
|---|---|
| **Security** | Every item in `SECURITY.md` implemented and tested. Threats and controls in `docs/THREAT_MODEL.md`. |
| **Performance** | First investigation step visible within 3 s of submission. Full investigation within 30 s (LLM) or 10 s (rule engine). API responses under 300 ms excluding investigations. |
| **Reliability** | The demo must complete with no internet/LLM access (rule-engine fallback). |
| **Privacy** | Personal data is minimised before being sent to the LLM provider. Baselines encrypted at rest. |
| **Accessibility** | Dashboard meets WCAG 2.1 AA: contrast, keyboard access, no meaning conveyed by colour alone. |
| **Maintainability** | Each feature ships with tests; CI runs tests and security scans on every push. |

## 8. Success metrics

| Metric | Target | How measured |
|---|---|---|
| Detection recall on malicious incidents | ≥ 90% | Labelled evaluation set (50–100 incidents) |
| False-positive rate on benign incidents | ≤ 10% | Same set |
| Prompt-injection attack success rate | **0** unauthorised tool calls or actions | Red-team suite of injection payloads |
| Plain-report readability | Flesch-Kincaid grade ≤ 8 | Automated check on generated reports |
| Evidence traceability | 100% of findings cite an existing evidence ID | Automated test |
| Demo reliability | End-to-end demo passes with LLM disabled | Automated test |

## 9. Release scope

- **MVP (weeks 1–6):** all P0 items.
- **Hardening (weeks 7–8):** P1 items, CI security gate, evaluation results, demo video.
- **Stretch:** P2 items, a real threat-intel feed, analyst feedback loop, campaign clustering.

The step-by-step build order is in [`ROADMAP.md`](ROADMAP.md).

## 10. Risks

| Risk | Mitigation |
|---|---|
| Three stacks (Java, Python, React) is a lot for 8 weeks. | One feature at a time; the Python prototype already proves the hardest part. |
| LLM tool-calling is flaky or the API is down during the demo. | Rule-engine fallback; recorded demo video as backup. |
| LLM cost. | Cheaper model configurable; cached/recorded runs for rehearsals. |
| The LLM gets manipulated by incident text. | Guardrails enforced in code, not in the prompt; score floor; human approval. |
| Scope creep. | This PRD's non-goals; P2 only after P0 is committed. |

## 11. Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | ~~Final product name.~~ Decided: **Casewright** (ADR-30). | Done |
| 2 | Which LLM model and budget for development vs demo. | Step 12 |
| 3 | Source of evaluation data (public phishing corpora vs fully synthetic). | Step 18 |
| 4 | Is HTTPS on localhost required for the demo, or is a reverse proxy acceptable? | Step 5 |
