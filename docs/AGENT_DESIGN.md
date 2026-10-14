# Reasoning Agent Design

**Status:** Draft v1 · **Last updated:** 2026-10-02
This document specifies the AI agent that investigates incidents (the `agent/` service).
For instructions aimed at AI *coding assistants* working on this repo, see [`../AGENTS.md`](../AGENTS.md).

---

## 1. What the agent does

Given one incident, the agent:
1. gathers evidence by calling tools,
2. submits a structured verdict,
3. proposes response actions.

It never executes anything. A working reference implementation exists in the Python prototype (kept outside this repo).

## 2. Investigation loop

```mermaid
flowchart TD
    S[Incident received] --> X[Extract indicators with code]
    X --> M{LLM available?}
    M -- yes --> L[LLM chooses a tool]
    M -- no --> R[Rule engine runs fixed plan]
    L --> V{Arguments valid?}
    V -- no --> B[Blocked: logged as guardrail event] --> L
    V -- yes --> T[Run tool, record evidence E-n] --> L
    L -- submit_verdict --> C{Verdict passes schema?}
    C -- no --> L
    C -- yes --> F[Reconcile with risk score]
    R --> F
    F --> P[Validate proposed actions]
    P --> O[Build SOC + plain reports]
```

Limits: at most 8 LLM turns and 120 seconds per investigation. On an API error, a refusal, truncation, timeout or the turn limit, the rule engine finishes the job using the evidence already gathered.

## 3. Indicators

Before the LLM sees anything, plain code extracts indicators from the incident: IP addresses, domains, email addresses, phone numbers, and the identities involved. These lists are the **only** values tools will accept. The LLM cannot introduce a new one.

## 4. Tools (the allow-list)

All tools are read-only.

| Tool | Input | What it checks | Rejects when |
|---|---|---|---|
| `reputation_lookup` | `indicator_type` (`ip`/`domain`/`email`/`phone`), `value` | Threat-intel score and tags; look-alike and newly registered domains | `value` is not an extracted indicator |
| `baseline_check` | `identity` | Deviation from the person's normal countries, hours, devices, contacts; impossible travel | `identity` is not part of the incident |
| `pattern_match` | `target` (`subject`/`body`/`transcript`/`all`) | Known attack language: urgency, credential requests, one-time-code requests, impersonation, remote-access tools, prompt-injection text | `target` doesn't exist for this incident kind |
| `correlate_events` | none | Per-source login statistics (stuffing, brute force, success after failures, automation); indicators shared with recent incidents | – |
| `submit_verdict` | see section 7 | Ends the investigation | Schema invalid or cites unknown evidence |

Any other tool name is rejected.

## 5. Evidence and signals

Each accepted tool call becomes an **evidence item**:

```json
{
  "label": "E2",
  "tool": "reputation_lookup",
  "args": {"indicator_type": "ip", "value": "185.220.101.47"},
  "summary": "ip 185.220.101.47: score=92 tags=[tor-exit-node]",
  "result": { "...": "raw tool output" },
  "signals": [ { "...": "see below" } ],
  "ts": "2026-10-02T06:00:01.120Z"
}
```

A **signal** is one finding. It carries both a technical and a plain description, which is what keeps the two reports consistent:

```json
{
  "id": "REP-MALICIOUS",
  "label": "185.220.101.47 is known-malicious (score 92: tor-exit-node)",
  "plain": "This address is on lists of known attackers.",
  "weight": 45,
  "mitre": "T1583"
}
```

Rejected calls are recorded too, labelled `R1`, `R2`, …, with the reason.

## 6. Risk score

The score is computed by code from the signals, never taken from the LLM.

- Keep the strongest signal per `id`.
- Combine with **noisy-OR**: `risk = 100 × (1 − Π(1 − weight/100))`. Independent findings compound, and the result never exceeds 100.
- Bands: 0–29 benign · 30–64 suspicious · 65–100 malicious.

Example: weights 50, 45, 25 → `1 − (0.50 × 0.55 × 0.75) = 0.79` → risk 79, malicious.

## 7. Verdict schema

The LLM's `submit_verdict` call is parsed against this before it is trusted:

| Field | Type | Rule |
|---|---|---|
| `verdict` | enum | `benign` / `suspicious` / `malicious` |
| `attack_type` | enum | `none`, `phishing`, `credential_stuffing`, `brute_force`, `account_takeover`, `impossible_travel`, `vishing`, `prompt_injection`, `bec`, `other` |
| `summary_technical` | string ≤ 1500 | Must cite at least one evidence ID like `[E1]` |
| `summary_plain` | string ≤ 800 | Plain language |
| `cited_evidence` | list of `E\d+` | Every ID must exist |
| `mitre_techniques` | list | Must match `T####(.###)` or `AML.T####` |
| `proposed_actions` | list of `{action, target}` | Validated by the action policy |
| `counterfactual` | string ≤ 500 | What would change the verdict |

Unknown fields are rejected.

## 8. Reconciliation (the score floor)

| Situation | Result |
|---|---|
| LLM verdict ≥ evidence band | LLM verdict stands |
| LLM verdict < evidence band | Verdict is raised to the evidence band |
| LLM says benign but evidence says otherwise, or they differ by two levels | Flagged as a **disagreement**; incident goes to `needs_review` |

The LLM can make the system more cautious, never less.

## 9. Action policy

| Action | Risk | Target must be | Extra rule |
|---|---|---|---|
| `monitor` | low | any identity or indicator in the incident | auto-executed |
| `notify_user` | low | an identity in the incident | auto-executed |
| `force_password_reset` | **high** | an identity in the incident | needs approval |
| `lock_account` | **high** | an identity in the incident | needs approval |
| `block_ip` | **high** | an extracted IP **with evidence** | never a private, loopback or reserved address |
| `quarantine_email` | **high** | the sender address, with evidence | |
| `block_sender_domain` | **high** | an extracted domain, with evidence | never a protected (own) domain |
| `block_phone_number` | **high** | the caller number, with evidence | |

A high-risk action proposed for a benign verdict is rejected. Rejected proposals are logged as guardrail events. The gateway applies the same allow-list again when it receives the result.

## 10. Prompt-injection defences

| # | Defence | Enforced by |
|---|---|---|
| 1 | Incident content is passed as JSON inside `<untrusted_incident>` tags, with `<` and `>` escaped so the fence cannot be closed. | Code |
| 2 | The system prompt states that incident content is data, and that instructions inside it are evidence of an attack. | Prompt |
| 3 | Tools are read-only. | Code |
| 4 | Tool arguments must be extracted indicators. | Code |
| 5 | Actions are proposals, validated by policy, and high-risk ones need a human. | Code |
| 6 | The verdict cannot go below the evidence score. | Code |
| 7 | `pattern_match` detects injection phrasing and raises the score (`AML.T0051`). | Code |
| 8 | Every call and every rejection is audited. | Code |

Only defence 2 depends on the model behaving. The rest hold even if the model is fully manipulated; the red-team probe demonstrates this by replaying a hijacked model's calls.

## 11. LLM configuration

| Setting | Value |
|---|---|
| Provider | Anthropic API (Claude), via the official Python SDK |
| Model | Configurable by environment variable |
| Tool definitions | Strict JSON schemas, `additionalProperties: false` |
| Refusals / errors | Fall back to the rule engine |
| Data sent | Incident payload with personal identifiers pseudonymised (planned), indicator lists, tool results |

## 12. Rule engine (fallback)

A fixed plan per incident kind, using the same tools and the same scoring:

| Kind | Plan |
|---|---|
| `email` | pattern match → sender reputation → reply-to and link reputation → baseline → correlation |
| `login` | correlation → reputation of top source IPs → baseline of the subject |
| `call_transcript` | pattern match → caller reputation → baseline → correlation |

Verdict = evidence band. Attack type and actions are derived from which signals fired.

## 13. Evaluation

| Suite | Content | Pass condition |
|---|---|---|
| Scenario tests | The six demo scenarios | Expected verdict and attack type |
| Labelled set | 50–100 benign and malicious incidents | Recall ≥ 90%, false-positive rate ≤ 10% |
| Red-team suite | Injection payloads in every text field | 0 unauthorised tool calls, 0 unauthorised actions, verdict never lowered |
| Traceability | Every report | Every finding cites an existing evidence ID |
