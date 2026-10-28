# Tasks

The working board. [`ROADMAP.md`](ROADMAP.md) is the long-term plan; this file tracks what is happening **now**.
Updated at the start and end of every step.

**Last updated:** 2026-10-29

---

## Now

### Step 12: LLM reasoning agent (on `feature/llm-agent`)
- [x] ADR-15 decided: a free local model (Ollama, `qwen3:8b`), provider and model as settings, address must be on this machine
- [x] The model chooses the tools and calls `submit_verdict`; every call through the same guardrail
- [x] Prompt-injection defences: fenced incident, summaries instead of raw results, the model's words never in events
- [x] Model output checked: size cap, strict verdict schema, citations must exist, evidence first
- [x] Limits: 8 turns, 120 s, 4 calls per turn; 200 investigations and 2M tokens a day; fallback to the fixed plan
- [x] Tools take a fixed set of argument names (stricter than before); refusals name the allowed ones; known wrapper shapes unwrapped
- [x] The model can add checks, never remove them: the standard checks always run after it (found in Mohit's own run)
- [x] Gateway accepts engine `llm`; deadline 3 minutes
- [x] Red-team suite (scripted hijacked model); tests: agent 228, gateway 185; 16 mutation checks
- [x] Live: all six scenarios correct, led by the model (8-14 s each); fallback with the model unreachable
- [ ] Merged

## Next

### Step 13: Dual explanation
A technical report and a plain-language report from the same evidence; every finding cites existing evidence.

## Later

See `ROADMAP.md` steps 7–18.

## Open questions

| # | Question | Needed by |
|---|---|---|
| 1 | Confirm the Proposed decisions in `DECISIONS.md` | Before the step each one affects |
| 2 | Evaluation data source | Step 18 |

## Done

- **2026-10-27:** Step 11 (risk score, verdict, rule engine) merged: PR #11.
- **2026-10-25:** Step 10b (related incidents) merged: PR #10.
- **2026-10-24:** Step 10 (baseline check, pattern match, correlation) merged: PR #9.
- **2026-10-23:** Step 9 (reputation lookup, evidence chain) merged: PR #8.
- **2026-10-22:** Fixed a flaky test: "not echoed" checks were sometimes fooled by the random trace ID (a short value like `ab` appears in one in about 17 trace IDs). Checks now blank the trace ID first (`NoEcho`).
- **2026-10-22:** Step 8 (agent service, secure connection) merged: PR #6. "Agent tests" is now a required check on `main`.
- **2026-10-21:** Step 7 (incident ingestion, encrypted baselines) merged: PR #5.
- **2026-10-19:** Step 6 (rate limiting) merged: PR #4.
- **2026-10-18:** Step 5b (local HTTPS) merged: PR #3.
- **2026-10-16:** Step 5a (CI on GitHub Actions, protected `main`) merged: PR #2.
- **2026-10-16:** Step 5 (errors, trace IDs, security headers, size limit) merged: PR #1.
- **2026-10-15:** Steps 0 to 4 committed and published to https://github.com/mKs2609/casewright.
- **2026-10-14:** Product name decided: Casewright.
