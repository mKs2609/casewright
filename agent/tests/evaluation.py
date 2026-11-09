"""Runs the evaluation sets through the agent, measures the result, and writes the report
(docs/EVALUATION.md) (PRD section 8, ADR-53).

An incident is "flagged" when the investigation ends `needs_review` (a person looks at it) and
"closed" when it ends `closed` (judged harmless, nobody looks). That is the decision that matters
in practice: a missed attack is closed, a false alarm takes someone's time.

- Detection rate (recall): flagged attacks / all attacks. PRD target: at least 90%.
- False-alarm rate (false-positive rate): flagged harmless incidents / all harmless ones. Target: at most 10%.

With 20 or 30 of each, one example is worth 3 to 5 percentage points, so each rate also gets a
95% confidence interval (the Wilson score interval): the range the true rate probably lies in.

Two sets (ADR-53): the development set (tests/evaluation_set.py), whose first run showed the
gaps that were then fixed, and the held-out set (tests/evaluation_heldout.py), written after
the fixes and run once. The held-out result is the honest one.
"""

import math
from dataclasses import dataclass
from typing import Any

from app import config
from app import verdict as decide
from app.budget import DailyBudget
from app.investigation import investigate
from app.llm import ChatModel
from app.models import CompleteEvent, InvestigateRequest, VerdictEvent
from tests.evaluation_heldout import HELD_OUT
from tests.evaluation_set import DEVELOPMENT, SOURCES, Example
from tests.scenarios import BASELINES

TARGET_DETECTION = 0.90
TARGET_FALSE_ALARMS = 0.10
KINDS = {"email": "Emails", "login": "Sign-in batches", "call_transcript": "Phone calls"}


@dataclass(frozen=True)
class Outcome:
    example: Example
    verdict: str          # after the score floor: what the gateway records
    risk: int
    flagged: bool
    engine: str           # "rules", or "llm" when the AI model ran
    findings: tuple[str, ...]

    @property
    def correct(self) -> bool:
        return self.flagged == (self.example.label == "malicious")


def run(example: Example, incident_id: int, model: ChatModel | None = None,
        budget: DailyBudget | None = None) -> Outcome:
    if model is None and config.llm_settings().provider != "off":
        # investigate() would fall back to the configured model, and a "rule engine" result would
        # silently be the AI's. The model, when wanted, is always passed in.
        raise RuntimeError("Measuring the rule engine needs LLM_PROVIDER=off.")
    request =InvestigateRequest.model_validate({
        "incident": {"id": incident_id, "kind": example.kind, "subjectIdentity": example.subject,
                     "payload": example.payload},
        "baseline": BASELINES[example.subject]})
    events = list(investigate(request, model=model, budget=budget or DailyBudget()))
    decision = next(e for e in events if isinstance(e, VerdictEvent))
    complete = events[-1]
    assert isinstance(complete, CompleteEvent)
    findings = sorted({s.id for e in events for s in getattr(e, "signals", [])})
    return Outcome(example, decide.more_severe(decision.verdict, decide.band(decision.risk_score)),
                   decision.risk_score, complete.result == "needs_review", complete.engine, tuple(findings))


def run_all(examples: list[Example], model: ChatModel | None = None) -> list[Outcome]:
    budget = DailyBudget(max_investigations=10_000, max_tokens=100_000_000)
    return [run(example, 1000 + i, model, budget) for i, example in enumerate(examples)]


def wilson(hits: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """The 95% Wilson score interval for hits/total. Unlike plain p +/- 2 standard errors, it stays
    inside 0..1 and behaves at 0% and 100%, which small sets often hit."""
    if total == 0:
        return 0.0, 1.0
    p = hits / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return max(0.0, centre - spread), min(1.0, centre + spread)


@dataclass(frozen=True)
class Rate:
    hits: int
    total: int

    @property
    def value(self) -> float:
        return self.hits / self.total if self.total else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson(self.hits, self.total)

    def shown(self) -> str:
        low, high = self.interval
        return f"{self.hits} of {self.total} ({self.value:.0%}), range {low:.0%} to {high:.0%}"


def _rate(outcomes: list[Outcome], label: str, kind: str | None) -> Rate:
    chosen = [o for o in outcomes if o.example.label == label and kind in (None, o.example.kind)]
    return Rate(sum(o.flagged for o in chosen), len(chosen))


def detection(outcomes: list[Outcome], kind: str | None = None) -> Rate:
    return _rate(outcomes, "malicious", kind)


def false_alarms(outcomes: list[Outcome], kind: str | None = None) -> Rate:
    return _rate(outcomes, "benign", kind)


# ------------------------------------------------------------------ the first run, kept as history

# The development set's first run (2026-11-09), before the detector changes it led to. These
# numbers cannot be recomputed (the detectors have changed since), so they are recorded here.
FIRST_RUN = {"detection": Rate(22, 30), "false_alarms": Rate(6, 30),
             "email": (Rate(9, 12), Rate(3, 12)), "login": (Rate(8, 10), Rate(2, 10)),
             "call_transcript": (Rate(5, 8), Rate(1, 8))}
FIRST_RUN_MISSED = ["email-document-share", "email-tax-refund", "email-parcel-customs-fee", "login-distributed-spray",
                    "login-stolen-creds-same-city", "call-digital-arrest", "call-electricity-cutoff",
                    "call-cloned-ceo-voice"]
FIRST_RUN_FALSE_ALARMS = ["email-otp-awareness", "email-bank-statement", "email-phishing-training",
                          "login-forgot-password-after-leave", "login-company-vpn-exit", "call-real-fraud-alert"]

CHANGES = [
    ("Asks for card or bank details", "New finding `SIG-FINANCIAL-DETAILS`.", "email-tax-refund"),
    ("Threatens arrest or legal action", "New finding `SIG-THREAT`.", "call-digital-arrest"),
    ("Asks to keep it secret", "New finding `SIG-SECRECY`.", "call-cloned-ceo-voice"),
    ("Password spraying over many addresses", "New finding `PASSWORD-SPRAY`: failures on 10+ accounts from 3+ "
     "addresses, at least 80% failing, when no single address is already credential stuffing.",
     "login-distributed-spray"),
    ("Police, customs and tax officials", "`SIG-IMPERSONATION` also recognises them, and \"I am ...\".",
     "call-digital-arrest"),
    ("Deadlines in days; power cuts", "`SIG-URGENCY` also recognises \"within 3 days\", \"will be disconnected\", "
     "\"do it fast\".", "email-tax-refund"),
    ("\"Sign in with your password\"", "`SIG-CRED-REQ` also recognises requests to enter or sign in with a password.",
     "email-document-share"),
    ("\"We will never ask for your OTP\"", "A request finding no longer fires on a mention that directly follows "
     "\"never ask for\". Deliberately narrow: a \"never\" anywhere else does not switch it off (tested in "
     "`test_patterns.py`).", "email-bank-statement"),
]


# ------------------------------------------------------------------ the report

def _target(rate: Rate, target: float, at_least: bool) -> str:
    met = rate.value >= target if at_least else rate.value <= target
    return ("met" if met else "**not met**") + f" ({'at least' if at_least else 'at most'} {target:.0%})"


def _summary_rows(name: str, outcomes: list[Outcome]) -> list[str]:
    d, f = detection(outcomes), false_alarms(outcomes)
    return [f"| {name}: attacks caught | {d.shown()} | {_target(d, TARGET_DETECTION, True)} |",
            f"| {name}: false alarms | {f.shown()} | {_target(f, TARGET_FALSE_ALARMS, False)} |"]


def _by_kind(outcomes: list[Outcome]) -> list[str]:
    rows = ["| Kind | Attacks caught | False alarms |", "|---|---|---|"]
    for kind, title in KINDS.items():
        d, f = detection(outcomes, kind), false_alarms(outcomes, kind)
        rows.append(f"| {title} | {d.hits} of {d.total} | {f.hits} of {f.total} |")
    return rows


def _wrong(outcomes: list[Outcome]) -> list[str]:
    rows = ["| Example | Truth | Casewright said | Risk | Findings | About it |", "|---|---|---|---|---|---|"]
    for o in outcomes:
        if not o.correct:
            findings = ", ".join(f"`{f}`" for f in o.findings) or "none"
            rows.append(f"| `{o.example.name}` | {o.example.label} | {o.verdict} | {o.risk} | {findings} | "
                        f"{o.example.note} |")
    return rows if len(rows) > 2 else ["None."]


def _model_section(model_run: dict[str, Any] | None, examples: list[Example]) -> list[str]:
    if model_run is None:
        return ["Not run yet. `scripts\\evaluate.py --model` runs both sets with the local AI model and records the "
                "result in `testdata/evaluation-model-run.json`, which this section is built from."]
    results = model_run["results"]
    lines = [f"Model `{model_run['model']}`, run on {model_run['date']}. The model's answers vary from run to run, so "
             "CI does not repeat this; it is a recorded measurement. The rules still set the minimum: the model can "
             "make a verdict more severe, never less (ADR-43).", "",
             "| Set | Attacks caught | False alarms | Investigations the model finished |", "|---|---|---|---|"]
    for title, chosen in (("Held-out", HELD_OUT), ("Development", DEVELOPMENT)):
        got = [results[e.name] for e in chosen]
        attacks = [r for e, r in zip(chosen, got) if e.label == "malicious"]
        harmless = [r for e, r in zip(chosen, got) if e.label == "benign"]
        d = Rate(sum(r["flagged"] for r in attacks), len(attacks))
        f = Rate(sum(r["flagged"] for r in harmless), len(harmless))
        lines.append(f"| {title} | {d.shown()} | {f.shown()} | {sum(r['engine'] == 'llm' for r in got)} of {len(got)} |")

    led = [results[e.name] for e in examples if results[e.name]["engine"] == "llm"]
    harmless = [results[e.name] for e in examples if e.label == "benign" and results[e.name]["engine"] == "llm"]
    quiet = [r for r in harmless if r["risk"] < 30]   # the evidence alone would have closed these
    raised = [r for r in quiet if r["flagged"]]
    lines += ["",
              f"**In plain words:** where the model led ({len(led)} of {len(examples)} investigations; the rest fell "
              "back to the rule engine after a model failure or time limit), it called "
              f"{sum(r['verdict'] == 'suspicious' for r in led)} \"suspicious\". Of the {len(quiet)} harmless incidents "
              f"whose evidence scored below 30 (benign by the rules), it flagged {len(raised)}: it treats any finding, "
              "even an unknown caller, as a warning sign. Because the model can raise a verdict but never lower it, "
              "it can add catches and false alarms but never turn a catch into a miss. With the model on, the system is safe but noisy: too "
              "many false alarms teach people to ignore them. Calibrating the model's verdicts is future work, and "
              "would need its own held-out measurement."]
    return lines


def report(development: list[Outcome], held_out: list[Outcome], model_run: dict[str, Any] | None) -> str:
    first = FIRST_RUN
    lines = [
        "# Evaluation",
        "",
        "How often Casewright gets it right, measured on labelled incidents (PRD section 8). The method is in "
        "ADR-53 in [`DECISIONS.md`](DECISIONS.md).",
        "",
        "**This file is generated** by `scripts\\evaluate.py` and checked by `agent/tests/test_evaluation.py`: if the "
        "numbers below stop matching what the agent does, CI fails.",
        "",
        "## What is measured",
        "",
        "- **Attacks caught** (detection rate, or recall): of the attacks, how many were sent to a person "
        "(`needs_review`) rather than closed as harmless.",
        "- **False alarms** (false-positive rate): of the harmless incidents, how many were sent to a person anyway.",
        "- Each rate comes with a **95% range** (Wilson score interval). With 20 or 30 examples, one example moves a "
        "rate by 3 to 5 points, so the range shows how sure the number is.",
        "- The rule engine is measured (no AI model), so every run gives the same answer.",
        "",
        "## Results",
        "",
        "| Measure | Result, and 95% range | PRD target |",
        "|---|---|---|",
        *_summary_rows("**Held-out set** (the honest number)", held_out),
        *_summary_rows("Development set, after the fixes", development),
        f"| Development set, first run: attacks caught | {first['detection'].shown()} | "
        f"{_target(first['detection'], TARGET_DETECTION, True)} |",
        f"| Development set, first run: false alarms | {first['false_alarms'].shown()} | "
        f"{_target(first['false_alarms'], TARGET_FALSE_ALARMS, False)} |",
        "",
        f"**In plain words:** on incidents it was not tuned on, the rule engine raised "
        f"{false_alarms(held_out).hits} false alarm(s) in {false_alarms(held_out).total} harmless incidents, but let "
        f"{detection(held_out).total - detection(held_out).hits} of {detection(held_out).total} attacks through. The "
        "ones it misses use no tell-tale words: a calm request with no link, no threat and nothing the threat list "
        "knows. The development set's after-fix numbers are flattering, because the fixes were made by looking at it; "
        "the held-out set was written after the fixes and run once, so it is the number to quote.",
        "",
        "## The sets",
        "",
        f"- **Development set**: {len(DEVELOPMENT)} incidents (`agent/tests/evaluation_set.py`), "
        f"{sum(e.label == 'malicious' for e in DEVELOPMENT)} attacks and {sum(e.label == 'benign' for e in DEVELOPMENT)} "
        "harmless. Written first, run, and used to find gaps.",
        f"- **Held-out set**: {len(HELD_OUT)} incidents (`agent/tests/evaluation_heldout.py`), "
        f"{sum(e.label == 'malicious' for e in HELD_OUT)} attacks and {sum(e.label == 'benign' for e in HELD_OUT)} "
        "harmless. Written after the fixes, with different scams and situations, and run once.",
        "- Every attack follows a pattern from a public source (below). The wording is our own and every name, address "
        "and number is a reserved example one. None is one of the six demo scenarios.",
        "- Both sets include hard cases on purpose, both ways: attacks with no obvious keyword, and harmless messages "
        "that contain one (a real bank alert that mentions an OTP, a security-training email that quotes phishing "
        "phrases, a company VPN in another country).",
        "- Both sets are frozen. A new example is added, never an old one changed.",
        "",
        "### By kind of incident",
        "",
        "Held-out set:",
        "",
        *_by_kind(held_out),
        "",
        "Development set, after the fixes (first run in brackets):",
        "",
        "| Kind | Attacks caught | False alarms |",
        "|---|---|---|",
        *[f"| {title} | {detection(development, kind).hits} of {detection(development, kind).total} "
          f"({first[kind][0].hits}) | {false_alarms(development, kind).hits} of {false_alarms(development, kind).total} "
          f"({first[kind][1].hits}) |" for kind, title in KINDS.items()],
        "",
        "## What the held-out set got wrong",
        "",
        *_wrong(held_out),
        "",
        "## What the development set still gets wrong",
        "",
        "Left as they are on purpose: a fix would only fit these examples, or would weaken a check that catches real "
        "attacks (for example, lowering the weight of \"success after many failures\" would hide the account "
        "takeover in `held-login-local-takeover`).",
        "",
        *_wrong(development),
        "",
        "## What the first run changed",
        "",
        f"The first run missed {len(FIRST_RUN_MISSED)} attacks and raised {len(FIRST_RUN_FALSE_ALARMS)} false alarms. "
        "Each change below is a general rule, written from what the attack does rather than the example's words.",
        "",
        "| Gap | Change | First seen in |",
        "|---|---|---|",
        *[f"| {gap} | {change} | `{seen}` |" for gap, change, seen in CHANGES],
        "",
        "Missed on the first run: " + ", ".join(f"`{n}`" for n in FIRST_RUN_MISSED) + ".",
        "",
        "False alarms on the first run: " + ", ".join(f"`{n}`" for n in FIRST_RUN_FALSE_ALARMS) + ".",
        "",
        "## With the local AI model",
        "",
        *_model_section(model_run, DEVELOPMENT + HELD_OUT),
        "",
        "## Limitations",
        "",
        "- **Small sets.** 50 attacks and 50 harmless incidents in all. The 95% ranges above are wide; a few more misses "
        "or catches would move the numbers noticeably.",
        "- **The same author** wrote the examples and the detectors. Writing the held-out set after the fixes reduces "
        "this, but an independent author, or real reported incidents, would be a stronger test.",
        "- **Synthetic text.** The examples follow published attack patterns, but they are not real messages: real "
        "attacks are messier, longer and in many languages (all of these are in English).",
        "- **A small threat list.** The built-in list knows a handful of example addresses (ADR-40), so most attacks here "
        "are judged on their words and behaviour alone. A real threat-intelligence feed would catch more.",
        "- **One incident at a time.** Each example is investigated on its own; links to other recent incidents "
        "(ADR-42), which would help with campaigns, are not part of this measurement.",
        "- **Only the decision is measured**: flagged or closed. Whether the attack type and the reports are right is "
        "checked by other tests, on the demo scenarios.",
        "",
        "## Sources",
        "",
        "The patterns the attacks follow:",
        "",
        *[f"- `{key}`: [{name}]({url})" for key, (name, url) in SOURCES.items()],
        "",
        "## Run it yourself",
        "",
        "```",
        "agent\\.venv\\Scripts\\python.exe scripts\\evaluate.py",
        "```",
        "",
        "Prints every example's result and rewrites this file. With `--model`, it also runs both sets with the local AI "
        "model (Ollama must be running) and records the result for the section above.",
        "",
    ]
    return "\n".join(lines)
