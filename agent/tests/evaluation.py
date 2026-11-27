"""Runs the evaluation sets through the agent, measures the result, and writes the report
(docs/EVALUATION.md) (PRD section 8, ADR-53).

An incident is "flagged" when the investigation ends `needs_review` (a person looks at it) and
"closed" when it ends `closed` (judged harmless, nobody looks). That is the decision that matters
in practice: a missed attack is closed, a false alarm takes someone's time.

- Detection rate (recall): flagged attacks / all attacks. PRD target: at least 90%.
- False-alarm rate (false-positive rate): flagged harmless incidents / all harmless ones. Target: at most 10%.

With 20 or 30 of each, one example is worth 3 to 5 percentage points, so each rate also gets a
95% confidence interval (the Wilson score interval): the range the true rate probably lies in.

The sets (ADR-53, ADR-63): the development set (tests/evaluation_set.py), whose first run showed
the gaps that were then fixed, and held-out sets, each written and committed before a round of
changes and run once after it. Once a set's mistakes are read to make changes it counts as seen;
the newest held-out set (now tests/evaluation_heldout4.py, step 24) gives the honest number.
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
from tests.evaluation_heldout2 import HELD_OUT_2
from tests.evaluation_heldout3 import HELD_OUT_3
from tests.evaluation_heldout4 import HELD_OUT_4
from tests.evaluation_independent import INDEPENDENT
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

# Step 22 (ADR-63), measured on 2026-11-26 with the detectors from before its changes (commit 278413a).
# Recorded because they cannot be recomputed now. The first held-out set's numbers are also its one
# honest run (2026-11-09), from before its misses were read.
BEFORE_STEP_22 = {"development": (Rate(27, 30), Rate(4, 30)), "held_out": (Rate(12, 20), Rate(1, 20)),
                  "held_out_2": (Rate(6, 20), Rate(3, 20)), "independent": (Rate(7, 12), Rate(1, 12))}

# The two harmless incidents that only the step-22 changes flag, and why (found by the fresh sets' one run).
STEP_22_NEW_FALSE_ALARMS = {
    "held2-email-vendor-bank-change-done-right": "`SIG-PAYMENT-CHANGE` reads the subject \"Change of bank details\" "
                                                 "as a request, though the email says to confirm by phone first",
    "ind-email-alumni-evening": "`SIG-ADVANCE-FEE` fires on \"There is no registration fee\": the no/not/never "
                                "guard was added to the bank-change finding but not to this one",
}

STEP_22_CHANGES = [
    ("\"Log in with your company credentials\"", "`SIG-CRED-REQ` also recognises signing in with your credentials "
     "or login details.", "held-email-benefits-enrolment"),
    ("\"I just need your bank account number\"", "`SIG-FINANCIAL-DETAILS` also recognises \"need your ...\".",
     "held-call-hr-bank-details"),
    ("Payment to a crypto wallet", "`SIG-PAYMENT` also recognises a wallet address.", "held-call-investment-advisor"),
    ("Changing where salary or payments go", "New finding `SIG-PAYMENT-CHANGE` (weight 30). Not when \"no\", \"not\" "
     "or \"never\" comes directly before (\"there is no change to our bank details\").", "held-email-payroll-diversion"),
    ("Pay a fee to receive money or a parcel", "New finding `SIG-ADVANCE-FEE` (weight 20): processing, customs, "
     "clearance, release, activation, registration or handling fees and charges.", "held-call-insurance-refund"),
    ("Guaranteed or unrealistic returns", "New finding `SIG-TOO-GOOD` (weight 30).", "held-call-investment-advisor"),
    ("Enable macros or content in a document", "New finding `SIG-ENABLE-CONTENT` (weight 30).",
     "held-email-macro-invoice"),
    ("Install an app from a link the sender gives", "New finding `SIG-APP-LINK` (weight 25).",
     "call-electricity-cutoff"),
    ("Text that speaks to an AI reading the message", "`SIG-AI-INJECTION` also recognises an AI addressed as the "
     "reader (\"AI assistant reading this inbox\", \"when you summarise this\").", "held-email-injection-summarise"),
]


# The step-22 fresh sets' one honest run (2026-11-26), now history: step 23 was designed by
# reading their mistakes (ADR-63).
STEP_22_RESULT = {"held_out_2": (Rate(6, 20), Rate(4, 20)), "independent": (Rate(7, 12), Rate(2, 12))}
STEP_22_SEEN_GAIN = 8   # its extra catches on the development and first held-out sets (same report)

# Step 23 (ADR-64), measured on 2026-11-27 with the detectors from before its changes (main at
# e7766b9), in the same run as the third held-out set's one run after them. Every set, and the
# phone calls alone, as (attacks caught, false alarms).
BEFORE_STEP_23 = {"development": (Rate(29, 30), Rate(4, 30)), "held_out": (Rate(18, 20), Rate(1, 20)),
                  "held_out_2": (Rate(6, 20), Rate(4, 20)), "independent": (Rate(7, 12), Rate(2, 12)),
                  "held_out_3": (Rate(3, 20), Rate(2, 20))}
BEFORE_STEP_23_CALLS = {"development": (Rate(8, 8), Rate(0, 8)), "held_out": (Rate(5, 6), Rate(0, 6)),
                        "held_out_2": (Rate(1, 6), Rate(0, 6)), "independent": (Rate(2, 5), Rate(0, 7)),
                        "held_out_3": (Rate(0, 10), Rate(0, 10))}

STEP_23_CHANGES = [
    ("A request to send or move money", "New finding `SIG-SEND-MONEY` (weight 25): pay, send, transfer, deposit, "
     "move or return money, an amount, a fee or a balance; \"send it back to this number\"; \"the payment goes "
     "there\". Not when the money comes to you (\"we'll pay\", \"I will transfer\"), nor after \"never\", \"not\" "
     "or \"don't\". A bare number is not an amount (\"send the report by 5\").", "held2-call-wrong-transfer"),
    ("A stranger asking for something", "New finding `BASELINE-STRANGER-ASKS` (weight 30), from the baseline check: "
     "the caller's number is unknown to the person and the caller's own lines ask for money, a code, a password, "
     "card or bank details, a payment change, a fee, remote-access software or an app from a link. Either alone "
     "stays low; together they cross the line. Only which kinds of request are recorded, never the caller's words.",
     "held-call-hr-bank-details"),
]

# The third held-out set's one honest run (2026-11-27), now history: step 24 was designed by
# reading its mistakes (ADR-63). Step 23's gain on the sets it was made from, from the same report.
STEP_23_RESULT = (Rate(8, 20), Rate(2, 20))
STEP_23_RESULT_CALLS = (Rate(3, 10), Rate(0, 10))
STEP_23_SEEN = {"attacks": 9, "false_alarms": 0, "calls_before": Rate(16, 25), "calls_after": Rate(24, 25)}

# Step 24 (ADR-65), measured on 2026-11-28 with the detectors from before its changes (commit
# 14b6717, whose agent code is main's), in the same run as the fourth held-out set's one run after
# them. Every set, and the phone calls alone, as (attacks caught, false alarms).
BEFORE_STEP_24 = {"development": (Rate(29, 30), Rate(4, 30)), "held_out": (Rate(19, 20), Rate(1, 20)),
                  "held_out_2": (Rate(10, 20), Rate(4, 20)), "independent": (Rate(11, 12), Rate(2, 12)),
                  "held_out_3": (Rate(8, 20), Rate(2, 20)), "held_out_4": (Rate(4, 20), Rate(3, 20))}
BEFORE_STEP_24_CALLS = {"development": (Rate(8, 8), Rate(0, 8)), "held_out": (Rate(6, 6), Rate(0, 6)),
                        "held_out_2": (Rate(5, 6), Rate(0, 6)), "independent": (Rate(5, 5), Rate(0, 7)),
                        "held_out_3": (Rate(3, 10), Rate(0, 10)), "held_out_4": (Rate(0, 10), Rate(2, 10))}

STEP_24_CHANGES = [
    ("Requests worded in ways no keyword rule knows", "New: a request is recognised by its shape "
     "(`agent/app/request_shape.py`). A clause counts when it starts as an instruction to the listener "
     "(\"Please ...\", \"Just ...\", \"you need to ...\", \"can you ...\") and pairs a request verb with something "
     "valuable: money (an amount, the money itself, or \"it\" sent to someone else's account), a code, private "
     "details (a PIN, card numbers, Aadhaar, date of birth), approving a prompt, or installing an app. Warnings and "
     "promises (\"don't pay any fee\", \"I'll send it\") never start as an instruction, so they do not count; nor "
     "does paying cash or at a counter. It feeds only `BASELINE-STRANGER-ASKS` (a stranger's call), so emails and "
     "the risk formula are unchanged.", "held3-call-card-back-numbers"),
    ("Advice that always talked about codes", "The finding, the employee's \"what to do\" and the analyst's next "
     "steps now name what the caller asked for: money, a code, private details, an approval or an app.",
     "held3-call-ceo-boarding"),
]

# Why each scam call the fourth held-out set still missed got past, and why its harmless calls were
# flagged (read after its one run; nothing was changed because of them).
STEP_24_FRESH_MISSES = {
    "held4-call-fastag-blacklist": "\"put your debit card details there\": \"put\" is not one of the request verbs",
    "held4-call-whatsapp-code": "\"tell me those numbers\": \"numbers\" on its own is not one of the valuable things",
    "held4-call-crypto-recovery": "\"our charge ... has to be cleared before we start\": a demand, but not worded "
                                  "as an instruction",
    "held4-call-money-mule-job": "\"what's the account number?\": a request asked as a question, left out on "
                                 "purpose because no seen call asked that way",
    "held4-call-refund-qr": "\"put your PIN\": \"put\" again",
    "held4-call-traffic-fine": "\"clear it today\" (the fine): \"clear\" is not one of the money verbs",
    "held4-call-it-current-password": "\"what's your current password?\": a question, as above",
    "held4-call-sim-5g-upgrade": "\"send an SMS ... with the word UPGRADE and the 20 digits\": cutting the clause "
                                 "at \"and\" separated the verb from the digits",
}
STEP_24_FRESH_FALSE_ALARMS = {
    "held4-call-school-fees": "the step-23 keyword rule `SIG-SEND-MONEY` reads \"please pay the fee on the school "
                              "portal\" as a request; it was flagged before step 24 too",
    "held4-call-mother-asks-advice": "the caller repeats someone else's request for an OTP while asking for advice; "
                                     "flagged before step 24 too",
}

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


def _rate_rows(name: str, d: Rate, f: Rate) -> list[str]:
    return [f"| {name}: attacks caught | {d.shown()} | {_target(d, TARGET_DETECTION, True)} |",
            f"| {name}: false alarms | {f.shown()} | {_target(f, TARGET_FALSE_ALARMS, False)} |"]


def _counts(examples: list[Example]) -> str:
    return (f"{len(examples)} incidents, {sum(e.label == 'malicious' for e in examples)} attacks and "
            f"{sum(e.label == 'benign' for e in examples)} harmless")


def _sum(rates: list[Rate]) -> Rate:
    return Rate(sum(r.hits for r in rates), sum(r.total for r in rates))


def report(development: list[Outcome], held_out: list[Outcome], held_out_2: list[Outcome],
           independent: list[Outcome], held_out_3: list[Outcome], held_out_4: list[Outcome],
           model_run: dict[str, Any] | None) -> str:
    first, before = FIRST_RUN, BEFORE_STEP_22
    step22 = STEP_22_RESULT
    d_fresh22 = _sum([step22["held_out_2"][0], step22["independent"][0]])
    f_fresh22 = _sum([step22["held_out_2"][1], step22["independent"][1]])
    fresh_before = (Rate(before["held_out_2"][0].hits + before["independent"][0].hits, d_fresh22.total),
                    Rate(before["held_out_2"][1].hits + before["independent"][1].hits, f_fresh22.total))
    fresh = held_out_4
    d_fresh, f_fresh = detection(fresh), false_alarms(fresh)
    b23 = BEFORE_STEP_23
    b24, b24c = BEFORE_STEP_24, BEFORE_STEP_24_CALLS
    seen_sets = {"development": development, "held_out": held_out, "held_out_2": held_out_2,
                 "independent": independent, "held_out_3": held_out_3}
    seen = [o for outcomes in seen_sets.values() for o in outcomes]
    seen_before = _sum([b24[k][0] for k in seen_sets]), _sum([b24[k][1] for k in seen_sets])
    seen_calls_before = _sum([b24c[k][0] for k in seen_sets])
    seen_calls_now = _sum([detection(o, "call_transcript") for o in seen_sets.values()])
    calls_now = detection(fresh, "call_transcript"), false_alarms(fresh, "call_transcript")
    lines = [
        "# Evaluation",
        "",
        "How often Casewright gets it right, measured on labelled incidents (PRD section 8). The method is in "
        "ADR-53 and ADR-63 in [`DECISIONS.md`](DECISIONS.md).",
        "",
        "**This file is generated** by `scripts\\evaluate.py` and checked by `agent/tests/test_evaluation.py`: if the "
        "numbers below stop matching what the agent does, CI fails.",
        "",
        "## What is measured",
        "",
        "- **Attacks caught** (detection rate, or recall): of the attacks, how many were sent to a person "
        "(`needs_review`) rather than closed as harmless.",
        "- **False alarms** (false-positive rate): of the harmless incidents, how many were sent to a person anyway.",
        "- Each rate comes with a **95% range** (Wilson score interval). With 12 to 30 examples, one example moves a "
        "rate by 3 to 8 points, so the range shows how sure the number is.",
        "- The rule engine is measured (no AI model), so every run gives the same answer.",
        "- A set only gives an honest number until someone changes the detectors after reading its mistakes. So each "
        "round of fixes is measured on sets written before the fixes and run once afterwards (ADR-53, ADR-63).",
        "",
        "## Results",
        "",
        "| Measure | Result, and 95% range | PRD target |",
        "|---|---|---|",
        *_rate_rows("**Fourth held-out set** (fresh: the honest number)", d_fresh, f_fresh),
        *_rate_rows("Third held-out set, its one honest run (step 23)", *STEP_23_RESULT),
        *_summary_rows("Third held-out set now", held_out_3),
        *_rate_rows("Second held-out and independent sets, their one honest run (step 22)", d_fresh22, f_fresh22),
        *_summary_rows("Second held-out set now", held_out_2),
        *_summary_rows("Independent set now", independent),
        *_rate_rows("First held-out set, its one honest run (before step 22)", *before["held_out"]),
        *_summary_rows("First held-out set now", held_out),
        *_summary_rows("Development set now", development),
        *_rate_rows("Development set, first run", first["detection"], first["false_alarms"]),
        "",
        f"**In plain words:** on {d_fresh.total} attacks and {f_fresh.total} harmless incidents it was never tuned on, "
        f"the rule engine caught {d_fresh.hits} attacks and raised {f_fresh.hits} false alarms. Step 24 recognises "
        "what a caller asks for by the shape of the request (an instruction, a request verb, something valuable) "
        f"instead of fixed phrases. On the fresh set's calls it caught {calls_now[0].hits} of {calls_now[0].total} "
        f"scams (before: {b24c['held_out_4'][0].hits}) with {calls_now[1].hits} false alarms (before: "
        f"{b24c['held_out_4'][1].hits}). The shapes still rely on lists of verbs and valuable things, and real "
        "callers used words outside them (\"put your PIN\", \"clear it today\", \"tell me those numbers\") or asked "
        "with a question (\"what's your current password?\"). Recognising a request in any wording is still the "
        "open problem.",
        "",
        "### Did step 24 help on incidents it was not made from?",
        "",
        "| Fourth held-out set (run once) | Before step 24 | After step 24 |",
        "|---|---|---|",
        f"| All attacks caught | {b24['held_out_4'][0].hits} of {b24['held_out_4'][0].total} | {d_fresh.hits} of "
        f"{d_fresh.total} |",
        f"| All false alarms | {b24['held_out_4'][1].hits} of {b24['held_out_4'][1].total} | {f_fresh.hits} of "
        f"{f_fresh.total} |",
        f"| Phone calls: scams caught | {b24c['held_out_4'][0].hits} of {b24c['held_out_4'][0].total} | "
        f"{calls_now[0].hits} of {calls_now[0].total} |",
        f"| Phone calls: false alarms | {b24c['held_out_4'][1].hits} of {b24c['held_out_4'][1].total} | "
        f"{calls_now[1].hits} of {calls_now[1].total} |",
        "",
        "A little, with no new false alarms, and far less than on the sets it was designed from. On those seen sets it "
        f"caught {detection(seen).hits - seen_before[0].hits} more attacks (phone calls: {seen_calls_before.hits} of "
        f"{seen_calls_before.total} before, {seen_calls_now.hits} of {seen_calls_now.total} after) and raised "
        f"{false_alarms(seen).hits - seen_before[1].hits} more false alarms. The gap between the two is why the fresh "
        "number is the one quoted.",
        "",
        "Why the fresh scam calls still got past (read after the one run; nothing was changed because of them):",
        "",
        *[f"- `{name}`: {why}." for name, why in STEP_24_FRESH_MISSES.items()],
        "",
        "And why its two harmless calls were flagged:",
        "",
        *[f"- `{name}`: {why}." for name, why in STEP_24_FRESH_FALSE_ALARMS.items()],
        "",
        "### Did step 23 help on incidents it was not made from?",
        "",
        "Step 23 changed how a phone call's evidence adds up (a stranger asking for something is enough for a person "
        "to look) and was measured on the third held-out set, run once (2026-11-27):",
        "",
        "| Third held-out set (run once) | Before step 23 | After step 23 |",
        "|---|---|---|",
        f"| All attacks caught | {b23['held_out_3'][0].hits} of {b23['held_out_3'][0].total} | "
        f"{STEP_23_RESULT[0].hits} of {STEP_23_RESULT[0].total} |",
        f"| All false alarms | {b23['held_out_3'][1].hits} of {b23['held_out_3'][1].total} | "
        f"{STEP_23_RESULT[1].hits} of {STEP_23_RESULT[1].total} |",
        f"| Phone calls: scams caught | {BEFORE_STEP_23_CALLS['held_out_3'][0].hits} of "
        f"{BEFORE_STEP_23_CALLS['held_out_3'][0].total} | {STEP_23_RESULT_CALLS[0].hits} of "
        f"{STEP_23_RESULT_CALLS[0].total} |",
        "",
        f"Yes, with no new false alarms. On the sets it was made from it caught {STEP_23_SEEN['attacks']} more attacks "
        f"(phone calls: {STEP_23_SEEN['calls_before'].hits} of {STEP_23_SEEN['calls_before'].total} before, "
        f"{STEP_23_SEEN['calls_after'].hits} of {STEP_23_SEEN['calls_after'].total} after) and raised "
        f"{STEP_23_SEEN['false_alarms']} more false alarms.",
        "",
        "### Did the step-22 fixes help on incidents they were not made from?",
        "",
        "Step 22 added keyword rules and was measured on the second held-out and independent sets, run once "
        "(2026-11-26):",
        "",
        "| Fresh set (run once) | Detectors before step 22 | After step 22 |",
        "|---|---|---|",
        *[f"| {title}: {what} | {old.hits} of {old.total} | {new.hits} of {new.total} |"
          for title, key in (("Second held-out set", "held_out_2"), ("Independent set", "independent"))
          for what, old, new in (("attacks caught", before[key][0], step22[key][0]),
                                 ("false alarms", before[key][1], step22[key][1]))],
        "",
        f"No: they caught {STEP_22_SEEN_GAIN} more attacks on the sets they were made from, but "
        f"{d_fresh22.hits - fresh_before[0].hits} more on the fresh sets, and added "
        f"{f_fresh22.hits - fresh_before[1].hits} false alarms. They are kept, because each describes a documented "
        "attack, but they were not proven on new data. The new false alarms, still not fixed (a fix made after "
        "reading them would need yet another fresh set to be measured on):",
        "",
        *[f"- `{name}`: {why}." for name, why in STEP_22_NEW_FALSE_ALARMS.items()],
        "",
        "## The sets",
        "",
        f"- **Development set**: {_counts(DEVELOPMENT)} (`agent/tests/evaluation_set.py`). Written first and used "
        "to find gaps (step 18b).",
        f"- **First held-out set**: {_counts(HELD_OUT)} (`agent/tests/evaluation_heldout.py`). Written after the "
        "step-18b fixes and run once. Its mistakes were then read and fixed in step 22, so it is now a development "
        "set too.",
        f"- **Second held-out set**: {_counts(HELD_OUT_2)} (`agent/tests/evaluation_heldout2.py`). Written before "
        "the step-22 fixes, committed and pushed before any of them, and run once after them. Read for step 23, so "
        "now seen.",
        f"- **Independent set**: {_counts(INDEPENDENT)}, emails and calls (`agent/tests/evaluation_independent.py`). "
        "The incidents were chosen by the project owner, who did not write the detectors, and worded with ChatGPT; "
        "nobody working on the detectors saw them until the step-22 fixes were frozen. Copied in with only the "
        "rupee sign, reserved phone numbers and source labels added, then run once. Read for step 23, so now seen.",
        f"- **Third held-out set**: {_counts(HELD_OUT_3)} (`agent/tests/evaluation_heldout3.py`), half of them phone "
        "calls. Written before the step-23 change and run once after it. Read for step 24, so now seen.",
        f"- **Fourth held-out set**: {_counts(HELD_OUT_4)} (`agent/tests/evaluation_heldout4.py`), half of them phone "
        "calls. Written before the step-24 change, committed and pushed before any of it, and run once after it was "
        "frozen. Its author had a rough idea of the change in mind, so it also has scams that do not fit that idea "
        "and harmless calls that do.",
        "- Every attack follows a pattern from a public source (below). Every name, address and number is a reserved "
        "example one. None is one of the six demo scenarios.",
        "- Every set includes hard cases on purpose, both ways: attacks with no obvious keyword, and harmless messages "
        "that contain one (a real bank email with a one-time code, an angry customer threatening legal action, a "
        "company VPN in another country).",
        "- All sets are frozen. A new example is added, never an old one changed.",
        "",
        "### By kind of incident",
        "",
        "Fourth held-out set:",
        "",
        *_by_kind(held_out_4),
        "",
        "Third held-out set now:",
        "",
        *_by_kind(held_out_3),
        "",
        "Second held-out set now:",
        "",
        *_by_kind(held_out_2),
        "",
        "Independent set now (no sign-ins):",
        "",
        *[row for row in _by_kind(independent) if "Sign-in" not in row],
        "",
        "First held-out set now:",
        "",
        *_by_kind(held_out),
        "",
        "Development set now (first run in brackets):",
        "",
        "| Kind | Attacks caught | False alarms |",
        "|---|---|---|",
        *[f"| {title} | {detection(development, kind).hits} of {detection(development, kind).total} "
          f"({first[kind][0].hits}) | {false_alarms(development, kind).hits} of {false_alarms(development, kind).total} "
          f"({first[kind][1].hits}) |" for kind, title in KINDS.items()],
        "",
        "## What the fourth held-out set got wrong",
        "",
        *_wrong(held_out_4),
        "",
        "## What step 24 changed",
        "",
        "Made by looking only at the five seen sets (the development set, the first, second and third held-out sets "
        "and the independent set). Agent only: the risk formula is unchanged, so the gateway, which recomputes every "
        "score, needed no change (ADR-43, ADR-65).",
        "",
        "| Gap | Change | First seen in |",
        "|---|---|---|",
        *[f"| {gap} | {change} | `{seen_in}` |" for gap, change, seen_in in STEP_24_CHANGES],
        "",
        "## What step 23 changed",
        "",
        "Made by looking only at the four sets seen at the time. Agent only (ADR-43, ADR-64).",
        "",
        "| Gap | Change | First seen in |",
        "|---|---|---|",
        *[f"| {gap} | {change} | `{seen_in}` |" for gap, change, seen_in in STEP_23_CHANGES],
        "",
        "## What step 22 changed",
        "",
        "Each change is a general rule, written from what the attack does rather than the example's words, and made "
        "by looking only at the development and first held-out sets.",
        "",
        "| Gap | Change | First seen in |",
        "|---|---|---|",
        *[f"| {gap} | {change} | `{seen_in}` |" for gap, change, seen_in in STEP_22_CHANGES],
        "",
        "## What the seen sets still get wrong",
        "",
        "Left as they are on purpose: a fix would only fit these examples, or would weaken a check that catches real "
        "attacks (for example, lowering the weight of \"success after many failures\" would hide the account "
        "takeover in `held-login-local-takeover`).",
        "",
        "Third held-out set:",
        "",
        *_wrong(held_out_3),
        "",
        "Second held-out set:",
        "",
        *_wrong(held_out_2),
        "",
        "Independent set:",
        "",
        *_wrong(independent),
        "",
        "First held-out set:",
        "",
        *_wrong(held_out),
        "",
        "Development set:",
        "",
        *_wrong(development),
        "",
        "## What the first run changed (step 18b)",
        "",
        f"The development set's first run missed {len(FIRST_RUN_MISSED)} attacks and raised "
        f"{len(FIRST_RUN_FALSE_ALARMS)} false alarms. Each change below is a general rule, written from what the "
        "attack does rather than the example's words.",
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
        "This recorded run covers the development and first held-out sets only, and predates steps 22 to 24; the "
        "later sets have not been run with the model.",
        "",
        "## Limitations",
        "",
        f"- **Small sets.** {sum(o.example.label == 'malicious' for o in seen + fresh)} attacks and "
        f"{sum(o.example.label == 'benign' for o in seen + fresh)} harmless incidents in all, and "
        f"only {d_fresh.total} of each in the fresh set. The 95% ranges above are wide; a few more misses or "
        "catches would move the numbers noticeably.",
        "- **The same author** wrote the detectors, the development set and all four held-out sets. Writing each "
        "held-out set before the fixes it measures reduces this; the independent set removes it for 24 incidents, but its "
        "wording was written by an AI model, which tends to state warning signs more plainly than real attackers do.",
        "- **Synthetic text.** The examples follow published attack patterns, but they are not real messages: real "
        "attacks are messier, longer and in many languages (all of these are in English). Public collections of real "
        "phishing exist, but none fits all three kinds of incident, and their messages cannot be published with the "
        "project; measuring on one is future work.",
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
        "Prints every example's result and rewrites this file. With `--model`, it also runs the development and first "
        "held-out sets with the local AI model (Ollama must be running) and records the result for the section above.",
        "",
    ]
    return "\n".join(lines)
