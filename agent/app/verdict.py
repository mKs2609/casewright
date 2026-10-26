"""From evidence to a decision (AGENT_DESIGN sections 6-8, ADR-9): the risk score, the
verdict, the attack type and the "what would change this" sentence. All computed by code,
never taken from an AI.

The gateway recomputes the same score from the evidence it stored (ADR-5), so the two must
agree exactly. Both sides therefore multiply the findings in the same order (sorted by id)
and round the same way (half up: 14.5 becomes 15). Python's round() would give 14, because
it rounds halves to the nearest even number; Java's Math.round gives 15.
"""

import math

from app.case import strongest_per_id
from app.models import Signal, StepEvent

# No single finding is treated as certain proof: the most any one can contribute is 95.
MAX_WEIGHT = 95

SEVERITY = {"benign": 0, "suspicious": 1, "malicious": 2}


def risk_score(signals: list[Signal]) -> int:
    """Noisy-OR: the chance that every finding is a false alarm, turned around.

    risk = 100 x (1 - product of (1 - weight/100)), keeping only the strongest finding of
    each kind. Independent findings compound, and the result never passes 100.
    """
    all_false_alarms = 1.0
    for signal in sorted(strongest_per_id(signals), key=lambda s: s.id):
        all_false_alarms *= 1 - min(signal.weight, MAX_WEIGHT) / 100
    return math.floor(100 * (1 - all_false_alarms) + 0.5)


def band(score: int) -> str:
    """0-29 benign, 30-64 suspicious, 65-100 malicious."""
    return "benign" if score < 30 else "suspicious" if score < 65 else "malicious"


def attack_type(kind: str, signals: list[Signal]) -> str:
    """The kind of attack, from which findings fired. The most specific wins, in this order."""
    ids = {s.id for s in signals}
    if not ids:
        return "none"
    if "CRED-STUFFING" in ids:
        return "credential_stuffing"
    if "BRUTE-FORCE" in ids:
        return "brute_force"
    if "IMPOSSIBLE-TRAVEL" in ids:
        return "impossible_travel"
    if ids & {"SUCCESS-AFTER-FAILURES", "BASELINE-GEO"}:
        return "account_takeover"
    if "SIG-AI-INJECTION" in ids:
        return "prompt_injection"
    if kind == "call_transcript" and ids & {"SIG-OTP-REQ", "SIG-IMPERSONATION", "SIG-REMOTE-TOOL", "REP-MALICIOUS"}:
        return "vishing"
    if kind == "email" and ids & {"LOOKALIKE-DOMAIN", "SIG-CRED-REQ", "REP-MALICIOUS", "REPLY-TO-MISMATCH"}:
        return "phishing"
    return "other"


def counterfactual(signals: list[Signal]) -> str:
    """What would change the verdict: the strongest finding, and the risk without it."""
    kept = sorted(strongest_per_id(signals), key=lambda s: (-s.weight, s.id))
    if not kept:
        return "Nothing suspicious was found. A known-bad detail, a request for credentials or codes, " \
               "or unusual behaviour for this person would have raised the risk."
    top, rest = kept[0], kept[1:]
    without = risk_score(rest)
    label = top.label if len(top.label) <= 200 else top.label[:197] + "..."
    return f"The strongest finding is \"{label}\". Without it the risk would be {without} ({band(without)})."


def cited_evidence(steps: list[StepEvent]) -> list[str]:
    """The evidence items behind the findings that count (the strongest of each kind), in order."""
    best: dict[str, tuple[int, str]] = {}
    for step in steps:
        for signal in step.signals:
            if signal.id not in best or signal.weight > best[signal.id][0]:
                best[signal.id] = (signal.weight, step.label)
    labels = {label for _, label in best.values()}
    return sorted(labels, key=lambda label: int(label[1:]))
