"""The two reports (step 13, PRD FR-17 to FR-19): one for the security team, one for the
employee, both built by code from the same evidence chain, so they can never contradict
each other or claim something that was not found.

Every finding in the SOC report is a recorded signal in its technical words (`label`);
every reason in the plain report is a recorded signal in its plain words (`plain`). The
gateway checks each one against the evidence it stored. The rest is fixed wording written
here, chosen by the verdict and the attack type. Nothing comes from the incident's text.
"""

from app import patterns, request_shape
from app import verdict as decide
from app.models import PlainReport, ReportFinding, ReportReason, SocReport, Signal, StepEvent

MAX_REASONS = 5

ATTACK_NAMES = {
    "none": "no attack", "phishing": "phishing", "credential_stuffing": "credential stuffing",
    "brute_force": "brute force", "account_takeover": "account takeover", "impossible_travel": "impossible travel",
    "vishing": "vishing (voice phishing)", "prompt_injection": "prompt injection", "bec": "business email compromise",
    "other": "unclassified attack",
}

# What the incident is, for the employee.
THINGS = {"email": "email", "call_transcript": "phone call", "login": "sign-in activity"}
WHAT_HAPPENED = {
    "email": "We checked an email that was reported as suspicious.",
    "call_transcript": "We checked a phone call that was reported as suspicious.",
    "login": "We checked a group of recent sign-in attempts.",
}

# Next steps for the analyst. Actions themselves (and their approval) come in step 15.
NEXT_STEPS = {
    "phishing": ["Quarantine the message and look for other recipients.",
                 "Block the sending domain if the evidence supports it.",
                 "Reset the password of anyone who entered it."],
    "bec": ["Confirm any payment or data request through a known channel.",
            "Quarantine the message and look for other recipients."],
    "prompt_injection": ["Quarantine the message; it targets automated analysis.",
                         "Check other recent messages from the same sender.",
                         "Block the sending domain if the evidence supports it."],
    "vishing": ["Block the caller number if the evidence supports it.",
                "Warn staff about this caller and script.",
                "Check whether anything was shared or paid."],
    "credential_stuffing": ["Block the source addresses if the evidence supports it.",
                            "Force a password reset for any account that was accessed.",
                            "Check for other targeted accounts."],
    "brute_force": ["Block the source address if the evidence supports it.",
                    "Check whether the targeted account was accessed."],
    "impossible_travel": ["Confirm the sign-ins with the employee.",
                          "Force a password reset and end active sessions if not confirmed."],
    "account_takeover": ["Confirm the activity with the employee.",
                         "Force a password reset and end active sessions if not confirmed."],
    "other": ["Review the evidence and decide whether action is needed."],
    "none": ["No action needed; the incident is closed."],
}

# For the employee: short, no jargon, no acronyms.
WHAT_TO_DO = {
    "phishing": ["Do not click links or open attachments in this email.",
                 "Do not reply, and never type your password into a page it leads to.",
                 "If you already did, tell the help desk straight away."],
    "bec": ["Do not send money or data because of this email.",
            "Check the request with the person by phone, using a number you already know.",
            "Tell the help desk if you already replied."],
    "prompt_injection": ["Do not click links or open attachments in this email.",
                         "Do not reply, and never type your password into a page it leads to.",
                         "If you already did, tell the help desk straight away."],
    "vishing": ["Hang up on calls like this, and call back on a number you already know.",
                "Real banks and staff never ask for money, codes or passwords on a call.",
                "If you already did what the caller asked, tell the help desk straight away."],
    "credential_stuffing": ["You do not need to do anything unless the help desk contacts you.",
                            "Use a password that you do not use for anything else."],
    "brute_force": ["You do not need to do anything unless the help desk contacts you.",
                    "Use a long password that you do not use for anything else."],
    "impossible_travel": ["If this was not you, change your password now.",
                          "Tell the help desk if you did not sign in from somewhere new."],
    "account_takeover": ["If this was not you, change your password now.",
                         "Tell the help desk if you did not sign in from somewhere new."],
    "other": ["Do not act on this until the help desk has looked at it.",
              "Tell the help desk if anything else seems strange."],
    "none": ["You do not need to do anything.",
             "If something still seems wrong, tell the help desk."],
}


# For a phone scam, the advice follows what the caller asked for (ADR-65), not always codes:
# the middle line of WHAT_TO_DO["vishing"] and the last of NEXT_STEPS["vishing"] are replaced
# by one line for each kind of request found.
VISHING_TO_DO = {
    "money": "Do not send or move money because someone asked on a call.",
    "code": "Never read out a code that was sent to your phone.",
    "details": "Never give card numbers, PINs, passwords or ID numbers on a call.",
    "approval": "Never approve a prompt on your phone that you did not start.",
    "install": "Do not install apps or give anyone access to your phone or computer.",
}
VISHING_NEXT = {
    "money": "Check whether a payment was made and ask the bank to stop it.",
    "code": "Check whether a code was shared and reset the account if so.",
    "details": "Check whether card or account details were given and have them blocked.",
    "approval": "Check for sign-ins approved from the employee's phone and end those sessions.",
    "install": "Check the employee's device for remote-access software.",
}
MAX_ASKED = 3


def asked_kinds(steps: list[StepEvent]) -> list[str]:
    """What the other side asked for: from the request findings, and from the baseline check's
    record of a stranger's requests. Only known kinds, in a fixed order."""
    kinds: set[str] = set()
    for step in steps:
        kinds |= {patterns.ASKS[s.id] for s in step.signals if s.id in patterns.ASKS}
        if step.tool == "baseline_check":
            recorded = step.result.get("callerAsksFor", [])
            kinds |= {k for k in recorded if isinstance(k, str)} if isinstance(recorded, list) else set()
    return [k for k in request_shape.KINDS if k in kinds]


def vishing_advice(kinds: list[str]) -> tuple[list[str], list[str]]:
    """What the employee should do, and the analyst's next steps, for the requests made."""
    if not kinds:
        return WHAT_TO_DO["vishing"], NEXT_STEPS["vishing"]
    kinds = kinds[:MAX_ASKED]
    first, _general, last = WHAT_TO_DO["vishing"]
    to_do = [first, *(VISHING_TO_DO[k] for k in kinds), last]
    return to_do, NEXT_STEPS["vishing"][:2] + [VISHING_NEXT[k] for k in kinds]


def plain_headline(kind: str, final: str, attack: str) -> str:
    thing = THINGS[kind]
    if final == "benign":
        return f"This {thing} looks safe."
    if attack in ("credential_stuffing", "brute_force"):
        return "Someone is trying to break into accounts." if final == "malicious" else \
            "These sign-in attempts look suspicious."
    if attack in ("impossible_travel", "account_takeover"):
        return "Someone else may be using this account." if final == "malicious" else \
            "This sign-in activity looks unusual."
    return f"This {thing} is a scam." if final == "malicious" else f"This {thing} looks suspicious."


def build(kind: str, steps: list[StepEvent], final: str, attack: str, score: int,
          ai_summary: str | None = None) -> tuple[SocReport, PlainReport]:
    """Both reports. `final` is the verdict after the score floor (what the gateway will record)."""
    findings = decide.counted_findings(steps)
    shown_attack = attack if final != "benign" else "none"
    next_steps, what_to_do = NEXT_STEPS[shown_attack], WHAT_TO_DO[shown_attack]
    if shown_attack == "vishing":
        what_to_do, next_steps = vishing_advice(asked_kinds(steps))

    soc = SocReport.model_validate({
        "headline": f"{final.capitalize()}: {ATTACK_NAMES[shown_attack]}, risk {score}/100 "
                    f"({decide.band(score)} by the evidence), {len(findings)} kind(s) of finding.",
        "findings": [ReportFinding(evidence=label, signal=s.id, text=s.label, weight=s.weight, mitre=s.mitre)
                     for label, s in findings],
        "techniques": sorted({s.mitre for _, s in findings if s.mitre}),
        "nextSteps": next_steps,
        "aiSummary": ai_summary,
    })
    reasons = [ReportReason(evidence=label, signal=s.id, text=s.plain)
               for label, s in findings if s.weight > 0][:MAX_REASONS]
    plain = PlainReport.model_validate({
        "headline": plain_headline(kind, final, shown_attack),
        "whatHappened": WHAT_HAPPENED[kind] + ("" if reasons else " We found nothing suspicious."),
        "reasons": reasons,
        "whatToDo": what_to_do,
    })
    return soc, plain
