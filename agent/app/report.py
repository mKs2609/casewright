"""The two reports (step 13, PRD FR-17 to FR-19): one for the security team, one for the
employee, both built by code from the same evidence chain, so they can never contradict
each other or claim something that was not found.

Every finding in the SOC report is a recorded signal in its technical words (`label`);
every reason in the plain report is a recorded signal in its plain words (`plain`). The
gateway checks each one against the evidence it stored. The rest is fixed wording written
here, chosen by the verdict and the attack type. Nothing comes from the incident's text.
"""

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
                "Check whether a code was shared and reset the account if so."],
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
    "vishing": ["Hang up on calls like this. Real staff never ask for codes.",
                "Never read out a code that was sent to your phone.",
                "If you already shared a code, tell the help desk straight away."],
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


def counted_findings(steps: list[StepEvent]) -> list[tuple[str, Signal]]:
    """The findings that count (the strongest of each kind) with their evidence label,
    strongest first; ties by kind, so the order is always the same."""
    best: dict[str, tuple[str, Signal]] = {}
    for step in steps:
        for signal in step.signals:
            if signal.id not in best or signal.weight > best[signal.id][1].weight:
                best[signal.id] = (step.label, signal)
    return sorted(best.values(), key=lambda pair: (-pair[1].weight, pair[1].id))


def build(kind: str, steps: list[StepEvent], final: str, attack: str, score: int,
          ai_summary: str | None = None) -> tuple[SocReport, PlainReport]:
    """Both reports. `final` is the verdict after the score floor (what the gateway will record)."""
    findings = counted_findings(steps)
    shown_attack = attack if final != "benign" else "none"

    soc = SocReport.model_validate({
        "headline": f"{final.capitalize()}: {ATTACK_NAMES[shown_attack]}, risk {score}/100 "
                    f"({decide.band(score)} by the evidence), {len(findings)} kind(s) of finding.",
        "findings": [ReportFinding(evidence=label, signal=s.id, text=s.label, weight=s.weight, mitre=s.mitre)
                     for label, s in findings],
        "techniques": sorted({s.mitre for _, s in findings if s.mitre}),
        "nextSteps": NEXT_STEPS[shown_attack],
        "aiSummary": ai_summary,
    })
    reasons = [ReportReason(evidence=label, signal=s.id, text=s.plain)
               for label, s in findings if s.weight > 0][:MAX_REASONS]
    plain = PlainReport.model_validate({
        "headline": plain_headline(kind, final, shown_attack),
        "whatHappened": WHAT_HAPPENED[kind] + ("" if reasons else " We found nothing suspicious."),
        "reasons": reasons,
        "whatToDo": WHAT_TO_DO[shown_attack],
    })
    return soc, plain
