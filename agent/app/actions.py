"""The response actions the agent proposes (step 15, ADR-47). Worked out by code from the
recorded findings, never by the AI, so text in an incident has no way to suggest an action.

These are only proposals. The gateway checks each one against its own policy, and a person must
approve every high-risk one.
"""

from app.case import Case
from app.models import ProposedAction, Signal, StepEvent
from app.threat_intel import is_internal_address

MAX_ACTIONS = 20

# Findings strong enough to justify proposing that their indicator be blocked.
BLOCK_FINDINGS = {"REP-MALICIOUS", "LOOKALIKE-DOMAIN", "CRED-STUFFING", "BRUTE-FORCE", "SUCCESS-AFTER-FAILURES"}
TAKEOVER_ATTACKS = {"account_takeover", "impossible_travel"}
GUESSING_ATTACKS = {"credential_stuffing", "brute_force"}


def _block_action(case: Case, signal: Signal) -> str | None:
    """Which block suits this finding's indicator, if any."""
    found, value = case.indicators, signal.indicator
    if signal.id not in BLOCK_FINDINGS or value is None:
        return None
    if value in found.ip:
        return None if is_internal_address(value) else "block_ip"
    if value in found.domain:
        return "block_sender_domain"
    if value in found.phone and value == case.incident.payload.get("callerNumber"):
        return "block_phone_number"
    return None


def propose(case: Case, steps: list[StepEvent], final: str, attack: str) -> list[ProposedAction]:
    """`final` is the verdict after the score floor. A benign incident gets no actions."""
    if final == "benign" or not steps:
        return []
    subject = case.incident.subject_identity
    proposed: dict[tuple[str, str], ProposedAction] = {}

    def add(action: str, target: str, evidence: str) -> None:
        proposed.setdefault((action, target), ProposedAction(action=action, target=target, evidence=evidence))

    first_finding = next((s.label for s in steps if any(f.weight > 0 for f in s.signals)), steps[0].label)
    add("monitor", subject, first_finding)
    add("notify_user", subject, first_finding)

    for step in steps:
        for signal in step.signals:
            block = _block_action(case, signal)
            if block:
                add(block, signal.indicator, step.label)   # type: ignore[arg-type]
            if signal.id == "SUCCESS-AFTER-FAILURES" and attack in GUESSING_ATTACKS:
                for accounts in _logged_into(step, signal):
                    if accounts in case.identities:
                        add("lock_account", accounts, step.label)

    if attack in TAKEOVER_ATTACKS:
        add("force_password_reset", subject, first_finding)
    sender = case.incident.payload.get("sender")
    if case.incident.kind == "email" and isinstance(sender, str) and sender in case.indicators.email:
        add("quarantine_email", sender, first_finding)
    return list(proposed.values())[:MAX_ACTIONS]


def _logged_into(step: StepEvent, signal: Signal) -> list[str]:
    source = step.result.get("perSource", {}).get(signal.indicator, {})
    return [a for a in source.get("accountsLoggedInto", []) if isinstance(a, str)]
