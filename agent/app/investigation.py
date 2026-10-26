"""The investigation: a fixed plan per incident kind (the "rules" engine, from AGENT_DESIGN
section 12), using the same tools an AI will choose from in step 12, ending in a verdict
computed by code from the evidence (step 11)."""

from collections import Counter
from collections.abc import Iterator

from app.case import Case
from app.models import (CompleteEvent, Event, IndicatorItem, IndicatorsEvent, InvestigateRequest, ThoughtEvent,
                        VerdictEvent)
from app import verdict as decide
from app.tools import ToolBox

KIND_NAMES = {"email": "an email", "login": "a batch of login events", "call_transcript": "a call transcript"}

# Upper bounds on lookups per investigation, whatever the incident contains.
MAX_LOOKUPS = 20
MAX_LOGIN_SOURCES_LOOKED_UP = 5


def _reputation_plan(case: Case) -> list[tuple[str, str]]:
    found = case.indicators
    if case.incident.kind == "login":
        # Only the busiest source addresses: a 500-event batch must not mean 500 lookups.
        attempts = Counter(str(e.get("ip")) for e in case.login_events())
        return [("ip", ip) for ip, _ in attempts.most_common(MAX_LOGIN_SOURCES_LOOKED_UP) if ip in found.ip]
    # Phone numbers, then IPs, then domains (an email address's reputation is its domain's).
    return ([("phone", v) for v in sorted(found.phone)] + [("ip", v) for v in sorted(found.ip)]
            + [("domain", v) for v in sorted(found.domain)])


def investigate(request: InvestigateRequest) -> Iterator[Event]:
    incident = request.incident
    case = Case.of(incident, request.baseline, request.recent_indicators)
    tools = ToolBox(case)
    # Only values the gateway has already validated, and counts, go into the agent's own
    # words: never the incident's (attacker-written) text.
    yield ThoughtEvent(
        text=f"Received incident {incident.id}: {KIND_NAMES[incident.kind]} about {incident.subject_identity}."
    )
    found = case.indicators
    yield ThoughtEvent(
        text=f"Found {found.count()} indicators: {len(found.ip)} IP addresses, {len(found.domain)} domains, "
        f"{len(found.email)} email addresses, {len(found.phone)} phone numbers."
    )
    # Reported to the gateway, which keeps them so later incidents can be compared (step 10b).
    yield IndicatorsEvent(indicators=[IndicatorItem(type=t, value=v) for t, v in found.items()])

    if incident.kind == "login":
        yield ThoughtEvent(text="Looking at the login events together, per source address.")
        yield tools.call("correlate_events", {})
    else:
        yield ThoughtEvent(text="Checking the text for known attack language.")
        yield tools.call("pattern_match", {"target": "all"})

    lookups = _reputation_plan(case)
    if lookups:
        yield ThoughtEvent(text=f"Checking the reputation of {min(len(lookups), MAX_LOOKUPS)} indicator(s).")
        if len(lookups) > MAX_LOOKUPS:
            yield ThoughtEvent(text=f"Checking the first {MAX_LOOKUPS} of {len(lookups)} indicators.")
        for indicator_type, value in lookups[:MAX_LOOKUPS]:
            yield tools.call("reputation_lookup", {"indicatorType": indicator_type, "value": value})

    yield ThoughtEvent(text=f"Comparing with what is normal for {incident.subject_identity}.")
    yield tools.call("baseline_check", {"identity": incident.subject_identity})

    if incident.kind != "login":
        yield ThoughtEvent(text="Looking for the same details in other recent incidents.")
        yield tools.call("correlate_events", {})

    signals = [s for step in tools.steps for s in step.signals]
    score = decide.risk_score(signals)
    verdict = decide.band(score)
    attack = decide.attack_type(incident.kind, signals) if verdict != "benign" else "none"
    kinds = len(decide.strongest_per_id(signals))
    yield ThoughtEvent(text=f"Risk {score}/100 from {kinds} kind(s) of finding: {verdict}.")
    # Built with the JSON (camelCase) names: the models accept only those, for code and callers alike.
    yield VerdictEvent.model_validate({
        "verdict": verdict, "attackType": attack, "riskScore": score,
        "citedEvidence": decide.cited_evidence(tools.steps), "counterfactual": decide.counterfactual(signals)})
    yield CompleteEvent(result="closed" if verdict == "benign" else "needs_review", engine="rules")
