"""The investigation. For now a fixed plan per incident kind (the "rules" engine, from
AGENT_DESIGN section 12), using the same tools an AI will choose from in step 12. The
verdict (step 11) and related incidents (step 10b) build on this."""

from collections import Counter
from collections.abc import Iterator

from app.case import Case
from app.models import CompleteEvent, Event, InvestigateRequest, ThoughtEvent
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
    case = Case.of(incident, request.baseline)
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

    yield ThoughtEvent(text="The verdict is not built yet, so this incident goes to a human for review.")
    yield CompleteEvent(result="needs_review", engine="rules")
