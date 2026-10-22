"""The investigation. For now a fixed plan (the "rules" engine): extract the indicators,
then look each one up. Tools 2-4 (step 10), the verdict (step 11) and the AI choosing the
tool calls (step 12) build on this."""

from collections.abc import Iterator

from app.indicators import extract_indicators
from app.models import CompleteEvent, Event, InvestigateRequest, ThoughtEvent
from app.tools import ToolBox

KIND_NAMES = {"email": "an email", "login": "a batch of login events", "call_transcript": "a call transcript"}

# Upper bound on lookups per investigation, whatever the incident contains.
MAX_LOOKUPS = 20


def investigate(request: InvestigateRequest) -> Iterator[Event]:
    incident = request.incident
    # Only values the gateway has already validated, and counts, go into the agent's own
    # words: never the incident's (attacker-written) text.
    yield ThoughtEvent(
        text=f"Received incident {incident.id}: {KIND_NAMES[incident.kind]} about {incident.subject_identity}."
    )
    indicators = extract_indicators(incident)
    yield ThoughtEvent(
        text=f"Found {indicators.count()} indicators: {len(indicators.ip)} IP addresses, "
        f"{len(indicators.domain)} domains, {len(indicators.email)} email addresses, "
        f"{len(indicators.phone)} phone numbers."
    )

    # Phone numbers, then IPs, then domains (an email address's reputation is its domain's).
    plan = [("phone", v) for v in sorted(indicators.phone)] + [("ip", v) for v in sorted(indicators.ip)] \
        + [("domain", v) for v in sorted(indicators.domain)]
    if len(plan) > MAX_LOOKUPS:
        yield ThoughtEvent(text=f"Checking the first {MAX_LOOKUPS} of {len(plan)} indicators.")
    tools = ToolBox(indicators)
    for indicator_type, value in plan[:MAX_LOOKUPS]:
        yield tools.call("reputation_lookup", {"indicatorType": indicator_type, "value": value})

    yield ThoughtEvent(text="The verdict is not built yet, so this incident goes to a human for review.")
    yield CompleteEvent(result="needs_review", engine="rules")
