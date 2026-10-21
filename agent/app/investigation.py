"""The investigation itself. For now a stub: it proves the connection end to end and
sends every incident to a human. The tools (step 9 on) and the LLM (step 12) replace it."""

from collections.abc import Iterator

from app.models import CompleteEvent, Event, InvestigateRequest, ThoughtEvent

KIND_NAMES = {"email": "an email", "login": "a batch of login events", "call_transcript": "a call transcript"}


def investigate(request: InvestigateRequest) -> Iterator[Event]:
    incident = request.incident
    # Only values the gateway has already validated go into the text: never the
    # incident's own (attacker-written) content.
    yield ThoughtEvent(
        text=f"Received incident {incident.id}: {KIND_NAMES[incident.kind]} about {incident.subject_identity}."
    )
    yield ThoughtEvent(text="The investigation tools are not built yet, so this incident goes to a human for review.")
    yield CompleteEvent(result="needs_review", engine="stub")
