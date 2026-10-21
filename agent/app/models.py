"""The shapes of everything the agent receives and sends. Strict: unknown fields are
refused, nothing is silently fixed. JSON field names are camelCase, like the gateway's."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from pydantic.alias_generators import to_camel

Identity = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
ShortText = Annotated[str, StringConstraints(max_length=254)]


class Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",             # an unexpected field is an error, not ignored
        frozen=True,                # values cannot be changed after checking
        alias_generator=to_camel,   # subject_identity in Python is subjectIdentity in JSON
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )


# ---------------------------------------------------------------- what the gateway sends

class Baseline(Strict):
    """What is normal for the employee the incident is about (decrypted by the gateway)."""

    usual_countries: Annotated[list[Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]], Field(max_length=50)]
    workday_start_utc: Annotated[int, Field(ge=0, le=23)]
    workday_end_utc: Annotated[int, Field(ge=0, le=23)]
    known_devices: Annotated[list[ShortText], Field(max_length=50)]
    known_contacts: Annotated[list[ShortText], Field(max_length=200)]
    known_numbers: Annotated[list[ShortText], Field(max_length=50)]
    home_city: Annotated[str, StringConstraints(max_length=64)]


class Incident(Strict):
    id: Annotated[int, Field(gt=0)]
    kind: Literal["email", "login", "call_transcript"]
    subject_identity: Identity
    # Already validated in detail by the gateway; the tools that read it (step 9 on)
    # check the parts they use. Its size is capped by the request size limit.
    payload: dict[str, Any]


class InvestigateRequest(Strict):
    incident: Incident
    baseline: Baseline


# ---------------------------------------------------------------- what the agent sends back
# One JSON object per line ("newline-delimited JSON"), so the gateway can act on each
# event as it arrives. The gateway checks every event again before trusting it (ADR-5).

class ThoughtEvent(Strict):
    """A short note on what the agent is doing, for the live view."""

    type: Literal["agent.thought"] = "agent.thought"
    # No control characters (such as line breaks): this text ends up in the gateway's logs.
    text: Annotated[str, StringConstraints(min_length=1, max_length=500, pattern=r"^[^\x00-\x1f\x7f]*$")]


class CompleteEvent(Strict):
    """The last event of every investigation."""

    type: Literal["investigation.complete"] = "investigation.complete"
    # Until the real investigation exists (steps 9-12), every incident goes to a human.
    result: Literal["needs_review"]
    engine: Literal["stub"]


Event = ThoughtEvent | CompleteEvent
