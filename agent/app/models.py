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


IndicatorType = Literal["ip", "domain", "email", "phone"]


class RecentIndicator(Strict):
    """An indicator seen in other recent incidents (values and incident numbers only, not who they were about)."""

    type: IndicatorType
    value: ShortText
    incident_ids: Annotated[list[Annotated[int, Field(gt=0)]], Field(min_length=1, max_length=20)]


class InvestigateRequest(Strict):
    incident: Incident
    baseline: Baseline
    # From the gateway, which keeps the history (ADR-3): indicators of incidents from the
    # last few days, so correlation can spot the same attacker in several reports.
    recent_indicators: Annotated[list[RecentIndicator], Field(max_length=1000)] = []


# ---------------------------------------------------------------- what the agent sends back
# One JSON object per line ("newline-delimited JSON"), so the gateway can act on each
# event as it arrives. The gateway checks every event again before trusting it (ADR-5).

class ThoughtEvent(Strict):
    """A short note on what the agent is doing, for the live view."""

    type: Literal["agent.thought"] = "agent.thought"
    # No control characters (such as line breaks): this text ends up in the gateway's logs.
    text: Annotated[str, StringConstraints(min_length=1, max_length=500, pattern=r"^[^\x00-\x1f\x7f]*$")]


Printable = Annotated[str, StringConstraints(min_length=1, max_length=500, pattern=r"^[^\x00-\x1f\x7f]*$")]
ShortPrintable = Annotated[str, StringConstraints(min_length=1, max_length=300, pattern=r"^[^\x00-\x1f\x7f]*$")]


class Signal(Strict):
    """One finding. The same finding in two voices: `label` for the security team,
    `plain` for everyone else. Both reports are later built from these."""

    id: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9-]{1,39}$")]
    label: ShortPrintable
    plain: ShortPrintable
    weight: Annotated[int, Field(ge=0, le=100)]   # how strongly it points to an attack (risk score, step 11)
    mitre: Annotated[str, StringConstraints(pattern=r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")] | None = None
    indicator: ShortText | None = None


ToolArgs = Annotated[dict[Annotated[str, StringConstraints(pattern=r"^[a-zA-Z]{1,40}$")], ShortText], Field(max_length=4)]


class StepEvent(Strict):
    """An accepted tool call: one evidence item, labelled E1, E2, ..."""

    type: Literal["agent.step"] = "agent.step"
    label: Annotated[str, StringConstraints(pattern=r"^E[1-9][0-9]{0,2}$")]
    tool: Literal["reputation_lookup", "baseline_check", "pattern_match", "correlate_events"]
    args: ToolArgs
    summary: Printable
    result: dict[str, Any]
    signals: Annotated[list[Signal], Field(max_length=20)]


class GuardrailEvent(Strict):
    """A tool call that was refused, labelled R1, R2, ..., with the reason."""

    type: Literal["agent.guardrail"] = "agent.guardrail"
    label: Annotated[str, StringConstraints(pattern=r"^R[1-9][0-9]{0,2}$")]
    tool: Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,40}$")]
    args: ToolArgs
    reason: Printable


Verdict = Literal["benign", "suspicious", "malicious"]
AttackType = Literal["none", "phishing", "credential_stuffing", "brute_force", "account_takeover",
                     "impossible_travel", "vishing", "prompt_injection", "bec", "other"]


class VerdictEvent(Strict):
    """The decision, computed by code from the evidence (ADR-9). The gateway recomputes the
    score from the evidence it stored and never lets a verdict fall below it."""

    type: Literal["verdict"] = "verdict"
    verdict: Verdict
    attack_type: AttackType
    risk_score: Annotated[int, Field(ge=0, le=100)]
    cited_evidence: Annotated[list[Annotated[str, StringConstraints(pattern=r"^E[1-9][0-9]{0,2}$")]],
                              Field(max_length=30)]
    counterfactual: Printable


class CompleteEvent(Strict):
    """The last event of every investigation."""

    type: Literal["investigation.complete"] = "investigation.complete"
    # Benign incidents are closed; anything else goes to a human (the gateway decides finally).
    result: Literal["needs_review", "closed"]
    # "rules": a fixed plan chose the tool calls (an AI chooses them from step 12).
    engine: Literal["rules"]


class IndicatorItem(Strict):
    type: IndicatorType
    value: ShortText


class IndicatorsEvent(Strict):
    """The indicators found in this incident, for the gateway to keep (step 10b): later
    incidents are compared against them."""

    type: Literal["incident.indicators"] = "incident.indicators"
    indicators: Annotated[list[IndicatorItem], Field(max_length=200)]


Event = ThoughtEvent | IndicatorsEvent | StepEvent | GuardrailEvent | VerdictEvent | CompleteEvent
