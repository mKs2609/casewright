"""The investigation tools (the allow-list) and the guardrails around them.

Every tool call goes through `ToolBox.call`, which:
- refuses unknown tools and arguments that are not part of this incident;
- numbers accepted calls E1, E2, ... (evidence) and refused ones R1, R2, ... (with the reason).

All tools are read-only: they look things up, they never change anything.
"""

from pydantic import ValidationError

from app import threat_intel
from app.baseline_check import baseline_check
from app.case import Case, ToolRejected, ToolResult, short
from app.correlation import correlate_events
from app.indicators import registrable
from app.models import GuardrailEvent, Signal, StepEvent
from app.patterns import pattern_match

INDICATOR_TYPES = ("ip", "domain", "email", "phone")

# The plain-language findings, worded for each kind of indicator (they become the report
# that non-experts read, so "this address" must not describe a phone number).
PLAIN_KNOWN_BAD = {
    "ip": "This internet address is on lists of known attackers.",
    "domain": "This website is on lists of known attackers.",
    "email": "This email address comes from a website on lists of known attackers.",
    "phone": "This phone number has been reported for scam calls.",
}
PLAIN_POOR = {
    "ip": "This internet address has been linked to shady activity before.",
    "domain": "This website has been linked to shady activity before.",
    "email": "This email address comes from a website linked to shady activity before.",
    "phone": "This phone number has been linked to shady activity before.",
}


def lookalike_of(domain: str) -> str | None:
    """The real brand domain this one imitates, if any.

    Only the part before the top-level domain is compared ("paypa1-secure-login" in
    paypa1-secure-login.example), with look-alike characters swapped back (1 -> l, 0 -> o, ...).
    The brand's own domain and its subdomains (mail.paypal.com) are not look-alikes.
    """
    name = domain.lower().rsplit(".", 1)[0]
    normalised = name.translate(threat_intel.LOOKALIKE_SWAPS).replace("rn", "m").replace("-", "").replace(".", "")
    for brand, real in threat_intel.BRANDS.items():
        if brand in normalised and registrable(domain) != real:
            return real
    return None


def reputation_lookup(case: Case, args: dict[str, str]) -> ToolResult:
    indicators = case.indicators
    indicator_type = args.get("indicatorType")
    value = args.get("value", "")
    if indicator_type not in INDICATOR_TYPES:
        raise ToolRejected("indicatorType must be one of ip, domain, email, phone")
    if value not in indicators.of_type(indicator_type):
        raise ToolRejected(f"This {indicator_type} does not appear in the incident; "
                           "lookups are limited to indicators extracted from it")

    record = threat_intel.REPUTATION[indicator_type].get(value)
    if record is None and indicator_type == "domain":
        record = threat_intel.REPUTATION["domain"].get(registrable(value))
    if record is None and indicator_type == "email":
        record = threat_intel.REPUTATION["domain"].get(registrable(value.split("@", 1)[1]))
    # An address on the list wins; otherwise an internal one (e.g. 10.x, 192.168.x) is noted as such.
    if record is None and indicator_type == "ip" and threat_intel.is_internal_address(value):
        record = {"score": None, "tags": ["private-address"]}

    signals: list[Signal] = []
    if record is None:
        record = {"score": None, "tags": ["no-intel"]}
        if indicator_type in ("domain", "email"):
            signals.append(Signal(id="REP-UNKNOWN", label=f"No reputation history for {short(value)}",
                                  plain="This web address has no track record, so nobody can vouch for it.",
                                  weight=8, indicator=value))
    elif record["score"] is not None and record["score"] >= 80:
        signals.append(Signal(id="REP-MALICIOUS",
                              label=f"{short(value)} is known-malicious (score {record['score']}: {', '.join(record['tags'])})",
                              plain=PLAIN_KNOWN_BAD[indicator_type],
                              weight=45, mitre="T1583", indicator=value))
    elif record["score"] is not None and record["score"] >= 50:
        signals.append(Signal(id="REP-SUSPICIOUS",
                              label=f"{short(value)} has a poor reputation (score {record['score']}: {', '.join(record['tags'])})",
                              plain=PLAIN_POOR[indicator_type],
                              weight=20, indicator=value))

    if indicator_type in ("domain", "email"):
        domain = value.split("@")[-1]
        real = lookalike_of(domain)
        if real:
            signals.append(Signal(id="LOOKALIKE-DOMAIN", label=f"{short(domain)} imitates {real}",
                                  plain=f"The address is made to look like {real}, but it isn't.",
                                  weight=35, mitre="T1583.001", indicator=domain))
        age = record.get("ageDays")
        if isinstance(age, int) and age < 30:
            signals.append(Signal(id="NEW-DOMAIN", label=f"{short(domain)} was registered {age} days ago",
                                  plain="The website was created only days ago, a common sign of a scam.",
                                  weight=15, indicator=domain))

    score = "unknown" if record["score"] is None else record["score"]
    summary = f"{indicator_type} {short(value, 200)}: score={score} tags={','.join(record['tags'])}"
    return summary, {"indicator": value, "type": indicator_type, **record}, signals


TOOLS = {
    "reputation_lookup": reputation_lookup,
    "baseline_check": baseline_check,
    "pattern_match": pattern_match,
    "correlate_events": correlate_events,
}


class ToolBox:
    """The tools for one investigation, limited to that incident (its indicators, people and text)."""

    def __init__(self, case: Case) -> None:
        self.case = case
        self.accepted = 0
        self.rejected = 0

    def call(self, tool: str, args: dict[str, str]) -> StepEvent | GuardrailEvent:
        try:
            if tool not in TOOLS:
                raise ToolRejected("This tool is not on the allow-list")
            summary, result, signals = TOOLS[tool](self.case, args)
        except ToolRejected as refusal:
            self.rejected += 1
            label, name = f"R{self.rejected}", _safe_tool_name(tool)
            try:
                return GuardrailEvent(label=label, tool=name, args=args, reason=str(refusal))
            except ValidationError:
                # Arguments too odd to even record (e.g. huge or strangely named): keep the refusal, drop them.
                return GuardrailEvent(label=label, tool=name, args={}, reason=f"{refusal} (arguments not recordable)")
        self.accepted += 1
        return StepEvent(label=f"E{self.accepted}", tool=tool, args=args, summary=summary, result=result,
                         signals=signals)


def _safe_tool_name(tool: str) -> str:
    """Tool names asked for are recorded; anything that is not a plain name is replaced."""
    return tool if tool.isascii() and tool.replace("_", "").isalpha() and tool.islower() and len(tool) <= 40 else "unknown"
