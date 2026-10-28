"""The investigation. A local AI model chooses the tool calls (step 12); without one, or when
it fails or reaches a limit, a fixed plan per incident kind does (the "rules" engine,
AGENT_DESIGN section 12). Either way the same tools are used through the same guardrail, and
the verdict's risk score is computed by code from the evidence (step 11)."""

from collections import Counter
from collections.abc import Iterator

from app.budget import BUDGET, DailyBudget
from app.case import Case
from app.llm import ChatModel
from app.models import (CompleteEvent, Event, IndicatorItem, IndicatorsEvent, InvestigateRequest, LlmVerdict,
                        ThoughtEvent, VerdictEvent)
from app import reasoning
from app import verdict as decide
from app.tools import ToolBox

KIND_NAMES = reasoning.KIND_NAMES

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


Calls = list[tuple[str, dict[str, str]]]


def standard_checks(case: Case) -> list[tuple[str, Calls]]:
    """The fixed plan: what is checked for every incident of this kind, as (note, calls) groups."""
    incident = case.incident
    if incident.kind == "login":
        groups = [("Looking at the login events together, per source address.", [("correlate_events", {})])]
    else:
        groups = [("Checking the text for known attack language.", [("pattern_match", {"target": "all"})])]

    lookups = _reputation_plan(case)
    if lookups:
        note = f"Checking the reputation of {min(len(lookups), MAX_LOOKUPS)} indicator(s)."
        if len(lookups) > MAX_LOOKUPS:
            note += f" (The first {MAX_LOOKUPS} of {len(lookups)}.)"
        groups.append((note, [("reputation_lookup", {"indicatorType": t, "value": v}) for t, v in lookups[:MAX_LOOKUPS]]))

    groups.append((f"Comparing with what is normal for {incident.subject_identity}.",
                   [("baseline_check", {"identity": incident.subject_identity})]))
    if incident.kind != "login":
        groups.append(("Looking for the same details in other recent incidents.", [("correlate_events", {})]))
    return groups


def already_made(case: Case, tools: ToolBox, tool: str, args: dict[str, str]) -> bool:
    if tools.earlier(tool, args) is not None:
        return True
    if tool == "pattern_match":
        # Scanning every text field one by one is the same as scanning "all".
        scanned = {step.args.get("target") for step in tools.steps if step.tool == "pattern_match"}
        return "all" in scanned or set(case.text_fields()) <= scanned
    return False


def fixed_plan(case: Case, tools: ToolBox) -> Iterator[Event]:
    """The rules engine. Also runs after the AI model: whatever the model did, every standard
    check is made, so a model (or an attacker steering it) cannot lower the score by skipping
    checks. Calls already made are not repeated."""
    for note, calls in standard_checks(case):
        pending = [(tool, args) for tool, args in calls if not already_made(case, tools, tool, args)]
        if pending:
            yield ThoughtEvent(text=note)
        for tool, args in pending:
            yield tools.call(tool, args)


def reported_attack_type(claim: LlmVerdict, band: str, from_evidence: str) -> str:
    """Like the score, the attack type comes from the evidence when the evidence is specific;
    the model's label is used only when it is not."""
    if claim.verdict == "benign" and band == "benign":
        return "none"
    if from_evidence not in ("none", "other"):
        return from_evidence
    return claim.attack_type if claim.attack_type != "none" else "other"


def investigate(request: InvestigateRequest, model: ChatModel | None = None,
                budget: DailyBudget = BUDGET) -> Iterator[Event]:
    """`model` defaults to the configured one (none when LLM_PROVIDER=off)."""
    incident = request.incident
    case = Case.of(incident, request.baseline, request.recent_indicators)
    tools = ToolBox(case)
    # Only values the gateway has already validated, and counts, go into the agent's own
    # words: never the incident's (attacker-written) text, nor the model's.
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

    model = model or reasoning.configured_model()
    claim: LlmVerdict | None = None
    if model is not None:
        if budget.try_start():
            yield ThoughtEvent(text="A local AI model chooses the tools; code checks every call.")
            claim = yield from reasoning.investigate_with_llm(case, tools, model, budget)
        else:
            yield ThoughtEvent(text="Today's limit for the AI model is reached; using the fixed plan.")
    if claim is not None and any(not already_made(case, tools, tool, args)
                                 for _, calls in standard_checks(case) for tool, args in calls):
        yield ThoughtEvent(text="Making the standard checks the model did not make.")
    yield from fixed_plan(case, tools)

    signals = [s for step in tools.steps for s in step.signals]
    score = decide.risk_score(signals)
    band = decide.band(score)
    kinds = len(decide.strongest_per_id(signals))
    yield ThoughtEvent(text=f"Risk {score}/100 from {kinds} kind(s) of finding: {band}.")
    cited = decide.cited_evidence(tools.steps)

    from_evidence = decide.attack_type(incident.kind, signals)
    if claim is None:
        verdict, engine = band, "rules"
        attack = from_evidence if band != "benign" else "none"
    else:
        # The model's own verdict is reported as it is: the gateway compares it with the
        # evidence, raises it if it is lower, and flags a disagreement (ADR-43).
        verdict, engine = claim.verdict, "llm"
        attack = reported_attack_type(claim, band, from_evidence)
        if decide.SEVERITY[verdict] < decide.SEVERITY[band]:
            yield ThoughtEvent(text=f"The model said {verdict}, but the evidence scores {score} ({band}). "
                                    "The verdict cannot go below the evidence; a person will review it.")
        # The evidence behind the score is always cited, whatever the model chose to cite.
        cited = sorted(set(cited) | set(claim.cited_evidence), key=lambda label: int(label[1:]))

    # Built with the JSON (camelCase) names: the models accept only those, for code and callers alike.
    yield VerdictEvent.model_validate({
        "verdict": verdict, "attackType": attack, "riskScore": score,
        "citedEvidence": cited, "counterfactual": decide.counterfactual(signals)})
    # Closed only when both the verdict and the evidence say benign (the gateway decides finally).
    yield CompleteEvent(result="closed" if decide.more_severe(verdict, band) == "benign" else "needs_review",
                        engine=engine)
