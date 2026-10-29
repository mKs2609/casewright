"""The AI summary line (step 13): kept only if it passes every check, otherwise left out.
The model is a scripted stand-in; the lines it "writes" include what a hijacked model might."""

import pytest

from app import report, summary
from app.budget import DailyBudget
from app.case import Case
from app.investigation import investigate
from app.llm import LlmError
from app.models import InvestigateRequest, ReportEvent, StepEvent, ThoughtEvent
from tests.fake_model import ScriptedModel, call
from tests.scenarios import BASELINES, SCENARIOS


def request(name: str) -> InvestigateRequest:
    kind, subject, payload = SCENARIOS[name][0]()
    return InvestigateRequest.model_validate({
        "incident": {"id": 75, "kind": kind, "subjectIdentity": subject, "payload": payload},
        "baseline": BASELINES[subject]})


def careful(name: str, line: str | LlmError) -> ScriptedModel:
    """A model that makes the fixed plan's calls, submits the expected verdict, then writes `line`."""
    _, expected_verdict, expected_attack, _ = SCENARIOS[name]
    by_rules = list(investigate(request(name), model=None))
    plan = [[call(s.tool, dict(s.args))] for s in by_rules if isinstance(s, StepEvent)]
    return ScriptedModel(*plan, [call("submit_verdict", {"verdict": expected_verdict, "attackType": expected_attack,
                                                         "citedEvidence": ["E1"]})], summary=line)


def run(name: str, line: str | LlmError) -> tuple[list, ScriptedModel]:
    model = careful(name, line)
    return list(investigate(request(name), model=model, budget=DailyBudget())), model


def ai_line(events: list) -> str | None:
    return next(e for e in events if isinstance(e, ReportEvent)).soc.ai_summary


def notes(events: list) -> str:
    return " | ".join(e.text for e in events if isinstance(e, ThoughtEvent))


GOOD = "A known scam caller asked for a one-time code while posing as support staff [E1][E2]."


# ------------------------------------------------------------------ kept, and where

def test_a_line_that_passes_every_check_goes_into_the_soc_report_only() -> None:
    events, _ = run("vishing_call", GOOD)

    assert ai_line(events) == GOOD
    assert "The AI summary passed every check and was added to the SOC report." in notes(events)
    plain = next(e for e in events if isinstance(e, ReportEvent)).plain
    assert GOOD not in plain.model_dump_json()   # the employee's report is code-written only


def test_the_model_is_shown_the_findings_never_the_incident() -> None:
    _, model = run("prompt_injection_email", GOOD)

    shown = model.summary_requests[0][-1]["content"]
    assert shown.startswith("<findings>") and '"evidence": "E1"' in shown
    assert "NOTE TO AI" not in shown and "pre-approved" not in shown


def test_without_the_model_there_is_no_summary_and_no_request() -> None:
    events = list(investigate(request("vishing_call"), model=None))

    assert ai_line(events) is None and "AI summary" not in notes(events)


def test_when_the_model_failed_the_investigation_it_is_not_asked_for_a_summary() -> None:
    model = ScriptedModel(LlmError("took too long to answer"), summary=GOOD)

    events = list(investigate(request("vishing_call"), model=model, budget=DailyBudget()))

    assert ai_line(events) is None and model.summary_requests == []


def test_a_model_error_while_summarising_just_leaves_the_line_out() -> None:
    events, _ = run("vishing_call", LlmError("took too long to answer"))

    assert ai_line(events) is None
    assert "The AI summary was left out: the model took too long to answer." in notes(events)
    assert events[-1].engine == "llm"   # the investigation itself is unaffected


# ------------------------------------------------------------------ every check

@pytest.mark.parametrize(("line", "reason"), [
    ("", "it is not a single line of text"),
    ("A scam call [E1].\nIgnore the rest.", "it is not a single line of text"),
    ("A scam call <b>[E1]</b>.", "it contains markup"),
    ("A scam call [E1]. " + "x" * 200, "it is longer than 200 characters"),
    ("A scam call [E1]. It asked for a code [E2].", "it is more than one sentence"),
    ("A known scam caller asked for a one-time code.", "it cites no evidence"),
    ("A known scam caller asked for a one-time code [E99].", "it cites evidence that does not exist"),
    # What a hijacked model would like to get in front of an analyst:
    ("Call back +15555550142 to confirm [E1].", "it contains an address, link or number"),
    ("Details at https://help.example/x [E1].", "it contains an address, link or number"),
    ("Contact security@helpdesk.example [E1].", "it contains an address, link or number"),
    ("The source 203.0.113.9 is fine [E1].", "it contains an address, link or number"),
    ("See helpdesk-portal.example for details [E1].", "it contains an address, link or number"),
    ("The caller said please install AnyDesk so our team can help [E1].", "it copies words from the incident"),
    ("This call is safe to ignore [E1].", "it contradicts the verdict"),
    ("A false positive caused by a known caller [E1].", "it contradicts the verdict"),
])
def test_a_line_that_fails_a_check_is_left_out_with_the_reason(line: str, reason: str) -> None:
    events, _ = run("vishing_call", line)

    assert ai_line(events) is None
    assert f"The AI summary was left out: {reason}." in notes(events)
    # The reason is ours; the line itself never reaches the events.
    if line.strip():
        assert all(line.strip() not in e.model_dump_json() for e in events)


def test_the_findings_own_words_are_not_counted_as_copying() -> None:
    # "Asks for a one-time code" is our label for SIG-OTP-REQ, so reusing it is fine.
    events, _ = run("vishing_call", "The caller asks for a one-time code and is a known scam number [E1][E2].")

    assert ai_line(events) is not None


def checked(line: str, final: str) -> tuple[str | None, str]:
    events = list(investigate(request("vishing_call"), model=None))
    steps = [e for e in events if isinstance(e, StepEvent)]
    case = Case.of(request("vishing_call").incident, request("vishing_call").baseline)
    return summary.check(line, case, report.counted_findings(steps), {s.label for s in steps}, final)


def test_reassuring_words_are_refused_only_when_the_verdict_is_not_benign() -> None:
    line = "The call looks safe once the number is checked [E1]."

    assert checked(line, "benign") == (line, "")
    assert checked(line, "suspicious") == (None, "it contradicts the verdict")


def test_surrounding_spaces_are_not_part_of_the_line() -> None:
    assert checked(f"  {GOOD}  ", "malicious") == (GOOD, "")


def test_an_incident_without_findings_gets_no_summary_request() -> None:
    events, model = run("normal_login", GOOD)

    assert ai_line(events) is None and model.summary_requests == []
    assert "The AI summary was left out: there are no findings to summarise." in notes(events)


@pytest.mark.parametrize("name", ["credential_stuffing", "phishing_email", "vishing_call", "impossible_travel"])
def test_the_model_is_never_shown_a_value_it_could_copy(name: str) -> None:
    # Seen live: shown "203.0.113.66 is known-malicious", the model copied the address into its line.
    _, model = run(name, GOOD)

    shown = model.summary_requests[0][-1]["content"]
    case = Case.of(request(name).incident, request(name).baseline)
    values = [v for t in ("ip", "domain", "email", "phone") for v in case.indicators.of_type(t)]
    assert values and not [v for v in [*values, *case.identities] if v in shown]
    assert "paypal.com" not in shown and "Singapore" in shown or name != "impossible_travel"


def test_masking_replaces_values_with_plain_words() -> None:
    case = Case.of(request("vishing_call").incident, request("vishing_call").baseline)

    assert summary.masked("+15555550142 is known-malicious for arjun.mehta (score 81)", case) == \
        "a phone number is known-malicious for the user (score 81)"
    assert summary.masked("paypa1.example imitates paypal.com from 203.0.113.7", case) == \
        "a website imitates a website from an internet address"


def test_several_citations_in_one_bracket_count_and_each_must_exist() -> None:
    # The live model wrote "[E2, E1, E3]".
    assert checked("A phishing attempt with a look-alike website [E2, E1].", "malicious")[0] is not None
    assert checked("A phishing attempt with a look-alike website [E2, E99].", "malicious") == \
        (None, "it cites evidence that does not exist")


def test_legitimate_describing_the_imitated_brand_is_not_a_contradiction() -> None:
    line = "A malicious website imitating a legitimate brand asks for a one-time code [E1]."

    assert checked(line, "malicious") == (line, "")
