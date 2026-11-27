"""The two reports (step 13): built from the evidence chain, consistent with each other,
readable for the employee, and free of anything the attacker wrote."""

import re

import pytest

from app import report
from app.investigation import investigate
from app.models import InvestigateRequest, ReportEvent, StepEvent, VerdictEvent
from tests.scenarios import BASELINES, SCENARIOS


def run(name: str) -> list:
    kind, subject, payload = SCENARIOS[name][0]()
    request = InvestigateRequest.model_validate({
        "incident": {"id": 70, "kind": kind, "subjectIdentity": subject, "payload": payload},
        "baseline": BASELINES[subject]})
    return list(investigate(request, model=None))


def reports(events: list) -> ReportEvent:
    return next(e for e in events if isinstance(e, ReportEvent))


def plain_text(event: ReportEvent) -> str:
    plain = event.plain
    return " ".join([plain.headline, plain.what_happened, *(r.text for r in plain.reasons), *plain.what_to_do])


# ------------------------------------------------------------------ reading level

def syllables(word: str) -> int:
    """A standard rough count: groups of vowels, minus a silent final e."""
    word = word.lower()
    groups = len(re.findall(r"[aeiouy]+", word))
    if word.endswith("e") and not word.endswith(("le", "ee")) and groups > 1:
        groups -= 1
    return max(groups, 1)


def grade_level(text: str) -> float:
    """Flesch-Kincaid grade: roughly the school year needed to read the text easily."""
    sentences = max(len(re.findall(r"[.!?](\s|$)", text)), 1)
    words = re.findall(r"[A-Za-z']+", text)
    return 0.39 * len(words) / sentences + 11.8 * sum(map(syllables, words)) / len(words) - 15.59


def test_the_grade_calculator_matches_known_examples() -> None:
    assert grade_level("The cat sat on the mat.") < 1
    assert grade_level("Notwithstanding considerable organisational complexity, institutional "
                       "accountability necessitates comprehensive documentation.") > 16


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_the_plain_report_reads_at_grade_8_or_below(name: str) -> None:
    text = plain_text(reports(run(name)))

    assert grade_level(text) <= 8, f"{name}: grade {grade_level(text):.1f}: {text}"


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_the_plain_report_has_no_acronyms(name: str) -> None:
    # Words in capitals (IT, MFA, URL...) are jargon for the employee.
    assert not re.findall(r"\b[A-Z]{2,}\b", plain_text(reports(run(name))))


# ------------------------------------------------------------------ built from the evidence

@pytest.mark.parametrize("name", list(SCENARIOS))
def test_every_finding_and_reason_is_a_recorded_signal_in_its_own_words(name: str) -> None:
    events = run(name)
    recorded = {(s.label, signal.id): signal for s in events if isinstance(s, StepEvent) for signal in s.signals}
    event = reports(events)

    for finding in event.soc.findings:
        signal = recorded[(finding.evidence, finding.signal)]
        assert (finding.text, finding.weight, finding.mitre) == (signal.label, signal.weight, signal.mitre)
    for reason in event.plain.reasons:
        assert reason.text == recorded[(reason.evidence, reason.signal)].plain
    assert set(event.soc.techniques) == {f.mitre for f in event.soc.findings if f.mitre}


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_both_reports_describe_the_same_findings(name: str) -> None:
    event = reports(run(name))

    socs = [(f.evidence, f.signal) for f in event.soc.findings if f.weight > 0]
    assert [(r.evidence, r.signal) for r in event.plain.reasons] == socs[:report.MAX_REASONS]


def test_findings_come_strongest_first_and_each_kind_once() -> None:
    event = reports(run("phishing_email"))

    weights = [f.weight for f in event.soc.findings]
    assert weights == sorted(weights, reverse=True)
    assert len({f.signal for f in event.soc.findings}) == len(event.soc.findings)


def test_the_headlines_match_the_verdict() -> None:
    vishing = reports(run("vishing_call"))
    assert vishing.soc.headline.startswith("Malicious: vishing (voice phishing), risk 8")
    assert vishing.plain.headline == "This phone call is a scam."
    assert vishing.plain.what_to_do[1] == "Never read out a code that was sent to your phone."

    stuffing = reports(run("credential_stuffing"))
    assert stuffing.plain.headline == "Someone is trying to break into accounts."


# Step 24 (ADR-65): the advice for a phone scam follows what the caller asked for.

def call(transcript: str) -> ReportEvent:
    request = InvestigateRequest.model_validate({
        "incident": {"id": 71, "kind": "call_transcript", "subjectIdentity": "arjun.mehta",
                     "payload": {"callerNumber": "+15555550142", "transcript": transcript}},
        "baseline": BASELINES["arjun.mehta"]})
    return reports(list(investigate(request, model=None)))


def test_a_caller_who_wants_money_gets_advice_about_money_not_codes() -> None:
    event = call("Caller: This is the bank fraud department. Please release Rs 40,000 to the safe account now.")

    assert event.plain.what_to_do == [
        "Hang up on calls like this, and call back on a number you already know.",
        "Do not send or move money because someone asked on a call.",
        "If you already did what the caller asked, tell the help desk straight away."]
    assert event.soc.next_steps[-1] == "Check whether a payment was made and ask the bank to stop it."
    assert not any("code" in line for line in event.plain.what_to_do + event.soc.next_steps)


def test_each_kind_of_request_gets_its_own_line_in_a_fixed_order() -> None:
    event = reports(run("vishing_call"))  # a code and remote access

    assert event.plain.what_to_do[1:3] == ["Never read out a code that was sent to your phone.",
                                           "Do not install apps or give anyone access to your phone or computer."]
    assert event.soc.next_steps[2:] == ["Check whether a code was shared and reset the account if so.",
                                        "Check the employee's device for remote-access software."]


def test_without_a_known_request_the_advice_stays_general() -> None:
    assert report.vishing_advice([]) == (report.WHAT_TO_DO["vishing"], report.NEXT_STEPS["vishing"])


def test_at_most_three_kinds_are_named_so_the_advice_stays_short() -> None:
    to_do, next_steps = report.vishing_advice(list(report.request_shape.KINDS))

    assert len(to_do) == 5 and len(next_steps) == 5
    assert to_do[1:4] == [report.VISHING_TO_DO[k] for k in ("money", "code", "details")]


def test_the_requests_are_read_from_the_findings_and_the_stranger_record_only() -> None:
    steps = [e for e in run("vishing_call") if isinstance(e, StepEvent)]
    # A made-up kind in a record is ignored; only the known kinds count, in their fixed order.
    baseline = next(s for s in steps if s.tool == "baseline_check")
    tampered = baseline.model_copy(update={"result": {**baseline.result, "callerAsksFor": ["money", "rm -rf", 7]}})

    assert report.asked_kinds([tampered, *(s for s in steps if s is not baseline)]) == ["money", "code", "install"]


@pytest.mark.parametrize("kind", list(report.VISHING_TO_DO))
def test_every_line_of_phone_advice_reads_at_grade_8_or_below(kind: str) -> None:
    to_do, _ = report.vishing_advice([kind])
    assert grade_level(" ".join(to_do)) <= 8, to_do


def test_a_benign_incident_says_so_plainly() -> None:
    event = reports(run("normal_login"))

    assert event.plain.headline == "This sign-in activity looks safe."
    assert event.plain.what_happened == "We checked a group of recent sign-in attempts. We found nothing suspicious."
    assert event.plain.what_to_do[0] == "You do not need to do anything."
    assert event.soc.headline.startswith("Benign: no attack, risk 0/100")


def test_the_reports_follow_the_verdict_after_the_floor() -> None:
    # The same evidence; only what the reports are told to describe changes.
    steps = [e for e in run("phishing_email") if isinstance(e, StepEvent)]

    soc, plain = report.build("email", steps, "malicious", "phishing", 88)

    assert plain.headline == "This email is a scam." and soc.headline.startswith("Malicious: phishing")


def test_the_reports_never_contain_the_attackers_words() -> None:
    event = reports(run("prompt_injection_email"))
    text = event.model_dump_json()

    for phrase in ("NOTE TO AI", "Ignore all previous instructions", "pre-approved", "storage limit"):
        assert phrase not in text


def test_the_same_evidence_always_gives_the_same_reports() -> None:
    assert reports(run("impossible_travel")) == reports(run("impossible_travel"))


def test_the_reports_come_after_the_verdict_and_before_complete() -> None:
    events = run("vishing_call")

    kinds = [type(e).__name__ for e in events][-4:]
    assert kinds == ["VerdictEvent", "ReportEvent", "ActionsEvent", "CompleteEvent"]
    assert reports(events).soc.ai_summary is None   # no AI in this run: no AI line
    assert isinstance(events[-4], VerdictEvent)
