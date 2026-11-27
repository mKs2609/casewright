"""Tool 2: deviations from what is normal for the person, without leaking the baseline itself."""

import json

import pytest

from app.baseline_check import baseline_check, distance_km, within_hours, CITY_COORDS
from app.case import ToolRejected
from app.patterns import pattern_match
from app.request_shape import KINDS, describe
from app.verdict import risk_score
from tests.conftest import make_case
from tests.test_report import grade_level


def login(user: str = "arjun.mehta", when: str = "2026-10-19T05:00:00Z", ok: bool = True, country: str = "IN",
          city: str | None = None, agent: str = "Mozilla/5.0 (Windows NT 10.0)") -> dict[str, object]:
    event: dict[str, object] = {"username": user, "ip": "198.51.100.7", "timestamp": when, "success": ok,
                                "country": country, "userAgent": agent}
    if city:
        event["city"] = city
    return event


def check(events: list[dict[str, object]], identity: str = "arjun.mehta") -> tuple[str, dict, list]:
    return baseline_check(make_case("login", {"events": events}, subject="arjun.mehta"), {"identity": identity})


def ids(signals: list) -> set[str]:
    return {s.id for s in signals}


def test_a_normal_login_raises_nothing() -> None:
    summary, result, signals = check([login()])

    assert signals == []
    assert result["deviations"] == []
    assert "0 deviation" in summary


def test_an_unusual_country_hour_and_device_are_each_noticed() -> None:
    _, _, signals = check([login(when="2026-10-19T23:30:00Z", country="RU", agent="python-requests/2.31")])

    assert ids(signals) == {"BASELINE-GEO", "BASELINE-HOURS", "BASELINE-DEVICE"}


def test_a_successful_foreign_login_counts_more_than_a_failed_one() -> None:
    _, _, failed = check([login(country="RU", ok=False)])
    _, _, succeeded = check([login(country="RU", ok=True)])

    assert failed[0].weight == 10
    assert succeeded[0].weight == 25


def test_impossible_travel_is_detected() -> None:
    _, result, signals = check([
        login(when="2026-10-19T05:00:00Z", city="Mumbai"),
        login(when="2026-10-19T05:12:00+00:00", city="Moscow", country="RU")])

    travel = next(s for s in signals if s.id == "IMPOSSIBLE-TRAVEL")
    assert travel.weight == 40
    assert "Mumbai to Moscow" in travel.label and "12 min" in travel.label


def test_the_same_trip_over_a_day_is_possible() -> None:
    _, _, signals = check([
        login(when="2026-10-19T05:00:00Z", city="Mumbai"),
        login(when="2026-10-20T05:00:00Z", city="Moscow", country="RU")])

    assert "IMPOSSIBLE-TRAVEL" not in ids(signals)


def test_time_zones_are_respected() -> None:
    # 10:30 in India is 05:00 UTC: inside working hours (3 to 15 UTC).
    _, _, signals = check([login(when="2026-10-19T10:30:00+05:30")])

    assert "BASELINE-HOURS" not in ids(signals)


def test_working_hours_can_wrap_past_midnight() -> None:
    assert within_hours(23, 22, 6) and within_hours(3, 22, 6)
    assert not within_hours(12, 22, 6)


def test_distances_are_great_circle_kilometres() -> None:
    assert distance_km(CITY_COORDS["mumbai"], CITY_COORDS["moscow"]) == pytest.approx(5028, abs=30)


def test_the_baseline_itself_never_ends_up_in_the_evidence() -> None:
    # Baselines are encrypted at rest; evidence is not. Only differences may be recorded.
    _, result, signals = check([login(when="2026-10-19T23:30:00Z", country="RU", city="Moscow")])

    recorded = json.dumps(result) + " ".join(s.label + s.plain for s in signals)
    assert "Mumbai" not in recorded            # home city
    assert "Windows NT 10.0" not in recorded   # known device
    assert '"IN"' not in recorded and "IN," not in recorded   # usual countries


def test_an_email_from_a_stranger_with_a_different_reply_to_is_noticed() -> None:
    case = make_case("email", {"sender": "security@paypa1.example", "replyTo": "billing@quick-verify-mail.example",
                               "subject": "", "body": ""})

    _, _, signals = baseline_check(case, {"identity": "priya.sharma"})

    assert ids(signals) == {"BASELINE-NEW-SENDER", "REPLY-TO-MISMATCH"}


def test_a_known_contact_raises_nothing() -> None:
    case = make_case("email", {"sender": "IT-Support@example.com", "subject": "", "body": ""})

    assert baseline_check(case, {"identity": "priya.sharma"})[2] == []


def test_an_unknown_caller_is_noticed_but_a_known_one_is_not() -> None:
    unknown = make_case("call_transcript", {"callerNumber": "+15555550142", "transcript": "hi"}, subject="sara.khan")
    known = make_case("call_transcript", {"callerNumber": "+15555550100", "transcript": "hi"}, subject="sara.khan")

    assert ids(baseline_check(unknown, {"identity": "sara.khan"})[2]) == {"BASELINE-UNKNOWN-CALLER"}
    assert baseline_check(known, {"identity": "sara.khan"})[2] == []


def test_another_account_in_the_batch_has_no_baseline_to_compare() -> None:
    _, _, signals = check([login(), login(user="user01")], identity="user01")

    assert ids(signals) == {"BASELINE-NONE"}


def test_someone_outside_the_incident_cannot_be_checked() -> None:
    with pytest.raises(ToolRejected):
        check([login()], identity="ceo.person")


# Step 23 (ADR-64): a stranger who asks for something is more than the sum of the two findings.

def call_check(transcript: str, number: str = "+15555550142") -> tuple[str, dict, list]:
    case = make_case("call_transcript", {"callerNumber": number, "transcript": transcript}, subject="sara.khan")
    return baseline_check(case, {"identity": "sara.khan"})


@pytest.mark.parametrize("ask", [
    "Caller: Pay Rs 12,000 today or we will post your photos.",
    "Caller: Please send it back to this number now.",
    "Caller: Move the money to our safe account.",
    "Caller: I just need your bank account number to update payroll.",
    "Caller: Read me the six-digit code we sent.",
    "Caller: Install AnyDesk so I can fix it.",
    "Caller: You must pay a registration fee first.",
])
def test_a_stranger_who_asks_for_money_a_code_or_details_is_a_finding_of_its_own(ask: str) -> None:
    _, result, signals = call_check(f"Caller: Hello.\nSara: Yes?\n{ask}")

    assert ids(signals) == {"BASELINE-UNKNOWN-CALLER", "BASELINE-STRANGER-ASKS"}
    assert result["callerAsksFor"]


def test_a_known_caller_asking_the_same_raises_nothing() -> None:
    assert call_check("Caller: Pay Rs 12,000 today.", number="+15555550100")[2] == []


@pytest.mark.parametrize("ordinary", [
    "Caller: Your parcel arrives tomorrow between 10 and 1.\nSara: Thanks.",
    "Caller: Send the invoice to our accounts team and we'll pay by wire transfer next week.",
    "Caller: There's nothing to do on this call. We will never ask for your PIN or OTP.",
])
def test_a_stranger_who_asks_for_nothing_is_only_an_unknown_number(ordinary: str) -> None:
    _, result, signals = call_check(ordinary)

    assert ids(signals) == {"BASELINE-UNKNOWN-CALLER"}
    assert "callerAsksFor" not in result


def test_what_the_person_says_back_is_not_a_request_made_to_them() -> None:
    # Sara's own words would be a request if the caller said them; here they are a question back.
    _, _, signals = call_check("Caller: Your profile is selected.\nSara: Should I pay Rs 1,499 now?\n"
                               "Caller: No, there is no fee. We will email the details.")

    assert ids(signals) == {"BASELINE-UNKNOWN-CALLER"}


def test_a_transcript_without_speaker_names_is_read_whole() -> None:
    assert "BASELINE-STRANGER-ASKS" in ids(call_check("hello madam please pay Rs 9,400 to release the bonus")[2])


def test_the_callers_words_never_reach_the_evidence() -> None:
    # The transcript is attacker-written: only which kinds of request were found is recorded.
    _, result, signals = call_check("Caller: Transfer Rs 4,711 to account 99887766 at Quickpay now.")

    recorded = json.dumps(result) + " ".join(s.label + s.plain for s in signals)
    assert "4,711" not in recorded and "99887766" not in recorded and "Quickpay" not in recorded
    assert result["callerAsksFor"] == ["money"]


# Step 24 (ADR-65): requests recognised by their shape, and findings that say what was asked.

@pytest.mark.parametrize(("ask", "kinds"), [
    ("Caller: Please release Rs 6,50,000 to the account I send you.", ["money"]),
    ("Caller: Just tap approve so I can finish the move.", ["approval"]),
    ("Caller: Download the support app and give me the ID it shows.", ["code", "install"]),
    ("Caller: For verification just read the 16 digits on the front.", ["details"]),
])
def test_a_stranger_asking_in_new_words_is_recognised_by_the_shape(ask: str, kinds: list[str]) -> None:
    _, result, signals = call_check(ask)

    assert result["callerAsksFor"] == kinds
    assert "BASELINE-STRANGER-ASKS" in ids(signals)


def test_the_finding_says_what_was_asked() -> None:
    _, result, signals = call_check("Caller: Just press approve and enter your PIN.")
    found = next(s for s in signals if s.id == "BASELINE-STRANGER-ASKS")

    assert found.label == "A caller sara.khan doesn't know asks them to give private details " \
                          "and approve something on their phone"
    assert found.plain.startswith("Someone you don't know asked you on the phone to give private details "
                                  "and approve something on your phone.")
    assert result["deviations"][-1].endswith("asks them to give private details and approve something on their phone")


def test_a_known_caller_asking_in_new_words_still_raises_nothing() -> None:
    assert call_check("Caller: Just tap approve.", number="+15555550100")[2] == []


def test_the_callers_own_account_and_paying_in_person_are_not_requests() -> None:
    _, result, _ = call_check("Caller: Your share is Rs 850. Just send it to my UPI whenever.\n"
                              "Caller: The recharge desk is downstairs, you can top up Rs 499 at the counter.")
    assert "callerAsksFor" not in result


@pytest.mark.parametrize("kinds", [[k] for k in KINDS] + [list(KINDS)])
def test_every_wording_of_the_finding_explains_itself_plainly(kinds: list[str]) -> None:
    plain = f"Someone you don't know asked you on the phone to {describe(kinds, to_you=True)}. " \
            "Most phone scams work this way."
    assert grade_level(plain) <= 8, plain


@pytest.mark.parametrize("ask", [
    # Each raises exactly one other finding (25), which with the unknown number alone stays at 29.
    "Caller: I am sending you a link to install the helper app.",
    "Caller: I need your bank account number to confirm.",
])
def test_one_request_from_a_stranger_is_enough_for_a_person_to_look(ask: str) -> None:
    case = make_case("call_transcript", {"callerNumber": "+15555550142", "transcript": ask}, subject="sara.khan")
    signals = pattern_match(case, {"target": "all"})[2] + baseline_check(case, {"identity": "sara.khan"})[2]

    assert risk_score(signals) >= 30


def test_the_new_finding_explains_itself_plainly() -> None:
    plain = next(s.plain for s in call_check("Caller: Pay Rs 500 now.")[2] if s.id == "BASELINE-STRANGER-ASKS")
    assert grade_level(plain) <= 8
