"""Tool 2: deviations from what is normal for the person, without leaking the baseline itself."""

import json

import pytest

from app.baseline_check import baseline_check, distance_km, within_hours, CITY_COORDS
from app.case import ToolRejected
from tests.conftest import make_case


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
