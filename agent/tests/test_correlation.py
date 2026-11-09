"""Tool 4: patterns across a batch of login events, per source address."""

import pytest

from app.case import ToolRejected
from app.correlation import MAX_SIGNALS, MAX_SOURCES_IN_RESULT, correlate_events
from tests.conftest import make_case


def event(user: str, ip: str = "203.0.113.66", minute: int = 0, ok: bool = False, second: int = 0) -> dict[str, object]:
    return {"username": user, "ip": ip, "timestamp": f"2026-10-19T02:{minute:02d}:{second:02d}Z",
            "success": ok, "country": "DE"}


def correlate(events: list[dict[str, object]]) -> tuple[str, dict, list]:
    return correlate_events(make_case("login", {"events": events}, subject="arjun.mehta"), {})


def ids(signals: list) -> set[str]:
    return {s.id for s in signals}


def test_one_address_trying_many_accounts_is_credential_stuffing() -> None:
    _, result, signals = correlate([event(f"user{i:02d}", minute=i) for i in range(10)])

    assert ids(signals) == {"CRED-STUFFING"}
    assert result["perSource"]["203.0.113.66"]["distinctAccounts"] == 10


def test_many_guesses_on_one_account_is_brute_force() -> None:
    _, _, signals = correlate([event("arjun.mehta", minute=i) for i in range(9)])

    assert ids(signals) == {"BRUTE-FORCE"}


def test_a_success_after_many_failures_means_an_account_may_be_taken_over() -> None:
    _, _, signals = correlate([event("arjun.mehta", minute=i) for i in range(6)] + [event("arjun.mehta", minute=7, ok=True)])

    takeover = next(s for s in signals if s.id == "SUCCESS-AFTER-FAILURES")
    assert "arjun.mehta" in takeover.label


def test_attempts_faster_than_a_person_can_type_are_automation() -> None:
    _, _, signals = correlate([event("arjun.mehta", second=i) for i in range(20)])   # 20 in one minute

    assert "AUTOMATION" in ids(signals)


def test_a_spray_spread_over_many_addresses_is_found_together() -> None:
    # 10 addresses, 2 accounts each: no single address looks like stuffing or brute force.
    events = [event(f"user{2 * n + k:02d}", ip=f"198.51.100.{n}", minute=3 * n + k) for n in range(10) for k in range(2)]

    _, _, signals = correlate(events)

    assert ids(signals) == {"PASSWORD-SPRAY"}
    assert next(s for s in signals).label == "Failed sign-ins on 20 accounts from 10 addresses"


def test_a_busy_shared_office_address_is_not_a_spray() -> None:
    # Many people signing in successfully, a couple of typos among them.
    events = [event(f"user{i:02d}", ip=f"192.0.2.{i % 4}", minute=i, ok=i % 6 != 0) for i in range(24)]

    assert "PASSWORD-SPRAY" not in ids(correlate(events)[2])


def test_a_spray_from_one_address_is_reported_once_as_credential_stuffing() -> None:
    _, _, signals = correlate([event(f"user{i:02d}", minute=i) for i in range(12)]
                              + [event(f"other{i}", ip=f"198.51.100.{i}") for i in range(3)])

    assert "CRED-STUFFING" in ids(signals) and "PASSWORD-SPRAY" not in ids(signals)


def test_a_few_ordinary_logins_raise_nothing() -> None:
    _, _, signals = correlate([event("arjun.mehta", ok=True), event("arjun.mehta", minute=30, ok=True)])

    assert signals == []


def test_a_huge_batch_from_many_addresses_still_gives_a_small_answer() -> None:
    # 500 events from 50 addresses, each trying 10 accounts: 50 stuffing findings, bounded to a few.
    events = [event(f"user{i % 10}", ip=f"198.51.100.{i // 10}", second=i % 60) for i in range(500)]

    _, result, signals = correlate(events)

    assert len(result["perSource"]) == MAX_SOURCES_IN_RESULT
    assert result["sourcesAnalysed"] == 50
    assert len(signals) == MAX_SIGNALS
    assert {s.id for s in signals} == {"CRED-STUFFING"}


def test_correlation_takes_no_arguments() -> None:
    with pytest.raises(ToolRejected):
        correlate_events(make_case("login", {"events": []}), {"ip": "203.0.113.66"})
