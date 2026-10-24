"""Related incidents (step 10b): the same attacker details in other recent reports."""

from app.correlation import MAX_RELATED_IN_RESULT, correlate_events, related_incidents
from app.models import RecentIndicator
from tests.conftest import make_case


def recent(indicator_type: str, value: str, *ids: int) -> RecentIndicator:
    return RecentIndicator.model_validate({"type": indicator_type, "value": value, "incidentIds": list(ids)})


def email_case(body: str, sender: str = "security@paypa1-secure-login.example", recent_seen: list | None = None):
    case = make_case("email", {"sender": sender, "subject": "Hi", "body": body})
    return type(case)(case.incident, case.baseline, case.indicators, recent_seen or [])


def test_a_shared_phishing_domain_links_incidents() -> None:
    case = email_case("hello", recent_seen=[recent("domain", "paypa1-secure-login.example", 6, 7)])

    _, result, signals = correlate_events(case, {})

    assert related_incidents(case) == {6: ["paypa1-secure-login.example"], 7: ["paypa1-secure-login.example"]}
    assert signals[0].id == "RELATED-INCIDENTS"
    assert signals[0].weight == 15            # two other incidents: a stronger sign of a campaign
    assert "7, 6" in signals[0].label


def test_one_related_incident_counts_less_than_several() -> None:
    case = email_case("hello", recent_seen=[recent("domain", "paypa1-secure-login.example", 6)])

    assert correlate_events(case, {})[2][0].weight == 10


def test_known_good_and_internal_details_never_link_incidents() -> None:
    # The company's own domain, a real brand, and the internal helpdesk appear in harmless mail all the time.
    case = email_case("Contact it-support@example.com or see https://paypal.com/help",
                      sender="newsletter@example.com",
                      recent_seen=[recent("domain", "example.com", 6), recent("email", "it-support@example.com", 6),
                                   recent("domain", "paypal.com", 7)])

    assert related_incidents(case) == {}
    assert correlate_events(case, {})[2] == []


def test_an_internal_address_never_links_incidents_but_an_attackers_does() -> None:
    events = [{"username": "arjun.mehta", "ip": ip, "timestamp": "2026-10-19T02:00:00Z", "success": True,
               "country": "IN"} for ip in ("10.1.2.3", "203.0.113.77")]
    base = make_case("login", {"events": events}, subject="arjun.mehta")
    case = type(base)(base.incident, base.baseline, base.indicators,
                      [recent("ip", "10.1.2.3", 4), recent("ip", "203.0.113.77", 6)])

    assert related_incidents(case) == {6: ["203.0.113.77"]}


def test_the_incident_itself_is_never_counted_as_related() -> None:
    case = email_case("hello", recent_seen=[recent("domain", "paypa1-secure-login.example", 1)])   # incident 1 = itself

    assert related_incidents(case) == {}


def test_many_related_incidents_give_a_bounded_answer() -> None:
    case = email_case("hello", recent_seen=[recent("domain", "paypa1-secure-login.example", *range(2, 22))])

    _, result, signals = correlate_events(case, {})

    assert len(result["relatedIncidents"]) == MAX_RELATED_IN_RESULT
    assert len(signals) == 1
    assert "and 15 more" in signals[0].label
