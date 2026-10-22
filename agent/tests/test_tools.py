"""Tool 1 (reputation lookup), the look-alike check, and the guardrails around every tool call."""

import pytest

from app.indicators import Indicators
from app.models import GuardrailEvent, StepEvent
from app.tools import ToolBox, lookalike_of


def toolbox(**found: set[str]) -> ToolBox:
    return ToolBox(Indicators(**found))


def signal_ids(event: StepEvent | GuardrailEvent) -> list[str]:
    assert isinstance(event, StepEvent)
    return [s.id for s in event.signals]


# ------------------------------------------------------------------ look-alike domains

@pytest.mark.parametrize("domain, imitates", [
    ("paypa1-secure-login.example", "paypal.com"),        # 1 instead of l
    ("micros0ft-helpdesk.example", "microsoft.com"),      # 0 instead of o
    ("login.paypa1-secure-login.example", "paypal.com"),  # a subdomain of a look-alike
    ("rnicrosoft-support.example", "microsoft.com"),      # "rn" reads as "m"
    ("examp1e-it-desk.example", "example.com"),           # imitating our own company
])
def test_look_alike_domains_are_recognised(domain: str, imitates: str) -> None:
    assert lookalike_of(domain) == imitates


@pytest.mark.parametrize("domain", ["paypal.com", "mail.paypal.com", "example.com", "quick-verify-mail.example",
                                    "weather.example"])
def test_real_brand_domains_and_unrelated_names_are_not_look_alikes(domain: str) -> None:
    # "weather.example": the .example ending must not count as imitating example.com.
    assert lookalike_of(domain) is None


# ------------------------------------------------------------------ reputation

def test_a_known_attacker_ip_is_flagged_and_numbered_e1() -> None:
    event = toolbox(ip={"203.0.113.66"}).call("reputation_lookup", {"indicatorType": "ip", "value": "203.0.113.66"})

    assert isinstance(event, StepEvent)
    assert event.label == "E1"
    assert signal_ids(event) == ["REP-MALICIOUS"]
    assert event.signals[0].plain == "This internet address is on lists of known attackers."
    assert event.result["score"] == 92


def test_a_phishing_domain_gives_three_findings() -> None:
    domain = "paypa1-secure-login.example"
    event = toolbox(domain={domain}).call("reputation_lookup", {"indicatorType": "domain", "value": domain})

    assert signal_ids(event) == ["REP-MALICIOUS", "LOOKALIKE-DOMAIN", "NEW-DOMAIN"]


def test_an_unknown_domain_is_mildly_suspicious_and_a_private_ip_is_just_noted() -> None:
    tools = toolbox(domain={"never-seen.example"}, ip={"10.1.2.3"})

    assert signal_ids(tools.call("reputation_lookup", {"indicatorType": "domain", "value": "never-seen.example"})) == ["REP-UNKNOWN"]
    private = tools.call("reputation_lookup", {"indicatorType": "ip", "value": "10.1.2.3"})
    assert signal_ids(private) == []
    assert private.result["tags"] == ["private-address"]


def test_known_good_entries_raise_nothing() -> None:
    tools = toolbox(domain={"paypal.com"}, phone={"+15555550100"})

    assert signal_ids(tools.call("reputation_lookup", {"indicatorType": "domain", "value": "paypal.com"})) == []
    assert signal_ids(tools.call("reputation_lookup", {"indicatorType": "phone", "value": "+15555550100"})) == []


# ------------------------------------------------------------------ guardrails

def test_a_lookup_of_something_not_in_the_incident_is_refused_and_recorded_as_r1() -> None:
    tools = toolbox(domain={"paypa1-secure-login.example"})

    event = tools.call("reputation_lookup", {"indicatorType": "domain", "value": "attacker-server.example"})

    assert isinstance(event, GuardrailEvent)
    assert event.label == "R1"
    assert "does not appear in the incident" in event.reason
    # Refusals and evidence are numbered separately: the next accepted call is still E1.
    accepted = tools.call("reputation_lookup", {"indicatorType": "domain", "value": "paypa1-secure-login.example"})
    assert accepted.label == "E1"


@pytest.mark.parametrize("tool, args", [
    ("delete_mailbox", {"identity": "priya.sharma"}),                         # not on the allow-list
    ("reputation_lookup", {"indicatorType": "url", "value": "x"}),            # unknown indicator type
    ("reputation_lookup", {"indicatorType": "domain"}),                       # value missing
    ("Robert'); DROP TABLE--", {"value": "x"}),                               # a tool name that is not a name
    ("reputation_lookup", {"indicatorType": "domain", "value": "x" * 5000}),  # arguments too big to record
])
def test_anything_off_the_allow_list_is_refused_never_run(tool: str, args: dict[str, str]) -> None:
    event = toolbox(domain={"paypa1-secure-login.example"}).call(tool, args)

    assert isinstance(event, GuardrailEvent)
    assert event.label == "R1"


def test_the_plain_wording_fits_the_kind_of_indicator() -> None:
    event = toolbox(phone={"+15555550142"}).call("reputation_lookup", {"indicatorType": "phone", "value": "+15555550142"})

    assert event.signals[0].plain == "This phone number has been reported for scam calls."
