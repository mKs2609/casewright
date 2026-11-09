"""The evaluation (step 18b, ADR-53): the sets are well formed and use only reserved example
names, and docs/EVALUATION.md still matches what the agent does today.

If the last test fails, a change altered the agent's results on the evaluation sets. That may
be an improvement or a regression; either way the published numbers must change with it, in the
same pull request, so the change is visible: run scripts/evaluate.py and commit the new report.
"""

import ipaddress
import json
import re
from pathlib import Path

import pytest

from app import config
from app.indicators import extract_indicators
from app.models import Incident
from tests.evaluation import false_alarms, detection, report, run_all, wilson
from tests.evaluation_heldout import HELD_OUT
from tests.evaluation_set import DEVELOPMENT, SOURCES, Example
from tests.scenarios import BASELINES, SCENARIOS

ROOT = Path(__file__).resolve().parents[2]
ALL = DEVELOPMENT + HELD_OUT

# The gateway's own rules for each kind (EmailIncidentRequest, LoginIncidentRequest,
# CallTranscriptIncidentRequest), so every example could be submitted through the API as it is.
EMAIL_ADDRESS = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,185}\.[A-Za-z]{2,24}$")
PHONE = re.compile(r"^\+?[0-9]{6,15}$")
CITY = re.compile(r"^[A-Za-z .'-]*$")

# Reserved for examples: RFC 5737 documentation addresses, RFC 2606 names, 555-01xx numbers.
DOCUMENTATION_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
EXAMPLE_PHONE = re.compile(r"^\+155555501[0-9]{2}$")


def reserved_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain.endswith(".example") or domain == "example.com" or domain.endswith(".example.com")


def test_the_sets_have_the_planned_size_and_balance() -> None:
    for chosen, size in ((DEVELOPMENT, 60), (HELD_OUT, 40)):
        assert len(chosen) == size
        assert sum(e.label == "malicious" for e in chosen) == size // 2
        assert {e.label for e in chosen} == {"malicious", "benign"}


def test_every_example_has_its_own_name() -> None:
    names = [e.name for e in ALL]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("example", ALL, ids=lambda e: e.name)
def test_every_attack_names_its_public_sources_and_nothing_harmless_does(example: Example) -> None:
    if example.label == "malicious":
        assert example.basis and set(example.basis) <= set(SOURCES)
    else:
        assert example.basis == ()


@pytest.mark.parametrize("example", ALL, ids=lambda e: e.name)
def test_every_example_would_pass_the_gateways_checks(example: Example) -> None:
    p = example.payload
    assert example.subject in BASELINES
    if example.kind == "email":
        assert set(p) <= {"sender", "replyTo", "subject", "body"}
        assert EMAIL_ADDRESS.match(p["sender"]) and len(p["sender"]) <= 254
        assert "replyTo" not in p or (EMAIL_ADDRESS.match(p["replyTo"]) and len(p["replyTo"]) <= 254)
        assert len(p["subject"]) <= 300 and 1 <= len(p["body"]) <= 20_000
    elif example.kind == "call_transcript":
        assert set(p) == {"callerNumber", "transcript"}
        assert PHONE.match(p["callerNumber"]) and 1 <= len(p["transcript"]) <= 20_000
    else:
        assert set(p) == {"events"} and 1 <= len(p["events"]) <= 500
        for event in p["events"]:
            assert set(event) == {"username", "ip", "timestamp", "success", "country", "city", "userAgent"}
            assert re.match(r"^[A-Z]{2}$", event["country"]) and CITY.match(event["city"]) and len(event["city"]) <= 64
            assert event["timestamp"].endswith("Z") and len(event["userAgent"]) <= 300
        # The person the incident is about appears in it, so their baseline is compared.
        assert any(e["username"] == example.subject for e in p["events"])


@pytest.mark.parametrize("example", ALL, ids=lambda e: e.name)
def test_every_example_uses_only_reserved_example_names(example: Example) -> None:
    incident = Incident.model_validate({"id": 1, "kind": example.kind, "subjectIdentity": example.subject,
                                        "payload": example.payload})
    found = extract_indicators(incident)

    for ip in found.ip:
        assert any(ipaddress.ip_address(ip) in net for net in DOCUMENTATION_NETWORKS), ip
    for domain in found.domain:
        assert reserved_domain(domain), domain
    for address in found.email:
        assert reserved_domain(address.split("@", 1)[1]), address
    for number in found.phone:
        assert EXAMPLE_PHONE.match(number), number


def test_no_example_is_a_demo_scenario() -> None:
    demos = [scenario()[2] for scenario, *_ in SCENARIOS.values()]
    assert not [e.name for e in ALL if e.payload in demos]


def test_the_95_percent_range_matches_known_values() -> None:
    low, high = wilson(22, 30)
    assert (round(low, 3), round(high, 3)) == (0.556, 0.858)
    assert wilson(0, 20)[0] == 0 and wilson(20, 20)[1] == 1   # stays inside 0..1 at the edges
    assert wilson(0, 20)[1] > 0                              # 0 of 20 does not prove "never"


def test_the_rule_engine_is_never_measured_with_the_model_switched_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # Found in a real run: with the model switched on, the "rule engine" pass quietly used it.
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    config.llm_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="LLM_PROVIDER=off"):
            run_all(HELD_OUT[:1])
    finally:
        monkeypatch.setenv("LLM_PROVIDER", "off")
        config.llm_settings.cache_clear()


def test_a_recorded_model_run_is_reported_per_set() -> None:
    development, held_out = run_all(DEVELOPMENT), run_all(HELD_OUT)
    # A made-up run: the model flags exactly the attacks, and finishes all but one investigation.
    results = {e.name: {"flagged": e.label == "malicious", "verdict": "malicious" if e.label == "malicious" else "benign",
                        "risk": 0, "engine": "llm"} for e in ALL}
    results[HELD_OUT[0].name]["engine"] = "rules"

    text = report(development, held_out, {"model": "test-model", "date": "2026-11-09", "results": results})

    assert "Model `test-model`, run on 2026-11-09." in text
    assert "| Held-out | 20 of 20 (100%), range 84% to 100% | 0 of 20 (0%), range 0% to 16% | 39 of 40 |" in text
    assert "| Development | 30 of 30 (100%)" in text


def test_the_published_report_matches_what_the_agent_does_today() -> None:
    development, held_out = run_all(DEVELOPMENT), run_all(HELD_OUT)
    model_file = ROOT / "testdata" / "evaluation-model-run.json"
    recorded = json.loads(model_file.read_text(encoding="utf-8")) if model_file.exists() else None
    published = (ROOT / "docs" / "EVALUATION.md").read_text(encoding="utf-8")

    assert published == report(development, held_out, recorded), (
        "The evaluation results changed (held-out: "
        f"{detection(held_out).shown()} caught, {false_alarms(held_out).shown()} false alarms). "
        "Run scripts\\evaluate.py and commit docs/EVALUATION.md with this change.")
