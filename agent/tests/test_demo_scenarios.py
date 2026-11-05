"""The dashboard's demo buttons (step 17a) fire the gateway's copy of these scenarios
(gateway/src/main/resources/demo/scenarios.json). These tests keep that copy identical to the
scenarios whose verdicts are tested here, and check that a demo run twice still ends the same way."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.investigation import investigate
from app.models import IndicatorsEvent, InvestigateRequest, VerdictEvent
from tests.scenarios import BASELINES, SCENARIOS

GATEWAY_FILE = Path(__file__).resolve().parents[2] / "gateway" / "src" / "main" / "resources" / "demo" / "scenarios.json"


def demo_file() -> list[dict[str, Any]]:
    return json.loads(GATEWAY_FILE.read_text(encoding="utf-8"))["scenarios"]


def test_the_gateway_offers_every_tested_scenario_and_nothing_else() -> None:
    assert sorted(s["name"] for s in demo_file()) == sorted(SCENARIOS)


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_the_gateways_copy_is_exactly_the_tested_scenario(name: str) -> None:
    shipped = next(s["incident"] for s in demo_file() if s["name"] == name)
    kind, subject, payload = SCENARIOS[name][0]()

    assert shipped == {"kind": kind, "subjectIdentity": subject, **payload}


def run(name: str, incident_id: int, recent: list[dict[str, Any]]) -> tuple[VerdictEvent, IndicatorsEvent]:
    kind, subject, payload = SCENARIOS[name][0]()
    request = InvestigateRequest.model_validate({
        "incident": {"id": incident_id, "kind": kind, "subjectIdentity": subject, "payload": payload},
        "baseline": BASELINES[subject], "recentIndicators": recent})
    events = list(investigate(request))
    decision = next(e for e in events if isinstance(e, VerdictEvent))
    indicators = next(e for e in events if isinstance(e, IndicatorsEvent))
    return decision, indicators


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_a_demo_fired_again_ends_the_same_way(name: str) -> None:
    # The second run sees the first as a recent incident sharing its details (ADR-42). That may add
    # a "related incidents" finding, but must not change the verdict or the kind of attack.
    _, expected_verdict, expected_attack, _ = SCENARIOS[name]
    _, first = run(name, 50, [])
    recent = [{"type": i.type, "value": i.value, "incidentIds": [50]} for i in first.indicators]

    again, _ = run(name, 51, recent)

    assert (again.verdict, again.attack_type) == (expected_verdict, expected_attack), f"risk {again.risk_score}"
