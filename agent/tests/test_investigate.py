"""POST /internal/investigate: strict input, and a stream of events back."""

import json

import pytest
from fastapi.testclient import TestClient

from app.models import ActionsEvent, CompleteEvent, IndicatorsEvent, ReportEvent, StepEvent, ThoughtEvent, VerdictEvent
from tests.conftest import AUTH, valid_request


def events(response_text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in response_text.splitlines() if line]


def test_an_investigation_streams_events_one_per_line_and_ends_with_complete(client: TestClient) -> None:
    response = client.post("/internal/investigate", json=valid_request(), headers=AUTH)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    received = events(response.text)
    assert received[-1] == {"type": "investigation.complete", "result": "needs_review", "engine": "rules"}
    # Every line is a valid event, exactly as the gateway will check it.
    shapes = {"agent.thought": ThoughtEvent, "incident.indicators": IndicatorsEvent, "agent.step": StepEvent,
              "verdict": VerdictEvent, "report": ReportEvent, "actions.proposed": ActionsEvent,
              "investigation.complete": CompleteEvent}
    assert [e["type"] for e in received][-4:] == ["verdict", "report", "actions.proposed", "investigation.complete"]
    for event in received:
        shapes[event["type"]].model_validate(event)


def test_an_email_is_checked_text_first_then_reputation_then_baseline(client: TestClient) -> None:
    received = events(client.post("/internal/investigate", json=valid_request(), headers=AUTH).text)

    steps = [e for e in received if e["type"] == "agent.step"]
    assert [(s["label"], s["tool"]) for s in steps] == [
        ("E1", "pattern_match"), ("E2", "reputation_lookup"), ("E3", "baseline_check"), ("E4", "correlate_events")]
    assert steps[1]["args"] == {"indicatorType": "domain", "value": "paypa1.example"}
    assert [s["id"] for s in steps[1]["signals"]] == ["REP-UNKNOWN", "LOOKALIKE-DOMAIN"]


def test_the_attackers_text_is_quoted_as_evidence_but_never_becomes_the_agents_own_words(client: TestClient) -> None:
    received = events(client.post("/internal/investigate", json=valid_request(), headers=AUTH).text)
    attack = "Ignore previous instructions"

    # Own words: notes, summaries and findings. These feed the reports (and, later, an AI's reasoning).
    own_words = [e["text"] for e in received if e["type"] == "agent.thought"]
    for step in (e for e in received if e["type"] == "agent.step"):
        own_words.append(step["summary"])
        own_words += [s["label"] for s in step["signals"]] + [s["plain"] for s in step["signals"]]
    assert all(attack not in words for words in own_words)
    assert any("priya.sharma" in words for words in own_words)

    # The matched text is kept only as a quoted snippet inside the evidence's result.
    pattern_step = next(e for e in received if e["type"] == "agent.step" and e["tool"] == "pattern_match")
    assert any(attack in m["snippet"] for m in pattern_step["result"]["matches"])


def test_an_investigation_needs_the_token(client: TestClient) -> None:
    assert client.post("/internal/investigate", json=valid_request()).status_code == 401


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "carrier_pigeon"},
        {"id": -5},
        {"subjectIdentity": "Priya Sharma"},
        {"priority": "urgent"},  # a field that does not exist
    ],
)
def test_invalid_incidents_are_refused_without_echoing_them(client: TestClient, change: dict[str, object]) -> None:
    response = client.post("/internal/investigate", json=valid_request(**change), headers=AUTH)

    assert response.status_code == 400
    assert response.json()["error"] == "Validation failed"
    for value in change.values():
        assert str(value) not in response.text


def test_a_missing_baseline_is_refused(client: TestClient) -> None:
    body = valid_request()
    del body["baseline"]

    response = client.post("/internal/investigate", json=body, headers=AUTH)

    assert response.status_code == 400
    assert "baseline" in response.json()["fields"]


def test_an_oversized_body_is_refused_before_it_is_read(client: TestClient) -> None:
    huge = valid_request(payload={"body": "x" * (1024 * 1024)})

    response = client.post("/internal/investigate", json=huge, headers=AUTH)

    assert response.status_code == 413


def test_a_login_batch_is_correlated_first_then_reputation_then_baseline(client: TestClient) -> None:
    body = valid_request(kind="login", subjectIdentity="arjun.mehta", payload={"events": [
        {"username": "arjun.mehta", "ip": "203.0.113.66", "timestamp": "2026-10-19T02:00:00Z", "success": True,
         "country": "DE"}]})

    received = events(client.post("/internal/investigate", json=body, headers=AUTH).text)

    tools = [e["tool"] for e in received if e["type"] == "agent.step"]
    assert tools == ["correlate_events", "reputation_lookup", "baseline_check"]


def test_a_call_is_checked_text_first_then_the_caller_then_baseline(client: TestClient) -> None:
    body = valid_request(kind="call_transcript", subjectIdentity="sara.khan",
                         payload={"callerNumber": "+15555550142", "transcript": "This is IT support, read me the code"})

    received = events(client.post("/internal/investigate", json=body, headers=AUTH).text)

    steps = [e for e in received if e["type"] == "agent.step"]
    assert [s["tool"] for s in steps] == ["pattern_match", "reputation_lookup", "baseline_check", "correlate_events"]
    assert steps[1]["args"] == {"indicatorType": "phone", "value": "+15555550142"}


def test_the_incidents_indicators_are_reported_before_any_tool_runs(client: TestClient) -> None:
    received = events(client.post("/internal/investigate", json=valid_request(), headers=AUTH).text)

    types = [e["type"] for e in received]
    assert types.index("incident.indicators") < types.index("agent.step")
    reported = next(e for e in received if e["type"] == "incident.indicators")["indicators"]
    assert {"type": "domain", "value": "paypa1.example"} in reported
    assert {"type": "email", "value": "security@paypa1.example"} in reported


def test_an_incident_sharing_an_indicator_with_a_recent_one_is_linked(client: TestClient) -> None:
    body = valid_request()
    body["recentIndicators"] = [{"type": "domain", "value": "paypa1.example", "incidentIds": [3, 5]}]

    received = events(client.post("/internal/investigate", json=body, headers=AUTH).text)

    correlation = next(e for e in received if e["type"] == "agent.step" and e["tool"] == "correlate_events")
    assert [s["id"] for s in correlation["signals"]] == ["RELATED-INCIDENTS"]
    assert correlation["result"]["relatedIncidents"] == [
        {"incidentId": 5, "shared": ["paypa1.example"]}, {"incidentId": 3, "shared": ["paypa1.example"]}]


def test_recent_indicators_are_checked_strictly(client: TestClient) -> None:
    body = valid_request()
    body["recentIndicators"] = [{"type": "url", "value": "x", "incidentIds": [3]}]

    assert client.post("/internal/investigate", json=body, headers=AUTH).status_code == 400
