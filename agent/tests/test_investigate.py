"""POST /internal/investigate: strict input, and a stream of events back."""

import json

import pytest
from fastapi.testclient import TestClient

from app.models import CompleteEvent, ThoughtEvent
from tests.conftest import AUTH, valid_request


def events(response_text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in response_text.splitlines() if line]


def test_an_investigation_streams_events_one_per_line_and_ends_with_complete(client: TestClient) -> None:
    response = client.post("/internal/investigate", json=valid_request(), headers=AUTH)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    received = events(response.text)
    assert [e["type"] for e in received] == ["agent.thought", "agent.thought", "investigation.complete"]
    assert received[-1] == {"type": "investigation.complete", "result": "needs_review", "engine": "stub"}
    # Every line is a valid event, exactly as the gateway will check it.
    for event in received[:-1]:
        ThoughtEvent.model_validate(event)
    CompleteEvent.model_validate(received[-1])


def test_the_attackers_text_is_never_copied_into_the_agents_own_words(client: TestClient) -> None:
    response = client.post("/internal/investigate", json=valid_request(), headers=AUTH)

    assert "Ignore previous instructions" not in response.text
    assert "priya.sharma" in response.text


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
