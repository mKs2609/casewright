"""Only the gateway, holding the service token, may use the agent (ADR-4)."""

import pytest
from fastapi.testclient import TestClient

from app.security import is_authorised
from tests.conftest import AUTH, TEST_TOKEN


def test_health_works_with_the_token(client: TestClient) -> None:
    response = client.get("/internal/health", headers=AUTH)

    assert response.status_code == 200
    assert response.json() == {"status": "UP", "service": "agent"}


@pytest.mark.parametrize(
    "headers",
    [
        {},                                                       # no token at all
        {"Authorization": "Bearer not-the-token"},                # wrong token
        {"Authorization": f"Bearer {TEST_TOKEN}x"},               # right token plus one character
        {"Authorization": f"Bearer {TEST_TOKEN[:-1]}"},           # right token minus one character
        {"Authorization": f"Basic {TEST_TOKEN}"},                 # right token, wrong scheme
        {"Authorization": TEST_TOKEN},                            # no scheme
        {"Authorization": f"bearer {TEST_TOKEN}"},                # scheme in the wrong case
    ],
)
def test_anything_but_the_exact_token_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    response = client.get("/internal/health", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"error": "Unauthorized"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_without_the_token_even_unknown_pages_say_401_not_404(client: TestClient) -> None:
    # Nobody without the token can even find out which addresses exist.
    assert client.get("/internal/does-not-exist").status_code == 401
    assert client.get("/internal/does-not-exist", headers=AUTH).status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_the_api_documentation_pages_are_switched_off(client: TestClient, path: str) -> None:
    assert client.get(path, headers=AUTH).status_code == 404


def test_the_comparison_only_accepts_an_exact_match() -> None:
    assert is_authorised("Bearer abc", "abc")
    assert not is_authorised(None, "abc")
    assert not is_authorised("Bearer ", "abc")
    assert not is_authorised("Bearer abcd", "abc")
