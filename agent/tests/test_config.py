"""The agent refuses to start without a proper service token."""

from pathlib import Path

import pytest

from app import config


@pytest.fixture
def no_token_anywhere(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    monkeypatch.delenv("AGENT_SERVICE_TOKEN", raising=False)
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / ".env")
    config.service_token.cache_clear()
    yield tmp_path / ".env"
    config.service_token.cache_clear()


def test_a_missing_token_stops_the_agent(no_token_anywhere: Path) -> None:
    with pytest.raises(config.SettingsError, match="setup-secrets"):
        config.service_token()


def test_a_short_token_stops_the_agent(no_token_anywhere: Path) -> None:
    no_token_anywhere.write_text("AGENT_SERVICE_TOKEN=too-short\n", encoding="utf-8")

    with pytest.raises(config.SettingsError):
        config.service_token()


def test_the_token_is_read_from_the_env_file(no_token_anywhere: Path) -> None:
    token = "t" * 44
    no_token_anywhere.write_text(f"# comment\nDB_USER=someone\nAGENT_SERVICE_TOKEN={token}\n", encoding="utf-8")

    assert config.service_token() == token
