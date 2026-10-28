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


# ------------------------------------------------------------------ the AI model's settings (ADR-15)

@pytest.fixture
def ai_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    """Nothing set anywhere; each test writes the .env lines it needs."""
    for name in ("LLM_PROVIDER", "LLM_MODEL", "OLLAMA_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / ".env")
    config.llm_settings.cache_clear()
    yield tmp_path / ".env"
    config.llm_settings.cache_clear()


def test_the_ai_is_off_unless_switched_on(ai_settings: Path) -> None:
    assert config.llm_settings() == config.LlmSettings("off", "qwen3:8b", "http://127.0.0.1:11434")


def test_the_ai_is_switched_on_in_the_env_file(ai_settings: Path) -> None:
    ai_settings.write_text("LLM_PROVIDER=ollama\nLLM_MODEL=llama3.1:8b\nOLLAMA_URL=http://localhost:11434/\n",
                           encoding="utf-8")

    assert config.llm_settings() == config.LlmSettings("ollama", "llama3.1:8b", "http://localhost:11434")


@pytest.mark.parametrize("url", [
    "http://10.0.0.8:11434",          # another machine on the network
    "http://192.168.1.20:11434",
    "https://ollama.example",         # a remote service
    "http://127.0.0.1.evil.example",  # looks local, is not
    "http://user@evil.example",
    "http://127.0.0.1:11434/proxy",   # a path could lead elsewhere
    "file:///C:/models",
])
def test_the_model_must_run_on_this_machine(ai_settings: Path, url: str) -> None:
    ai_settings.write_text(f"LLM_PROVIDER=ollama\nOLLAMA_URL={url}\n", encoding="utf-8")

    with pytest.raises(config.SettingsError, match="must not leave this machine"):
        config.llm_settings()


@pytest.mark.parametrize(("line", "message"), [
    ("LLM_PROVIDER=openai", "LLM_PROVIDER must be off or ollama"),
    ("LLM_MODEL=../../etc", "LLM_MODEL is not a valid model name"),
    ("LLM_MODEL=Qwen 3", "LLM_MODEL is not a valid model name"),
])
def test_unusable_ai_settings_stop_the_agent(ai_settings: Path, line: str, message: str) -> None:
    ai_settings.write_text(line + "\n", encoding="utf-8")

    with pytest.raises(config.SettingsError, match=message):
        config.llm_settings()
