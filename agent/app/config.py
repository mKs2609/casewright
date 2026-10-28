"""Settings, read once. The service token is a secret: it comes from the environment
or from the repo-root .env file (the same one the gateway reads), never from code."""

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

# agent/app/config.py -> the repository root
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

# setup-secrets.ps1 makes a 44-character token (32 random bytes, Base64).
MIN_TOKEN_LENGTH = 32


class SettingsError(RuntimeError):
    """A required setting is missing or unusable. The agent refuses to start."""


def read_env_file(path: Path) -> dict[str, str]:
    """NAME=value lines; blank lines and # comments are skipped."""
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                values[name.strip()] = value.strip()
    return values


@lru_cache(maxsize=1)
def service_token() -> str:
    """The shared secret the gateway must present on every request."""
    token = os.environ.get("AGENT_SERVICE_TOKEN") or read_env_file(ENV_FILE).get("AGENT_SERVICE_TOKEN", "")
    if len(token) < MIN_TOKEN_LENGTH:
        raise SettingsError(
            "AGENT_SERVICE_TOKEN is missing or shorter than 32 characters. "
            "Run scripts\\setup-secrets.ps1, or set it as an environment variable."
        )
    return token


# The model runs on this machine (ADR-15): incident data must never leave it, so the model's
# address may only be a loopback one.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")
MODEL_NAME = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")


@dataclass(frozen=True)
class LlmSettings:
    provider: str   # "off": the fixed plan only; "ollama": a local model chooses the tools
    model: str
    url: str


def setting(name: str, default: str) -> str:
    return os.environ.get(name) or read_env_file(ENV_FILE).get(name) or default


@lru_cache(maxsize=1)
def llm_settings() -> LlmSettings:
    provider = setting("LLM_PROVIDER", "off")
    model = setting("LLM_MODEL", "qwen3:8b")
    url = setting("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
    if provider not in ("off", "ollama"):
        raise SettingsError("LLM_PROVIDER must be off or ollama.")
    if not MODEL_NAME.match(model):
        raise SettingsError("LLM_MODEL is not a valid model name.")
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname not in LOOPBACK_HOSTS or parts.path or parts.query:
        raise SettingsError("OLLAMA_URL must be a local address such as http://127.0.0.1:11434; "
                            "incident data must not leave this machine.")
    return LlmSettings(provider, model, url)
