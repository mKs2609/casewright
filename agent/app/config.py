"""Settings, read once. The service token is a secret: it comes from the environment
or from the repo-root .env file (the same one the gateway reads), never from code."""

import os
from functools import lru_cache
from pathlib import Path

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
