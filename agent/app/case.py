"""The case: everything the tools may look at for one investigation, and nothing else.

Every tool receives the same Case. It holds what the gateway sent (the incident and the
subject's baseline, ADR-3) plus the indicators extracted from the incident.
"""

from dataclasses import dataclass
from typing import Any

from app.indicators import Indicators, extract_indicators
from app.models import Baseline, Incident, Signal

# What every tool returns: a one-line summary, the raw result, and the findings.
ToolResult = tuple[str, dict[str, Any], list[Signal]]


class ToolRejected(Exception):
    """The call is outside the allow-list or outside this incident. Recorded, never run."""


def short(value: str, limit: int = 80) -> str:
    """Long values are shortened inside descriptions, which have a length limit."""
    return value if len(value) <= limit else value[: limit - 3] + "..."


@dataclass(frozen=True)
class Case:
    incident: Incident
    baseline: Baseline
    indicators: Indicators

    @staticmethod
    def of(incident: Incident, baseline: Baseline) -> "Case":
        return Case(incident, baseline, extract_indicators(incident))

    @property
    def identities(self) -> set[str]:
        """The people this incident involves: its subject, plus any account named in its login events."""
        found = {self.incident.subject_identity}
        if self.incident.kind == "login":
            found |= {e["username"] for e in self.login_events() if isinstance(e.get("username"), str)}
        return found

    def login_events(self) -> list[dict[str, Any]]:
        events = self.incident.payload.get("events", []) if self.incident.kind == "login" else []
        return [e for e in events if isinstance(e, dict)]

    def text_fields(self) -> dict[str, str]:
        """The free text an attacker wrote, by field name. (A login batch has none.)"""
        payload = self.incident.payload
        if self.incident.kind == "email":
            return {"subject": str(payload.get("subject", "")), "body": str(payload.get("body", ""))}
        if self.incident.kind == "call_transcript":
            return {"transcript": str(payload.get("transcript", ""))}
        return {}


def strongest_per_id(signals: list[Signal]) -> list[Signal]:
    """One finding per kind: the same signal found several times counts once, at its strongest."""
    best: dict[str, Signal] = {}
    for signal in signals:
        if signal.id not in best or signal.weight > best[signal.id].weight:
            best[signal.id] = signal
    return list(best.values())
