"""Tool 2: compare the incident with what is normal for the person it is about.

Privacy: the baseline is encrypted in the database (ADR-37), but evidence is not. So the
findings describe only the DIFFERENCE ("a country this person doesn't normally use") and
never copy the baseline itself (which countries, which hours, which city) into evidence.
"""

import math
from datetime import UTC, datetime
from typing import Any

from app.case import Case, ToolRejected, ToolResult, short, strongest_per_id
from app.models import Signal

# Approximate city centres (latitude, longitude) for the impossible-travel check.
CITY_COORDS: dict[str, tuple[float, float]] = {
    "bengaluru": (12.97, 77.59), "mumbai": (19.07, 72.88), "delhi": (28.61, 77.21),
    "dubai": (25.20, 55.27), "singapore": (1.35, 103.82), "frankfurt": (50.11, 8.68),
    "london": (51.51, -0.13), "moscow": (55.75, 37.62), "new york": (40.71, -74.01),
    "sao paulo": (-23.55, -46.63),
}

# Faster than an airliner, over a distance worth flying: one person cannot have done both logins.
IMPOSSIBLE_SPEED_KMH = 900
MIN_DISTANCE_KM = 500


def distance_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance (the haversine formula): the shortest route over the Earth's surface."""
    (lat1, lon1), (lat2, lon2) = a, b
    rad = math.pi / 180
    h = (math.sin((lat2 - lat1) * rad / 2) ** 2
         + math.cos(lat1 * rad) * math.cos(lat2 * rad) * math.sin((lon2 - lon1) * rad / 2) ** 2)
    return 12742 * math.asin(math.sqrt(h))


def within_hours(hour: int, start: int, end: int) -> bool:
    """Working hours may wrap past midnight (e.g. 22 to 6)."""
    return start <= hour <= end if start <= end else hour >= start or hour <= end


def _utc(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp).astimezone(UTC)


def _check_logins(case: Case, identity: str, deviations: list[str], signals: list[Signal]) -> None:
    baseline = case.baseline
    events = sorted((e for e in case.login_events() if e.get("username") == identity),
                    key=lambda e: _utc(e["timestamp"]))
    previous: tuple[datetime, str] | None = None
    for event in events:
        when = _utc(event["timestamp"])
        success = bool(event.get("success"))
        if event["country"] not in baseline.usual_countries:
            deviations.append(f"{'successful' if success else 'failed'} login from {event['country']}, not a usual country")
            signals.append(Signal(
                id="BASELINE-GEO", label=f"{'Successful' if success else 'Failed'} login from {event['country']}, "
                f"outside {identity}'s usual countries",
                plain="Someone signed in from a country this person doesn't normally use.",
                weight=25 if success else 10, mitre="T1078"))
        if not within_hours(when.hour, baseline.workday_start_utc, baseline.workday_end_utc):
            deviations.append(f"login at {when.hour:02d}:00 UTC, outside usual working hours")
            signals.append(Signal(
                id="BASELINE-HOURS", label=f"Login at {when.hour:02d}:00 UTC, outside {identity}'s usual working hours",
                plain="The sign-in happened at a time this person is normally offline.", weight=10))
        agent = str(event.get("userAgent") or "")
        if agent and not any(device.lower() in agent.lower() for device in baseline.known_devices):
            # The device text itself is attacker-controlled, so it is not copied into the finding.
            deviations.append("login from an unrecognised device")
            signals.append(Signal(
                id="BASELINE-DEVICE", label=f"Login from a device never seen for {identity}",
                plain="The sign-in came from a device this person has never used.", weight=10))
        city = str(event.get("city") or "").lower()
        if success and city in CITY_COORDS:
            if previous is not None and previous[1] != city:
                km = distance_km(CITY_COORDS[previous[1]], CITY_COORDS[city])
                hours = max((when - previous[0]).total_seconds() / 3600, 1 / 60)
                if km > MIN_DISTANCE_KM and km / hours > IMPOSSIBLE_SPEED_KMH:
                    minutes = round(hours * 60)
                    deviations.append(f"impossible travel: {previous[1].title()} to {city.title()}, "
                                      f"{km:.0f} km in {minutes} min")
                    signals.append(Signal(
                        id="IMPOSSIBLE-TRAVEL",
                        label=f"Impossible travel: {previous[1].title()} to {city.title()} "
                        f"({km:.0f} km in {minutes} min)",
                        plain="The account was used in two far-apart places too quickly for one person to travel.",
                        weight=40, mitre="T1078"))
            previous = (when, city)


def baseline_check(case: Case, args: dict[str, str]) -> ToolResult:
    identity = args.get("identity", "")
    if identity not in case.identities:
        raise ToolRejected("This identity is not part of the incident")

    if identity != case.incident.subject_identity:
        # The gateway sends only the subject's baseline (ADR-3); there is nothing to compare others with.
        signal = Signal(id="BASELINE-NONE", label=f"No baseline available for {identity}",
                        plain="We have no history for this account to compare against.", weight=5)
        return f"{identity}: no baseline available", {"identity": identity, "deviations": []}, [signal]

    deviations: list[str] = []
    signals: list[Signal] = []
    payload = case.incident.payload
    if case.incident.kind == "login":
        _check_logins(case, identity, deviations, signals)
    elif case.incident.kind == "email":
        sender = str(payload.get("sender", "")).lower()
        if sender and sender not in {c.lower() for c in case.baseline.known_contacts}:
            deviations.append("first email from this sender")
            signals.append(Signal(
                id="BASELINE-NEW-SENDER", label=f"{identity} has never had mail from {short(sender)}",
                plain="This person has never received mail from this sender before.", weight=8, indicator=sender))
        reply_to = str(payload.get("replyTo") or "").lower()
        if reply_to and reply_to != sender:
            deviations.append("reply-to address differs from the sender")
            signals.append(Signal(
                id="REPLY-TO-MISMATCH", label=f"Reply-To ({short(reply_to)}) differs from From ({short(sender)})",
                plain="Replies would go to a different address than the one shown, a classic trick.",
                weight=15, mitre="T1566", indicator=reply_to))
    elif case.incident.kind == "call_transcript":
        caller = str(payload.get("callerNumber", ""))
        if caller not in case.baseline.known_numbers:
            deviations.append("call from an unknown number")
            signals.append(Signal(
                id="BASELINE-UNKNOWN-CALLER", label=f"{caller} is not a number {identity} knows",
                plain="The call came from a number this person doesn't know.", weight=5, indicator=caller))

    result: dict[str, Any] = {"identity": identity, "deviations": deviations[:20]}
    return f"{identity}: {len(deviations)} deviation(s) from normal behaviour", result, strongest_per_id(signals)
