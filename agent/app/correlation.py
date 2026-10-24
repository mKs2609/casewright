"""Tool 4: what a batch of login events shows when looked at together, per source address.

- credential stuffing: one address trying many different accounts, mostly failing
  (passwords leaked from other websites being tried everywhere);
- brute force: many failed guesses on one or two accounts;
- success after failures: after many wrong guesses, a login worked, so an account may be taken over;
- automation: attempts faster than a person can type.

It also looks across incidents (step 10b): the gateway sends the indicators of recent
incidents, and any that this incident shares (ignoring known-good and internal ones) mean
the same attacker may be hitting several people: a campaign.
"""

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app import threat_intel
from app.case import Case, ToolRejected, ToolResult, short
from app.models import Signal

STUFFING_MIN_ACCOUNTS = 8
STUFFING_MIN_FAILURE_SHARE = 0.7
BRUTE_FORCE_MIN_FAILURES = 8
SUCCESS_AFTER_MIN_FAILURES = 5
AUTOMATION_PER_MINUTE = 15

# Bounds, so a 500-event batch from many addresses still gives a small, valid answer.
MAX_SOURCES_IN_RESULT = 25
MAX_SIGNALS = 12
MAX_RELATED_IN_RESULT = 10


def related_incidents(case: Case) -> dict[int, list[str]]:
    """Other recent incidents sharing a meaningful indicator with this one: {incident id: shared values}."""
    mine = {(t, v) for t, v in case.indicators.items() if not threat_intel.is_noise(t, v)}
    related: dict[int, list[str]] = {}
    for seen in case.recent:
        if (seen.type, seen.value) in mine:
            for incident_id in seen.incident_ids:
                if incident_id != case.incident.id:
                    related.setdefault(incident_id, []).append(seen.value)
    return related


def _related_signal(related: dict[int, list[str]]) -> Signal:
    ids = sorted(related, reverse=True)
    shared = sorted({v for values in related.values() for v in values})
    listed = ", ".join(str(i) for i in ids[:5]) + (f" and {len(ids) - 5} more" if len(ids) > 5 else "")
    return Signal(id="RELATED-INCIDENTS",
                  label=f"Shares {short(shared[0], 60)}{f' (+{len(shared) - 1} more)' if len(shared) > 1 else ''} "
                        f"with recent incident(s) {listed}",
                  plain="The same attacker details turned up in other recent reports, so this may be part of a "
                        "wider attack on several people.",
                  weight=15 if len(ids) >= 2 else 10, mitre="T1583")


def correlate_events(case: Case, args: dict[str, str]) -> ToolResult:
    if args:
        raise ToolRejected("correlate_events takes no arguments")
    related = related_incidents(case)
    related_part = [{"incidentId": i, "shared": sorted(set(v))[:5]}
                    for i, v in sorted(related.items(), reverse=True)[:MAX_RELATED_IN_RESULT]]
    related_signals = [_related_signal(related)] if related else []

    events = case.login_events()
    if not events:
        summary = f"{len(related)} related recent incident(s)"
        return summary, {"perSource": {}, "relatedIncidents": related_part}, related_signals

    per_ip: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"accounts": set(), "failures": 0, "successes": 0, "times": [], "loggedInto": set()})
    for event in events:
        source = per_ip[str(event.get("ip"))]
        source["accounts"].add(str(event.get("username")))
        source["times"].append(datetime.fromisoformat(event["timestamp"]).astimezone(UTC))
        if event.get("success"):
            source["successes"] += 1
            source["loggedInto"].add(str(event.get("username")))
        else:
            source["failures"] += 1

    stats: dict[str, dict[str, Any]] = {}
    signals: list[Signal] = []
    busiest_first = sorted(per_ip.items(), key=lambda item: -(item[1]["failures"] + item[1]["successes"]))
    for ip, s in busiest_first:
        total = s["failures"] + s["successes"]
        minutes = max((max(s["times"]) - min(s["times"])).total_seconds() / 60, 1)
        per_minute = total / minutes
        accounts = len(s["accounts"])
        if len(stats) < MAX_SOURCES_IN_RESULT:
            stats[ip] = {"attempts": total, "failures": s["failures"], "successes": s["successes"],
                         "distinctAccounts": accounts, "attemptsPerMinute": round(per_minute, 1),
                         "accountsLoggedInto": sorted(s["loggedInto"])[:10]}
        if accounts >= STUFFING_MIN_ACCOUNTS and s["failures"] / total >= STUFFING_MIN_FAILURE_SHARE:
            signals.append(Signal(
                id="CRED-STUFFING", label=f"{ip} tried {accounts} accounts; {s['failures']} of {total} attempts failed",
                plain="One computer tried passwords on many different accounts: the pattern of attacks using "
                      "passwords stolen from other websites.",
                weight=50, mitre="T1110.004", indicator=ip))
        elif s["failures"] >= BRUTE_FORCE_MIN_FAILURES and accounts <= 2:
            signals.append(Signal(
                id="BRUTE-FORCE", label=f"{ip}: {s['failures']} failed attempts on {accounts} account(s)",
                plain="Someone kept guessing the password for this account.", weight=35, mitre="T1110.001",
                indicator=ip))
        if s["successes"] and s["failures"] >= SUCCESS_AFTER_MIN_FAILURES:
            who = ", ".join(sorted(s["loggedInto"])[:5])
            signals.append(Signal(
                id="SUCCESS-AFTER-FAILURES", label=f"{ip} logged in to {who} after {s['failures']} failed attempts",
                plain="After many wrong guesses, a sign-in worked, so an account may now be in an attacker's hands.",
                weight=40, mitre="T1078", indicator=ip))
        if per_minute > AUTOMATION_PER_MINUTE:
            signals.append(Signal(
                id="AUTOMATION", label=f"{ip}: {per_minute:.0f} attempts per minute",
                plain="The attempts came faster than any person could type.", weight=10, indicator=ip))

    # Strongest first; a flood from many addresses is summarised, not listed one by one.
    signals.sort(key=lambda s: -s.weight)
    signals = signals[:MAX_SIGNALS - len(related_signals)] + related_signals
    summary = f"{len(per_ip)} source address(es) analysed, {len(related)} related recent incident(s)"
    return summary, {"perSource": stats, "sourcesAnalysed": len(per_ip), "relatedIncidents": related_part}, signals
