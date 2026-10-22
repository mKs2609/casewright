"""Indicators: the checkable things inside an incident (IP addresses, domains, email
addresses, phone numbers). Extracted by plain code, never by the AI.

These lists are the ONLY values the tools will accept (see tools.py). So even when an AI
chooses which tools to call (step 12), it cannot be talked into looking up something that
is not actually in the incident, such as an address written in an attacker's email
"for the analyst to check".
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.models import Incident

# Upper bound per type, so an enormous email cannot turn into thousands of lookups.
MAX_PER_TYPE = 50

OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
# Four numbers 0-255 without leading zeros, and not part of a longer number or dotted run.
IPV4_IN_TEXT = re.compile(rf"(?<![\d.]){OCTET}(?:\.{OCTET}){{3}}(?![\d.]|\.\d)")
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
EMAIL_IN_TEXT = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,185}\.[A-Za-z]{2,24}\b")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def registrable(domain: str) -> str:
    """The part of a domain someone registers, e.g. login.paypa1.example -> paypa1.example.

    Simplified: the last two labels. Real tools use the Public Suffix List, because of
    names like example.co.uk (where it should be the last three).
    """
    labels = domain.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


@dataclass
class Indicators:
    ip: set[str] = field(default_factory=set)
    domain: set[str] = field(default_factory=set)
    email: set[str] = field(default_factory=set)
    phone: set[str] = field(default_factory=set)

    def of_type(self, indicator_type: str) -> set[str]:
        return {"ip": self.ip, "domain": self.domain, "email": self.email, "phone": self.phone}[indicator_type]

    def add(self, indicator_type: str, value: str) -> None:
        bucket = self.of_type(indicator_type)
        if len(bucket) < MAX_PER_TYPE:
            bucket.add(value)

    def add_domain(self, host: str) -> None:
        host = host.lower().strip(".")
        if DOMAIN.match(host):
            self.add("domain", host)
            self.add("domain", registrable(host))

    def add_email(self, address: str) -> None:
        address = address.lower()
        self.add("email", address)
        self.add_domain(address.split("@", 1)[1])

    def add_ip(self, value: str) -> None:
        try:
            self.add("ip", str(ipaddress.ip_address(value)))   # one canonical spelling, e.g. for IPv6
        except ValueError:
            pass

    def count(self) -> int:
        return len(self.ip) + len(self.domain) + len(self.email) + len(self.phone)


def _scan_text(text: str, found: Indicators) -> None:
    for url in URL_IN_TEXT.findall(text):
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            continue
        if IPV4_IN_TEXT.fullmatch(host):
            found.add_ip(host)
        else:
            found.add_domain(host)
    for ip in IPV4_IN_TEXT.findall(text):
        found.add_ip(ip)
    for address in EMAIL_IN_TEXT.findall(text):
        found.add_email(address)


def extract_indicators(incident: Incident) -> Indicators:
    payload = incident.payload
    found = Indicators()
    if incident.kind == "email":
        for address in (payload.get("sender"), payload.get("replyTo")):
            if isinstance(address, str):
                found.add_email(address)
        _scan_text(f"{payload.get('subject', '')}\n{payload.get('body', '')}", found)
    elif incident.kind == "login":
        for event in payload.get("events", []):
            if isinstance(event, dict) and isinstance(event.get("ip"), str):
                found.add_ip(event["ip"])
    elif incident.kind == "call_transcript":
        if isinstance(payload.get("callerNumber"), str):
            found.add("phone", payload["callerNumber"])
        _scan_text(str(payload.get("transcript", "")), found)
    return found
