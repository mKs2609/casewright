"""A small, built-in threat-intelligence list (the PRD's "static mock dataset").

Every bad entry uses names and numbers reserved for examples, so this public list never
accuses a real website, network or person:
- domains under .example (RFC 2606), plus real well-known sites listed as harmless;
- IP addresses from the documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737);
- phone numbers in the fictional 555-01xx range.
A real feed could replace this later, behind a setting.
"""

import ipaddress
from typing import Any

from app.indicators import registrable

# Addresses that only exist inside an organisation's own network (or the machine itself).
# Deliberately narrower than Python's is_private, which also counts the documentation
# ranges that the mock attackers in this file use.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(address.version == net.version and address in net for net in INTERNAL_NETWORKS)

REPUTATION: dict[str, dict[str, dict[str, Any]]] = {
    "ip": {
        "203.0.113.66": {"score": 92, "tags": ["tor-exit-node", "credential-stuffing-source"], "country": "DE"},
        "198.51.100.23": {"score": 88, "tags": ["botnet", "bruteforce"], "country": "RU"},
        "192.0.2.150": {"score": 64, "tags": ["anonymizing-vpn"], "country": "SG"},
        "198.51.100.7": {"score": 3, "tags": ["residential-isp"], "country": "IN"},
    },
    "domain": {
        "paypa1-secure-login.example": {"score": 96, "tags": ["phishing", "newly-registered"], "ageDays": 3},
        "micros0ft-helpdesk.example": {"score": 94, "tags": ["phishing", "credential-harvesting"], "ageDays": 6},
        "quick-verify-mail.example": {"score": 70, "tags": ["disposable-mail"], "ageDays": 40},
        "example.com": {"score": 0, "tags": ["internal"], "ageDays": 4200},   # the demo company's own domain
        "paypal.com": {"score": 0, "tags": ["well-known"], "ageDays": 9900},
        "microsoft.com": {"score": 0, "tags": ["well-known"], "ageDays": 12000},
        "google.com": {"score": 0, "tags": ["well-known"], "ageDays": 9800},
    },
    "email": {},
    "phone": {
        "+15555550142": {"score": 81, "tags": ["reported-scam-caller", "it-support-impersonation"]},
        "+15555550100": {"score": 0, "tags": ["internal-helpdesk"]},
    },
}


# Entries scored below this are known to be harmless (e.g. residential-isp scores 3).
HARMLESS_BELOW = 10


def is_noise(indicator_type: str, value: str) -> bool:
    """Indicators that appear in lots of harmless incidents and so must not link them: entries
    the threat list knows to be harmless (score below 10: the company's own domain, paypal.com,
    an ordinary home internet connection) and internal network addresses. Linking on these would
    make everything "related"; a person's own home address showing up twice proves nothing.
    Unknown indicators still count: a new phishing domain on no list should link incidents."""
    if indicator_type == "ip":
        try:
            if is_internal_address(value):
                return True
        except ValueError:
            return True
    domain = value.split("@")[-1] if indicator_type in ("domain", "email") else None
    record = REPUTATION[indicator_type].get(value) if indicator_type in ("ip", "phone") else (
        REPUTATION["domain"].get(domain) or REPUTATION["domain"].get(registrable(domain)))
    return record is not None and record.get("score") is not None and record["score"] < HARMLESS_BELOW


# Brands that phishing sites imitate -> the brand's real registrable domain.
BRANDS: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "example": "example.com",   # the demo company itself
}

# Characters swapped in to fool the eye: paypa1 (1 for l), micros0ft (0 for o), 3 for e,
# 5 for s, 8 for b, @ for a. ("rn" for "m" is handled separately, as it is two letters.)
LOOKALIKE_SWAPS = str.maketrans("01358@", "olesba")
