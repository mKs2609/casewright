"""Checking that a request really comes from the gateway (ADR-4)."""

import hmac

SCHEME = "Bearer "


def is_authorised(authorization_header: str | None, expected_token: str) -> bool:
    """True only for exactly "Bearer <the service token>".

    hmac.compare_digest takes the same time however many characters match, so an
    attacker cannot find the token one character at a time by timing wrong guesses.
    (A plain == stops at the first different character, which is measurably faster.)
    """
    presented = ""
    if authorization_header is not None and authorization_header.startswith(SCHEME):
        presented = authorization_header[len(SCHEME):]
    return hmac.compare_digest(presented.encode("utf-8"), expected_token.encode("utf-8"))
