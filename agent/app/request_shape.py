"""Recognising what a caller asks for by the shape of the request, not its exact words (ADR-65).

The keyword rules in `patterns` know a request only when it is phrased the way the rule
expects ("tell me the OTP"). Scammers ask in endless other ways ("read the three small
numbers on the back", "just tap approve"). What every request has in common is its shape:

    an instruction to the listener  +  a request verb  +  something valuable

- The instruction: the clause starts as an order ("Send...", "Please read...", "Just tap..."),
  optionally after a request frame ("you need to...", "can you...", "I need you to...").
  Because the clause must START that way, warnings ("don't pay any fee", "we'll never ask
  you to read out a code") and promises ("I'll send it", "we'll pay you") never match:
  there is a subject or a "don't" in front of the verb.
- The verb and the valuable thing decide the kind of request: money, a code, private
  details, approving a prompt, or installing an app.

The text is cut into clauses first (sentences, then commas, "and", "then"), so the verb
and the valuable thing must be in the same clause.

Only the kinds are returned, never the caller's words (they are attacker-written).
"""

import re

from app import patterns

# The kinds of request, in the order advice about them is given.
KINDS = ("money", "code", "details", "approval", "install")


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Clause boundaries: line breaks, sentence ends (not the dot in "Rs. 500"), ", ", and/then.
# A comma inside a number ("Rs 6,50,000") has no space after it, so it does not split.
_CLAUSES = _rx(r"\n|(?<!\brs)[.!?;:]+(?:\s+|$)|,\s+|\s+(?:and then|and|then)\s+")

# Words that may come before the instruction without changing who acts: politeness,
# order, a purpose ("for verification", "to unblock it").
_LEAD = (r"(?:(?:please|kindly|just|simply|now|first|then|so|also|quickly|only|ok(?:ay)?|sir|madam|ma['’]?am"
         r"|for \w+|to \w+(?: \w+)?)\s+)*")
# Ways of asking that put the listener in front of the verb.
_FRAME = (r"(?:you(?: \w+)? (?:need to|have to|must|should|can|could|will need to|['’]ll need to)"
          r"|(?:can|could|would|will) you(?: please| just| kindly)?"
          r"|(?:i|we) (?:need|want|would like) you to)\s+")
_START = rf"^{_LEAD}(?:{_FRAME}{_LEAD})?"

# Money: an amount with a currency (a bare number is often a time or a date), or money itself.
_MONEY = (r"(?:\brs\.? ?\d|₹ ?\d|\$ ?\d|\binr\b|\busd\b|\d[\d,]* (?:rupees|dollars)\b|\b(?:lakh|crore|thousand)s?\b"
          r"|\bthe money\b|\byour (?:savings|balance|salary)\b|\bthe (?:full |whole )?(?:amount|balance)\b|\bfees?\b)")
# Someone else's account, or one the caller will send: "my friend's account", "this number".
# "Send it to my UPI, same as last time" is the caller's own and does not count.
_ELSEWHERE = (r"(?:(?:my|our|his|her) \w+['’]s|this|that|a|another|a new|the new|our new|the following)"
              r" (?:\w+ )?(?:account|number|upi(?: id)?|wallet)\b")
# Paying face to face is not something a phone scam can collect.
_IN_PERSON = _rx(r"\b(?:cash|in person|at the (?:door|gate|counter|desk|branch|office|shop|store|reception))\b")

_GIVE = r"(?:read|tell|give|share|send|forward|say|repeat|confirm|enter|type|provide)(?: out)?(?: (?:me|us|it to me))?\b"
# A code: one sent to the phone, or one an app shows ("give me the ID it shows").
_CODE = (r"(?<!source )(?<!zip )(?<!postal )(?<!promo )(?<!discount )(?<!dress )(?<!qr )"
         r"\b(?:otp|codes?|one[- ]time \w+|(?:id|number|code)s? (?:it|that) (?:shows|appears|comes))\b")
_DETAILS = (r"\b(?:pin|password|passcode|cvv|expiry(?: date)?|card (?:number|details)|account (?:number|details)"
            r"|bank details|aadhaar|pan (?:card|number)|date of birth|passport number|maiden name"
            r"|\d+ digits|(?:numbers?|digits) on the (?:front|back)|login details|net ?banking)\b")

SHAPES: dict[str, re.Pattern[str]] = {
    "money": _rx(_START + r"(?:(?:pay|send|transfer|deposit|move|release|return|invest|put in|start with|top up)\b"
                 rf"[\w '’-]{{0,40}}?{_MONEY}"
                 rf"|(?:pay|send|transfer|move|return)(?: it| that| the rest)?(?: back)? to {_ELSEWHERE})"),
    "code": _rx(_START + _GIVE + r"[\w '’-]{0,30}?" + _CODE),
    "details": _rx(_START + rf"(?:{_GIVE}[\w '’-]{{0,30}}?|(?:i|we) (?:just |only )?need your [\w '’-]{{0,20}}?)"
                   + _DETAILS),
    "approval": _rx(_START + r"(?:(?:tap|press|click|hit|select|choose) (?:on )?[\"'“]?(?:approve|accept|allow|yes|confirm)\b"
                    r"|(?:approve|accept|allow) (?:the|this|that)(?: \w+)? "
                    r"(?:request|prompt|notification|pop-?up|sign-?in|login)\b)"),
    "install": _rx(_START + r"(?:download|install)\b[\w '’-]{0,30}?\b(?:app|apk|application|software|program|tool)\b"),
}


def clauses(text: str) -> list[str]:
    """The text cut into clauses, after the same normalising as the keyword rules."""
    normal = "\n".join(patterns.normalise(line)[0] for line in text.splitlines())
    return [c.strip() for c in _CLAUSES.split(normal) if c and c.strip()]


def shape_kinds(text: str) -> set[str]:
    """The kinds of request whose shape appears in the text."""
    found: set[str] = set()
    for clause in clauses(text):
        for kind, shape in SHAPES.items():
            if shape.search(clause) and not (kind == "money" and _IN_PERSON.search(clause)):
                found.add(kind)
    return found


def asked_for(text: str) -> list[str]:
    """Every kind of request in the text: by its shape, or by a keyword rule in `patterns.ASKS`."""
    found = shape_kinds(text) | {patterns.ASKS[sid] for sid in patterns.asks(text)}
    return [kind for kind in KINDS if kind in found]


# How each kind reads in a finding: "asks them to send money and read out a code".
_DOING = {"money": "send money", "code": "read out a code", "details": "give private details",
          "approval": "approve something on their phone", "install": "install an app"}
_DOING_YOU = {**_DOING, "approval": "approve something on your phone"}


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def describe(kinds: list[str], *, to_you: bool = False) -> str:
    """The kinds as words, for findings ("send money and read out a code")."""
    words = _DOING_YOU if to_you else _DOING
    return _join([words[k] for k in kinds])
