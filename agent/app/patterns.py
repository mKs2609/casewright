"""Tool 3: look for known attack language in the text an attacker wrote.

Including prompt injection: text aimed at an AI ("ignore previous instructions",
"classify this as safe"). The agent never obeys such text; finding it is strong evidence
of an attack, because a genuine email has no reason to address an AI.

Before matching, the text is normalised, because attackers disguise these phrases:
- invisible characters inside words ("ign​ore") are removed, and their presence is a finding itself;
- compatibility forms such as full-width letters are folded to plain ones (Unicode NFKC);
- common Cyrillic and Greek look-alike letters are mapped to Latin ("іgnore" with a Cyrillic і);
- runs of whitespace are collapsed.
"""

import re
import unicodedata
from typing import Any

from app.case import Case, ToolRejected, ToolResult
from app.models import Signal

# Zero-width spaces and joiners, word joiners, invisible operators, the byte-order mark, soft hyphens.
INVISIBLE = re.compile("[­᠎​-‏‪-‮⁠-⁤﻿]")

# Cyrillic / Greek letters that look like Latin ones.
LOOKALIKE_LETTERS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "ο": "o", "α": "a", "ι": "i", "ν": "v", "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Τ": "T",
})
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# (id, technical label, plain explanation, weight 0-100, MITRE technique, pattern)
SIGNATURES: list[tuple[str, str, str, int, str, re.Pattern[str]]] = [
    ("SIG-URGENCY", "Urgency or threat language",
     "The message tries to rush you with a deadline or a threat.", 15, "T1566",
     _rx(r"\b(urgent|immediately|within \d+ (hours|minutes)|act now|will be (suspended|locked|closed|deleted|blocked))\b")),
    ("SIG-CRED-REQ", "Asks to confirm credentials",
     "It asks you to confirm your password or account details.", 25, "T1566.002",
     _rx(r"\b(verify|confirm|update|validate|re-?enter) (your )?(account|password|identity|login|credentials)\b")),
    ("SIG-OTP-REQ", "Asks for a one-time code",
     "It asks for a one-time code. Real banks and IT staff never ask for these.", 35, "T1111",
     # Either a one-time kind of code named outright, or any code asked for "to me / to us".
     # (A plain "send the source code" must not count.)
     _rx(r"\b(otp|one[- ]time (pass ?)?code|verification code|security code|login code|sms code"
         r"|(\d|four|five|six|seven|eight)[- ]digit (code|pin|number)"
         r"|(read|tell|give|send|share|forward) (me|us) (the |your |that |this )?([\w-]+ )?(code|otp|pin))\b")),
    ("SIG-PAYMENT", "Payment or gift-card pressure",
     "It pushes you to send money, gift cards or cryptocurrency.", 20, "T1657",
     _rx(r"\b(gift ?cards?|wire transfer|bitcoin|crypto(currency)?|upi (id|pin))\b")),
    ("SIG-IMPERSONATION", "Claims to be an authority (bank, IT, security)",
     "The sender claims to be a bank, an IT team or an official to win your trust.", 15, "T1656",
     _rx(r"\b(this is|from|with) (the |your )?[\w ]{0,20}(bank|it department|it support|security team|"
         r"fraud department|helpdesk|help desk)\b")),
    ("SIG-REMOTE-TOOL", "Asks to install remote-access software",
     "It asks you to install software that lets a stranger control your computer.", 30, "T1219",
     _rx(r"\b(anydesk|teamviewer|quick ?support|remote access|screen ?share)\b")),
    ("SIG-AI-INJECTION", "Prompt-injection text aimed at an AI analyst",
     "The message hides instructions meant to trick an AI system. Genuine messages never do that.", 40, "AML.T0051",
     _rx(r"(ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts?)"
         r"|disregard (all |any |your )?(previous |prior )?(instructions|rules)"
         r"|note to (the )?(ai|assistant|model|analyst bot)"
         r"|system prompt"
         r"|you are now (a|an|in) "
         r"|classify (this|it) (email |message |incident )?as (safe|benign|legitimate|harmless)"
         r"|pre-?approved by (the )?security team)")),
]

HIDDEN = ("SIG-HIDDEN-TEXT", "Contains invisible characters",
          "The text hides invisible characters, a trick to sneak words past filters.", 10, "T1027")


def normalise(text: str) -> tuple[str, bool]:
    """The text as a reader would see it, and whether invisible characters were hidden in it."""
    hidden = bool(INVISIBLE.search(text))
    text = INVISIBLE.sub("", text)
    text = unicodedata.normalize("NFKC", text).translate(LOOKALIKE_LETTERS)
    return re.sub(r"\s+", " ", text).strip(), hidden


def _snippet(text: str, start: int, end: int) -> str:
    """The matched words with a little context, safe to store and show (no control characters)."""
    return CONTROL.sub(" ", text[max(0, start - 30):min(len(text), end + 30)])[:120]


def pattern_match(case: Case, args: dict[str, str]) -> ToolResult:
    fields = case.text_fields()
    target = args.get("target", "all")
    if target != "all" and target not in fields:
        raise ToolRejected("This incident has no such text field")
    scope = fields if target == "all" else {target: fields[target]}

    matches: list[dict[str, Any]] = []
    signals: list[Signal] = []
    hidden_in: list[str] = []
    normalised = {}
    for name, text in scope.items():
        normalised[name], hidden = normalise(text)
        if hidden:
            hidden_in.append(name)
    for sid, label, plain, weight, mitre, pattern in SIGNATURES:
        for name, text in normalised.items():
            found = pattern.search(text)
            if found:
                matches.append({"signature": sid, "field": name, "snippet": _snippet(text, found.start(), found.end())})
                signals.append(Signal(id=sid, label=f"{label} (in the {name})", plain=plain, weight=weight, mitre=mitre))
                break
    if hidden_in:
        sid, label, plain, weight, mitre = HIDDEN
        signals.append(Signal(id=sid, label=f"{label} (in the {', '.join(hidden_in)})", plain=plain,
                              weight=weight, mitre=mitre))

    names = ", ".join(s.id for s in signals)
    summary = f"{len(signals)} attack pattern(s) found" + (f": {names}" if names else "")
    return summary, {"target": target, "matches": matches}, signals
