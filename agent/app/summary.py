"""The AI summary line (step 13, ADR-45): one sentence the model writes for the SOC report,
after all the evidence is in.

This is the only place where the model's own words become part of the output, so the line
is kept only if it passes every check below; otherwise it is left out (never "fixed"), and
the reason, in our words, goes into the live notes. It appears in the SOC report only,
labelled as the AI's; the employee's plain report is written entirely by code.
"""

import re
from typing import Any

from app.budget import DailyBudget
from app.case import Case
from app.llm import ChatModel, LlmError
from app.models import Signal
from app.reasoning import fence
from app.tools import INDICATOR_TYPES

MAX_CHARS = 200
TIME_LIMIT_SECONDS = 30

SUMMARY_PROMPT = """You write a one-sentence summary of a finished security investigation, for a security analyst.
Rules:
- One sentence, at most 200 characters.
- Cite the evidence labels you rely on in square brackets, like [E2].
- Describe only the findings you are given. Do not add facts.
- Never include a name, address, website, link, email address, phone number or quotation; say "the user",
  "the website", "the caller" instead."""

# [E2], or several in one bracket: [E2, E1, E3]
CITATION = re.compile(r"\[(E[1-9][0-9]{0,2}(?:, ?E[1-9][0-9]{0,2})*)\]")
SENTENCE_END = re.compile(r"[.!?](\s|$)")
# Things that must never reach a report through the model: links, addresses, numbers.
LOOKS_LIKE_INDICATOR = [
    re.compile(r"https?://|www\.", re.IGNORECASE),
    re.compile(r"\S@\S"),
    re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"),
    re.compile(r"\+?\d[\d ().-]{6,}\d"),
    re.compile(r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.IGNORECASE),
]
# Words that would tell an analyst "nothing to see" about an incident the evidence says is not benign.
# ("legitimate" is not among them: the live model used it for the brand a website imitates.)
REASSURING = re.compile(r"\b(safe|benign|harmless|no threat|not malicious|nothing suspicious"
                        r"|false positive|no risk)\b", re.IGNORECASE)
COPY_RUN = 4   # this many words in a row from the incident counts as copying it


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9']+", text.lower())


def _runs(words: list[str]) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + COPY_RUN]) for i in range(len(words) - COPY_RUN + 1)}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


# What the model is shown instead of each value, so it cannot copy one into the line.
MASKS = [
    (re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE), "a link"),
    (re.compile(r"\S+@\S+"), "an email address"),
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), "an internet address"),
    (re.compile(r"\+?\d[\d ().-]{6,}\d"), "a phone number"),
    (re.compile(r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.IGNORECASE), "a website"),
]


def masked(label: str, case: Case) -> str:
    """A finding's label with people's usernames and every address, link and number replaced
    by a plain description. Seen in the live run: shown the values, the model copies them."""
    for identity in sorted(case.identities, key=len, reverse=True):
        label = re.sub(rf"\b{re.escape(identity)}\b", "the user", label)
    for pattern, words in MASKS:
        label = pattern.sub(words, label)
    return label


def check(line: str, case: Case, findings: list[tuple[str, Signal]], evidence: set[str],
          final: str) -> tuple[str | None, str]:
    """The line if it passes every check, otherwise None and the reason (in our words)."""
    line = line.strip()
    if not line or re.search(r"[\x00-\x1f\x7f]", line):   # control characters include line breaks
        return None, "it is not a single line of text"
    if "<" in line or ">" in line:
        return None, "it contains markup"
    if len(line) > MAX_CHARS:
        return None, f"it is longer than {MAX_CHARS} characters"
    if len(SENTENCE_END.findall(line)) > 1:
        return None, "it is more than one sentence"
    cited = [label.strip() for group in CITATION.findall(line) for label in group.split(",")]
    if not cited:
        return None, "it cites no evidence"
    if not set(cited) <= evidence:
        return None, "it cites evidence that does not exist"
    lowered = line.lower()
    values = [v.lower() for t in INDICATOR_TYPES for v in case.indicators.of_type(t)]
    if any(v in lowered for v in values) or any(p.search(line) for p in LOOKS_LIKE_INDICATOR):
        return None, "it contains an address, link or number"
    ours = _runs([w for _, s in findings for w in _words(masked(s.label, case))])
    theirs = _runs([w for text in _strings(case.incident.payload) for w in _words(text)])
    if (_runs(_words(line)) & theirs) - ours:
        return None, "it copies words from the incident"
    if final != "benign" and REASSURING.search(line):
        return None, "it contradicts the verdict"
    return line, ""


def write(case: Case, findings: list[tuple[str, Signal]], evidence: set[str], final: str, attack: str,
          score: int, model: ChatModel, budget: DailyBudget) -> tuple[str | None, str]:
    """Asks the model for the line and checks it. Returns (line, "") or (None, why it was left out)."""
    if not findings:
        return None, "there are no findings to summarise"
    if not budget.tokens_left():
        return None, "the model reached today's usage limit"
    facts = {"verdict": final, "attackType": attack, "riskScore": score,
             "findings": [{"evidence": label, "finding": masked(s.label, case)} for label, s in findings]}
    messages = [{"role": "system", "content": SUMMARY_PROMPT},
                {"role": "user", "content": f"<findings>{fence(facts)}</findings>\nWrite the sentence."}]
    try:
        reply = model.chat(messages, [], timeout=TIME_LIMIT_SECONDS)
    except LlmError as error:
        return None, f"the model {error}"
    budget.spend(reply.tokens)
    text = reply.message.get("content")
    if reply.tool_calls or not isinstance(text, str):
        return None, "the model did not write a sentence"
    return check(text, case, findings, evidence, final)
