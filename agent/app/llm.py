"""Talking to the language model (ADR-15): a local model served by Ollama, on this machine.

The model's replies are treated like anything else from outside: their size is capped, their
shape is checked, and any problem (not running, too slow, an odd reply) becomes one
`LlmError`, after which the fixed plan finishes the investigation.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

# A reply bigger than this is not a reply we want: refuse it rather than read it.
MAX_REPLY_BYTES = 256 * 1024
# The most the model may write in one turn (a tool call is a few dozen tokens).
MAX_REPLY_TOKENS = 512
# How much text the model can hold at once. Large enough for the incident plus eight turns,
# small enough to fit next to the model in an 8 GB graphics card.
CONTEXT_TOKENS = 12288


class LlmError(Exception):
    """The model could not give a usable answer. The message is ours, never the model's, and
    completes the sentence "The AI model ...", e.g. "took too long to answer"."""


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: object   # unchecked: whatever the model sent; checked by the caller


@dataclass(frozen=True)
class Reply:
    tool_calls: list[ToolCall]
    has_text: bool
    tokens: int
    # The reply as the model sent it, to be sent back in the conversation history.
    message: dict[str, Any] = field(default_factory=dict)


class ChatModel(Protocol):
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], timeout: float) -> Reply: ...


class OllamaModel:
    def __init__(self, url: str, model: str, transport: httpx.BaseTransport | None = None) -> None:
        self.url = url
        self.model = model
        self.transport = transport   # tests replace the network with a fake

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], timeout: float) -> Reply:
        body = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            # No long "thinking out loud": the same tool choices, about nine times faster.
            "think": False,
            "options": {"temperature": 0, "num_predict": MAX_REPLY_TOKENS, "num_ctx": CONTEXT_TOKENS},
        }
        try:
            with httpx.Client(transport=self.transport, timeout=timeout) as client:
                with client.stream("POST", f"{self.url}/api/chat", json=body) as response:
                    if response.status_code != 200:
                        raise LlmError(f"service answered with status {response.status_code}")
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw += chunk
                        if len(raw) > MAX_REPLY_BYTES:
                            raise LlmError("sent a reply that was too large")
        except httpx.TimeoutException:
            raise LlmError("took too long to answer") from None
        except httpx.HTTPError:
            raise LlmError("could not be reached (is Ollama running?)") from None
        return parse_reply(bytes(raw))


def parse_reply(raw: bytes) -> Reply:
    try:
        data = json.loads(raw)
    except ValueError:
        raise LlmError("sent a reply that was not valid JSON") from None
    message = data.get("message") if isinstance(data, dict) else None
    if not isinstance(message, dict):
        raise LlmError("sent a reply without a message")
    if data.get("done_reason") == "length":
        raise LlmError("wrote a reply that was cut off")

    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function") if isinstance(call, dict) else None
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise LlmError("asked for a tool in an unreadable form")
        arguments = function.get("arguments", {})
        if isinstance(arguments, str):   # some models send the arguments as a JSON string
            try:
                arguments = json.loads(arguments) if arguments.strip() else {}
            except ValueError:
                raise LlmError("sent tool arguments that are not valid JSON") from None
        calls.append(ToolCall(function["name"], arguments))

    tokens = sum(n for n in (data.get("prompt_eval_count"), data.get("eval_count")) if isinstance(n, int))
    text = message.get("content")
    return Reply(tool_calls=calls, has_text=isinstance(text, str) and bool(text.strip()), tokens=tokens,
                 message={"role": "assistant", "content": text if isinstance(text, str) else "",
                          "tool_calls": message.get("tool_calls") or []})
