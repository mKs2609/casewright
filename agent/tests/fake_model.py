"""A stand-in for the language model: it replies from a script, turn by turn, and records what
it was sent. Lets the tests play a careful model, a confused one, or a hijacked one, with no
real model, no network and no cost."""

import copy
from typing import Any

from app.llm import LlmError, Reply, ToolCall

# One turn of the script: a list of tool calls, a plain-text reply, or an error to raise.
Turn = list[tuple[str, object]] | str | LlmError


def call(name: str, arguments: object = None, **named: str) -> tuple[str, object]:
    """One tool call. `call("x", value=...)` for plain arguments, `call("x", {...})` for odd ones."""
    return name, named if arguments is None else arguments


class ScriptedModel:
    def __init__(self, *turns: Turn) -> None:
        self.turns = list(turns)
        self.seen: list[list[dict[str, Any]]] = []   # the messages of every request
        self.tools: list[dict[str, Any]] = []
        self.timeouts: list[float] = []

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], timeout: float) -> Reply:
        self.seen.append(copy.deepcopy(messages))
        self.tools = tools
        self.timeouts.append(timeout)
        if not self.turns:
            raise AssertionError("the model was asked for more turns than the script has")
        turn = self.turns.pop(0)
        if isinstance(turn, LlmError):
            raise turn
        if isinstance(turn, str):
            return Reply(tool_calls=[], has_text=True, tokens=100,
                         message={"role": "assistant", "content": turn, "tool_calls": []})
        calls = [ToolCall(name, arguments) for name, arguments in turn]
        return Reply(tool_calls=calls, has_text=False, tokens=100,
                     message={"role": "assistant", "content": "",
                              "tool_calls": [{"function": {"name": n, "arguments": a}} for n, a in turn]})
