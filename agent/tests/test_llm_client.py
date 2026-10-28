"""The Ollama client: what it sends, and how every kind of bad reply becomes one LlmError.
The network is replaced by httpx's MockTransport: no real model is involved."""

import json
from collections.abc import Callable

import httpx
import pytest

from app.llm import MAX_REPLY_BYTES, LlmError, OllamaModel

URL = "http://127.0.0.1:11434"
TOOLS = [{"type": "function", "function": {"name": "correlate_events", "parameters": {"type": "object"}}}]


def model_answering(handler: Callable[[httpx.Request], httpx.Response]) -> OllamaModel:
    return OllamaModel(URL, "qwen3:8b", transport=httpx.MockTransport(handler))


def reply(message: dict[str, object], **extra: object) -> httpx.Response:
    return httpx.Response(200, json={"message": message, "done_reason": "stop", **extra})


def test_the_request_asks_for_one_complete_answer_without_thinking_and_without_randomness() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return reply({"role": "assistant", "content": "", "tool_calls": []})

    model_answering(handler).chat([{"role": "user", "content": "hi"}], TOOLS, timeout=5)

    assert str(sent[0].url) == f"{URL}/api/chat"
    body = json.loads(sent[0].content)
    assert (body["model"], body["stream"], body["think"]) == ("qwen3:8b", False, False)
    assert body["options"]["temperature"] == 0 and body["options"]["num_predict"] == 512
    assert body["tools"] == TOOLS


def test_tool_calls_are_read_whether_arguments_come_as_an_object_or_as_text() -> None:
    calls = [{"function": {"name": "reputation_lookup", "arguments": {"indicatorType": "ip", "value": "192.0.2.1"}}},
             {"function": {"name": "pattern_match", "arguments": "{\"target\": \"all\"}"}},
             {"function": {"name": "correlate_events", "arguments": ""}}]
    model = model_answering(lambda _: reply({"role": "assistant", "content": "", "tool_calls": calls},
                                            prompt_eval_count=300, eval_count=40))

    answer = model.chat([], TOOLS, timeout=5)

    assert [(c.name, c.arguments) for c in answer.tool_calls] == [
        ("reputation_lookup", {"indicatorType": "ip", "value": "192.0.2.1"}),
        ("pattern_match", {"target": "all"}),
        ("correlate_events", {})]
    assert answer.tokens == 340 and not answer.has_text
    assert answer.message["role"] == "assistant" and answer.message["tool_calls"] == calls


def refuse_with(error: Exception) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error
    return handler


@pytest.mark.parametrize(("handler", "message"), [
    (lambda _: httpx.Response(500, text="boom"), "service answered with status 500"),
    (refuse_with(httpx.ConnectError("refused")), "could not be reached (is Ollama running?)"),
    (refuse_with(httpx.ReadTimeout("slow")), "took too long to answer"),
    (lambda _: httpx.Response(200, text="not json"), "sent a reply that was not valid JSON"),
    (lambda _: httpx.Response(200, json={"done": True}), "sent a reply without a message"),
    (lambda _: httpx.Response(200, json=["a list"]), "sent a reply without a message"),
    (lambda _: reply({"content": "Hello, how are"}, done_reason="length"), "wrote a reply that was cut off"),
    (lambda _: reply({"tool_calls": [{"name": "no function wrapper"}]}), "asked for a tool in an unreadable form"),
    (lambda _: reply({"tool_calls": [{"function": {"name": 7}}]}), "asked for a tool in an unreadable form"),
    (lambda _: reply({"tool_calls": [{"function": {"name": "x", "arguments": "{oops"}}]}),
     "sent tool arguments that are not valid JSON"),
    (lambda _: httpx.Response(200, content=b"x" * (MAX_REPLY_BYTES + 1)), "sent a reply that was too large"),
])
def test_every_kind_of_bad_reply_is_one_llm_error_in_our_own_words(
        handler: Callable[[httpx.Request], httpx.Response], message: str) -> None:
    with pytest.raises(LlmError) as error:
        model_answering(handler).chat([], TOOLS, timeout=5)

    assert str(error.value) == message
