"""Recognising a request by its shape (ADR-65): an instruction to the listener, a request verb,
and something valuable, in one clause. Warnings, promises and ordinary requests must not count."""

import pytest

from app.patterns import ASKS
from app.request_shape import KINDS, SHAPES, asked_for, clauses, describe, shape_kinds


@pytest.mark.parametrize(("text", "kind"), [
    # money: an amount, the money itself, or "it" going to someone else's account
    ("Please release Rs 6,50,000 to the account I'm sending you.", "money"),
    ("You can start with only Rs 50,000.", "money"),
    ("Please send it to my friend's account now.", "money"),
    ("Just transfer the full amount to this account.", "money"),
    ("You need to deposit ₹2,000 first.", "money"),
    ("Could you pay Rs. 750 today?", "money"),
    ("Invest twenty thousand and watch it grow.", "money"),
    ("Move your savings to the holding account.", "money"),
    # code: one sent to the phone, or one an app shows
    ("For verification just read me the code we sent.", "code"),
    ("Give me the ID it shows.", "code"),
    ("Can you tell me the number that appears on the screen? Tell me the number it shows.", "code"),
    ("Kindly share the OTP.", "code"),
    # details
    ("For verification just read the 16 digits on the front.", "details"),
    ("Tell me your Aadhaar number and date of birth.", "details"),
    ("Enter your PIN to receive the money.", "details"),
    ("Read out the numbers on the back of the card.", "details"),
    ("I just need your bank account number.", "details"),
    ("Please confirm your card number and expiry date.", "details"),
    # approval
    ("Just tap approve so I can finish.", "approval"),
    ("Press accept on the request.", "approval"),
    ("Please approve the sign-in request on your phone.", "approval"),
    ("You need to click yes on the pop-up.", "approval"),
    # install
    ("Download the support app there.", "install"),
    ("Please install this small tool from the website.", "install"),
    ("You have to install the security application now.", "install"),
])
def test_a_request_is_recognised_by_its_shape(text: str, kind: str) -> None:
    assert kind in shape_kinds(text)


@pytest.mark.parametrize("text", [
    # warnings: a "don't" or "never" stands in front of the verb
    "Don't pay any fee to anyone who calls.",
    "We'll never ask you to read out a code.",
    "Never approve a prompt you didn't start.",
    "No need to send me any login details.",
    "You don't need to give us anything.",
    "Please don't share your OTP with anyone.",
    # promises: the money or the action goes the other way
    "I'll transfer Rs 5,000 to you tonight.",
    "We will pay the full amount next week.",
    "We've approved the renewal.",
    "I'll send you the link to download our app.",
    # money paid face to face, or to the caller's own account they always use
    "You can pay Rs 499 cash on delivery.",
    "Please pay Rs 200 at the counter.",
    "Just send it to my UPI whenever.",
    "You can pay it through your normal purchase order process.",
    # ordinary requests about ordinary things
    "Please send the report by 5.",
    "Can you send the updated pricing sheet today?",
    "Could you review slides six through eight?",
    "Please confirm your appointment for Thursday.",
    "Please bring your PAN card to the branch.",
    "Read me the zip code on the parcel.",
    "Send me the source code when it's ready.",
    "Please download the agenda before the meeting.",
    "Ring the number on the back of your card.",
    "You can renew on the insurer's website or app with your policy number.",
    # the verb and the valuable thing are in different clauses
    "Please send the report. The money arrived fine.",
    "Read the notice, and the code of conduct is attached.",
])
def test_warnings_promises_and_ordinary_requests_are_not_requests(text: str) -> None:
    assert shape_kinds(text) == set()


def test_clauses_split_at_sentences_commas_and_and_but_not_inside_amounts() -> None:
    assert clauses("Caller: Please pay Rs. 6,50,000 now, then tap approve and wait.") == [
        "Caller", "Please pay Rs. 6,50,000 now", "then tap approve", "wait"]


def test_disguised_letters_are_normalised_first() -> None:
    # A Cyrillic "а" and an invisible space inside the verb change nothing.
    assert shape_kinds("Just tаp appr​ove now.") == {"approval"}


def test_asked_for_joins_the_shapes_and_the_keyword_rules_in_a_fixed_order() -> None:
    # "Install AnyDesk" is only known to a keyword rule (no "app" in it); the code is a shape.
    assert asked_for("Install AnyDesk now. Then give me the ID it shows.") == ["code", "install"]
    assert asked_for("Your parcel arrives tomorrow.") == []


def test_every_keyword_request_and_every_shape_has_a_known_kind() -> None:
    assert set(ASKS.values()) <= set(KINDS)
    assert set(SHAPES) == set(KINDS)


def test_the_kinds_read_as_one_phrase() -> None:
    assert describe(["money"]) == "send money"
    assert describe(["money", "code", "approval"]) == \
        "send money, read out a code and approve something on their phone"
    assert describe(["approval"], to_you=True) == "approve something on your phone"
