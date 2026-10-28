"""The daily cap on model use."""

from datetime import date

from app.budget import DailyBudget


def test_investigations_are_counted_up_to_the_daily_limit() -> None:
    budget = DailyBudget(max_investigations=2, max_tokens=1000)

    assert [budget.try_start() for _ in range(3)] == [True, True, False]


def test_tokens_are_counted_and_no_investigation_starts_once_they_run_out() -> None:
    budget = DailyBudget(max_investigations=10, max_tokens=1000)
    assert budget.try_start()

    budget.spend(999)
    assert budget.tokens_left()
    budget.spend(1)

    assert not budget.tokens_left() and not budget.try_start()


def test_a_negative_count_cannot_give_tokens_back() -> None:
    budget = DailyBudget(max_tokens=100)
    budget.spend(100)
    budget.spend(-50)

    assert not budget.tokens_left()


def test_the_budget_starts_again_each_day() -> None:
    day = [date(2026, 10, 29)]
    budget = DailyBudget(max_investigations=1, max_tokens=100, today=lambda: day[0])
    assert budget.try_start()
    budget.spend(100)
    assert not budget.try_start()

    day[0] = date(2026, 10, 30)

    assert budget.tokens_left() and budget.try_start()
