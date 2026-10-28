"""The daily cap on model use (ADR-15). With a local model this protects time and the
graphics card rather than money: a flood of incidents cannot keep the model busy all day.
Over the cap, investigations still run, with the fixed plan.

Counted in memory and reset each day (UTC); restarting the agent also resets it.
"""

import threading
from collections.abc import Callable
from datetime import UTC, date, datetime

MAX_INVESTIGATIONS_PER_DAY = 200
MAX_TOKENS_PER_DAY = 2_000_000


def today_utc() -> date:
    return datetime.now(UTC).date()


class DailyBudget:
    def __init__(self, max_investigations: int = MAX_INVESTIGATIONS_PER_DAY, max_tokens: int = MAX_TOKENS_PER_DAY,
                 today: Callable[[], date] = today_utc) -> None:
        self.max_investigations = max_investigations
        self.max_tokens = max_tokens
        self.today = today
        self.lock = threading.Lock()   # investigations run on several threads at once
        self.day = today()
        self.investigations = 0
        self.tokens = 0

    def _roll_over(self) -> None:
        if self.today() != self.day:
            self.day, self.investigations, self.tokens = self.today(), 0, 0

    def try_start(self) -> bool:
        """Counts one investigation if today's budget allows it."""
        with self.lock:
            self._roll_over()
            if self.investigations >= self.max_investigations or self.tokens >= self.max_tokens:
                return False
            self.investigations += 1
            return True

    def spend(self, tokens: int) -> None:
        with self.lock:
            self._roll_over()
            self.tokens += max(tokens, 0)

    def tokens_left(self) -> bool:
        with self.lock:
            self._roll_over()
            return self.tokens < self.max_tokens


BUDGET = DailyBudget()
