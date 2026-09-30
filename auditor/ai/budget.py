"""Call budgets for the AI review layer.

A free tier is a hard limit, not a soft one, and a loop bug that fires a
thousand requests is a realistic failure. The budget makes the limit
explicit and enforced in code: when it is reached the run stops with a
clear error rather than quietly hammering an API.

Like the cache, this is a wrapper around the Provider interface. Every
backend is budgeted without either backend knowing about it.
"""

from __future__ import annotations

from auditor.ai.providers import Provider

_DEFAULT_MAX_CALLS = 50
_DEFAULT_MAX_PROMPT_CHARS = 100_000


class BudgetExceeded(RuntimeError):
    """Raised when a run would exceed its configured limits."""


class CallBudget:
    """Tracks and enforces per-run limits on model calls."""

    def __init__(self, max_calls=None, max_prompt_chars=None):
        self.max_calls = (
            _DEFAULT_MAX_CALLS if max_calls is None else max_calls
        )
        self.max_prompt_chars = (
            _DEFAULT_MAX_PROMPT_CHARS
            if max_prompt_chars is None
            else max_prompt_chars
        )
        self.calls = 0
        self.chars_sent = 0

    def check(self, prompt: str):
        """Raise if this prompt would breach a limit. Call before sending."""
        if self.calls >= self.max_calls:
            raise BudgetExceeded(
                f"call budget of {self.max_calls} reached"
            )
        if len(prompt) > self.max_prompt_chars:
            raise BudgetExceeded(
                f"prompt of {len(prompt)} chars exceeds the "
                f"{self.max_prompt_chars} char limit"
            )

    def record(self, prompt: str):
        self.calls += 1
        self.chars_sent += len(prompt)

    @property
    def remaining(self):
        return max(0, self.max_calls - self.calls)

    @property
    def stats(self):
        return {
            "calls": self.calls,
            "remaining": self.remaining,
            "chars_sent": self.chars_sent,
        }


class BudgetedProvider(Provider):
    """Wraps any Provider and refuses calls that breach the budget."""

    def __init__(self, inner, budget=None):
        self.inner = inner
        self.budget = budget if budget is not None else CallBudget()
        self.name = f"{inner.name}+budget"

    @property
    def model(self):
        return getattr(self.inner, "model", "")

    def generate(self, prompt: str) -> str:
        self.budget.check(prompt)
        response = self.inner.generate(prompt)
        self.budget.record(prompt)
        return response