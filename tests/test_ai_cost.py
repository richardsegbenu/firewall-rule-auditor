"""Tests for caching, call budgets, and batching.

Cost control is only real if it is enforced. These tests assert on how many
times the underlying provider was actually called, which is the thing that
costs money and quota.
"""

import json
from dataclasses import dataclass

import pytest

from auditor.ai import (
    BudgetedProvider,
    BudgetExceeded,
    CachingProvider,
    CallBudget,
    ResponseCache,
    batch_findings,
    cache_key,
    review_findings_detailed,
)
from auditor.ai.providers import Provider


@dataclass
class SampleFinding:
    finding_id: str
    severity: str
    message: str


class CountingProvider(Provider):
    name = "counting"
    model = "test-model"

    def __init__(self, response="", responses=None):
        self._response = response
        self._responses = list(responses) if responses else None
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        if self._responses:
            return self._responses.pop(0)
        return self._response


def _finding(fid="FW-001"):
    return SampleFinding(
        finding_id=fid,
        severity="critical",
        message="Any-any allow rule.",
    )


def _response(*ids):
    return json.dumps(
        {
            "narratives": [
                {
                    "finding_id": fid,
                    "summary": "An overly broad allow rule.",
                    "risk": "It removes the firewall as a control point.",
                    "recommendation": "Scope it to known services.",
                }
                for fid in ids
            ]
        }
    )


# --- cache keys ----------------------------------------------------------


def test_cache_key_is_stable():
    assert cache_key("gemini", "m", "prompt") == cache_key("gemini", "m", "prompt")


def test_cache_key_changes_with_prompt():
    assert cache_key("gemini", "m", "a") != cache_key("gemini", "m", "b")


def test_cache_key_changes_with_provider():
    assert cache_key("gemini", "m", "p") != cache_key("ollama", "m", "p")


def test_cache_key_changes_with_model():
    assert cache_key("gemini", "m1", "p") != cache_key("gemini", "m2", "p")


# --- cache behaviour -----------------------------------------------------


def test_second_identical_call_is_served_from_cache(tmp_path):
    inner = CountingProvider("hello")
    cache = ResponseCache(directory=tmp_path)
    provider = CachingProvider(inner, cache=cache)

    assert provider.generate("same prompt") == "hello"
    assert provider.generate("same prompt") == "hello"
    assert inner.calls == 1  # the expensive call happened once
    assert cache.stats == {"hits": 1, "misses": 1}


def test_different_prompts_are_not_shared(tmp_path):
    inner = CountingProvider("hello")
    provider = CachingProvider(inner, cache=ResponseCache(directory=tmp_path))
    provider.generate("prompt one")
    provider.generate("prompt two")
    assert inner.calls == 2


def test_disabled_cache_always_calls_through(tmp_path):
    inner = CountingProvider("hello")
    cache = ResponseCache(directory=tmp_path, enabled=False)
    provider = CachingProvider(inner, cache=cache)
    provider.generate("same prompt")
    provider.generate("same prompt")
    assert inner.calls == 2


def test_corrupt_cache_entry_degrades_to_a_miss(tmp_path):
    inner = CountingProvider("hello")
    cache = ResponseCache(directory=tmp_path)
    provider = CachingProvider(inner, cache=cache)
    provider.generate("same prompt")

    for path in tmp_path.glob("*.json"):
        path.write_text("not json at all", encoding="utf-8")

    assert provider.generate("same prompt") == "hello"
    assert inner.calls == 2  # recovered rather than raised


def test_cache_clear_removes_entries(tmp_path):
    inner = CountingProvider("hello")
    cache = ResponseCache(directory=tmp_path)
    provider = CachingProvider(inner, cache=cache)
    provider.generate("same prompt")
    cache.clear()
    provider.generate("same prompt")
    assert inner.calls == 2


# --- budget --------------------------------------------------------------


def test_budget_allows_calls_up_to_the_limit():
    inner = CountingProvider("ok")
    provider = BudgetedProvider(inner, budget=CallBudget(max_calls=2))
    provider.generate("a")
    provider.generate("b")
    assert inner.calls == 2


def test_budget_blocks_the_call_over_the_limit():
    inner = CountingProvider("ok")
    provider = BudgetedProvider(inner, budget=CallBudget(max_calls=1))
    provider.generate("a")
    with pytest.raises(BudgetExceeded):
        provider.generate("b")
    assert inner.calls == 1  # the blocked call never reached the backend


def test_budget_blocks_an_oversized_prompt():
    inner = CountingProvider("ok")
    provider = BudgetedProvider(inner, budget=CallBudget(max_prompt_chars=10))
    with pytest.raises(BudgetExceeded):
        provider.generate("x" * 11)
    assert inner.calls == 0


def test_budget_reports_usage():
    budget = CallBudget(max_calls=5)
    provider = BudgetedProvider(CountingProvider("ok"), budget=budget)
    provider.generate("abc")
    assert budget.stats == {"calls": 1, "remaining": 4, "chars_sent": 3}


def test_cache_hit_does_not_spend_budget(tmp_path):
    # Order matters: the cache wraps the budget, so a hit returns before
    # the budget is consulted. Wrapped the other way round, every repeat
    # prompt would still burn quota it never actually used.
    budget = CallBudget(max_calls=1)
    inner = CountingProvider("ok")
    provider = CachingProvider(
        BudgetedProvider(inner, budget=budget),
        cache=ResponseCache(directory=tmp_path),
    )
    provider.generate("same")
    provider.generate("same")
    assert inner.calls == 1
    assert budget.calls == 1  # the cached call cost nothing


# --- batching ------------------------------------------------------------


def test_batch_findings_splits_evenly():
    batches = batch_findings([_finding(str(i)) for i in range(5)], size=2)
    assert [len(b) for b in batches] == [2, 2, 1]


def test_batch_findings_rejects_zero_size():
    with pytest.raises(ValueError):
        batch_findings([_finding()], size=0)


def test_review_batches_large_input():
    findings = [_finding("FW-001"), _finding("FW-002"), _finding("FW-003")]
    provider = CountingProvider(
        responses=[_response("FW-001", "FW-002"), _response("FW-003")]
    )
    result = review_findings_detailed(findings, provider=provider, batch_size=2)
    assert provider.calls == 2
    assert len(result.accepted) == 3


def test_batches_are_grounded_independently():
    findings = [_finding("FW-001"), _finding("FW-002")]
    provider = CountingProvider(
        responses=[_response("FW-001"), _response("FW-999")]
    )
    result = review_findings_detailed(findings, provider=provider, batch_size=1)
    assert len(result.accepted) == 1
    assert len(result.rejected) == 1