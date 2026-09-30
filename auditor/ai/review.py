"""Orchestration for the AI review layer.

Findings in, validated and grounded narratives out. It batches the
findings, builds a prompt per batch, calls the selected provider, runs each
raw response through the strict schema, then checks every surviving
narrative against the findings of its own batch.

Batching is cost and quality control in one. A 500-finding audit sent as a
single prompt is slow, expensive, more likely to hit a context limit, and
more likely to come back with the model quietly dropping findings it lost
track of. Small batches fail smaller and cost less.

Nothing here trusts the model. Two independent gates stand between raw
model output and anything a user sees, and both are enforced in code.
"""

from __future__ import annotations

from auditor.ai.grounding import GroundingResult, check_grounding, merge
from auditor.ai.prompt import build_prompt
from auditor.ai.providers import get_provider
from auditor.ai.schema import parse_response

DEFAULT_BATCH_SIZE = 20


def batch_findings(findings, size=DEFAULT_BATCH_SIZE):
    """Split findings into fixed-size batches."""
    if size < 1:
        raise ValueError("batch size must be at least 1")
    findings = list(findings)
    return [findings[i : i + size] for i in range(0, len(findings), size)]


def review_findings_detailed(
    findings,
    provider=None,
    provider_name=None,
    batch_size=DEFAULT_BATCH_SIZE,
):
    """Return a GroundingResult for a list of deterministic findings.

    Use this when the caller needs to know what was rejected and why, for
    reporting or for the eval harness. With no findings, no call is made:
    an empty input has an empty answer and there is no reason to spend a
    request on it.
    """
    findings = list(findings)
    if not findings:
        return GroundingResult()

    if provider is None:
        provider = get_provider(provider_name)

    results = []
    for batch in batch_findings(findings, batch_size):
        prompt = build_prompt(batch)
        raw = provider.generate(prompt)
        narratives = parse_response(raw)
        results.append(check_grounding(narratives, batch))

    return merge(results)


def review_findings(
    findings,
    provider=None,
    provider_name=None,
    batch_size=DEFAULT_BATCH_SIZE,
):
    """Return only the narratives that passed schema and grounding checks."""
    result = review_findings_detailed(
        findings,
        provider=provider,
        provider_name=provider_name,
        batch_size=batch_size,
    )
    return result.accepted