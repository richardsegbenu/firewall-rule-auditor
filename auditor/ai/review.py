"""Orchestration for the AI review layer.

This is the wiring: findings in, validated narratives out. It builds the
prompt, calls the selected provider, and runs the raw response through the
strict schema. Nothing here trusts the model: the return value is only ever
a list of schema-validated ReviewNarrative objects, or it raises.

Grounding (rejecting narratives that cite findings that do not exist) is
added in the next layer. This module deliberately stops at schema validity.
"""

from __future__ import annotations

from auditor.ai.prompt import build_prompt
from auditor.ai.providers import get_provider
from auditor.ai.schema import ReviewNarrative, parse_response


def review_findings(findings, provider=None, provider_name=None):
    """Return AI narratives for a list of deterministic findings.

    If no provider instance is passed, one is built by name (or from the
    AI_PROVIDER environment default). With no findings, no call is made:
    an empty input has an empty answer, and there is no reason to spend a
    request on it.
    """
    findings = list(findings)
    if not findings:
        return []

    if provider is None:
        provider = get_provider(provider_name)

    prompt = build_prompt(findings)
    raw = provider.generate(prompt)
    narratives = parse_response(raw)

    assert all(isinstance(n, ReviewNarrative) for n in narratives)
    return narratives
