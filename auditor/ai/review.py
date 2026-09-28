"""Orchestration for the AI review layer.

Findings in, validated and grounded narratives out. It builds the prompt,
calls the selected provider, runs the raw response through the strict
schema, then checks every surviving narrative against the findings it
claims to describe.

Nothing here trusts the model. Two independent gates stand between raw
model output and anything a user sees, and both are enforced in code. The
prompt asks for good behaviour; the prompt is not what guarantees it.
"""

from __future__ import annotations

from auditor.ai.grounding import GroundingResult, check_grounding
from auditor.ai.prompt import build_prompt
from auditor.ai.providers import get_provider
from auditor.ai.schema import parse_response


def review_findings_detailed(findings, provider=None, provider_name=None):
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

    prompt = build_prompt(findings)
    raw = provider.generate(prompt)
    narratives = parse_response(raw)
    return check_grounding(narratives, findings)


def review_findings(findings, provider=None, provider_name=None):
    """Return only the narratives that passed schema and grounding checks."""
    result = review_findings_detailed(
        findings, provider=provider, provider_name=provider_name
    )
    return result.accepted
