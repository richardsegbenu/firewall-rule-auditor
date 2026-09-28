"""Tests for prompt building and review orchestration.

No network: a fake provider returns canned responses, so these tests check
that orchestration wires prompt, provider, and schema together correctly.
"""

import json
from dataclasses import dataclass

import pytest

from auditor.ai import build_prompt, finding_id, finding_to_dict, review_findings
from auditor.ai.providers import Provider
from auditor.ai.schema import SchemaError


@dataclass
class SampleFinding:
    finding_id: str
    severity: str
    message: str


class FakeProvider(Provider):
    name = "fake"

    def __init__(self, response=""):
        self._response = response
        self.calls = []

    def generate(self, prompt):
        self.calls.append(prompt)
        return self._response


def _finding(fid="FW-001"):
    return SampleFinding(
        finding_id=fid,
        severity="critical",
        message="Any-any allow rule on the perimeter firewall.",
    )


def _good_response(fid="FW-001"):
    return json.dumps(
        {
            "narratives": [
                {
                    "finding_id": fid,
                    "summary": "An overly broad allow rule.",
                    "risk": "It removes the firewall as a control point.",
                    "recommendation": "Scope it to known services.",
                }
            ]
        }
    )


# --- orchestration -------------------------------------------------------


def test_review_findings_returns_validated_narratives():
    provider = FakeProvider(_good_response())
    result = review_findings([_finding()], provider=provider)
    assert len(result) == 1
    assert result[0].finding_id == "FW-001"
    assert len(provider.calls) == 1


def test_review_findings_empty_short_circuits():
    provider = FakeProvider(_good_response())
    result = review_findings([], provider=provider)
    assert result == []
    assert provider.calls == []  # provider never called


def test_review_findings_propagates_schema_error():
    provider = FakeProvider("this is not json")
    with pytest.raises(SchemaError):
        review_findings([_finding()], provider=provider)


def test_review_findings_passes_findings_into_prompt():
    provider = FakeProvider(_good_response())
    review_findings([_finding("FW-042")], provider=provider)
    assert "FW-042" in provider.calls[0]


# --- prompt building -----------------------------------------------------


def test_build_prompt_contains_finding_and_contract():
    prompt = build_prompt([_finding("FW-007")])
    assert "FW-007" in prompt
    assert "narratives" in prompt
    assert "recommendation" in prompt
    assert "JSON only" in prompt


def test_build_prompt_handles_multiple_findings():
    prompt = build_prompt([_finding("FW-001"), _finding("FW-002")])
    assert "FW-001" in prompt
    assert "FW-002" in prompt


# --- finding normalisation ----------------------------------------------


def test_finding_id_from_object():
    assert finding_id(_finding("FW-009")) == "FW-009"


def test_finding_id_from_dict():
    assert finding_id({"id": "FW-010"}) == "FW-010"


def test_finding_id_missing_raises():
    with pytest.raises(ValueError):
        finding_id({"severity": "high"})


def test_finding_to_dict_normalises_id_key():
    result = finding_to_dict({"rule_id": "FW-011", "severity": "low"})
    assert result["finding_id"] == "FW-011"
    assert result["severity"] == "low"
