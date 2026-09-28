"""Tests for grounding checks, the hallucination guard.

Each test represents a way a model can return well-formed JSON that is
still not about anything real. The layer must drop those, not repair them.
"""

import json
from dataclasses import dataclass

from auditor.ai import (
    ReviewNarrative,
    check_grounding,
    parse_narrative,
    review_findings,
    review_findings_detailed,
    ungrounded_references,
)
from auditor.ai.providers import Provider


@dataclass
class SampleFinding:
    finding_id: str
    severity: str
    message: str
    source: str


class FakeProvider(Provider):
    name = "fake"

    def __init__(self, response=""):
        self._response = response
        self.calls = []

    def generate(self, prompt):
        self.calls.append(prompt)
        return self._response


def _finding(fid="FW-001", source="10.0.0.0/8"):
    return SampleFinding(
        finding_id=fid,
        severity="critical",
        message="Any-any allow rule on the perimeter firewall.",
        source=source,
    )


def _narrative(fid="FW-001", risk="It removes the firewall as a control."):
    return parse_narrative(
        {
            "finding_id": fid,
            "summary": "An overly broad allow rule.",
            "risk": risk,
            "recommendation": "Scope it to known services.",
        }
    )


# --- accepted ------------------------------------------------------------


def test_grounded_narrative_is_accepted():
    result = check_grounding([_narrative()], [_finding()])
    assert len(result.accepted) == 1
    assert result.rejected == []
    assert result.grounding_rate == 1.0


def test_narrative_citing_a_real_address_is_accepted():
    narrative = _narrative(risk="The rule exposes 10.0.0.0/8 to the internet.")
    result = check_grounding([narrative], [_finding(source="10.0.0.0/8")])
    assert len(result.accepted) == 1


def test_empty_batch_is_vacuously_grounded():
    result = check_grounding([], [_finding()])
    assert result.total == 0
    assert result.grounding_rate == 1.0


# --- rejected ------------------------------------------------------------


def test_unknown_finding_id_is_rejected():
    result = check_grounding([_narrative("FW-999")], [_finding("FW-001")])
    assert result.accepted == []
    assert len(result.rejected) == 1
    assert "unknown finding_id" in result.rejected[0].reason


def test_duplicate_narrative_is_rejected():
    narratives = [_narrative("FW-001"), _narrative("FW-001")]
    result = check_grounding(narratives, [_finding("FW-001")])
    assert len(result.accepted) == 1
    assert len(result.rejected) == 1
    assert "duplicate" in result.rejected[0].reason


def test_invented_address_is_rejected():
    narrative = _narrative(risk="Traffic from 192.168.99.4 reaches the host.")
    result = check_grounding([narrative], [_finding(source="10.0.0.0/8")])
    assert result.accepted == []
    assert "192.168.99.4" in result.rejected[0].reason


def test_partial_batch_keeps_the_good_one():
    narratives = [_narrative("FW-001"), _narrative("FW-404")]
    result = check_grounding(narratives, [_finding("FW-001")])
    assert len(result.accepted) == 1
    assert len(result.rejected) == 1
    assert result.grounding_rate == 0.5


def test_ungrounded_references_finds_invented_tokens():
    narrative = _narrative(risk="Both 10.0.0.0/8 and 172.31.5.9 are allowed.")
    invented = ungrounded_references(narrative, '{"source": "10.0.0.0/8"}')
    assert invented == ["172.31.5.9"]


# --- end to end ----------------------------------------------------------


def _response(fid):
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


def test_review_findings_drops_hallucinated_narrative():
    provider = FakeProvider(_response("FW-999"))
    result = review_findings([_finding("FW-001")], provider=provider)
    assert result == []


def test_review_findings_detailed_reports_the_rejection():
    provider = FakeProvider(_response("FW-999"))
    result = review_findings_detailed([_finding("FW-001")], provider=provider)
    assert len(result.rejected) == 1
    assert result.grounding_rate == 0.0


def test_review_findings_returns_grounded_narrative():
    provider = FakeProvider(_response("FW-001"))
    result = review_findings([_finding("FW-001")], provider=provider)
    assert len(result) == 1
    assert isinstance(result[0], ReviewNarrative)
