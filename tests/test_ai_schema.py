"""Tests for the AI review narrative schema."""

import json

import pytest

from dataclasses import FrozenInstanceError

from auditor.ai import (
    ReviewNarrative,
    SchemaError,
    parse_narrative,
    parse_response,
)


def _good_narrative():
    return {
        "finding_id": "FW-001",
        "summary": "Any-any allow rule on the perimeter firewall.",
        "risk": (
            "Permits all traffic in both directions, which removes the "
            "firewall as a control point at the perimeter."
        ),
        "recommendation": (
            "Replace with least-privilege rules scoped to known services."
        ),
    }


def test_parse_narrative_valid():
    result = parse_narrative(_good_narrative())
    assert isinstance(result, ReviewNarrative)
    assert result.finding_id == "FW-001"
    assert result.summary.startswith("Any-any")


def test_parse_response_valid():
    raw = json.dumps({"narratives": [_good_narrative()]})
    result = parse_response(raw)
    assert len(result) == 1
    assert result[0].finding_id == "FW-001"


def test_parse_response_multiple():
    n1 = _good_narrative()
    n2 = _good_narrative()
    n2["finding_id"] = "FW-002"
    raw = json.dumps({"narratives": [n1, n2]})
    result = parse_response(raw)
    assert [n.finding_id for n in result] == ["FW-001", "FW-002"]


def test_parse_response_strips_code_fences():
    body = json.dumps({"narratives": [_good_narrative()]})
    raw = "```json\n" + body + "\n```"
    result = parse_response(raw)
    assert len(result) == 1


def test_parse_response_allows_empty_list():
    raw = json.dumps({"narratives": []})
    assert parse_response(raw) == []


def test_review_narrative_is_frozen():
    n = parse_narrative(_good_narrative())
    with pytest.raises(FrozenInstanceError):
        n.finding_id = "changed"
