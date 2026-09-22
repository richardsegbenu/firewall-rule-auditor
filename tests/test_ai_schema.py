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


# --- failure paths -------------------------------------------------------


def test_parse_response_rejects_non_string():
    with pytest.raises(SchemaError):
        parse_response(123)


def test_parse_response_rejects_empty_string():
    with pytest.raises(SchemaError):
        parse_response("   ")


def test_parse_response_rejects_invalid_json():
    with pytest.raises(SchemaError):
        parse_response("{not valid json")


def test_parse_response_rejects_non_object_top_level():
    with pytest.raises(SchemaError):
        parse_response(json.dumps([_good_narrative()]))


def test_parse_response_rejects_missing_narratives():
    with pytest.raises(SchemaError):
        parse_response(json.dumps({"items": []}))


def test_parse_response_rejects_extra_top_level_key():
    payload = {"narratives": [_good_narrative()], "notes": "extra"}
    with pytest.raises(SchemaError):
        parse_response(json.dumps(payload))


def test_parse_response_rejects_narratives_not_a_list():
    with pytest.raises(SchemaError):
        parse_response(json.dumps({"narratives": _good_narrative()}))


def test_parse_narrative_rejects_non_dict():
    with pytest.raises(SchemaError):
        parse_narrative("not a dict")


def test_parse_narrative_rejects_missing_field():
    bad = _good_narrative()
    del bad["risk"]
    with pytest.raises(SchemaError):
        parse_narrative(bad)


def test_parse_narrative_rejects_extra_field():
    bad = _good_narrative()
    bad["severity"] = "high"
    with pytest.raises(SchemaError):
        parse_narrative(bad)


def test_parse_narrative_rejects_non_string_field():
    bad = _good_narrative()
    bad["finding_id"] = 42
    with pytest.raises(SchemaError):
        parse_narrative(bad)


def test_parse_narrative_rejects_empty_field():
    bad = _good_narrative()
    bad["summary"] = "   "
    with pytest.raises(SchemaError):
        parse_narrative(bad)
