"""Strict schema for AI review narratives.

The deterministic auditor produces the findings. The optional AI review
layer produces plain-English narratives that sit on top of those findings.
Model output is untrusted text, so every narrative crosses this boundary
before anything downstream is allowed to use it. This module is that
boundary: it turns raw model output into validated objects, or it raises.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


class SchemaError(ValueError):
    """Raised when model output does not match the narrative schema."""


@dataclass(frozen=True)
class ReviewNarrative:
    """One plain-English narrative attached to a single deterministic finding.

    finding_id ties the narrative back to the finding it explains, which is
    what the later grounding check relies on. Nothing here can change a
    finding or its severity: a narrative only describes.
    """

    finding_id: str
    summary: str
    risk: str
    recommendation: str


_NARRATIVE_FIELDS = ("finding_id", "summary", "risk", "recommendation")


def _require_non_empty_str(value, field):
    if not isinstance(value, str):
        raise SchemaError(
            f"field '{field}' must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise SchemaError(f"field '{field}' must not be empty")
    return value


def parse_narrative(obj) -> ReviewNarrative:
    """Validate one narrative object and return a ReviewNarrative.

    Strict: the object must be a dict whose keys are exactly the expected
    fields (no missing, no extra), each mapping to a non-empty string.
    """
    if not isinstance(obj, dict):
        raise SchemaError(
            f"narrative must be an object, got {type(obj).__name__}"
        )

    keys = set(obj)
    expected = set(_NARRATIVE_FIELDS)

    missing = expected - keys
    if missing:
        raise SchemaError(f"narrative missing fields: {sorted(missing)}")

    extra = keys - expected
    if extra:
        raise SchemaError(f"narrative has unexpected fields: {sorted(extra)}")

    values = {f: _require_non_empty_str(obj[f], f) for f in _NARRATIVE_FIELDS}
    return ReviewNarrative(**values)


def _strip_code_fences(raw: str) -> str:
    text = raw.strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    # Drop the opening fence line (``` or ```json).
    lines = lines[1:]
    # Drop a closing fence if the model added one.
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def parse_response(raw: str) -> list[ReviewNarrative]:
    """Validate a full model response and return its narratives.

    The response must be a JSON object with a single 'narratives' key
    mapping to a list. Each element is validated by parse_narrative. An
    empty list is structurally valid here; orchestration decides what an
    empty result means.
    """
    if not isinstance(raw, str):
        raise SchemaError(
            f"response must be a string, got {type(raw).__name__}"
        )

    text = _strip_code_fences(raw)
    if not text:
        raise SchemaError("response was empty")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"response was not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise SchemaError(
            f"response must be a JSON object, got {type(payload).__name__}"
        )

    if "narratives" not in payload:
        raise SchemaError("response missing 'narratives'")

    extra = set(payload) - {"narratives"}
    if extra:
        raise SchemaError(f"response has unexpected keys: {sorted(extra)}")

    narratives = payload["narratives"]
    if not isinstance(narratives, list):
        raise SchemaError(
            f"'narratives' must be a list, got {type(narratives).__name__}"
        )

    return [parse_narrative(item) for item in narratives]
