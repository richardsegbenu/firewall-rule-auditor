"""Prompt construction for the AI review layer.

Pure functions: no network, no state. Given the deterministic findings,
build the exact text sent to a provider. The prompt asks the model to
explain each finding and return JSON matching the narrative schema.

The prompt is best-effort only. It cannot enforce anything: the schema
parse and the later grounding check are what hold the line. That is
deliberate. Safety lives in code, not in the wording of a prompt.
"""

from __future__ import annotations

import json

# Attribute or key names an existing finding might use for its identifier.
# If your Finding type uses a different name, add it here and nothing else
# in the AI layer needs to change.
_ID_KEYS = ("finding_id", "id", "rule_id", "ref")


SYSTEM_INSTRUCTION = (
    "You are a security review assistant for a firewall rule auditor.\n"
    "A deterministic tool has already produced the findings below. Your only\n"
    "job is to explain them in plain English for a non-specialist reader.\n"
    "\n"
    "Rules you must follow:\n"
    "1. Write exactly one narrative per finding given, no more, no fewer.\n"
    "2. Use the finding_id exactly as it appears in the input. Do not invent,\n"
    "   rename, merge, or drop finding_ids.\n"
    "3. Do not invent findings, severities, or rules that are not in the\n"
    "   input. You describe what is there, you do not add to it.\n"
    "4. Do not restate or change any severity. Severity is not yours to set.\n"
    "\n"
    "Return JSON only. No prose before or after, no code fences. The shape is:\n"
    "{\n"
    '  "narratives": [\n'
    "    {\n"
    '      "finding_id": "<the id from the input>",\n'
    '      "summary": "<one sentence: what the finding is>",\n'
    '      "risk": "<two or three sentences: why it matters>",\n'
    '      "recommendation": "<one or two sentences: what to do>"\n'
    "    }\n"
    "  ]\n"
    "}"
)


def finding_id(finding) -> str:
    """Pull a stable identifier from a finding (dict or object).

    Findings come from our own deterministic auditor, so a missing id is a
    programming error, not untrusted input: it raises ValueError loudly.
    """
    if isinstance(finding, dict):
        source = finding
    elif hasattr(finding, "__dict__"):
        source = vars(finding)
    else:
        source = {}

    for key in _ID_KEYS:
        value = source.get(key) if isinstance(source, dict) else None
        if value not in (None, ""):
            return str(value)

    # Fall back to attribute access for objects that expose the id via a
    # property rather than __dict__.
    for key in _ID_KEYS:
        value = getattr(finding, key, None)
        if value not in (None, ""):
            return str(value)

    raise ValueError(
        f"finding has no identifier; looked for {list(_ID_KEYS)}"
    )


def finding_to_dict(finding) -> dict:
    """Normalise a finding into a plain JSON-serialisable dict.

    The finding_id key is always present and normalised, which is what the
    prompt and the later grounding check rely on. Everything else is passed
    through so the model has the context it needs to write a narrative.
    """
    if isinstance(finding, dict):
        data = dict(finding)
    elif hasattr(finding, "__dict__"):
        data = {k: v for k, v in vars(finding).items() if not k.startswith("_")}
    else:
        raise ValueError(
            f"cannot serialise finding of type {type(finding).__name__}"
        )

    data["finding_id"] = finding_id(finding)
    return data


def build_prompt(findings) -> str:
    """Build the full prompt string for a list of findings."""
    payload = [finding_to_dict(f) for f in findings]
    findings_json = json.dumps(payload, indent=2, default=str)
    return (
        f"{SYSTEM_INSTRUCTION}\n\n"
        f"Findings to review:\n{findings_json}\n"
    )
