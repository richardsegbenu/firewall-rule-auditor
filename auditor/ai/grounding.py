"""Grounding checks for AI review narratives.

Schema validation proves a narrative is shaped correctly. It does not prove
the narrative is about anything real: well-formed JSON can still cite a
finding that does not exist or an address range that appears nowhere in the
input. This module is the hallucination guard.

Every narrative is checked against the deterministic findings it claims to
describe. Anything that cannot be traced back is dropped, not repaired and
not passed through with a warning. Failing closed is the point: when a
narrative is rejected the deterministic finding stands on its own, which is
correct, because the finding was never the model's to produce.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from auditor.ai.prompt import finding_id, finding_to_dict

# Address-shaped tokens are the references a model most often invents:
# an IPv4 address or a CIDR block that sounds plausible but is not in the
# input. Extend this list if other reference types need grounding.
_ADDRESS_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")

_NARRATIVE_TEXT_FIELDS = ("summary", "risk", "recommendation")


@dataclass(frozen=True)
class Rejection:
    """One narrative that failed grounding, and why."""

    finding_id: str
    reason: str


@dataclass
class GroundingResult:
    """Outcome of grounding a batch of narratives."""

    accepted: list = field(default_factory=list)
    rejected: list = field(default_factory=list)

    @property
    def total(self):
        return len(self.accepted) + len(self.rejected)

    @property
    def grounding_rate(self):
        """Share of narratives that survived, 1.0 when there were none."""
        if self.total == 0:
            return 1.0
        return len(self.accepted) / self.total


def build_corpus(findings) -> str:
    """Flatten the findings into one searchable text blob.

    A reference is grounded if it appears somewhere in the input the model
    was given. Serialising the findings once is cheaper and less brittle
    than walking arbitrary finding shapes per check.
    """
    payload = [finding_to_dict(f) for f in findings]
    return json.dumps(payload, default=str)


def narrative_text(narrative) -> str:
    return " ".join(
        getattr(narrative, field_name, "") or ""
        for field_name in _NARRATIVE_TEXT_FIELDS
    )


def ungrounded_references(narrative, corpus) -> list:
    """Return address-shaped tokens in the narrative absent from the input."""
    tokens = set(_ADDRESS_PATTERN.findall(narrative_text(narrative)))
    return sorted(token for token in tokens if token not in corpus)


def check_grounding(narratives, findings) -> GroundingResult:
    """Accept only narratives that trace back to the given findings.

    Three ways a narrative fails:
    1. It cites a finding_id that was never sent to the model.
    2. It is the second narrative for a finding already covered, which means
       the model split or duplicated a finding it was told not to touch.
    3. It cites an address or range that appears nowhere in the input.
    """
    known_ids = {finding_id(f) for f in findings}
    corpus = build_corpus(findings)

    result = GroundingResult()
    seen = set()

    for narrative in narratives:
        nid = narrative.finding_id

        if nid not in known_ids:
            result.rejected.append(
                Rejection(nid, f"unknown finding_id '{nid}' not in input")
            )
            continue

        if nid in seen:
            result.rejected.append(
                Rejection(nid, f"duplicate narrative for finding_id '{nid}'")
            )
            continue

        invented = ungrounded_references(narrative, corpus)
        if invented:
            result.rejected.append(
                Rejection(nid, f"references not found in input: {invented}")
            )
            continue

        seen.add(nid)
        result.accepted.append(narrative)

    return result


def merge(results) -> GroundingResult:
    """Combine per-batch GroundingResults into one.

    Batching is a transport detail. The caller asked about a set of
    findings and should get one answer, not one per chunk.
    """
    merged = GroundingResult()
    for result in results:
        merged.accepted.extend(result.accepted)
        merged.rejected.extend(result.rejected)
    return merged