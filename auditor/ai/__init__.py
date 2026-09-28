"""AI review layer for firewall-rule-auditor.

Optional, additive, and strictly bounded. The deterministic checks remain
authoritative. This package only adds plain-English narratives on top and
never creates, removes, or re-grades a finding.
"""

from auditor.ai.grounding import (
    GroundingResult,
    Rejection,
    check_grounding,
    ungrounded_references,
)
from auditor.ai.prompt import build_prompt, finding_id, finding_to_dict
from auditor.ai.review import review_findings, review_findings_detailed
from auditor.ai.schema import (
    ReviewNarrative,
    SchemaError,
    parse_narrative,
    parse_response,
)

__all__ = [
    "ReviewNarrative",
    "SchemaError",
    "parse_narrative",
    "parse_response",
    "build_prompt",
    "finding_id",
    "finding_to_dict",
    "review_findings",
    "review_findings_detailed",
    "GroundingResult",
    "Rejection",
    "check_grounding",
    "ungrounded_references",
]
