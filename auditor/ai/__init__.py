"""AI review layer for firewall-rule-auditor.

Optional, additive, and strictly bounded. The deterministic checks remain
authoritative. This package only adds plain-English narratives on top and
never creates, removes, or re-grades a finding.
"""

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
]
