"""Data model for firewall rules.

We normalise rules from any source (iptables, Cisco ASA, generic JSON)
into a common shape so the rule analysis logic can stay vendor-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Literal

Action = Literal["allow", "deny", "log"]


@dataclass
class Rule:
    """A single normalised firewall rule.

    `any` semantics:
        - source = ["any"] means match any source
        - ports = [] means match any port
        - protocol = "any" means match any protocol
    """

    rule_id: str
    action: Action
    source: list[str] = field(default_factory=lambda: ["any"])
    destination: list[str] = field(default_factory=lambda: ["any"])
    protocol: str = "any"
    ports: list[str] = field(default_factory=list)
    description: str = ""
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_allow(self) -> bool:
        return self.action == "allow"

    @property
    def matches_any_source(self) -> bool:
        return self.source == ["any"] or "0.0.0.0/0" in self.source or "::/0" in self.source

    @property
    def matches_any_destination(self) -> bool:
        return self.destination == ["any"] or "0.0.0.0/0" in self.destination or "::/0" in self.destination

    @property
    def matches_any_protocol(self) -> bool:
        return self.protocol.lower() == "any"

    @property
    def matches_any_port(self) -> bool:
        return not self.ports


@dataclass
class Finding:
    """A single audit finding against a rule (or pair of rules)."""

    severity: Literal["critical", "high", "medium", "low", "info"]
    rule_ids: list[str]
    code: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
