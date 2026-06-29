"""Load firewall rules from various sources.

Supported sources:
    * Generic JSON (the canonical normalised format)
    * Generic YAML (same shape as JSON)
    * iptables-save output (subset — common ACCEPT/DROP rules)

To add a new vendor, implement `load_*` and ensure it returns
`list[Rule]`. The auditor doesn't care where rules came from.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from auditor.models import Rule


def load_json(path: str | Path) -> list[Rule]:
    data = json.loads(Path(path).read_text())
    return _from_dicts(data.get("rules", data))


def load_yaml(path: str | Path) -> list[Rule]:
    data = yaml.safe_load(Path(path).read_text())
    return _from_dicts(data.get("rules", data))


def _from_dicts(rules_raw: list[dict]) -> list[Rule]:
    rules: list[Rule] = []
    for r in rules_raw:
        rules.append(Rule(
            rule_id=str(r["rule_id"]),
            action=r["action"],
            source=r.get("source") or ["any"],
            destination=r.get("destination") or ["any"],
            protocol=r.get("protocol") or "any",
            ports=r.get("ports") or [],
            description=r.get("description", ""),
            enabled=r.get("enabled", True),
        ))
    return rules


# ---------- iptables-save parser ----------

# Match e.g. -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT
_IPTABLES_LINE = re.compile(r"^-A\s+(\S+)\s+(.*)\s+-j\s+(\S+)\s*$")


def parse_iptables_save(text: str) -> list[Rule]:
    """Parse a subset of `iptables-save` output into normalised rules.

    Limitations:
        * Only ACCEPT, DROP, REJECT, LOG actions
        * No state-matching, marking, or NAT rules
        * One source/destination per rule

    This is enough for an auditor demo. Production users should feed
    in pre-normalised JSON exported from their firewall management
    tool of choice.
    """
    rules: list[Rule] = []
    counter = 1
    action_map = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny", "LOG": "log"}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(":") or line.startswith("*"):
            continue
        match = _IPTABLES_LINE.match(line)
        if not match:
            continue
        chain, predicates, action_token = match.groups()
        if action_token not in action_map:
            continue

        rule = Rule(
            rule_id=f"ipt-{counter:04d}",
            action=action_map[action_token],
            description=f"iptables chain {chain}",
        )
        counter += 1

        for token, value in _tokenise(predicates):
            if token == "-s":
                rule.source = [value]
            elif token == "-d":
                rule.destination = [value]
            elif token == "-p":
                rule.protocol = value
            elif token in ("--dport", "--sport"):
                rule.ports = value.split(",")

        rules.append(rule)
    return rules


def _tokenise(predicates: str) -> list[tuple[str, str]]:
    """Pair up flags and values from an iptables predicate string."""
    parts = predicates.split()
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(parts):
        token = parts[i]
        if token.startswith("-") and i + 1 < len(parts) and not parts[i + 1].startswith("-"):
            out.append((token, parts[i + 1]))
            i += 2
        else:
            i += 1
    return out


def load_iptables(path: str | Path) -> list[Rule]:
    return parse_iptables_save(Path(path).read_text())
