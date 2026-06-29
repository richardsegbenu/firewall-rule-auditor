"""Audit checks that scan a list of rules for governance issues.

Every check is a function `check_<name>(rules) -> list[Finding]`.
Adding a new check is just adding a function and registering it.

Current checks:
    - any_any_allow:        catch wide-open allow rules
    - high_risk_ports_open: SSH, RDP, SMB, etc. exposed to the internet
    - shadowed_rules:       a rule that can never fire because an earlier
                            rule already covers its packet set
    - redundant_rules:      two rules with the same predicate and action
    - disabled_rules:       rules toggled off — info-level housekeeping
    - missing_description:  unauditable rules (no description)
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

from auditor.models import Finding, Rule

HIGH_RISK_PORTS = {
    "22": "SSH",
    "23": "Telnet",
    "445": "SMB",
    "3389": "RDP",
    "5985": "WinRM (HTTP)",
    "5986": "WinRM (HTTPS)",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "1433": "MS SQL",
}


def check_any_any_allow(rules: Iterable[Rule]) -> list[Finding]:
    out: list[Finding] = []
    for r in rules:
        if not r.enabled or not r.is_allow:
            continue
        if r.matches_any_source and r.matches_any_destination and r.matches_any_protocol and r.matches_any_port:
            out.append(Finding(
                severity="critical",
                rule_ids=[r.rule_id],
                code="ANY_ANY_ALLOW",
                message=(f"Rule {r.rule_id} allows any-source -> any-destination on any "
                         "protocol/port. This effectively disables the firewall for this path."),
            ))
    return out


def check_high_risk_ports_open(rules: Iterable[Rule]) -> list[Finding]:
    out: list[Finding] = []
    for r in rules:
        if not r.enabled or not r.is_allow or not r.matches_any_source:
            continue
        for port in r.ports:
            service = HIGH_RISK_PORTS.get(port)
            if service:
                out.append(Finding(
                    severity="high",
                    rule_ids=[r.rule_id],
                    code="HIGH_RISK_PORT_OPEN",
                    message=(f"Rule {r.rule_id} allows any-source access to port {port} "
                             f"({service}). High-risk services should be restricted to a "
                             "specific source range."),
                ))
    return out


def check_disabled_rules(rules: Iterable[Rule]) -> list[Finding]:
    return [
        Finding(
            severity="info",
            rule_ids=[r.rule_id],
            code="DISABLED_RULE",
            message=f"Rule {r.rule_id} is disabled. Consider removing it to keep the ruleset clean.",
        )
        for r in rules
        if not r.enabled
    ]


def check_missing_description(rules: Iterable[Rule]) -> list[Finding]:
    return [
        Finding(
            severity="low",
            rule_ids=[r.rule_id],
            code="MISSING_DESCRIPTION",
            message=f"Rule {r.rule_id} has no description. Audit trail will be hard to follow.",
        )
        for r in rules
        if not r.description.strip()
    ]


def check_redundant_rules(rules: Iterable[Rule]) -> list[Finding]:
    """Two rules with identical predicates and action are redundant."""
    rules = [r for r in rules if r.enabled]
    seen: dict[tuple, list[str]] = {}
    for r in rules:
        key = (
            r.action,
            tuple(sorted(r.source)),
            tuple(sorted(r.destination)),
            r.protocol,
            tuple(sorted(r.ports)),
        )
        seen.setdefault(key, []).append(r.rule_id)
    out: list[Finding] = []
    for ids in seen.values():
        if len(ids) > 1:
            out.append(Finding(
                severity="medium",
                rule_ids=ids,
                code="REDUNDANT_RULES",
                message=f"Rules {', '.join(ids)} have identical predicates and action.",
            ))
    return out


def _subset_of(child: list[str], parent: list[str]) -> bool:
    """True if every element of `child` is covered by `parent` (treats 'any'/0.0.0.0/0 as universe).

    Only handles IPv4 CIDR + 'any' + '0.0.0.0/0'. Sufficient for demo;
    a production version would handle IPv6 and hostnames.
    """
    if parent == ["any"] or "0.0.0.0/0" in parent:
        return True
    try:
        parent_nets = [ipaddress.ip_network(p, strict=False) for p in parent]
        child_nets = [ipaddress.ip_network(c, strict=False) for c in child]
        return all(any(cn.subnet_of(pn) for pn in parent_nets) for cn in child_nets)
    except ValueError:
        # Hostnames or non-CIDR — bail out conservatively.
        return False


def check_shadowed_rules(rules: list[Rule]) -> list[Finding]:
    """A rule is shadowed if a strictly earlier rule covers its packet set with the same action."""
    out: list[Finding] = []
    enabled = [r for r in rules if r.enabled]
    for i, r in enumerate(enabled):
        for earlier in enabled[:i]:
            if earlier.action != r.action:
                continue
            if (earlier.protocol.lower() != "any" and earlier.protocol.lower() != r.protocol.lower()):
                continue
            # Earlier rule must cover all of r's source/dest.
            if not _subset_of(r.source, earlier.source):
                continue
            if not _subset_of(r.destination, earlier.destination):
                continue
            if earlier.ports and r.ports and not set(r.ports).issubset(set(earlier.ports)):
                continue
            if earlier.ports and not r.ports:
                # earlier is specific, child is "any port" -> not shadowed
                continue
            out.append(Finding(
                severity="medium",
                rule_ids=[r.rule_id, earlier.rule_id],
                code="SHADOWED_RULE",
                message=(f"Rule {r.rule_id} is shadowed by earlier rule {earlier.rule_id}; "
                         "it will never be evaluated and can be removed."),
            ))
            break  # only report the first shadower per rule
    return out


ALL_CHECKS = (
    check_any_any_allow,
    check_high_risk_ports_open,
    check_redundant_rules,
    check_shadowed_rules,
    check_disabled_rules,
    check_missing_description,
)


def audit(rules: list[Rule]) -> list[Finding]:
    """Run every registered check and return the combined findings."""
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(rules))
    return findings
