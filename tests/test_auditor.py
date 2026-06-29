"""Tests for the firewall rule auditor."""

from __future__ import annotations

import json
from pathlib import Path

from auditor.checks import (
    audit,
    check_any_any_allow,
    check_high_risk_ports_open,
    check_redundant_rules,
    check_shadowed_rules,
    check_disabled_rules,
    check_missing_description,
)
from auditor.loaders import load_json, parse_iptables_save
from auditor.models import Rule
from auditor.report import render_html, render_json, render_text


def _allow(rule_id, **kwargs):
    return Rule(rule_id=rule_id, action="allow", **kwargs)


def test_any_any_allow_flags_open_rule():
    rules = [_allow("R1", source=["any"], destination=["any"], protocol="any", ports=[],
                    description="x")]
    findings = check_any_any_allow(rules)
    assert len(findings) == 1
    assert findings[0].code == "ANY_ANY_ALLOW"
    assert findings[0].severity == "critical"


def test_any_any_allow_ignores_specific_rules():
    rules = [_allow("R1", source=["10.0.0.0/8"], destination=["any"], description="x")]
    assert check_any_any_allow(rules) == []


def test_high_risk_port_detection():
    rules = [_allow("R1", source=["any"], destination=["10.1.0.5"],
                    protocol="tcp", ports=["22"], description="ssh")]
    findings = check_high_risk_ports_open(rules)
    assert len(findings) == 1
    assert "SSH" in findings[0].message


def test_high_risk_port_only_when_source_is_any():
    rules = [_allow("R1", source=["10.0.0.0/8"], destination=["10.1.0.5"],
                    protocol="tcp", ports=["22"], description="ssh")]
    assert check_high_risk_ports_open(rules) == []


def test_redundant_rules_detected():
    rules = [
        _allow("R1", source=["10.0.0.0/8"], destination=["10.1.0.0/16"],
               protocol="tcp", ports=["443"], description="a"),
        _allow("R2", source=["10.0.0.0/8"], destination=["10.1.0.0/16"],
               protocol="tcp", ports=["443"], description="b"),
    ]
    findings = check_redundant_rules(rules)
    assert len(findings) == 1
    assert set(findings[0].rule_ids) == {"R1", "R2"}


def test_shadowed_rule_detected():
    """A specific allow inside an earlier broader allow is shadowed."""
    rules = [
        _allow("R1", source=["10.0.0.0/8"], destination=["10.1.0.0/16"],
               protocol="tcp", ports=["443"], description="broad"),
        _allow("R2", source=["10.5.5.5/32"], destination=["10.1.0.0/24"],
               protocol="tcp", ports=["443"], description="specific"),
    ]
    findings = check_shadowed_rules(rules)
    assert any(f.code == "SHADOWED_RULE" and "R2" in f.rule_ids for f in findings)


def test_disabled_rule_is_info_finding():
    rules = [Rule(rule_id="R1", action="deny", enabled=False, description="x")]
    findings = check_disabled_rules(rules)
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_missing_description():
    rules = [_allow("R1", description="")]
    assert len(check_missing_description(rules)) == 1


def test_load_json_from_file(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"rules": [
        {"rule_id": "X", "action": "allow", "description": "x"}
    ]}))
    rules = load_json(p)
    assert len(rules) == 1
    assert rules[0].rule_id == "X"


def test_iptables_parser():
    text = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
"""
    rules = parse_iptables_save(text)
    assert len(rules) == 2
    assert rules[0].source == ["10.0.0.0/8"]
    assert rules[0].ports == ["22"]
    assert rules[1].source == ["any"]


def test_full_audit_on_sample(tmp_path):
    rules = load_json(Path(__file__).parent.parent / "samples" / "rules.json")
    findings = audit(rules)

    codes = {f.code for f in findings}
    # The sample is deliberately bad — all of these should fire.
    assert "ANY_ANY_ALLOW" in codes      # R002
    assert "HIGH_RISK_PORT_OPEN" in codes # R003, R004
    assert "REDUNDANT_RULES" in codes    # R001/R005
    assert "MISSING_DESCRIPTION" in codes # R004
    assert "DISABLED_RULE" in codes      # R007


def test_render_text_works():
    rules = [_allow("R1", source=["any"], destination=["10.1.0.5"], protocol="tcp",
                    ports=["22"], description="ssh")]
    findings = audit(rules)
    text = render_text(rules, findings)
    assert "HIGH_RISK_PORT_OPEN" in text


def test_render_json_is_valid_json():
    rules = [_allow("R1", description="x")]
    findings = audit(rules)
    parsed = json.loads(render_json(rules, findings))
    assert "findings" in parsed
    assert parsed["rule_count"] == 1


def test_render_html_includes_header():
    rules = [_allow("R1", description="x")]
    findings = audit(rules)
    html_out = render_html(rules, findings)
    assert "<title>Firewall Rule Audit Report</title>" in html_out
