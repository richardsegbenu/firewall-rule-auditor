"""Render audit findings to JSON, plain text, or HTML.

The HTML report is intended for ticket attachments and audit
evidence. Plain text and JSON are for CI pipelines and tooling.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from auditor.models import SEVERITY_RANK, Finding, Rule


def render_json(rules: list[Rule], findings: list[Finding]) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule_count": len(rules),
        "finding_count": len(findings),
        "findings_by_severity": dict(Counter(f.severity for f in findings)),
        "findings": [f.to_dict() for f in _sorted(findings)],
    }
    return json.dumps(payload, indent=2)


def render_text(rules: list[Rule], findings: list[Finding]) -> str:
    lines = [
        "Firewall Rule Audit Report",
        "=" * 40,
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Rules scanned:  {len(rules)}",
        f"Findings:       {len(findings)}",
        "",
    ]
    counts = Counter(f.severity for f in findings)
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"  {sev.upper():<9} {counts[sev]}")
    lines.append("")

    if not findings:
        lines.append("No findings — ruleset clean against current checks.")
        return "\n".join(lines)

    for f in _sorted(findings):
        lines.append(f"[{f.severity.upper()}] {f.code}")
        lines.append(f"  Rules: {', '.join(f.rule_ids)}")
        lines.append(f"  {f.message}")
        lines.append("")
    return "\n".join(lines)


def render_html(rules: list[Rule], findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    rows = []
    for f in _sorted(findings):
        rows.append(
            f"<tr class='sev-{f.severity}'>"
            f"<td><span class='pill {f.severity}'>{f.severity.upper()}</span></td>"
            f"<td><code>{html.escape(f.code)}</code></td>"
            f"<td>{', '.join(html.escape(r) for r in f.rule_ids)}</td>"
            f"<td>{html.escape(f.message)}</td>"
            f"</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Firewall Rule Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0; background: #f5f6fa; color: #1f2937; }}
  header {{ background: #1f4e79; color: white; padding: 24px 32px; }}
  main {{ padding: 24px 32px; max-width: 1100px; margin: 0 auto; }}
  .summary {{ display: grid; grid-template-columns: repeat(5, 1fr);
              gap: 12px; margin-bottom: 24px; }}
  .card {{ background: white; border-radius: 8px; padding: 14px;
           box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
  .card .n {{ font-size: 28px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 8px; overflow: hidden;
           box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
  th, td {{ padding: 12px 16px; text-align: left; font-size: 14px;
            border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  th {{ background: #f9fafb; font-size: 11px; text-transform: uppercase;
        letter-spacing: .05em; color: #374151; }}
  .pill {{ display: inline-block; padding: 3px 10px; border-radius: 999px;
           font-size: 11px; font-weight: 700; }}
  .pill.critical {{ background: #fee2e2; color: #991b1b; }}
  .pill.high     {{ background: #fed7aa; color: #9a3412; }}
  .pill.medium   {{ background: #fef9c3; color: #854d0e; }}
  .pill.low      {{ background: #dbeafe; color: #1e40af; }}
  .pill.info     {{ background: #e5e7eb; color: #374151; }}
  code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px;
          font-size: 12px; }}
</style>
</head>
<body>
<header>
  <h1 style="margin:0;font-size:22px;">Firewall Rule Audit Report</h1>
  <p style="margin:4px 0 0;opacity:.85;font-size:13px;">
    Generated {html.escape(datetime.now(timezone.utc).isoformat())} ·
    {len(rules)} rules scanned · {len(findings)} findings
  </p>
</header>
<main>
  <div class="summary">
    {''.join(f'<div class="card"><div class="n">{counts.get(s,0)}</div>'
             f'<div style="font-size:12px;text-transform:uppercase;color:#6b7280;">{s}</div></div>'
             for s in ('critical','high','medium','low','info'))}
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Code</th><th>Rules</th><th>Detail</th></tr></thead>
    <tbody>{''.join(rows) or '<tr><td colspan=4>No findings</td></tr>'}</tbody>
  </table>
</main>
</body>
</html>"""


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.code))
