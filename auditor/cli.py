"""CLI for the firewall rule auditor.

Examples:
    python -m auditor.cli sample-rules.json
    python -m auditor.cli rules.yaml --format html --out report.html
    python -m auditor.cli iptables.txt --type iptables --fail-on high
"""

from __future__ import annotations

import argparse
from pathlib import Path

from auditor.checks import audit
from auditor.loaders import load_iptables, load_json, load_yaml
from auditor.models import SEVERITY_RANK
from auditor.report import render_html, render_json, render_text

LOADERS = {
    "json": load_json,
    "yaml": load_yaml,
    "iptables": load_iptables,
}

RENDERERS = {
    "text": render_text,
    "json": render_json,
    "html": render_html,
}


def _guess_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return "yaml"
    if suffix == ".json":
        return "json"
    if "iptables" in path.name.lower() or suffix == ".rules":
        return "iptables"
    return "json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a firewall rule file")
    parser.add_argument("path", type=Path)
    parser.add_argument("--type", choices=LOADERS.keys(), default=None,
                        help="Input type (guessed from file extension if omitted)")
    parser.add_argument("--format", choices=RENDERERS.keys(), default="text")
    parser.add_argument("--out", type=Path, default=None,
                        help="Write report to file instead of stdout")
    parser.add_argument("--fail-on", choices=SEVERITY_RANK.keys(), default=None,
                        help="Exit non-zero if any finding meets or exceeds this severity")

    args = parser.parse_args(argv)

    input_type = args.type or _guess_type(args.path)
    rules = LOADERS[input_type](args.path)
    findings = audit(rules)
    rendered = RENDERERS[args.format](rules, findings)

    if args.out:
        args.out.write_text(rendered)
    else:
        print(rendered)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
