# Firewall Rule Auditor

Static analysis for firewall rulesets. Loads rules from JSON, YAML, or `iptables-save` output and flags governance issues: any-any allows, exposed high-risk ports, shadowed rules, redundancies, and missing audit trail.

Designed to drop into a CI pipeline so firewall changes get reviewed before they hit a change advisory board.

[![CI](https://github.com/richardsegbenu/firewall-rule-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/richardsegbenu/firewall-rule-auditor/actions)

## Why this exists

Firewall reviews in enterprise environments are usually annual, manual, and miserable. By the time auditors arrive, rulesets have accumulated years of "just for now" rules, shadowed entries that can't fire, and undocumented changes nobody owns.

This tool runs the same checks an auditor would, but in seconds and as part of every change request. The output is a JSON / text / HTML report you can attach to a ticket as evidence before action.

## Checks implemented

| Code | Severity | What it catches |
|---|---|---|
| `ANY_ANY_ALLOW` | Critical | A rule that allows any source to any destination on any protocol/port |
| `HIGH_RISK_PORT_OPEN` | High | SSH, RDP, SMB, database ports etc. open to "any" source |
| `SHADOWED_RULE` | Medium | A rule covered by an earlier rule with the same action — will never fire |
| `REDUNDANT_RULES` | Medium | Two rules with identical predicates and action |
| `DISABLED_RULE` | Info | Disabled rules left in the ruleset (housekeeping) |
| `MISSING_DESCRIPTION` | Low | Rules with no description — unauditable |

Adding a new check is one function. See `auditor/checks.py`.

## Quick start

```bash
git clone https://github.com/richardsegbenu/firewall-rule-auditor.git
cd firewall-rule-auditor
pip install -r requirements.txt

# Audit the sample (deliberately bad) ruleset
python -m auditor.cli samples/rules.json

# Generate an HTML report you can attach to a change ticket
python -m auditor.cli samples/rules.json --format html --out report.html

# Audit an iptables-save dump
python -m auditor.cli samples/iptables.rules --type iptables

# Use in CI: exit non-zero on any high or critical finding
python -m auditor.cli samples/rules.json --fail-on high
```

Docker:
```bash
docker build -t firewall-rule-auditor .
docker run --rm -v $(pwd)/samples:/app/samples \
  firewall-rule-auditor samples/rules.json --format text
```

## CI integration example

```yaml
# .github/workflows/firewall-review.yml
on: [pull_request]
jobs:
  firewall-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - run: |
          docker run --rm -v $PWD:/work YOUR_REGISTRY/firewall-rule-auditor:latest \
            /work/firewall/production.json --fail-on high
```

## Rule format

JSON (canonical):
```json
{
  "rules": [
    {
      "rule_id": "R001",
      "action": "allow",
      "source": ["10.0.0.0/8"],
      "destination": ["10.1.0.0/16"],
      "protocol": "tcp",
      "ports": ["443"],
      "description": "Allow internal HTTPS to web servers"
    }
  ]
}
```

YAML works the same way. iptables-save is auto-detected from common predicates (`-s`, `-d`, `-p`, `--dport`, `-j`). For other vendor formats, write a loader — see `auditor/loaders.py`.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

## Roadmap

- [ ] Cisco ASA / FTD loader
- [ ] Palo Alto loader
- [ ] Rule-coverage diff between two versions of the same ruleset
- [ ] Pre-commit hook helper
- [ ] Severity overrides via policy file

## Licence

MIT
