# ESXi Stealth Vulnerability Assessment

This repository contains a phased internal vulnerability-assessment framework
for ESXi and surrounding private-network infrastructure. It supports the
original Python 3.6 openSUSE/SLES assessment host as well as current Python
versions.

Use only on networks and systems you are authorized to assess.

## One-command run

```bash
python3 master_assessment.py
```

No target is required. When configured scope is empty, the launcher detects
private local networks, discovers live hosts, and executes every enabled phase.
The default `thorough` profile performs complete TCP coverage, configured UDP
coverage, safe enumeration of every discovered open service, web-protocol
probing on every open TCP port, and safe Nuclei scanning across all discovered
endpoints.

Public subnets and Nuclei templates tagged `dos`, `fuzz`, or `intrusive` remain
excluded by default. Those safeguards are independent of scan completeness
inside the authorized private scope.

## Pipeline

0. Framework and Nuclei-template update when explicitly enabled
1. Prerequisite installation, validation, and scope initialization
2. Live-host discovery, all-port TCP scanning, ESXi classification, and UDP discovery
3. Every-open-service enumeration and safe configuration checks
4. TLS/certificate analysis on every detected TLS endpoint
5. HTTP/HTTPS probing on every open TCP port and contextual web checks
6. Nuclei scanning across all open endpoints with unsafe template classes excluded
7. Delta analysis, state checkpointing, archival, and report generation

Independent hosts and endpoints are processed through configurable worker pools.
This shortens total runtime without omitting checks. Per-command timeouts remain
in place, while the overall pipeline runtime ceiling is disabled by default for
large full-coverage assessments.

## Reports

A successful run writes:

- `output/assessment_report.json` — normalized scanner data plus contextual analysis
- `output/assessment_report.md` — executive summary, implications, measures, closure criteria, asset inventory, and detailed evidence
- `output/assessment_report.html` — self-contained HTML overview
- `output/assessment_state.json` — raw crash-recovery checkpoint
- `output/history/YYYY-Wxx/` — archived reports
- `logs/assessment_*.log` — execution and audit logs

The contextual engine is fully local and deterministic. Its hardcoded scenario
knowledge base maps exact template IDs, names, descriptions, tags, categories,
and severity to:

- conclusions and practical implications;
- remediation steps and validation criteria;
- risk priority and confidence;
- selected control mappings and references.

Unknown scanner findings receive a conservative generic explanation. The code
does not invent CVE-specific fixed versions, prerequisites, or vendor facts.
Scanner evidence and authoritative vendor advisories remain the source of truth.

## Coverage profiles

```bash
# Full coverage (default)
python3 master_assessment.py

# Explicitly select the full profile
python3 master_assessment.py --profile thorough

# Complete TCP coverage with lighter fingerprinting
python3 master_assessment.py --profile standard

# Intentionally reduced coverage for troubleshooting only
python3 master_assessment.py --profile quick
```

`quick` is the only profile that intentionally limits TCP port coverage and
finding severities. It must be selected explicitly.

## Other useful commands

```bash
# Use configured targets/subnets only
python3 master_assessment.py --no-auto-network

# Force local private-network detection
python3 master_assessment.py --auto-network

# Verify configuration/tools without scanning or installing
python3 master_assessment.py --dry-run --no-install

# End-to-end synthetic report verification
python3 master_assessment.py --mock --no-auto-network

# Write reports and artifacts to a chosen directory
python3 master_assessment.py --output-dir /var/reports/esxi-assessment

# Resume from a checkpointed phase
python3 master_assessment.py --phase 4

# Guided terminal setup
python3 run_assessment.py --setup
```

Configuration is stored in:

- `config/assessment.yaml` — scope, phases, all-port coverage, safe scanners, and worker counts
- `config/scan_profile.yaml` — quick, standard, and thorough profiles
- `config/stealth_profile.yaml` — rates, delays, timeouts, and total runtime policy

## Full-coverage controls

The relevant defaults are:

```yaml
vm_discovery:
  max_hosts: 0                  # zero means no host cap

expanded_discovery:
  tcp_ports: 1-65535
  max_addresses_per_subnet: 0   # zero means no configured private-subnet size cap
  udp:
    top_ports: 65535

security_tests:
  max_ports_per_host: 0         # enumerate every open service

web:
  probe_all_open_ports: true

nuclei:
  severity_filter: critical,high,medium,low,info
  tags: []                       # do not restrict to selected safe tag families
  exclude_tags: [dos, fuzz, intrusive, sqli, xss]
```

Adjust worker counts under `assessment.performance` to fit the scanner host and
network. Parallelism changes execution time, not which targets or checks are
selected.

## Email delivery

When email delivery is enabled, the JSON, Markdown, and HTML reports can all be
attached. The message body includes the contextual risk rating, delta summary,
and report-generation health.

For Gmail, enable 2-Step Verification and create an app password. The setup
wizard stores credentials in `config/.email_credentials` with mode `0600`, not
in YAML. A local loopback-only Postfix path is also supported through
`scripts/setup_local_mail.sh`.

## Interpretation limits

Automated scanning cannot prove the absence of vulnerabilities. High-impact
findings require version/configuration confirmation, and high-assurance reviews
still require authenticated checks, patch validation, architecture review, and
manual testing where authorized.
