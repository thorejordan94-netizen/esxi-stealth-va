# ESXi Stealth Vulnerability Assessment

This repository contains a comprehensive, phased internal assessment framework.
It supports the original Python 3.6 openSUSE/SLES host as well as current Python
versions.

Use it only on networks and systems you are explicitly authorized to assess.
The comprehensive profile is intentionally noisy and resource-intensive. DoS,
fuzzing, and intrusive Nuclei templates remain excluded to avoid avoidable
service impact; all non-destructive severity levels are included.

## One-command run

```bash
python3 master_assessment.py
```

No target is required. The launcher installs missing Python dependencies,
installs missing external tools when privileges permit, ignores common
container/virtual interfaces, discovers private local subnets, identifies live
hosts, and executes the configured assessment phases.

The default `comprehensive` profile covers every TCP port, every UDP port, all
discovered live hosts, every confirmed-open service, non-standard HTTP/HTTPS
ports, and all non-destructive Nuclei severity levels.

## Pipeline

0. Framework and Nuclei-template update
1. Prerequisite installation, validation, and scope initialization
2. Complete live-host discovery and full TCP/UDP port discovery
3. Version detection and safe NSE checks on every confirmed-open service
4. TLS/certificate analysis
5. HTTP security assessment on standard and non-standard web ports
6. Nuclei vulnerability scanning across discovered endpoints
7. Delta analysis, state checkpointing, archival, and report generation

Broad private networks are split into smaller discovery sweeps for progress and
recoverability. This chunking does not truncate scope. Host and service scans
are parallelized with configurable worker limits.

## Quality-preserving acceleration

The main optimization is a two-stage TCP workflow:

1. Phase 2 checks all 65,535 TCP ports without running expensive version probes.
2. Phase 3 runs version detection and safe NSE scripts only on ports confirmed
   open in Phase 2.

This avoids running deep probes against closed ports while preserving complete
port coverage. Independent hosts are processed concurrently, and service
enumeration is split into deterministic batches to reduce command timeouts.

## Report outputs

A completed run writes:

- `output/assessment_report.json` — raw scanner results plus normalized findings,
  coverage data, contextual conclusions, implications, remediation measures,
  verification steps, priority actions, and an operational risk indicator.
- `output/assessment_report.md` — the primary human-readable report with an
  executive summary, prioritized remediation plan, detailed contextual finding
  explanations, evidence, asset coverage, delta analysis, and limitations.
- `output/assessment_report.html` — compact visual overview.
- `output/assessment_state.json` — phase checkpoint used for recovery.
- `output/history/` — historical JSON reports for delta comparison.
- `logs/` — execution and audit logs.

The contextual engine is deterministic and offline. Its hardcoded knowledge base
covers common network, web, TLS, authentication, exposure, and CVE scenarios.
Unknown findings are retained and receive a conservative validation workflow;
the software does not invent exploitability when no specific rule matches.

The operational 0–100 indicator is a prioritization aid, not a CVSS score.

## Useful commands

```bash
# Full comprehensive run (default)
python3 master_assessment.py

# Explicit comprehensive profile
python3 run_assessment.py --profile comprehensive

# Fast triage profile
python3 run_assessment.py --profile quick

# Conservative exhaustive TCP profile
python3 run_assessment.py --profile thorough

# Use only configured targets/subnets
python3 master_assessment.py --no-auto-network

# Verify configuration/tools without scanning or installing
python3 master_assessment.py --dry-run --no-install

# End-to-end synthetic verification
python3 master_assessment.py --mock --no-auto-network

# Write reports and scan artifacts to a chosen directory
python3 master_assessment.py --output-dir /var/reports/esxi-assessment

# Resume from a checkpointed phase
python3 master_assessment.py --phase 4

# Guided terminal setup
python3 run_assessment.py --setup
```

Configuration is in `config/assessment.yaml`, `config/scan_profile.yaml`, and
`config/stealth_profile.yaml`.

Important coverage controls:

- `assessment.scan.parallel_hosts` controls concurrent host port scans.
- `assessment.security_tests.parallel_hosts` controls concurrent deep service
  enumeration.
- `assessment.security_tests.ports_per_batch` controls open-port batch size.
- `assessment.expanded_discovery.tcp_ports` controls TCP coverage.
- `assessment.expanded_discovery.udp.ports` controls UDP coverage.
- `assessment.web.parallel_targets` controls concurrent web endpoints.
- `assessment.nuclei.rate_limit` and `concurrency` control Nuclei throughput.

A value of `max_hosts: 0` and `max_ports_per_host: 0` means no truncation.

## Guided setup and email delivery

`--setup` opens a short guided terminal wizard. It asks for the primary target,
one scan-coverage profile, and optional report delivery, then shows a final
review before saving. Advanced timing, phase, tool, and scan settings stay behind
one explicit option instead of appearing during normal setup.

For Gmail, enable 2-Step Verification and create a Google app password. The
wizard stores that password in `config/.email_credentials` with mode `0600`, not
in YAML. The configured report sender uses Gmail SMTP with STARTTLS.

For a local delivery path, choose the automated Postfix option. The wizard can
install, configure, start, and health-check a loopback-only Postfix server and
automatically generates the local hostname, mail domain, and sender address.
The underlying script also supports Debian/Ubuntu, RHEL/Fedora, and openSUSE/SLES:

```bash
scripts/setup_local_mail.sh --check-only
```

Email delivery can attach the Markdown, JSON, and HTML reports and includes the
overall risk, actionable-finding count, priority measures, delta, and execution
health in the message body.

## Testing

```bash
python3 -m compileall -q orchestrator run_assessment.py master_assessment.py setup_wizard.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

GitHub Actions runs the compile and unit-test suite on supported Python versions.
