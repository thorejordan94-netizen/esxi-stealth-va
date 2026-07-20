# ESXi Stealth Vulnerability Assessment

This repository contains the restored comprehensive, phased internal
assessment framework. It supports the original Python 3.6 openSUSE/SLES host
as well as current Python versions.

## One-command run

```bash
python3 master_assessment.py
```

No target is required. The launcher installs missing Python dependencies,
installs missing external tools when privileges permit, ignores common
container/virtual interfaces, discovers private local subnets, identifies live
hosts, and executes the configured assessment phases.

Use only on networks and systems you are authorized to assess.

## Pipeline

0. Framework and Nuclei-template update
1. Prerequisite installation, validation, and scope initialization
2. Live-host discovery, TCP service scanning, ESXi classification, and bounded UDP discovery
3. Focused service enumeration and safe configuration checks
4. TLS/certificate analysis
5. HTTP security assessment
6. Nuclei vulnerability scanning with intrusive/DoS tags excluded
7. Delta analysis, state checkpointing, archival, and HTML/JSON reports

Docker, CNI, bridge, veth, and similar virtual interfaces are excluded from
automatic scope by default. Broad private subnets up to `/16` are split into
smaller sweeps and every long Nmap scan emits periodic progress messages.

## Useful commands

```bash
# Full automatic run (default)
python3 master_assessment.py

# Fast automatic profile
python3 master_assessment.py --profile quick

# Use only configured targets/subnets
python3 master_assessment.py --no-auto-network

# Verify configuration/tools without scanning or installing
python3 master_assessment.py --dry-run --no-install

# End-to-end synthetic verification
python3 master_assessment.py --mock --no-auto-network

# Write all reports and scan artifacts to a chosen directory
python3 master_assessment.py --output-dir /var/reports/esxi-assessment

# Resume from a checkpointed phase
python3 master_assessment.py --phase 4

# Guided terminal setup
python3 run_assessment.py --setup
```

Reports are written to `output/assessment_report.json` and
`output/assessment_report.html`; logs are written to `logs/`. The legacy
`--output PATH` spelling is retained as an alias for `--output-dir PATH`.

Configuration is in `config/assessment.yaml`, `config/scan_profile.yaml`, and
`config/stealth_profile.yaml`.

## Guided setup and email delivery

`--setup` opens a short guided terminal wizard. It asks for the primary target,
one scan-coverage profile, and optional report delivery, then shows a final
review before saving. Advanced timing, phase, tool, and stealth settings stay
behind one explicit option instead of appearing during normal setup.

The recommended baseline is designed for this internal ESXi assessment:
private networks only, public subnet scanning excluded, core discovery and
security phases enabled, delta reporting enabled, external SSL Labs checks
disabled, automatic code/tool updates disabled, and email delivery disabled
until explicitly configured. Existing values are preserved when the wizard is
run again.

For Gmail, enable 2-Step Verification and create a Google app password. The
wizard stores that password in `config/.email_credentials` with mode `0600`,
not in YAML. The configured report sender uses Gmail SMTP with STARTTLS.

For a local delivery path, choose the automated Postfix option. The wizard can
install, configure, start, and health-check a loopback-only Postfix server and
automatically generates the local hostname, mail domain, and sender address
(for example `assessment@example.internal`). The underlying script can also
queue a test message when invoked manually and supports Debian/
Ubuntu, RHEL/Fedora, and openSUSE/SLES:

```bash
scripts/setup_local_mail.sh --check-only
```

The mail script detects whether systemd is actually running instead of merely
checking whether `systemctl` is installed. In containers it falls back to the
service/Postfix command, creates `/etc/aliases` with a root alias, rebuilds the
alias database, and then verifies the SMTP listener.

The quick email path keeps the HTML, JSON, delta, and health/error report scope
and runs delivery after a successful report generation. Edit the YAML directly
if a different subject or report scope is required.

Advanced boolean settings use direct checkboxes: `[x]` means `True/Enabled`
and `[ ]` means `False/Disabled`. Numeric, string, list, and mapping settings
open a typed value prompt with validation appropriate to their current type;
lists also accept comma-separated input.

Nmap per-host and process timeouts are intentionally shorter by default:
`5m` for service/ESXi hosts, `90s` for discovery sweeps, and `300s` for UDP
and safe NSE scans. They remain editable in the setup wizard.
