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
```

Reports are written to `output/assessment_report.json` and
`output/assessment_report.html`; logs are written to `logs/`. The legacy
`--output PATH` spelling is retained as an alias for `--output-dir PATH`.

Configuration is in `config/assessment.yaml`, `config/scan_profile.yaml`, and
`config/stealth_profile.yaml`.
