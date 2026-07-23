# Contextual Reporting and Full-Coverage Scan Changes

## Reporting

- Added `assessment_report.md` with executive summary, asset inventory, risk prioritization, contextual implications, remediation steps, validation criteria, evidence, delta, and execution health.
- Added a local hardcoded finding knowledge base with exact-ID, keyword, tag, category, and severity matching.
- Enriched `assessment_report.json` with `report_summary`, `contextual_analysis`, normalized contextual findings, priority actions, coverage metrics, risk rating, and schema version.
- Added Markdown report delivery to configured assessment email.

## Coverage

- Default profile changed to `thorough`.
- Default TCP range changed to `1-65535`.
- Host cap and service-enumeration port cap use zero as unlimited.
- Configured UDP coverage changed to the complete Nmap UDP service range.
- Every open TCP port is probed for HTTP and HTTPS.
- Every open endpoint is included in the Nuclei target list.
- All safe Nuclei severities are enabled; DoS, fuzz, and intrusive template classes remain excluded.

## Performance

- Added configurable worker pools for UDP scans, service enumeration, TLS analysis, web-protocol probing, and web assessment.
- Disabled the overall pipeline runtime ceiling by default; individual process and host timeouts remain active.

## Verification

- Added contextual reporting tests.
- Added full-coverage target-selection and no-cap enumeration tests.
- Added GitHub Actions syntax compilation and unit-test workflow for Python 3.9 and 3.12.
