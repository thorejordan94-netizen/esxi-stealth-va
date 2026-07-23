"""Generate enriched JSON and contextual Markdown assessment reports."""

import json
import logging
from collections import Counter
from pathlib import Path

from orchestrator.finding_knowledge import (
    contextualize_all,
    overall_risk,
    prioritized_actions,
    risk_score,
)
from orchestrator.models import AssessmentReport


logger = logging.getLogger(__name__)


def _endpoint(host, port=0, url=""):
    if url:
        return url
    return "{}:{}".format(host, port) if port else host


def _base_finding(finding_id, title, severity, category, target, description,
                  evidence="", scanner="", tags=None, references=None):
    return {
        "id": finding_id or title,
        "title": title or finding_id or "Unnamed finding",
        "severity": str(severity or "info").lower(),
        "category": category,
        "target": target,
        "description": description or "No scanner description was supplied.",
        "evidence": evidence or "",
        "scanner": scanner or "unknown",
        "tags": list(tags or []),
        "references": list(references or []),
    }


def normalize_findings(report):
    """Convert scanner-specific results into one stable finding schema."""
    findings = []

    for item in report.findings_vulns:
        findings.append(_base_finding(
            item.template_id or item.name,
            item.name or item.template_id,
            item.severity,
            "vulnerability",
            _endpoint(item.host, item.port, item.url),
            item.description,
            item.evidence,
            item.scanner,
            item.tags,
            item.reference,
        ))

    for result in report.findings_web:
        for item in result.findings:
            findings.append(_base_finding(
                item.id, item.title, item.severity, "web",
                _endpoint(result.host, result.port, result.url),
                item.description, item.evidence, "web-assessment",
                ["http", "web"],
            ))

    for item in report.findings_crypto:
        target = _endpoint(item.host, item.port)
        for index, vulnerability in enumerate(item.vulnerabilities):
            findings.append(_base_finding(
                "TLS-{}-{}".format(item.host.replace(".", "-"), index + 1),
                vulnerability, item.severity, "crypto", target,
                "TLS assessment reported: {}".format(vulnerability),
                scanner=item.scan_method, tags=["tls", "ssl", "crypto"],
            ))

        certificate = item.certificate
        if certificate and certificate.self_signed:
            findings.append(_base_finding(
                "TLS-SELF-SIGNED-{}-{}".format(item.host.replace(".", "-"), item.port),
                "Self-signed certificate", "medium", "crypto", target,
                "The endpoint presents a self-signed certificate outside the approved trust chain.",
                "Subject: {}; Issuer: {}; Valid to: {}".format(
                    certificate.subject, certificate.issuer, certificate.valid_to
                ),
                item.scan_method, ["tls", "certificate", "self-signed"],
            ))

        legacy = []
        for version, enabled in (item.tls_versions or {}).items():
            normalized = str(version).lower().replace("_", "").replace(" ", "")
            if enabled and normalized in {
                "sslv2", "sslv3", "tlsv1", "tls1.0", "tlsv1.0", "tlsv1.1", "tls1.1"
            }:
                legacy.append(str(version))
        if legacy:
            findings.append(_base_finding(
                "TLS-LEGACY-{}-{}".format(item.host.replace(".", "-"), item.port),
                "Legacy TLS/SSL protocols enabled", "medium", "crypto", target,
                "The endpoint accepts obsolete protocol versions: {}.".format(", ".join(sorted(legacy))),
                scanner=item.scan_method, tags=["tls", "ssl", "crypto", "legacy"],
            ))

        if item.grade and item.grade not in ("A+", "A", "N/A") and not item.vulnerabilities:
            findings.append(_base_finding(
                "TLS-GRADE-{}-{}".format(item.host.replace(".", "-"), item.port),
                "Suboptimal TLS configuration", item.severity, "crypto", target,
                "The TLS endpoint received grade {} and requires configuration review.".format(item.grade),
                scanner=item.scan_method, tags=["tls", "ssl", "crypto"],
            ))

    deduplicated = {}
    for finding in findings:
        key = (
            finding.get("category"), finding.get("target"), finding.get("id"),
            finding.get("title"), finding.get("evidence"),
        )
        deduplicated[key] = finding
    return list(deduplicated.values())


def _coverage(report):
    role_counts = Counter((host.role or "unknown") for host in report.findings_infrastructure)
    protocol_counts = Counter()
    service_counts = Counter()
    assets = []
    for host in sorted(report.findings_infrastructure, key=lambda item: item.host):
        ports = []
        for port in sorted(host.ports, key=lambda item: (item.protocol, item.port)):
            protocol_counts[port.protocol] += 1
            service_counts[port.service or "unknown"] += 1
            ports.append(port.to_dict())
        assets.append({
            "host": host.host,
            "hostname": host.hostname,
            "role": host.role or "unknown",
            "os_fingerprint": host.os_fingerprint,
            "open_ports": ports,
            "open_port_count": len(ports),
        })
    return {
        "asset_count": len(assets),
        "role_counts": dict(role_counts),
        "protocol_counts": dict(protocol_counts),
        "service_counts": dict(service_counts.most_common()),
        "assets": assets,
    }


def build_enriched_payload(report):
    contextual = contextualize_all(normalize_findings(report))
    score = risk_score(contextual)
    severity_counts = Counter(item.get("severity", "info") for item in contextual)
    payload = report.to_dict()
    payload["reporting"] = {
        "schema_version": "3.0",
        "human_report": "assessment_report.md",
        "context_engine": "hardcoded-knowledge-base-with-generic-fallback",
        "risk_score_note": "Operational 0-100 indicator; not a CVSS score.",
    }
    payload["coverage"] = _coverage(report)
    payload["assessment_conclusions"] = {
        "overall_risk": overall_risk(score, contextual),
        "operational_risk_score": score,
        "total_contextual_findings": len(contextual),
        "actionable_findings": sum(
            1 for item in contextual if item.get("context", {}).get("problematic")
        ),
        "severity_distribution": {
            severity: severity_counts.get(severity, 0)
            for severity in ("critical", "high", "medium", "low", "info")
        },
        "priority_actions": prioritized_actions(contextual),
        "findings": contextual,
    }
    return payload


def write_enriched_json(report, output_path):
    payload = build_enriched_payload(report)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Enriched JSON report generated: %s", path)
    return payload


def _md(value):
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _bullets(values, empty="No additional guidance available."):
    cleaned = [str(value).strip() for value in (values or []) if str(value).strip()]
    return ["- {}".format(value) for value in cleaned] if cleaned else ["- {}".format(empty)]


def _severity_label(value):
    return str(value or "info").upper()


def generate_markdown_report(report, output_path, payload=None):
    payload = payload or build_enriched_payload(report)
    metadata = payload.get("metadata", {})
    conclusions = payload.get("assessment_conclusions", {})
    findings = conclusions.get("findings", [])
    coverage = payload.get("coverage", {})
    severity = conclusions.get("severity_distribution", {})
    errors = payload.get("execution_errors", [])

    lines = [
        "# ESXi Vulnerability Assessment",
        "",
        "> Scanner matches are explained contextually but must still be validated against the affected product, configuration, and business context.",
        "",
        "## Executive summary",
        "",
        "| Field | Result |",
        "|---|---|",
        "| Run ID | `{}` |".format(_md(metadata.get("run_id", "unknown"))),
        "| Assessment period | {} |".format(_md(metadata.get("scan_week", "unknown"))),
        "| Primary target | {} |".format(_md(metadata.get("target_primary", "not preselected"))),
        "| Overall risk | **{}** |".format(_severity_label(conclusions.get("overall_risk"))),
        "| Operational risk indicator | **{}/100** |".format(conclusions.get("operational_risk_score", 0)),
        "| Assets covered | {} |".format(coverage.get("asset_count", 0)),
        "| Open ports recorded | {} |".format(sum(
            item.get("open_port_count", 0) for item in coverage.get("assets", [])
        )),
        "| Contextual findings | {} |".format(conclusions.get("total_contextual_findings", 0)),
        "| Actionable findings | {} |".format(conclusions.get("actionable_findings", 0)),
        "| Execution errors | {} |".format(len(errors)),
        "",
        "### Severity distribution",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        "| {} | {} | {} | {} | {} |".format(
            severity.get("critical", 0), severity.get("high", 0), severity.get("medium", 0),
            severity.get("low", 0), severity.get("info", 0),
        ),
        "",
        "## Prioritized remediation plan",
        "",
    ]

    actions = conclusions.get("priority_actions", [])
    if actions:
        lines.extend(["| Priority | Target | Action | Source |", "|---|---|---|---|"])
        for action in actions:
            lines.append("| {} | {} | {} | {} |".format(
                _md(action.get("priority")), _md(action.get("target")),
                _md(action.get("action")), _md(action.get("source_finding")),
            ))
    else:
        lines.append("No remediation actions were derived from the recorded findings.")

    lines.extend(["", "## Detailed findings", ""])
    if not findings:
        lines.extend([
            "No findings were recorded. This does not prove the environment is vulnerability-free; review coverage and execution errors.",
            "",
        ])

    number = 0
    for level in ("critical", "high", "medium", "low", "info"):
        selected = [item for item in findings if item.get("severity") == level]
        if not selected:
            continue
        lines.extend(["### {}".format(level.upper()), ""])
        for finding in selected:
            number += 1
            context = finding.get("context", {})
            lines.extend([
                "#### {}. {}".format(number, _md(finding.get("title"))),
                "",
                "| Attribute | Value |", "|---|---|",
                "| ID | `{}` |".format(_md(finding.get("id"))),
                "| Target | `{}` |".format(_md(finding.get("target"))),
                "| Category | {} |".format(_md(finding.get("category"))),
                "| Severity / priority | **{}** / {} |".format(
                    _severity_label(finding.get("severity")), _md(finding.get("priority"))
                ),
                "| Scanner | {} |".format(_md(finding.get("scanner"))),
                "| Problematic | {} |".format(
                    "Yes" if context.get("problematic") else "Contextual observation"
                ),
                "| Knowledge rule | `{}` |".format(_md(context.get("knowledge_rule"))),
                "", "**Observation**", "",
                str(finding.get("description") or "No description supplied."),
                "", "**Conclusion**", "",
                str(context.get("risk_statement") or "No contextual conclusion available."),
                "", "**Implications**", "",
            ])
            lines.extend(_bullets(context.get("implications")))
            lines.extend(["", "**Recommended measures**", ""])
            lines.extend(_bullets(context.get("recommended_actions")))
            lines.extend(["", "**Verification after remediation**", ""])
            lines.extend(_bullets(context.get("validation_steps")))

            evidence = str(finding.get("evidence") or "").strip()
            if evidence:
                lines.extend([
                    "", "<details><summary>Scanner evidence</summary>", "", "```text",
                    evidence[:8000], "```", "", "</details>",
                ])
            references = finding.get("references") or []
            if references:
                lines.extend(["", "**References supplied by scanner**", ""])
                lines.extend("- {}".format(value) for value in references)
            lines.append("")

    lines.extend([
        "## Asset and service coverage", "",
        "| Host | Hostname | Role | OS fingerprint | Open ports |",
        "|---|---|---|---|---|",
    ])
    for asset in coverage.get("assets", []):
        ports = ", ".join(
            "{}/{} {}{}".format(
                item.get("port"), item.get("protocol", "tcp"), item.get("service") or "unknown",
                " ({})".format(item.get("version")) if item.get("version") else "",
            )
            for item in asset.get("open_ports", [])
        ) or "none confirmed"
        lines.append("| `{}` | {} | {} | {} | {} |".format(
            _md(asset.get("host")), _md(asset.get("hostname")), _md(asset.get("role")),
            _md(asset.get("os_fingerprint")), _md(ports),
        ))

    delta = payload.get("delta") or {}
    lines.extend(["", "## Change analysis", ""])
    if delta:
        summary = delta.get("summary") or {}
        lines.extend([
            "| New | Resolved | Changed | Unchanged |", "|---:|---:|---:|---:|",
            "| {} | {} | {} | {} |".format(
                summary.get("new", 0), summary.get("resolved", 0),
                summary.get("changed", 0), summary.get("unchanged", 0),
            ),
        ])
    else:
        lines.append("No prior assessment was available for delta comparison.")

    lines.extend(["", "## Execution health and limitations", ""])
    if errors:
        for error in errors:
            lines.append("- **{}/{}:** {}".format(
                _md(error.get("phase")), _md(error.get("module")), _md(error.get("error"))
            ))
    else:
        lines.append("- No execution errors were recorded.")
    lines.extend([
        "- A negative scanner result is not proof that a weakness is absent.",
        "- UDP detection can remain inconclusive when firewalls silently drop probes.",
        "- Generic templates and version-based CVE matches require validation before operational decisions.",
        "- The operational risk indicator is a prioritization aid and is not a CVSS calculation.",
        "", "## Report artifacts", "",
        "- `assessment_report.json`: raw findings plus normalized contextual conclusions.",
        "- `assessment_report.md`: this human-readable analysis.",
        "- `assessment_report.html`: compact visual overview.",
    ])

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    logger.info("Markdown report generated: %s", path)
