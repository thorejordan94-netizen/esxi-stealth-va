"""Generate a contextual, self-contained Markdown assessment report."""

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List

from orchestrator.finding_knowledge import build_contextual_analysis


logger = logging.getLogger(__name__)


def _one_line(value: Any) -> str:
    return " ".join(str(value or "").replace("|", "\\|").split())


def _target(item: Dict[str, Any]) -> str:
    host = item.get("host", "") or "unknown"
    port = int(item.get("port", 0) or 0)
    return "{}:{}".format(host, port) if port else host


def _code_block(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "_No scanner evidence was included._"
    # Four-backtick fences safely contain ordinary triple-backtick scanner output.
    return "````text\n{}\n````".format(text[:12000])


def _bullets(values: Iterable[Any], empty: str = "None recorded.") -> List[str]:
    items = [str(value).strip() for value in values or [] if str(value).strip()]
    if not items:
        return ["- {}".format(empty)]
    return ["- {}".format(value) for value in items]


def _risk_statement(analysis: Dict[str, Any]) -> str:
    rating = analysis["risk_rating"]
    distribution = analysis["severity_distribution"]
    if distribution["Critical"]:
        return "Critical findings are present. Immediate validation, containment, and remediation are required."
    if distribution["High"]:
        return "High-severity findings are present. The environment has material exposure that should be remediated urgently."
    if distribution["Medium"]:
        return "No critical or high findings were normalized, but meaningful control weaknesses remain and require planned remediation."
    if distribution["Low"]:
        return "The observed risk is primarily hardening and attack-surface reduction."
    if analysis["coverage"]["execution_errors"]:
        return "No material findings were normalized, but execution errors prevent a clean assurance conclusion."
    return "No material weakness was normalized from the available scanner evidence. This is not proof that the environment is vulnerability-free."


def _asset_rows(report) -> List[str]:
    rows = []
    for host in sorted(report.findings_infrastructure, key=lambda item: item.host):
        tcp = [str(port.port) for port in host.ports if port.protocol == "tcp"]
        udp = [str(port.port) for port in host.ports if port.protocol == "udp"]
        services = []
        for port in host.ports:
            label = "{}/{}".format(port.protocol, port.port)
            if port.service:
                label += " ({})".format(port.service)
            if port.version:
                label += " — {}".format(_one_line(port.version))
            services.append(label)
        rows.append("| {} | {} | {} | {} | {} | {} |".format(
            _one_line(host.host),
            _one_line(host.hostname or "—"),
            _one_line(host.role or "unknown"),
            ", ".join(tcp) or "—",
            ", ".join(udp) or "—",
            "<br>".join(_one_line(value) for value in services) or "No open ports recorded",
        ))
    return rows


def generate_report(report, output_path: str):
    analysis = build_contextual_analysis(report)
    metadata = report.metadata
    coverage = analysis["coverage"]
    severity = analysis["severity_distribution"]
    lines = []

    lines.extend([
        "# ESXi Vulnerability Assessment Report",
        "",
        "> **Risk rating:** {} &nbsp;|&nbsp; **Risk score:** {}/100 &nbsp;|&nbsp; **Run ID:** `{}`".format(
            analysis["risk_rating"], analysis["risk_score"], metadata.run_id,
        ),
        "",
        "## Executive Summary",
        "",
        _risk_statement(analysis),
        "",
        "This report combines raw scanner observations with a deterministic local knowledge base. The contextual conclusions explain likely implications, recommended measures, and validation steps. Scanner evidence and authoritative vendor advisories remain the source of truth.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        "| Hosts represented | {} |".format(coverage["hosts_in_report"]),
        "| Open ports represented | {} |".format(coverage["open_ports_total"]),
        "| TCP / UDP ports | {} / {} |".format(coverage["open_ports_by_protocol"].get("tcp", 0), coverage["open_ports_by_protocol"].get("udp", 0)),
        "| TLS endpoints assessed | {} |".format(coverage["tls_endpoints_assessed"]),
        "| Web endpoints assessed | {} |".format(coverage["web_endpoints_assessed"]),
        "| Scanner findings | {} |".format(coverage["scanner_findings"]),
        "| Execution errors | {} |".format(coverage["execution_errors"]),
        "",
        "### Severity Distribution",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        "| {} | {} | {} | {} | {} |".format(severity["Critical"], severity["High"], severity["Medium"], severity["Low"], severity["Info"]),
        "",
        "## Priority Action Plan",
        "",
    ])

    actions = analysis["priority_actions"]
    if actions:
        lines.extend([
            "| Priority | Severity | Target | Finding | Immediate action |",
            "|---|---|---|---|---|",
        ])
        for action in actions:
            lines.append("| {} | {} | `{}` | {} | {} |".format(
                _one_line(action["priority"]), _one_line(action["severity"]),
                _one_line(action["target"]), _one_line(action["finding"]),
                _one_line(action["action"]),
            ))
    else:
        lines.append("No Critical, High, or Medium remediation item was normalized from the available evidence.")

    lines.extend([
        "",
        "## Scope and Scan Coverage",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Primary target | `{}` |".format(_one_line(metadata.target_primary or "not preselected")),
        "| Target hostname | `{}` |".format(_one_line(metadata.target_hostname or "not recorded")),
        "| Environment | {} |".format(_one_line(metadata.environment)),
        "| Assessment type | {} |".format(_one_line(metadata.assessment_type)),
        "| Scan profile | `{}` |".format(_one_line(metadata.scan_profile)),
        "| Started | {} |".format(_one_line(metadata.started_at or "not recorded")),
        "| Finished | {} |".format(_one_line(metadata.finished_at or "not recorded")),
        "| VM count reported by discovery | {} |".format(metadata.vm_count),
        "",
        "The default full-coverage configuration scans every discovered host, all TCP ports, all configured UDP ports, every discovered service during safe enumeration, and every detected or probed web/TLS endpoint. Public subnets and intrusive/DoS/fuzz templates remain excluded unless explicitly authorized in configuration.",
        "",
        "## Asset and Open-Port Inventory",
        "",
        "| Address | Hostname | Role | TCP ports | UDP ports | Services |",
        "|---|---|---|---|---|---|",
    ])
    rows = _asset_rows(report)
    lines.extend(rows or ["| — | — | — | — | — | No host findings recorded |"])

    lines.extend(["", "## Contextual Findings", ""])
    if not analysis["findings"]:
        lines.append("No contextual findings were generated from the available scanner evidence.")

    for index, item in enumerate(analysis["findings"], 1):
        context = item["context"]
        lines.extend([
            "### {}. [{}] {}".format(index, item["severity"], item["title"]),
            "",
            "| Attribute | Value |",
            "|---|---|",
            "| Target | `{}` |".format(_one_line(_target(item))),
            "| Category | {} |".format(_one_line(item["category"])),
            "| Priority | {} |".format(_one_line(item["priority"])),
            "| Scanner / source | `{}` |".format(_one_line(item.get("scanner") or "not recorded")),
            "| Source ID | `{}` |".format(_one_line(item.get("source_id") or "not recorded")),
            "| Knowledge rule | `{}` |".format(_one_line(context["knowledge_rule"])),
            "| Context confidence | {} |".format(_one_line(context["confidence"])),
            "| Likelihood | {} |".format(_one_line(context["likelihood"])),
            "",
            "**Scanner description**",
            "",
            item.get("description") or "No scanner description was included.",
            "",
            "**Conclusion**",
            "",
            context["conclusion"],
            "",
            "**Implications**",
            "",
        ])
        lines.extend(_bullets(context["implications"]))
        lines.extend(["", "**Recommended measures**", ""])
        for number, action in enumerate(context["remediation"], 1):
            lines.append("{}. {}".format(number, action))
        lines.extend(["", "**Validation / closure criteria**", ""])
        lines.extend(_bullets(context["validation"]))
        if context.get("compliance"):
            lines.extend(["", "**Control mapping**", ""])
            lines.extend(_bullets(context["compliance"]))
        if item.get("references"):
            lines.extend(["", "**References provided by scanner or knowledge rule**", ""])
            lines.extend(_bullets(item["references"]))
        lines.extend(["", "**Evidence**", "", _code_block(item.get("evidence")), ""])

    lines.extend(["## Delta from Previous Assessment", ""])
    if report.delta:
        summary = report.delta.summary
        lines.extend([
            "| New | Resolved | Changed | Unchanged |",
            "|---:|---:|---:|---:|",
            "| {} | {} | {} | {} |".format(summary.get("new", 0), summary.get("resolved", 0), summary.get("changed", 0), summary.get("unchanged", 0)),
            "",
        ])
        for entry in report.delta.entries:
            lines.append("- **{} / {} / {}:** {}".format(entry.change_type, entry.severity, entry.category, entry.summary))
    else:
        lines.append("No previous-run delta was available for this assessment.")

    lines.extend(["", "## Execution Health and Limitations", ""])
    if report.execution_errors:
        lines.extend(["| Phase | Module | Error | Time |", "|---|---|---|---|"])
        for error in report.execution_errors:
            lines.append("| {} | {} | {} | {} |".format(
                _one_line(error.phase), _one_line(error.module), _one_line(error.error), _one_line(error.timestamp),
            ))
        lines.extend(["", "Because execution errors occurred, absence of a finding in an affected phase must not be interpreted as a clean result."])
    else:
        lines.append("No execution errors were recorded by the orchestrator.")

    lines.extend([
        "",
        "## Interpretation Notes",
        "",
        "- Findings are contextualized by exact template IDs, keywords, tags, categories, and severity. Exact identifiers receive the highest match weight.",
        "- Unknown findings use a conservative generic fallback. The report does not invent CVE-specific versions, exploitability prerequisites, or vendor fixes.",
        "- Open ports are included in the asset inventory. High-value, plaintext, administrative, and data-service exposures are also elevated as contextual observations.",
        "- Automated scanning cannot prove the absence of vulnerabilities. Authenticated checks, architecture review, patch verification, and manual validation remain necessary for high-assurance conclusions.",
        "",
        "---",
        "",
        "Generated by ESXi Stealth Vulnerability Assessment on {}. Knowledge base version: `{}`.".format(
            datetime.utcnow().isoformat() + "Z", analysis["knowledge_base_version"],
        ),
        "",
    ])

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    logger.info("Markdown report generated: %s", output_path)
