import json
import tempfile
import unittest
from pathlib import Path

from orchestrator.finding_knowledge import build_contextual_analysis, contextualize_finding
from orchestrator.models import (
    AssessmentMetadata,
    AssessmentReport,
    HostFinding,
    PortEntry,
    VulnerabilityFinding,
    WebAssessmentResult,
    WebVulnerability,
)
from orchestrator.report_json import build_enriched_report, write_enriched_json
from orchestrator.report_markdown import generate_report
from orchestrator.reporting_policy import calculate_risk_score, risk_rating


class ContextualKnowledgeTests(unittest.TestCase):
    def test_exact_template_id_selects_smbv1_rule(self):
        result = contextualize_finding({
            "category": "vulnerability",
            "host": "10.0.0.10",
            "port": 445,
            "title": "SMBv1 Protocol Enabled",
            "severity": "high",
            "description": "The host advertises obsolete SMBv1.",
            "evidence": "NT LM 0.12",
            "source_id": "NMAP-SMB1",
            "scanner": "nmap-safe-nse",
            "tags": ["smb", "legacy"],
            "references": [],
        })

        self.assertEqual("High", result["severity"])
        self.assertEqual("smbv1", result["context"]["knowledge_rule"])
        self.assertIn("Disable SMBv1", " ".join(result["context"]["remediation"]))
        self.assertTrue(result["finding_key"])

    def test_unknown_finding_uses_conservative_fallback(self):
        result = contextualize_finding({
            "category": "vulnerability",
            "host": "10.0.0.20",
            "port": 12345,
            "title": "Unknown custom scanner condition",
            "severity": "medium",
            "description": "Vendor-specific condition.",
            "evidence": "opaque evidence",
            "source_id": "CUSTOM-001",
            "scanner": "custom",
            "tags": [],
            "references": [],
        })

        self.assertEqual("generic-medium", result["context"]["knowledge_rule"])
        self.assertEqual("low", result["context"]["confidence"])
        self.assertIn("Validate", result["context"]["validation"][0])

    def test_highest_finding_sets_minimum_environment_rating(self):
        high_score = calculate_risk_score([{"severity": "High"}])
        critical_score = calculate_risk_score([{"severity": "Critical"}])
        self.assertEqual("High", risk_rating(high_score))
        self.assertEqual("Critical", risk_rating(critical_score))


class ContextualReportTests(unittest.TestCase):
    def _report(self):
        report = AssessmentReport(AssessmentMetadata(
            target_primary="10.0.0.10",
            target_hostname="esxi01.internal",
            started_at="2026-07-23T10:00:00+00:00",
            scan_profile="thorough",
        ))
        report.add_host(HostFinding(
            host="10.0.0.10",
            hostname="esxi01.internal",
            role="esxi_host",
            ports=[
                PortEntry(port=443, protocol="tcp", service="https", version="VMware ESXi"),
                PortEntry(port=445, protocol="tcp", service="microsoft-ds"),
                PortEntry(port=161, protocol="udp", service="snmp"),
            ],
        ))
        report.add_vuln(VulnerabilityFinding(
            host="10.0.0.10",
            port=445,
            template_id="NMAP-SMB1",
            name="SMBv1 Protocol Enabled",
            severity="high",
            description="The host advertises obsolete SMBv1.",
            evidence="NT LM 0.12",
            tags=["smb", "legacy"],
            scanner="nmap-safe-nse",
        ))
        report.add_web(WebAssessmentResult(
            host="10.0.0.10",
            port=443,
            url="https://10.0.0.10",
            findings=[WebVulnerability(
                id="WEB-500",
                title="Missing HSTS",
                severity="High",
                description="Downgrade prevention",
                evidence="strict-transport-security missing",
            )],
        ))
        report.set_finished()
        return report

    def test_analysis_contains_coverage_and_priorities(self):
        analysis = build_contextual_analysis(self._report())
        self.assertEqual(1, analysis["coverage"]["hosts_in_report"])
        self.assertEqual(3, analysis["coverage"]["open_ports_total"])
        self.assertEqual(2, analysis["coverage"]["open_ports_by_protocol"]["tcp"])
        self.assertGreaterEqual(analysis["severity_distribution"]["High"], 2)
        self.assertTrue(analysis["priority_actions"])

    def test_enriched_json_preserves_raw_sections_and_high_rating(self):
        payload = build_enriched_report(self._report())
        self.assertIn("findings_infrastructure", payload)
        self.assertIn("findings_vulns", payload)
        self.assertIn("contextual_analysis", payload)
        self.assertEqual("2.2-contextual", payload["schema_version"])
        self.assertEqual("High", payload["contextual_analysis"]["risk_rating"])

    def test_json_and_markdown_are_written(self):
        report = self._report()
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "assessment_report.json"
            md_path = Path(directory) / "assessment_report.md"
            write_enriched_json(report, str(json_path))
            generate_report(report, str(md_path))

            data = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("contextual_analysis", data)
            self.assertEqual("High", data["contextual_analysis"]["risk_rating"])
            self.assertIn("# ESXi Vulnerability Assessment Report", markdown)
            self.assertIn("**Risk rating:** High", markdown)
            self.assertIn("## Priority Action Plan", markdown)
            self.assertIn("**Implications**", markdown)
            self.assertIn("**Recommended measures**", markdown)
            self.assertIn("SMBv1 Protocol Enabled", markdown)


if __name__ == "__main__":
    unittest.main()
