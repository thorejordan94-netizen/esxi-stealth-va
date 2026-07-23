import json
import tempfile
import unittest
from pathlib import Path

from orchestrator.models import (
    AssessmentMetadata,
    AssessmentReport,
    HostFinding,
    PortEntry,
    VulnerabilityFinding,
    WebAssessmentResult,
    WebVulnerability,
)
from orchestrator.report_markdown import (
    build_enriched_payload,
    generate_markdown_report,
    write_enriched_json,
)


class ContextualReportingTests(unittest.TestCase):
    def _report(self):
        report = AssessmentReport(
            metadata=AssessmentMetadata(
                target_primary="10.20.30.40",
                target_hostname="esxi01.example.internal",
                scan_week="2026-W30",
            )
        )
        report.add_host(HostFinding(
            host="10.20.30.40",
            hostname="esxi01.example.internal",
            role="esxi_host",
            ports=[
                PortEntry(port=443, service="https", version="VMware ESXi"),
                PortEntry(port=445, service="microsoft-ds", version="SMB"),
            ],
        ))
        report.add_vuln(VulnerabilityFinding(
            host="10.20.30.40",
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
            host="10.20.30.40",
            port=443,
            url="https://10.20.30.40",
            findings=[WebVulnerability(
                id="WEB-500",
                title="Missing HSTS",
                severity="High",
                description="Downgrade prevention is absent.",
                evidence="strict-transport-security missing",
            )],
        ))
        return report

    def test_payload_contains_context_and_remediation(self):
        payload = build_enriched_payload(self._report())
        conclusions = payload["assessment_conclusions"]
        self.assertEqual("high", conclusions["overall_risk"])
        self.assertGreaterEqual(conclusions["actionable_findings"], 2)
        rules = {
            item["context"]["knowledge_rule"]
            for item in conclusions["findings"]
        }
        self.assertIn("smbv1", rules)
        self.assertIn("missing-security-header", rules)
        self.assertTrue(conclusions["priority_actions"])
        self.assertEqual(2, payload["coverage"]["assets"][0]["open_port_count"])

    def test_json_and_markdown_are_written(self):
        report = self._report()
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "assessment_report.json"
            markdown_path = Path(directory) / "assessment_report.md"
            payload = write_enriched_json(report, str(json_path))
            generate_markdown_report(report, str(markdown_path), payload)

            parsed = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("assessment_conclusions", parsed)
            self.assertIn("## Prioritized remediation plan", markdown)
            self.assertIn("**Implications**", markdown)
            self.assertIn("**Recommended measures**", markdown)
            self.assertIn("SMBv1 Protocol Enabled", markdown)


if __name__ == "__main__":
    unittest.main()
