import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from orchestrator.models import AssessmentMetadata, AssessmentReport
from orchestrator.phase6_vulnscan import Phase6VulnScan


class Phase6VulnScanTests(unittest.TestCase):
    def test_parse_jsonl_normalizes_reference_tags_and_evidence(self):
        scanner = Phase6VulnScan({})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            path.write_text(json.dumps({
                "host": "https://10.20.30.40:443",
                "ip": "10.20.30.40",
                "matched-at": "https://10.20.30.40/login",
                "template-id": "CVE-2026-1234",
                "matcher-name": "version",
                "info": {
                    "name": "Example vulnerability",
                    "severity": "high",
                    "description": "Example description",
                    "reference": "https://example.invalid/advisory",
                    "tags": "cve,network",
                },
                "extracted-results": ["version 1.2.3"],
            }) + "\n", encoding="utf-8")

            findings = scanner._parse_nuclei_jsonl(path)

        self.assertEqual(1, len(findings))
        self.assertEqual(443, findings[0].port)
        self.assertEqual(["https://example.invalid/advisory"], findings[0].reference)
        self.assertEqual(["cve", "network"], findings[0].tags)
        self.assertEqual("version 1.2.3", findings[0].evidence)

    def test_execute_uses_configured_runtime_and_no_positive_tag_filter(self):
        scanner = Phase6VulnScan({})
        report = AssessmentReport(
            metadata=AssessmentMetadata(target_primary="10.20.30.40", target_hostname="")
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            target_file = directory_path / "targets.txt"
            target_file.write_text("10.20.30.40:22\n", encoding="utf-8")
            config = {
                "_output_dir": directory,
                "assessment": {
                    "nuclei": {
                        "enabled": True,
                        "severity_filter": "critical,high,medium,low,info",
                        "rate_limit": 100,
                        "concurrency": 20,
                        "timeout": 15,
                        "execution_timeout_s": 1234,
                        "tags": [],
                        "exclude_tags": ["dos", "fuzz", "intrusive"],
                        "extra_args": [],
                    }
                },
            }
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = list(command)
                captured["timeout"] = kwargs.get("timeout")
                output_path = Path(command[command.index("-o") + 1])
                output_path.write_text(json.dumps({
                    "host": "10.20.30.40:22",
                    "ip": "10.20.30.40",
                    "matched-at": "10.20.30.40:22",
                    "template-id": "ssh-example",
                    "info": {
                        "name": "SSH example",
                        "severity": "info",
                        "description": "Example",
                        "tags": ["network"],
                    },
                }) + "\n", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch.object(scanner, "_get_nuclei_cmd", return_value=["nuclei"]), \
                    patch.object(scanner, "_prepare_targets", return_value=target_file), \
                    patch("orchestrator.phase6_vulnscan.run_command", side_effect=fake_run):
                scanner.execute(report, config)

        self.assertEqual(1234, captured["timeout"])
        self.assertNotIn("-tags", captured["command"])
        self.assertIn("-etags", captured["command"])
        self.assertEqual(1, len(report.findings_vulns))


if __name__ == "__main__":
    unittest.main()
