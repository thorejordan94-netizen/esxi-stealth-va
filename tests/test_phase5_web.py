import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from orchestrator.phase5_web import Phase5Web


class Phase5WebTests(unittest.TestCase):
    def test_hsts_is_only_required_for_https(self):
        scanner = Phase5Web({})
        response_headers = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'\r\n"
        with patch.object(scanner, "_run_curl", return_value=(0, response_headers, "")):
            http_findings = scanner._check_security_headers(
                "http://10.20.30.40", "test-agent", False
            )
            https_findings = scanner._check_security_headers(
                "https://10.20.30.40", "test-agent", False
            )

        self.assertFalse(any("HSTS" in finding.title for finding in http_findings))
        self.assertTrue(any("HSTS" in finding.title for finding in https_findings))

    def test_nikto_runs_complete_catalog_without_implicit_tuning_filter(self):
        scanner = Phase5Web({})
        captured = {}

        def fake_run(command, **kwargs):
            captured["command"] = list(command)
            captured["timeout"] = kwargs.get("timeout")
            output_path = Path(command[command.index("-output") + 1])
            output_path.write_text(json.dumps({
                "vulnerabilities": [{
                    "id": "001",
                    "msg": "Example Nikto result",
                    "description": "Example description",
                    "url": "/admin",
                    "method": "GET",
                }]
            }), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(scanner, "_get_nikto_cmd", return_value=["nikto"]), \
                patch("orchestrator.phase5_web.run_command", side_effect=fake_run):
            findings = scanner._run_nikto(
                "10.20.30.40",
                443,
                Path(directory),
                {"assessment": {"web": {"nikto_timeout_s": 987, "nikto_tuning": ""}}},
            )

        self.assertNotIn("-Tuning", captured["command"])
        self.assertEqual(987, captured["timeout"])
        self.assertEqual(1, len(findings))
        self.assertEqual("NIKTO-001", findings[0].id)

    def test_explicit_nikto_tuning_is_respected(self):
        scanner = Phase5Web({})
        captured = {}

        def fake_run(command, **kwargs):
            captured["command"] = list(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(scanner, "_get_nikto_cmd", return_value=["nikto"]), \
                patch("orchestrator.phase5_web.run_command", side_effect=fake_run):
            scanner._run_nikto(
                "10.20.30.40",
                80,
                Path(directory),
                {"assessment": {"web": {"nikto_tuning": "123x"}}},
            )

        tuning_index = captured["command"].index("-Tuning")
        self.assertEqual("123x", captured["command"][tuning_index + 1])


if __name__ == "__main__":
    unittest.main()
