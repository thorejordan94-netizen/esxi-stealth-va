import json
import tempfile
import unittest
from pathlib import Path

from orchestrator.email_report import build_message


class EmailReportTests(unittest.TestCase):
    def test_message_includes_selected_attachments_delta_and_health(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "assessment_report.html").write_text("<html>ok</html>", encoding="utf-8")
            (output / "assessment_report.json").write_text(json.dumps({
                "metadata": {"target_primary": "10.0.0.2", "target_hostname": "esxi.local", "run_id": "run-1"},
                "delta": {"summary": {"new": 2, "resolved": 1, "changed": 0, "unchanged": 3}},
                "execution_errors": [{"phase": "phase2", "module": "nmap", "error": "timed out"}],
            }), encoding="utf-8")
            config = {"assessment": {"email": {
                "enabled": True,
                "backend": "local",
                "recipient": "receiver@example.com",
                "sender": "sender@example.com",
                "scope": ["HTML report", "Delta summary", "Errors and health status"],
            }}}

            message = build_message(config, output)

            self.assertEqual("ESXi assessment report", message["Subject"])
            self.assertEqual(["assessment_report.html"], [part.get_filename() for part in message.iter_attachments()])
            body = message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("New: 2", body)
            self.assertIn("phase2/nmap", body)
            self.assertIn("Report JSON: OK", body)


if __name__ == "__main__":
    unittest.main()
