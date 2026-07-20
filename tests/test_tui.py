import sys
import unittest
from unittest.mock import patch

from orchestrator.tui import PROJECT_ROOT, assessment_command, tool_status


class TUICommandTests(unittest.TestCase):
    def test_validation_command_is_non_scanning_dry_run(self):
        command = assessment_command("validate")
        self.assertEqual(command[:2], [sys.executable, str(PROJECT_ROOT / "run_assessment.py")])
        self.assertIn("--auto-network", command)
        self.assertIn("--dry-run", command)

    def test_demo_command_uses_mock_mode(self):
        command = assessment_command("demo")
        self.assertIn("--mock", command)
        self.assertIn("--no-delta", command)

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(ValueError):
            assessment_command("remove-everything")

    @patch("orchestrator.tui.shutil.which", return_value=None)
    def test_status_reports_missing_tools(self, _which):
        self.assertEqual(tool_status(), ["python3: fehlt", "nmap: fehlt", "curl: fehlt", "git: fehlt"])


if __name__ == "__main__":
    unittest.main()
