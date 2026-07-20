import unittest
from unittest.mock import patch

from orchestrator.phase1_init import Phase1Init
from orchestrator.models import AssessmentReport, AssessmentMetadata


class Phase1InitTests(unittest.TestCase):
    def setUp(self):
        self.phase = Phase1Init({})
        self.report = AssessmentReport(metadata=AssessmentMetadata(target_primary="1.2.3.4", target_hostname="host"))
        self.config = {
            "assessment": {
                "target": {"ip": "1.2.3.4", "hostname": "host"},
                "environment": {"classification": "Internal / Isolated ESXi Network"},
            },
            "stealth": {},
        }

    @patch("orchestrator.phase1_init.shutil.which")
    def test_dry_run_skips_tool_install_when_package_manager_unavailable(self, mock_which):
        mock_which.side_effect = lambda name: {
            "wsl": None,
            "bash": None,
            "apt-get": None,
            "apt": None,
            "zypper": None,
            "yum": None,
            "sudo": None,
        }.get(name)
        self.config["_dry_run"] = True

        with patch("orchestrator.phase1_init.get_privilege_prefix", return_value=None):
            self.phase.execute(self.report, self.config)

        self.assertIn("nmap", self.config["_tool_status"])
        self.assertFalse(self.config["_tool_status"]["nmap"])
        self.assertIn("nuclei", self.config["_tool_status"])
        self.assertFalse(self.config["_tool_status"]["nuclei"])
        self.assertEqual([], self.report.execution_errors)


if __name__ == "__main__":
    unittest.main()
