import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestrator.phase3_enum import Phase3Enum


class Phase3TimeoutTests(unittest.TestCase):
    @patch("orchestrator.phase3_enum.run_command")
    def test_deep_enum_uses_configured_nmap_timeout(self, runner):
        runner.return_value = subprocess.CompletedProcess(["nmap"], 0, "", "")
        config = {"assessment": {"scan": {
            "nmap_host_timeout": "45s",
            "host_timeout_s": 45,
        }}}
        with tempfile.TemporaryDirectory() as directory:
            Phase3Enum()._deep_service_scan(
                "10.0.0.2", [443], {"network": {}}, 1, Path(directory), config
            )

        command = runner.call_args.args[0]
        self.assertEqual("45s", command[command.index("--host-timeout") + 1])
        self.assertEqual(45, runner.call_args.kwargs["timeout"])


if __name__ == "__main__":
    unittest.main()
