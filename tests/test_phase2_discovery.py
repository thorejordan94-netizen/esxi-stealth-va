import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestrator.phase2_discovery import Phase2Discovery


MINIMAL_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="VMware ESXi" version="8.0"/></port></ports>
</host></nmaprun>"""


class Phase2DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.phase = Phase2Discovery({})

    def test_port_expression_conversion(self):
        self.assertEqual(["--top-ports", "1000"], self.phase._build_port_args("top-1000"))
        self.assertEqual(["-p", "22,80,443,1-10"], self.phase._build_port_args("22, 80,443,1-10"))
        self.assertEqual(["--top-ports", "1000"], self.phase._build_port_args("not-valid"))

    def test_esxi_classification_uses_vmware_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(MINIMAL_XML, encoding="utf-8")
            findings = self.phase._parse_nmap_xml(path)
        self.assertEqual(1, len(findings))
        self.assertTrue(self.phase._looks_like_esxi(findings[0]))

    @patch("orchestrator.phase2_discovery.run_command_with_progress")
    def test_nonzero_nmap_is_failure_even_when_xml_exists(self, runner):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.xml"

            def fake_run(*_args, **_kwargs):
                output.write_text(MINIMAL_XML, encoding="utf-8")
                return subprocess.CompletedProcess(["nmap"], 2, "", "fatal")

            runner.side_effect = fake_run
            with patch.object(self.phase, "_get_nmap_cmd", return_value=["nmap"]):
                self.assertFalse(self.phase._run_nmap(["-sn", "10.0.0.0/24"], output, {}, 10))
        self.assertIn("rc=2", self.phase._last_nmap_error)

    @patch("orchestrator.phase2_discovery.run_command_with_progress")
    def test_zero_nmap_with_valid_xml_succeeds(self, runner):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.xml"

            def fake_run(*_args, **_kwargs):
                output.write_text(MINIMAL_XML, encoding="utf-8")
                return subprocess.CompletedProcess(["nmap"], 0, "", "")

            runner.side_effect = fake_run
            with patch.object(self.phase, "_get_nmap_cmd", return_value=["nmap"]):
                self.assertTrue(self.phase._run_nmap(["-sV", "10.0.0.2"], output, {}, 10))


if __name__ == "__main__":
    unittest.main()
