import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestrator.full_coverage import (
    FullCoverageCrypto,
    FullCoverageDiscovery,
    FullCoverageServiceEnum,
    FullCoverageVulnScan,
    FullCoverageWeb,
    _is_tls_port,
    _is_web_port,
)
from orchestrator.models import (
    AssessmentMetadata,
    AssessmentReport,
    HostFinding,
    PortEntry,
)
from orchestrator.phase2_discovery import Phase2Discovery


class FullCoverageSelectionTests(unittest.TestCase):
    def test_service_heuristics_cover_nonstandard_web_and_tls_ports(self):
        self.assertTrue(_is_web_port(PortEntry(port=12345, service="http-alt")))
        self.assertTrue(_is_tls_port(PortEntry(port=12346, service="ssl/custom")))
        self.assertTrue(_is_tls_port(PortEntry(port=8443, service="unknown")))
        self.assertFalse(_is_web_port(PortEntry(port=22, service="ssh")))

    def test_crypto_targets_include_all_detected_tls_services(self):
        report = AssessmentReport(AssessmentMetadata("10.0.0.1", "esxi"))
        report.add_host(HostFinding(
            host="10.0.0.1",
            ports=[
                PortEntry(port=443, service="https"),
                PortEntry(port=12346, service="ssl/custom"),
                PortEntry(port=22, service="ssh"),
            ],
        ))
        targets = FullCoverageCrypto()._targets(report, {"assessment": {"crypto": {"tls_ports": []}}})
        self.assertEqual([("10.0.0.1", 443), ("10.0.0.1", 12346)], targets)

    def test_discovery_forces_unlimited_hosts_and_complete_tcp_range(self):
        report = AssessmentReport(AssessmentMetadata("", ""))
        config = {
            "assessment": {
                "expanded_discovery": {"tcp_ports": "1-65535", "udp": {"enabled": False}},
                "scan": {"ports": "top-100"},
                "vm_discovery": {"max_hosts": 5},
                "performance": {"udp_workers": 1},
            },
            "stealth": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            config["_output_dir"] = directory
            with patch.object(Phase2Discovery, "execute", return_value=None) as execute:
                FullCoverageDiscovery().execute(report, config)

        runtime_config = execute.call_args[0][2]
        self.assertEqual("1-65535", runtime_config["assessment"]["scan"]["ports"])
        self.assertEqual(0, runtime_config["assessment"]["vm_discovery"]["max_hosts"])


class RecordingServiceEnum(FullCoverageServiceEnum):
    def __init__(self):
        super().__init__()
        self.deep_ports = []
        self.nse_ports = []

    def _deep_service_scan(self, host, ports, stealth, intensity, output_dir, config):
        self.deep_ports.extend(ports)
        return []

    def _enrich_host(self, host, enriched):
        return None

    def _run_safe_nse(self, host, ports, protocol, config, output_dir):
        self.nse_ports.extend((protocol, item.port) for item in ports)
        return {}

    def stealth_delay(self, category):
        return None


class FullCoverageEnumerationTests(unittest.TestCase):
    def test_zero_port_limit_enumerates_every_open_service(self):
        report = AssessmentReport(AssessmentMetadata("10.0.0.1", "host"))
        report.add_host(HostFinding(
            host="10.0.0.1",
            ports=[
                PortEntry(port=22, protocol="tcp", service="ssh"),
                PortEntry(port=443, protocol="tcp", service="https"),
                PortEntry(port=65000, protocol="tcp", service="unknown"),
                PortEntry(port=53, protocol="udp", service="domain"),
                PortEntry(port=161, protocol="udp", service="snmp"),
            ],
        ))
        scanner = RecordingServiceEnum()
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "_output_dir": directory,
                "assessment": {
                    "security_tests": {"enabled": True, "max_ports_per_host": 0},
                    "scan": {"version_intensity": 2},
                    "performance": {"service_workers": 1},
                },
                "stealth": {},
            }
            scanner.execute(report, config)

        self.assertEqual([22, 443, 65000], scanner.deep_ports)
        self.assertEqual(
            {("tcp", 22), ("tcp", 443), ("tcp", 65000), ("udp", 53), ("udp", 161)},
            set(scanner.nse_ports),
        )

    def test_positive_port_limit_remains_explicitly_configurable(self):
        report = AssessmentReport(AssessmentMetadata("10.0.0.1", "host"))
        report.add_host(HostFinding(
            host="10.0.0.1",
            ports=[PortEntry(port=value, protocol="tcp") for value in (1, 2, 3)],
        ))
        scanner = RecordingServiceEnum()
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "_output_dir": directory,
                "assessment": {
                    "security_tests": {"enabled": True, "max_ports_per_host": 2},
                    "scan": {"version_intensity": 2},
                    "performance": {"service_workers": 1},
                },
                "stealth": {},
            }
            scanner.execute(report, config)
        self.assertEqual([1, 2], scanner.deep_ports)


class FullCoverageEndpointTests(unittest.TestCase):
    def test_nuclei_target_file_contains_every_open_port(self):
        report = AssessmentReport(AssessmentMetadata("10.0.0.1", "host"))
        report.add_host(HostFinding(
            host="10.0.0.1",
            ports=[
                PortEntry(port=22, protocol="tcp", service="ssh"),
                PortEntry(port=8443, protocol="tcp", service="https-alt"),
                PortEntry(port=161, protocol="udp", service="snmp"),
            ],
        ))
        with tempfile.TemporaryDirectory() as directory:
            config = {"_output_dir": directory}
            path = FullCoverageVulnScan()._prepare_targets(report, config)
            content = path.read_text(encoding="utf-8").splitlines()

        self.assertIn("10.0.0.1:22", content)
        self.assertIn("10.0.0.1:161", content)
        self.assertIn("https://10.0.0.1:8443", content)

    def test_web_probe_checks_unknown_tcp_ports(self):
        scanner = FullCoverageWeb()
        scanner._run_curl = lambda args, timeout=15: (0, "200", "")
        result = scanner._probe_endpoint(
            "10.0.0.1", PortEntry(port=65000, protocol="tcp", service="unknown"), False,
        )
        self.assertEqual("http://10.0.0.1:65000", result)


if __name__ == "__main__":
    unittest.main()
