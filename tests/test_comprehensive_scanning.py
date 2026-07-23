import tempfile
import unittest
from pathlib import Path

from orchestrator.comprehensive_scanning import (
    ComprehensiveDiscovery,
    ComprehensiveVulnScan,
    _chunks,
    _is_tls_web_service,
    _is_web_service,
)
from orchestrator.models import AssessmentMetadata, AssessmentReport, HostFinding, PortEntry


class ComprehensiveScanningTests(unittest.TestCase):
    def test_private_broad_scope_is_chunked_not_rejected(self):
        scanner = ComprehensiveDiscovery({})
        network = scanner._validate_private_subnet(
            "10.0.0.0/8",
            {"assessment": {"expanded_discovery": {"allow_public_subnets": False}}},
        )
        self.assertIsNotNone(network)
        self.assertEqual(16777216, network.num_addresses)

    def test_port_batches_do_not_truncate(self):
        ports = list(range(1, 1026))
        flattened = []
        for batch in _chunks(ports, 256):
            flattened.extend(batch)
        self.assertEqual(ports, flattened)

    def test_nonstandard_web_services_are_included(self):
        http = PortEntry(port=12345, service="http-alt", version="custom HTTP service")
        https = PortEntry(port=10443, service="ssl/http", version="TLS web console")
        self.assertTrue(_is_web_service(http))
        self.assertTrue(_is_web_service(https))
        self.assertFalse(_is_tls_web_service(http))
        self.assertTrue(_is_tls_web_service(https))

    def test_nuclei_target_file_contains_every_endpoint(self):
        report = AssessmentReport(
            metadata=AssessmentMetadata(target_primary="10.20.30.40", target_hostname="")
        )
        report.add_host(HostFinding(
            host="10.20.30.40",
            role="vm",
            ports=[
                PortEntry(port=22, protocol="tcp", service="ssh"),
                PortEntry(port=12345, protocol="tcp", service="http-alt"),
                PortEntry(port=161, protocol="udp", service="snmp"),
            ],
        ))
        scanner = ComprehensiveVulnScan({})
        with tempfile.TemporaryDirectory() as directory:
            config = {"_output_dir": directory, "assessment": {}}
            target_file = scanner._prepare_targets(report, config)
            targets = set(Path(target_file).read_text(encoding="utf-8").splitlines())
        self.assertIn("10.20.30.40", targets)
        self.assertIn("10.20.30.40:22", targets)
        self.assertIn("http://10.20.30.40:12345", targets)
        self.assertIn("10.20.30.40:161", targets)


if __name__ == "__main__":
    unittest.main()
