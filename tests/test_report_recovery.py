import unittest

from orchestrator.models import (
    AssessmentMetadata,
    AssessmentReport,
    HostFinding,
    PortEntry,
    VulnerabilityFinding,
)


class ReportRecoveryTests(unittest.TestCase):
    def test_repeated_host_scan_merges_ports_and_esxi_role(self):
        report = AssessmentReport(metadata=AssessmentMetadata(target_primary="", target_hostname=""))
        report.add_host(HostFinding(
            host="10.20.30.40", role="vm",
            ports=[PortEntry(port=443, service="https")],
        ))
        report.add_host(HostFinding(
            host="10.20.30.40", hostname="esxi.local", role="esxi_host",
            ports=[
                PortEntry(port=443, service="https", version="VMware ESXi 8.0"),
                PortEntry(port=902, service="vmware-auth"),
            ],
        ))
        self.assertEqual(1, len(report.findings_infrastructure))
        host = report.findings_infrastructure[0]
        self.assertEqual("esxi_host", host.role)
        self.assertEqual([443, 902], [port.port for port in host.ports])
        self.assertEqual("VMware ESXi 8.0", host.ports[0].version)

    def test_repeated_vulnerability_is_replaced(self):
        report = AssessmentReport(metadata=AssessmentMetadata(target_primary="", target_hostname=""))
        first = VulnerabilityFinding(
            host="10.20.30.40", port=443, url="https://10.20.30.40",
            template_id="test", matcher_name="header", evidence="old",
        )
        second = VulnerabilityFinding(
            host="10.20.30.40", port=443, url="https://10.20.30.40",
            template_id="test", matcher_name="header", evidence="new",
        )
        report.add_vuln(first)
        report.add_vuln(second)
        self.assertEqual(1, len(report.findings_vulns))
        self.assertEqual("new", report.findings_vulns[0].evidence)


if __name__ == "__main__":
    unittest.main()
