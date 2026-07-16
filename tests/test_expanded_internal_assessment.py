import unittest

from orchestrator.expanded_internal_assessment import ExpandedDiscovery, ExpandedServiceEnum
from orchestrator.models import PortEntry


class ExpandedDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.phase = ExpandedDiscovery({})

    def test_private_scope_guard_accepts_bounded_private_subnet(self):
        config = {"assessment": {"expanded_discovery": {"max_addresses_per_subnet": 4096}}}
        network = self.phase._validate_private_subnet("10.20.30.0/24", config)
        self.assertEqual(str(network), "10.20.30.0/24")

    def test_private_scope_guard_rejects_public_and_oversized_subnets(self):
        config = {"assessment": {"expanded_discovery": {"max_addresses_per_subnet": 4096}}}
        self.assertIsNone(self.phase._validate_private_subnet("8.8.8.0/24", config))
        self.assertIsNone(self.phase._validate_private_subnet("10.0.0.0/8", config))

    def test_port_merge_keeps_tcp_and_udp_and_richer_version(self):
        class Host:
            ports = [PortEntry(port=443, protocol="tcp", service="https", version="")]

        host = Host()
        self.phase._merge_ports(host, [
            PortEntry(port=443, protocol="tcp", service="https", version="VMware ESXi"),
            PortEntry(port=161, protocol="udp", service="snmp", version="net-snmp"),
        ])
        self.assertEqual([(p.protocol, p.port) for p in host.ports], [("tcp", 443), ("udp", 161)])
        self.assertEqual(host.ports[0].version, "VMware ESXi")


class ExpandedSecurityTests(unittest.TestCase):
    def setUp(self):
        self.phase = ExpandedServiceEnum({})

    def test_safe_script_selection_covers_network_and_machine_services(self):
        smb = self.phase._scripts_for_port(PortEntry(port=445, service="microsoft-ds"))
        ssh = self.phase._scripts_for_port(PortEntry(port=22, service="ssh"))
        snmp = self.phase._scripts_for_port(PortEntry(port=161, protocol="udp", service="snmp"))
        self.assertIn("smb2-security-mode", smb)
        self.assertIn("ssh2-enum-algos", ssh)
        self.assertIn("snmp-info", snmp)

    def test_safe_nse_output_becomes_normalized_findings(self):
        results = {
            ("tcp", 445): {
                "smb-protocols": "dialects: NT LM 0.12, 2:1",
                "smb2-security-mode": "Message signing enabled but not required",
            },
            ("tcp", 22): {
                "ssh2-enum-algos": "kex_algorithms: diffie-hellman-group1-sha1",
            },
            ("tcp", 21): {
                "ftp-anon": "Anonymous FTP login allowed (FTP code 230)",
            },
        }
        findings = self.phase._derive_findings("10.20.30.40", results)
        identifiers = {finding.template_id for finding in findings}
        self.assertTrue({
            "NMAP-SMB1",
            "NMAP-SMB-SIGNING",
            "NMAP-SSH-WEAK-ALGO",
            "NMAP-FTP-ANON",
        }.issubset(identifiers))
        self.assertTrue(all(finding.scanner == "nmap-safe-nse" for finding in findings))


if __name__ == "__main__":
    unittest.main()
