import subprocess
import unittest
from unittest.mock import patch

from orchestrator import network_detector


class NetworkDetectorTests(unittest.TestCase):
    @patch("orchestrator.network_detector.run_command")
    @patch("orchestrator.network_detector.shutil.which", return_value="/usr/sbin/ip")
    def test_interface_detection_filters_container_bridges(self, _which, run_command):
        run_command.return_value = subprocess.CompletedProcess(
            ["ip"], 0,
            stdout=(
                "2: eth0    inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0\n"
                "3: docker0 inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
                "4: veth123@if3 inet 172.18.0.2/16 brd 172.18.255.255 scope global veth123\n"
            ),
            stderr="",
        )
        interfaces = network_detector.get_local_interfaces()
        self.assertEqual(["eth0"], list(interfaces))
        self.assertEqual("10.20.30.0/24", interfaces["eth0"]["network"])

    def test_auto_config_clears_stale_target_when_no_esxi_found(self):
        config = {
            "assessment": {
                "target": {"ip": "10.251.2.28", "hostname": "old"},
                "vm_discovery": {},
                "web": {"base_url": "https://10.251.2.28"},
            },
            "stealth": {"network": {}},
        }
        detected = {
            "target_ip": None,
            "target_hostname": "",
            "subnets": ["10.20.30.0/24"],
            "subnet_interfaces": {"10.20.30.0/24": "ens224"},
            "exclude_ips": ["10.20.30.1", "10.20.30.40"],
        }
        updated = network_detector.update_config_with_detected_network(config, detected)
        self.assertEqual("", updated["assessment"]["target"]["ip"])
        self.assertEqual("", updated["assessment"]["web"]["base_url"])
        self.assertEqual(["10.20.30.0/24"], updated["assessment"]["vm_discovery"]["subnets"])
        self.assertEqual("ens224", updated["assessment"]["stealth"]["network"]["interface"])

    @patch("orchestrator.network_detector.detect_esxi_hosts", return_value=[])
    @patch("orchestrator.network_detector.shutil.which", return_value="/usr/bin/nmap")
    @patch("orchestrator.network_detector.get_default_route", return_value=("10.20.30.1", "ens224"))
    @patch("orchestrator.network_detector.get_local_interfaces")
    def test_auto_detection_keeps_interface_per_subnet(self, interfaces, _route, _which, _detect):
        interfaces.return_value = {
            "ens224": {"ip": "10.20.30.40", "netmask": "/24", "network": "10.20.30.0/24"},
            "ens225": {"ip": "192.168.50.20", "netmask": "/24", "network": "192.168.50.0/24"},
        }
        result = network_detector.auto_detect_network({"assessment": {"auto_network": {}}})
        self.assertEqual("ens224", result["scan_interface"])
        self.assertEqual("ens225", result["subnet_interfaces"]["192.168.50.0/24"])
        self.assertIsNone(result["target_ip"])


if __name__ == "__main__":
    unittest.main()
