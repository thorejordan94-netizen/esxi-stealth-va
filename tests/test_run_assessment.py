import unittest

import run_assessment


class RunAssessmentScopeTests(unittest.TestCase):
    def test_legacy_ssl_sweep_requires_explicit_subnets(self):
        config = {
            "assessment": {
                "ssl_automation": {"enabled": True, "subnets": []},
                "vm_discovery": {"subnets": ["10.20.30.0/24"]},
            }
        }

        self.assertEqual([], run_assessment.get_ssl_automation_subnets(config))

    def test_explicit_legacy_ssl_subnets_are_preserved(self):
        config = {
            "assessment": {
                "ssl_automation": {
                    "enabled": True,
                    "subnets": ["10.20.30.0/24", "", None],
                }
            }
        }

        self.assertEqual(
            ["10.20.30.0/24"],
            run_assessment.get_ssl_automation_subnets(config),
        )

    def test_configured_scope_disables_implicit_network_detection(self):
        config = {
            "assessment": {
                "target": {"ip": "10.20.30.40"},
                "vm_discovery": {"subnets": ["10.20.30.0/24"]},
            }
        }

        self.assertTrue(run_assessment.has_configured_scope(config))

    def test_empty_scope_keeps_automatic_detection_available(self):
        self.assertFalse(run_assessment.has_configured_scope({"assessment": {}}))

    def test_comprehensive_profile_enables_full_tcp_and_udp_coverage(self):
        config = {
            "scan_profile": {"active_profile": "comprehensive"},
            "assessment": {
                "scan": {"ports": "top-100"},
                "expanded_discovery": {"tcp_ports": "", "udp": {"ports": "top-20"}},
                "security_tests": {"max_ports_per_host": 128},
                "nuclei": {"severity_filter": "critical,high"},
            },
            "stealth": {"general": {"max_runtime_s": 100}},
        }

        run_assessment._apply_comprehensive_runtime_defaults(config)

        self.assertEqual("1-65535", config["assessment"]["scan"]["ports"])
        self.assertEqual("1-65535", config["assessment"]["expanded_discovery"]["tcp_ports"])
        self.assertEqual("1-65535", config["assessment"]["expanded_discovery"]["udp"]["ports"])
        self.assertEqual(0, config["assessment"]["security_tests"]["max_ports_per_host"])
        self.assertIn("info", config["assessment"]["nuclei"]["severity_filter"])

    def test_quick_profile_is_not_forced_to_full_port_coverage(self):
        config = {
            "scan_profile": {"active_profile": "quick"},
            "assessment": {
                "scan": {"ports": "top-100"},
                "expanded_discovery": {"tcp_ports": "", "udp": {"ports": "top-20"}},
            },
        }

        run_assessment._apply_comprehensive_runtime_defaults(config)

        self.assertEqual("top-100", config["assessment"]["scan"]["ports"])
        self.assertEqual("", config["assessment"]["expanded_discovery"]["tcp_ports"])
        self.assertEqual("top-20", config["assessment"]["expanded_discovery"]["udp"]["ports"])


if __name__ == "__main__":
    unittest.main()
