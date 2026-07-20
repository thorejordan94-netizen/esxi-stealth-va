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


if __name__ == "__main__":
    unittest.main()

