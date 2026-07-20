import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import setup_wizard


class SetupWizardTests(unittest.TestCase):
    def test_menu_redraw_does_not_emit_screen_clear_escape_codes(self):
        with patch("setup_wizard.sys.stdout", new_callable=StringIO) as output:
            setup_wizard._clear_screen()

        self.assertNotIn("\033[2J", output.getvalue())

    def test_recommended_defaults_fill_a_new_config(self):
        configs = {}

        setup_wizard.apply_recommended_defaults(configs)

        self.assertEqual("standard", configs["scan_profile"]["active_profile"])
        self.assertFalse(configs["assessment"]["auto_network"]["allow_public_subnets"])
        self.assertFalse(configs["assessment"]["ssllabs"]["enabled"])
        self.assertFalse(configs["assessment"]["email"]["enabled"])
        self.assertTrue(configs["assessment"]["nuclei"]["enabled"])
        self.assertTrue(configs["assessment"]["phases"]["phase7_delta"])

    def test_recommended_defaults_do_not_overwrite_existing_choices(self):
        configs = {
            "assessment": {
                "auto_network": {"allow_public_subnets": True},
                "email": {"enabled": True},
            },
            "scan_profile": {"active_profile": "thorough"},
        }

        setup_wizard.apply_recommended_defaults(configs)

        self.assertTrue(configs["assessment"]["auto_network"]["allow_public_subnets"])
        self.assertTrue(configs["assessment"]["email"]["enabled"])
        self.assertEqual("thorough", configs["scan_profile"]["active_profile"])

    @patch("setup_wizard.choose_one", return_value=1)
    def test_scan_profile_selection_is_the_only_basic_scan_choice(self, _menu):
        scan_profile = {
            "active_profile": "standard",
            "profiles": {
                "quick": {"description": "Fast"},
                "standard": {"description": "Balanced"},
                "thorough": {"description": "Deep"},
            },
        }

        setup_wizard.configure_scan_profile(scan_profile)

        self.assertEqual("standard", scan_profile["active_profile"])
        _menu.assert_called_once()

    def test_flatten_settings_covers_nested_scalars_and_lists(self):
        leaves = dict(setup_wizard._flatten_settings({
            "target": {"ip": "10.0.0.2"},
            "phases": {"phase1": True},
            "tags": ["cve", "misconfig"],
        }))
        self.assertEqual("10.0.0.2", leaves[("target", "ip")])
        self.assertTrue(leaves[("phases", "phase1")])
        self.assertEqual(["cve", "misconfig"], leaves[("tags",)])

    def test_parse_value_preserves_common_yaml_setting_types(self):
        self.assertEqual(300, setup_wizard._parse_value("300", 10))
        self.assertEqual(2.5, setup_wizard._parse_value("2.5", 1.0))
        self.assertEqual(["22", "443"], setup_wizard._parse_value("22,443", []))
        self.assertFalse(setup_wizard._parse_value("no", True))

    def test_saved_credentials_are_mode_600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".email_credentials"
            setup_wizard._save_credentials(path, {"username": "u", "password": "p"})
            self.assertEqual(0o600, os.stat(str(path)).st_mode & 0o777)

    @patch("setup_wizard.socket.getfqdn", return_value="scanner.example.internal")
    def test_local_mail_identity_is_generated_from_machine_fqdn(self, _fqdn):
        identity = setup_wizard._local_mail_identity()
        self.assertEqual("scanner.example.internal", identity["hostname"])
        self.assertEqual("example.internal", identity["domain"])
        self.assertEqual("assessment@example.internal", identity["sender"])

    @patch("setup_wizard.socket.getfqdn", return_value="localhost")
    @patch("setup_wizard.socket.gethostname", return_value="scanner")
    def test_local_mail_identity_has_safe_fallback_domain(self, _hostname, _fqdn):
        identity = setup_wizard._local_mail_identity()
        self.assertEqual("scanner.local", identity["hostname"])
        self.assertEqual("scanner.local", identity["domain"])
        self.assertEqual("assessment@scanner.local", identity["sender"])

    @patch("setup_wizard.choose", side_effect=[{0}, set()])
    def test_boolean_checkbox_selection_is_the_saved_value(self, _menu):
        settings = {"enabled": False, "audit": True, "target": "10.0.0.2"}
        setup_wizard.edit_settings("Smoke", settings, skip_email=False)
        self.assertTrue(settings["enabled"])
        self.assertFalse(settings["audit"])

    def test_change_summary_reports_differences_without_secret_values(self):
        original = {"assessment": {"email": {"password": "old-secret"}, "scan": {"host_timeout_s": 600}}}
        current = {"assessment": {"email": {"password": "new-secret"}, "scan": {"host_timeout_s": 300}}}
        changes = setup_wizard._changed_settings(original, current)
        self.assertEqual(2, len(changes))
        password_change = next(item for item in changes if item[1] == "email.password")
        self.assertEqual("<saved securely>", password_change[2])
        self.assertEqual("<saved securely>", password_change[3])


if __name__ == "__main__":
    unittest.main()
