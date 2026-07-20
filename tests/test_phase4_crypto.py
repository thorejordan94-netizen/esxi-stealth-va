import unittest

from orchestrator.phase4_crypto import _valid_scan_host


class Phase4TargetValidationTests(unittest.TestCase):
    def test_empty_and_punctuation_only_hosts_are_rejected(self):
        self.assertFalse(_valid_scan_host(""))
        self.assertFalse(_valid_scan_host(".."))
        self.assertFalse(_valid_scan_host("https://"))

    def test_ip_and_internal_dns_names_are_accepted(self):
        self.assertTrue(_valid_scan_host("10.20.30.40"))
        self.assertTrue(_valid_scan_host("esxi01.example.internal"))


if __name__ == "__main__":
    unittest.main()

