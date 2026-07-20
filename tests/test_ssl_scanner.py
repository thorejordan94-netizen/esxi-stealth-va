import unittest

from orchestrator import ssl_scanner


class StandaloneSslScannerTests(unittest.TestCase):
    def test_invalid_targets_are_not_accepted(self):
        self.assertFalse(ssl_scanner._valid_ipv4(""))
        self.assertFalse(ssl_scanner._valid_ipv4(".."))
        self.assertFalse(ssl_scanner._valid_ipv4("example.internal"))

    def test_ipv4_targets_are_accepted(self):
        self.assertTrue(ssl_scanner._valid_ipv4("10.20.30.40"))


if __name__ == "__main__":
    unittest.main()

