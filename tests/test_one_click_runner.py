import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "RUN_ASSESSMENT.sh"


class OneClickRunnerTests(unittest.TestCase):
    def test_script_exists_and_has_valid_bash_syntax(self):
        self.assertTrue(SCRIPT.exists())
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_is_non_destructive_and_documents_default_profile(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("complete assessment automatically", result.stdout)
        self.assertIn("Default: standard", result.stdout)

    def test_invalid_profile_fails_before_any_installation(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--profile", "invalid"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid profile", result.stderr)


if __name__ == "__main__":
    unittest.main()
