import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "easy_assessment.sh"


class GuidedLauncherTests(unittest.TestCase):
    def test_launcher_has_valid_bash_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(LAUNCHER)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_is_standalone_and_non_destructive(self):
        result = subprocess.run(
            ["bash", str(LAUNCHER), "--help"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Guided", result.stdout + result.stderr)
        self.assertIn("--offline", result.stdout)
        self.assertIn("--proxy", result.stdout)


if __name__ == "__main__":
    unittest.main()
