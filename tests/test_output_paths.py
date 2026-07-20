import tempfile
import unittest
from pathlib import Path

from orchestrator.main import load_config, run_pipeline


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class OutputPathTests(unittest.TestCase):
    def test_custom_output_directory_contains_complete_mock_run(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = load_config(PROJECT_ROOT / "config")
            config["_output_dir"] = temporary_directory
            config["_auto_install"] = False

            report = run_pipeline(config, start_phase=0, mock_mode=True)
            output_dir = Path(temporary_directory)

            self.assertTrue((output_dir / "assessment_state.json").is_file())
            self.assertTrue((output_dir / "assessment_report.json").is_file())
            self.assertTrue((output_dir / "assessment_report.html").is_file())
            self.assertTrue(list((output_dir / "history").glob("*/assessment_report.json")))
            self.assertEqual([], report.execution_errors)
            self.assertTrue(report.metadata.finished_at)


if __name__ == "__main__":
    unittest.main()
