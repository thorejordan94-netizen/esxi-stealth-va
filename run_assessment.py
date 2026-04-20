#!/usr/bin/env python3
"""
ESXi Vulnerability Assessment Framework
========================================

Single-command entry point for the assessment pipeline.

Usage:
  python run_assessment.py                # Full assessment (all 5 phases)
  python run_assessment.py --dry-run      # Validate config + check tools only
  python run_assessment.py --mock         # Full pipeline with synthetic data
  python run_assessment.py --phase 3      # Resume from Phase 3
  python run_assessment.py --mock --phase 2  # Mock from Phase 2 onward

Environment:
  ASSESSMENT_MOCK_MODE=1   → Activates mock mode (same as --mock)

Output:
  output/assessment_report.json  → The final normalized JSON report
  output/assessment_state.json   → Intermediate state (crash recovery)
  output/assessment_summary.json → Statistical summary
  logs/assessment_*.log          → Full debug log
"""

import sys
import argparse
from pathlib import Path

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.main import setup_logging, load_config, run_pipeline


def main():
    # Fix Windows console encoding
    import io
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(
        description="ESXi Vulnerability Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_assessment.py                 Full assessment
  python run_assessment.py --dry-run       Check config & tools only
  python run_assessment.py --mock          Synthetic data pipeline
  python run_assessment.py --phase 3       Resume from Phase 3
        """
    )

    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate configuration and check tool availability, then exit."
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Run the full pipeline with synthetic mock data (no real scans)."
    )
    parser.add_argument(
        "--phase", type=int, choices=[1, 2, 3, 4, 5], default=1,
        help="Resume pipeline from this phase number (default: 1)."
    )
    parser.add_argument(
        "--config-dir", type=str, default="config",
        help="Path to configuration directory (default: ./config)."
    )

    args = parser.parse_args()

    # --- Banner ---
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     ESXi Vulnerability Assessment Framework                    ║")
    print("║     Internal Use Only — CyberArk PSM Monitored Environment    ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    # --- Setup ---
    log_dir = PROJECT_ROOT / "logs"
    log_file = setup_logging(log_dir)

    config_dir = PROJECT_ROOT / args.config_dir
    if not config_dir.exists():
        print(f"ERROR: Config directory not found: {config_dir}")
        sys.exit(1)

    config = load_config(config_dir)

    # --- Run Pipeline ---
    report = run_pipeline(
        config=config,
        start_phase=args.phase,
        mock_mode=args.mock,
        dry_run=args.dry_run,
    )

    # --- Final output ---
    report_path = PROJECT_ROOT / "output" / "assessment_report.json"
    if report_path.exists():
        print(f"\n✅ Report saved: {report_path.absolute()}")
    else:
        print(f"\n⚠️  Report not generated. Check logs: {log_file}")

    print(f"📋 Log file: {log_file}")
    print()


if __name__ == "__main__":
    main()
