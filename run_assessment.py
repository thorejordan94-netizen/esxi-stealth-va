#!/usr/bin/env python3
"""
ESXi Vulnerability Assessment Framework (v2.1.0)
================================================

Single-command entry point for the expanded automated pentest pipeline.

Usage:
  python run_assessment.py                # Full assessment (Phase 1-7)
  python run_assessment.py --update       # Update tools then run full scan (Phase 0-7)
  python run_assessment.py --profile thorough  # deep scan (1-65535 ports)
  python run_assessment.py --mock         # Full pipeline with synthetic data
  python run_assessment.py --phase 6      # Resume from Nuclei vuln scanning

Environment:
  ASSESSMENT_MOCK_MODE=1   → Activates mock mode

Output:
  output/assessment_report.json  → Final JSON report
  output/assessment_report.html  → Premium HTML report
  output/history/YYYY-Wxx/       → Archived reports
  logs/assessment_*.log          → Audit log
"""

import sys
import argparse
import logging
import io
from pathlib import Path

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Cleaned up imports (no duplicates)
from orchestrator.main import setup_logging, load_config, run_pipeline
from orchestrator.ssl_scanner import run_ssl_automation

def main():
    # Fix Windows console encoding
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(
        description="ESXi Vulnerability Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--update", action="store_true",
        help="Run Phase 0 (Self-Update) before starting the assessment."
    )
    parser.add_argument(
        "--profile", type=str, choices=["quick", "standard", "thorough"], default=None,
        help="Scan intensity profile (defaults to value in scan_profile.yaml)."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate configuration and check tool availability, then exit."
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Run the full pipeline with synthetic mock data."
    )
    parser.add_argument(
        "--phase", type=int, choices=range(0, 8), default=None,
        help="Resume pipeline from this phase number (0-7)."
    )
    parser.add_argument(
        "--no-delta", action="store_true",
        help="Skip phase 7 (Delta Analysis)."
    )
    parser.add_argument(
        "--config-dir", type=str, default="config",
        help="Path to configuration directory (default: ./config)."
    )

    args = parser.parse_args()

    # --- Banner ---
    print("\033[94m")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     ESXi Vulnerability Assessment Framework v2.1.0               ║")
    print("║     Automated Weekly Pentest Orchestrator                        ║")
    print("║     Internal Use Only — CyberArk PSM Monitored                   ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\033[0m")

    # --- Setup ---
    log_dir = PROJECT_ROOT / "logs"
    log_file = setup_logging(log_dir)

    config_dir = PROJECT_ROOT / args.config_dir
    if not config_dir.exists():
        print(f"ERROR: Config directory not found: {config_dir}")
        sys.exit(1)

    config = load_config(config_dir)

    # Override scan profile if specified via CLI
    if args.profile:
        config["scan_profile"]["active_profile"] = args.profile
        print(f"[*] Overriding scan profile: {args.profile}")

    # Determine start phase
    start_phase = 1
    if args.update:
        start_phase = 0
    if args.phase is not None:
        start_phase = args.phase

    # Disable delta if requested
    if args.no_delta:
        config["assessment"]["phases"]["phase7_delta"] = False

    # --- Run Pipeline ---
    try:
        # --> TRIGGER SSL AUTOMATION BEFORE MAIN PIPELINE <--
        # We skip it during a dry-run so it doesn't accidentally launch Nmap
        if not args.dry_run:
            run_ssl_automation(subnet="192.168.157.0/24")

        # Now run the main framework pipeline
        report = run_pipeline(
            config=config,
            start_phase=start_phase,
            mock_mode=args.mock,
            dry_run=args.dry_run,
        )

        # --- Final output ---
        output_dir = PROJECT_ROOT / "output"
        json_path = output_dir / "assessment_report.json"
        html_path = output_dir / "assessment_report.html"

        if json_path.exists():
            print(f"\n\033[92m✅ Assessment Completed Successfully\033[0m")
            print(f"📊 JSON Report: {json_path.absolute()}")
            if html_path.exists():
                print(f"🖥️  HTML Report: {html_path.absolute()}")
            
            if report and hasattr(report, 'delta') and report.delta:
                d = report.delta.summary
                print(f"Δ  Delta: \033[91m{d.get('new', 0)} new\033[0m, "
                      f"\033[92m{d.get('resolved', 0)} resolved\033[0m")
        else:
            print(f"\n⚠️  Report not generated correctly. Check logs.")

    except KeyboardInterrupt:
        print("\n\n[!] Assessment interrupted by user. State saved for recovery.")
    except Exception as e:
        print(f"\n\n[!] FATAL ERROR: {e}")
        logging.getLogger(__name__).critical("Execution failed", exc_info=True)

    print(f"\n📋 Log file: {log_file}")
    print()

if __name__ == "__main__":
    main()