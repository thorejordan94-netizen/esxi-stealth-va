#!/usr/bin/env python3
"""
ESXi Vulnerability Assessment Framework (v2.2.0)
================================================

Single-command entry point for the comprehensive internal assessment pipeline.

Usage:
  python run_assessment.py
  python run_assessment.py --auto-network
  python run_assessment.py --profile thorough
  python run_assessment.py --mock
  python run_assessment.py --phase 6

Output:
  output/assessment_report.json  -> enriched machine-readable report
  output/assessment_report.md    -> contextual human-readable report
  output/assessment_report.html  -> self-contained HTML report
  output/history/YYYY-Wxx/       -> archived reports
  logs/assessment_*.log          -> audit log
"""

import sys
import argparse
import logging
import io
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.main import (
    determine_default_start_phase,
    load_config,
    run_pipeline,
    setup_logging,
)
from orchestrator.ssl_scanner import run_ssl_automation
from orchestrator.network_detector import (
    auto_detect_network,
    update_config_with_detected_network,
)
from orchestrator.bootstrap import ensure_discovery_prerequisites
from orchestrator.email_report import send_report


def get_ssl_automation_subnets(config):
    """Return explicitly configured subnets for the legacy SSL sweep.

    The main pipeline already performs TLS checks on discovered TLS endpoints.
    The legacy sweep therefore runs only when explicitly enabled and scoped.
    """
    assessment_cfg = config.get("assessment", {})
    ssl_cfg = assessment_cfg.get("ssl_automation", {})
    if not ssl_cfg.get("enabled", False):
        return []
    configured_subnets = ssl_cfg.get("subnets")
    if not isinstance(configured_subnets, (list, tuple)):
        return []
    return [subnet.strip() for subnet in configured_subnets if isinstance(subnet, str) and subnet.strip()]


def has_configured_scope(config):
    """Whether normal execution has a usable target/scope already configured."""
    assessment = config.get("assessment", {})
    target = assessment.get("target", {}) or {}
    discovery = assessment.get("vm_discovery", {}) or {}
    return bool(
        str(target.get("ip") or target.get("hostname") or target.get("target_domain") or "").strip()
        or discovery.get("static_ips")
        or discovery.get("subnets")
    )


def main():
    if sys.stdout.encoding != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="ESXi Vulnerability Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--update", action="store_true", help="Force the pipeline to start from Phase 0 (Self-Update).")
    parser.add_argument(
        "--profile", type=str, choices=["quick", "standard", "thorough"], default=None,
        help="Scan profile. Thorough is the full-coverage default; quick intentionally reduces coverage.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate configuration and tool availability, then exit.")
    parser.add_argument("--mock", action="store_true", help="Run the full pipeline with synthetic mock data.")
    parser.add_argument(
        "--phase", type=int, choices=range(0, 8), default=None,
        help="Resume pipeline from this phase number (0-7).",
    )
    parser.add_argument("--no-delta", action="store_true", help="Skip Phase 7 (Delta Analysis).")
    parser.add_argument("--config-dir", type=str, default="config", help="Configuration directory (default: ./config).")
    parser.add_argument(
        "--output-dir", "--output", dest="output_dir", type=str, default=None,
        help="Report/artifact directory (default: <project>/output).",
    )
    parser.add_argument(
        "--auto-network", dest="auto_network", action="store_true",
        help="Automatically detect private network configuration and run assessment.",
    )
    parser.add_argument(
        "--no-auto-network", dest="auto_network", action="store_false",
        help="Use only targets and subnets from the configuration files.",
    )
    parser.add_argument("--no-install", action="store_true", help="Do not automatically install missing tools or packages.")
    parser.add_argument(
        "--setup", action="store_true",
        help="Open the terminal setup wizard for scope, settings, and email delivery.",
    )
    parser.set_defaults(auto_network=None)
    args = parser.parse_args()

    if args.setup:
        from setup_wizard import main as setup_main
        return setup_main(config_dir=PROJECT_ROOT / args.config_dir)

    print("\033[94m")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     ESXi Vulnerability Assessment Framework v2.2.0               ║")
    print("║     Full Coverage + Contextual Reporting                         ║")
    print("║     Internal Use Only — Authorized Scope Required                ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\033[0m")

    log_dir = PROJECT_ROOT / "logs"
    log_file = setup_logging(log_dir)
    config_dir = PROJECT_ROOT / args.config_dir
    if not config_dir.exists():
        print("ERROR: Config directory not found: {}".format(config_dir))
        return 1

    config = load_config(config_dir)
    config["_auto_install"] = not args.no_install
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else PROJECT_ROOT / "output"
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir
    config["_output_dir"] = str(output_dir)

    if args.auto_network is None:
        args.auto_network = not has_configured_scope(config)
        if args.auto_network:
            print("[*] No target scope is configured; automatic private-network discovery is enabled.")
        else:
            print("[*] Using configured target/subnets. Use --auto-network to override.")

    if args.auto_network and not args.dry_run and not args.mock:
        print("\n[*] Auto-detecting network configuration...")
        prerequisite_status = ensure_discovery_prerequisites(auto_install=not args.no_install)
        if not prerequisite_status.get("ip"):
            print("ERROR: The 'ip' command is required for automatic network detection.")
            return 1
        detected = auto_detect_network(config)
        config = update_config_with_detected_network(config, detected)
        if not detected["subnets"]:
            print("ERROR: Failed to auto-detect a private network. Configure scope manually or check connectivity.")
            return 1

    if args.profile:
        config["scan_profile"]["active_profile"] = args.profile
        print("[*] Overriding scan profile: {}".format(args.profile))

    start_phase = determine_default_start_phase(config)
    if args.update:
        start_phase = 0
    if args.phase is not None:
        start_phase = args.phase
    if args.dry_run:
        start_phase = 1
    if args.no_delta:
        config["assessment"]["phases"]["phase7_delta"] = False

    try:
        if not args.dry_run and not args.mock:
            ssl_subnets = get_ssl_automation_subnets(config)
            if ssl_subnets:
                run_ssl_automation(subnets=ssl_subnets, output_dir=output_dir)
            else:
                logging.getLogger(__name__).info("Skipping standalone SSL automation because no subnets are configured.")

        report = run_pipeline(
            config=config,
            start_phase=start_phase,
            mock_mode=args.mock,
            dry_run=args.dry_run,
        )

        json_path = output_dir / "assessment_report.json"
        markdown_path = output_dir / "assessment_report.md"
        html_path = output_dir / "assessment_report.html"

        if args.dry_run:
            print("\n\033[92mDry-run completed successfully\033[0m")
            exit_code = 0
        elif json_path.exists():
            print("\n\033[92mAssessment completed successfully\033[0m")
            print("JSON report: {}".format(json_path.absolute()))
            if markdown_path.exists():
                print("Markdown report: {}".format(markdown_path.absolute()))
            if html_path.exists():
                print("HTML report: {}".format(html_path.absolute()))

            if report and getattr(report, "delta", None):
                delta = report.delta.summary
                print("Delta: {} new, {} resolved".format(delta.get("new", 0), delta.get("resolved", 0)))

            if config.get("assessment", {}).get("email", {}).get("enabled"):
                try:
                    send_report(config, output_dir)
                    print("Email report sent")
                except Exception as email_error:
                    logging.getLogger(__name__).error("Email delivery failed: %s", email_error)
                    print("Email delivery failed: {}".format(email_error))
            exit_code = 0
        else:
            print("\nReport was not generated correctly. Check logs.")
            exit_code = 2

    except KeyboardInterrupt:
        print("\nAssessment interrupted. State was preserved for recovery.")
        exit_code = 130
    except Exception as exc:
        print("\nFATAL ERROR: {}".format(exc))
        logging.getLogger(__name__).critical("Execution failed", exc_info=True)
        exit_code = 2

    print("\nLog file: {}\n".format(log_file))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
