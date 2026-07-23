#!/usr/bin/env python3
"""
ESXi Vulnerability Assessment Framework (v3.0.0)
================================================

Single-command entry point for the comprehensive internal assessment pipeline.

Usage:
  python run_assessment.py                # Configured scope, or auto-detect when scope is empty
  python run_assessment.py --auto-network # Auto-detect network and run assessment
  python run_assessment.py --update       # Force start from Phase 0
  python run_assessment.py --profile comprehensive  # every TCP/UDP port and all findings
  python run_assessment.py --mock         # Full pipeline with synthetic data
  python run_assessment.py --phase 6      # Resume from Nuclei vulnerability scanning

Environment:
  ASSESSMENT_MOCK_MODE=1   → Activates mock mode

Output:
  output/assessment_report.json  → Raw results plus normalized conclusions/remediation
  output/assessment_report.md    → Contextual human-readable assessment
  output/assessment_report.html  → Compact visual overview
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

import orchestrator.main as orchestrator_main
from orchestrator.main import (
    determine_default_start_phase,
    load_config,
    run_pipeline,
    setup_logging,
)
from orchestrator.comprehensive_scanning import (
    ComprehensiveDiscovery,
    ComprehensiveServiceEnum,
    ComprehensiveVulnScan,
    ComprehensiveWeb,
)
from orchestrator.report_markdown import generate_markdown_report, write_enriched_json
from orchestrator.ssl_scanner import run_ssl_automation
from orchestrator.network_detector import (
    auto_detect_network,
    update_config_with_detected_network,
)
from orchestrator.bootstrap import ensure_discovery_prerequisites
from orchestrator.email_report import send_report


# run_pipeline resolves these classes through orchestrator.main's module globals.
# Replacing them here preserves the existing phase/checkpoint architecture while
# enabling complete coverage and parallel execution.
orchestrator_main.ExpandedDiscovery = ComprehensiveDiscovery
orchestrator_main.ExpandedServiceEnum = ComprehensiveServiceEnum
orchestrator_main.Phase5Web = ComprehensiveWeb
orchestrator_main.Phase6VulnScan = ComprehensiveVulnScan


def get_ssl_automation_subnets(config):
    """Return explicitly configured subnets for the legacy SSL sweep.

    The main pipeline already performs TLS checks on discovered HTTPS hosts.
    Falling back to every VM-discovery subnet here can launch a second,
    multi-minute sweep across a /16, so the legacy sweep must be explicitly
    scoped.
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


def _apply_comprehensive_runtime_defaults(config):
    """Apply non-truncating runtime defaults without overriding explicit scope."""
    profile_name = config.get("scan_profile", {}).get("active_profile", "standard")
    if profile_name != "comprehensive":
        return

    assessment = config.setdefault("assessment", {})
    scan = assessment.setdefault("scan", {})
    expanded = assessment.setdefault("expanded_discovery", {})
    udp = expanded.setdefault("udp", {})
    security = assessment.setdefault("security_tests", {})
    nuclei = assessment.setdefault("nuclei", {})

    scan["ports"] = "1-65535"
    expanded["tcp_ports"] = "1-65535"
    udp["enabled"] = True
    udp["ports"] = "1-65535"
    security["max_ports_per_host"] = 0
    nuclei["severity_filter"] = "critical,high,medium,low,info"

    # The orchestrator's runtime guard remains as a failure-safety mechanism,
    # but a comprehensive run is not practically truncated by the old 4-8 hour
    # default. One year is effectively unbounded for an individual run.
    config.setdefault("stealth", {}).setdefault("general", {})["max_runtime_s"] = 31536000


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
        help="Force the pipeline to start from Phase 0 (Self-Update)."
    )
    parser.add_argument(
        "--profile", type=str, choices=["quick", "standard", "thorough", "comprehensive"], default=None,
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
    parser.add_argument(
        "--output-dir", "--output", dest="output_dir", type=str, default=None,
        help="Report/artifact directory (default: <project>/output)."
    )
    parser.add_argument(
        "--auto-network", dest="auto_network", action="store_true",
        help="Automatically detect network configuration and run assessment."
    )
    parser.add_argument(
        "--no-auto-network", dest="auto_network", action="store_false",
        help="Use only the targets and subnets from the configuration files."
    )
    parser.add_argument(
        "--no-install", action="store_true",
        help="Do not automatically install missing tools or Python packages."
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Open the terminal checkbox setup wizard for scope, settings, and email delivery."
    )
    parser.set_defaults(auto_network=None)

    args = parser.parse_args()

    if args.setup:
        from setup_wizard import main as setup_main
        return setup_main(config_dir=PROJECT_ROOT / args.config_dir)

    print("\033[94m")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     ESXi Vulnerability Assessment Framework v3.0.0               ║")
    print("║     Comprehensive coverage + contextual remediation reporting    ║")
    print("║     Internal Use Only — Authorized Scope Required                ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\033[0m")

    log_dir = PROJECT_ROOT / "logs"
    log_file = setup_logging(log_dir)

    config_dir = PROJECT_ROOT / args.config_dir
    if not config_dir.exists():
        print(f"ERROR: Config directory not found: {config_dir}")
        sys.exit(1)

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
            print("[*] Using the target/subnets from configuration. Use --auto-network to override.")

    if args.auto_network and not args.dry_run and not args.mock:
        print("\n[*] Auto-detecting network configuration...")
        prerequisite_status = ensure_discovery_prerequisites(auto_install=not args.no_install)
        if not prerequisite_status.get("ip"):
            print("ERROR: The 'ip' command is required for automatic network detection.")
            sys.exit(1)
        detected = auto_detect_network(config)
        config = update_config_with_detected_network(config, detected)

        if not detected['subnets']:
            print("ERROR: Failed to auto-detect network. Please configure manually or check network connectivity.")
            sys.exit(1)

    if args.profile:
        config["scan_profile"]["active_profile"] = args.profile
        print(f"[*] Overriding scan profile: {args.profile}")

    _apply_comprehensive_runtime_defaults(config)

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
                logging.getLogger(__name__).info(
                    "Skipping standalone SSL automation because no subnets are configured."
                )

        report = run_pipeline(
            config=config,
            start_phase=start_phase,
            mock_mode=args.mock,
            dry_run=args.dry_run,
        )

        json_path = output_dir / "assessment_report.json"
        markdown_path = output_dir / "assessment_report.md"
        html_path = output_dir / "assessment_report.html"

        if not args.dry_run and report is not None:
            enriched_payload = write_enriched_json(report, str(json_path))
            generate_markdown_report(report, str(markdown_path), enriched_payload)

        if args.dry_run:
            print(f"\n\033[92mDry-run completed successfully\033[0m")
            exit_code = 0
        elif json_path.exists() and markdown_path.exists():
            print(f"\n\033[92m✅ Assessment Completed Successfully\033[0m")
            print(f"📊 JSON Report: {json_path.absolute()}")
            print(f"📝 Markdown Report: {markdown_path.absolute()}")
            if html_path.exists():
                print(f"🖥️  HTML Report: {html_path.absolute()}")

            if report and hasattr(report, 'delta') and report.delta:
                d = report.delta.summary
                print(f"Δ  Delta: \033[91m{d.get('new', 0)} new\033[0m, "
                      f"\033[92m{d.get('resolved', 0)} resolved\033[0m")
            if config.get("assessment", {}).get("email", {}).get("enabled"):
                try:
                    send_report(config, output_dir)
                    print("✉️  Email report sent")
                except Exception as email_error:
                    logging.getLogger(__name__).error("Email delivery failed: %s", email_error)
                    print(f"⚠️  Email delivery failed: {email_error}")
            exit_code = 0
        else:
            print(f"\n⚠️  Report not generated correctly. Check logs.")
            exit_code = 2

    except KeyboardInterrupt:
        print("\n\n[!] Assessment interrupted by user. State saved for recovery.")
        exit_code = 130
    except Exception as e:
        print(f"\n\n[!] FATAL ERROR: {e}")
        logging.getLogger(__name__).critical("Execution failed", exc_info=True)
        exit_code = 2

    print(f"\n📋 Log file: {log_file}")
    print()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
