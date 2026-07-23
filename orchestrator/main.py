"""
Central Orchestrator — Phase-Driven Execution Engine (v2.2.0)

Runs all 8 phases in strict dependency order. Independent targets inside the
network, service, TLS, and web phases are processed concurrently by the
full-coverage implementations.

Final deliverables:
- normalized and context-enriched JSON
- contextual Markdown
- self-contained HTML
- phase state checkpoints for crash recovery
"""

import os
import sys
import time
import json
import logging
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Ensure project root is in PYTHONPATH
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.models import AssessmentReport, AssessmentMetadata
from orchestrator.phase0_update import Phase0Update
from orchestrator.phase1_init import Phase1Init
from orchestrator.full_coverage import (
    FullCoverageCrypto,
    FullCoverageDiscovery,
    FullCoverageServiceEnum,
    FullCoverageVulnScan,
    FullCoverageWeb,
)
from orchestrator.phase7_delta import Phase7Delta
from orchestrator.runtime import get_output_dir

logger = logging.getLogger(__name__)


PHASE_TOGGLE_NAMES = {
    0: "phase0_update",
    1: "phase1_init",
    2: "phase2_discovery",
    3: "phase3_enum",
    4: "phase4_crypto",
    5: "phase5_web",
    6: "phase6_vulnscan",
    7: "phase7_delta",
}


def setup_logging(log_dir: Path):
    """Configure dual logging: file + console."""
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / "assessment_{}.log".format(timestamp)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    logger.info("Logging initialized: %s", log_file)
    return log_file


def load_config(config_dir: Path) -> Dict[str, Any]:
    """Load and merge all YAML configuration files."""
    config = {}
    expected_files = ["assessment.yaml", "stealth_profile.yaml", "scan_profile.yaml"]
    for config_file in expected_files:
        path = config_dir / config_file
        if not path.exists():
            logger.error("Config file not found: %s", path)
            sys.exit(1)

        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        if config_file == "assessment.yaml":
            config["assessment"] = data
        elif config_file == "stealth_profile.yaml":
            config["stealth"] = data
        elif config_file == "scan_profile.yaml":
            config["scan_profile"] = data
    return config


def apply_scan_profile(config: Dict[str, Any]) -> Dict[str, Any]:
    """Overlay the active scan profile onto the base configuration."""
    scan_profile = config.get("scan_profile", {})
    active_name = scan_profile.get("active_profile", "thorough")
    profile = scan_profile.get("profiles", {}).get(active_name, {})
    if not profile:
        logger.warning("Scan profile '%s' not found. Using base config values.", active_name)
        return config

    assessment_cfg = config.setdefault("assessment", {})
    stealth_cfg = config.setdefault("stealth", {})
    scan_cfg = assessment_cfg.setdefault("scan", {})
    web_cfg = assessment_cfg.setdefault("web", {})
    nuclei_cfg = assessment_cfg.setdefault("nuclei", {})
    ssllabs_cfg = assessment_cfg.setdefault("ssllabs", {})
    network_cfg = stealth_cfg.setdefault("network", {})
    http_cfg = stealth_cfg.setdefault("http", {})

    if profile.get("ports"):
        scan_cfg["ports"] = profile["ports"]
    if profile.get("version_intensity") is not None:
        scan_cfg["version_intensity"] = profile["version_intensity"]
    if profile.get("nuclei_rate") is not None:
        nuclei_cfg["rate_limit"] = profile["nuclei_rate"]
    if profile.get("nuclei_concurrency") is not None:
        nuclei_cfg["concurrency"] = profile["nuclei_concurrency"]
    if profile.get("nuclei_severity"):
        nuclei_cfg["severity_filter"] = profile["nuclei_severity"]
    if profile.get("max_rate_pps") is not None:
        network_cfg["max_rate_pps"] = profile["max_rate_pps"]
    if profile.get("scan_delay_ms") is not None:
        network_cfg["scan_delay_ms"] = profile["scan_delay_ms"]
    if profile.get("http_request_delay_s") is not None:
        http_cfg["request_delay_s"] = profile["http_request_delay_s"]

    if "skip_nikto" in profile:
        web_cfg["use_nikto"] = web_cfg.get("use_nikto", True) and not profile["skip_nikto"]
    if "skip_ssllabs" in profile:
        ssllabs_cfg["enabled"] = ssllabs_cfg.get("enabled", False) and not profile["skip_ssllabs"]

    logger.info("Applied scan profile '%s'", active_name)
    return config


def is_phase_enabled(config: Dict[str, Any], phase_number: int) -> bool:
    """Return whether a phase is enabled in config."""
    phase_key = PHASE_TOGGLE_NAMES.get(phase_number)
    if phase_key is None:
        return True
    phases_cfg = config.get("assessment", {}).get("phases", {})
    return phases_cfg.get(phase_key, True)


def determine_default_start_phase(config: Dict[str, Any]) -> int:
    """Choose the earliest enabled phase when the user does not override it."""
    for phase_number in range(0, 8):
        if is_phase_enabled(config, phase_number):
            return phase_number
    return 1


def _generate_final_reports(report: AssessmentReport, output_dir: Path):
    """Write all final report formats while preserving raw phase state."""
    final_json = output_dir / "assessment_report.json"
    markdown_path = output_dir / "assessment_report.md"
    html_path = output_dir / "assessment_report.html"

    try:
        from orchestrator.finding_knowledge import write_enriched_json
        write_enriched_json(report, str(final_json))
        logger.info("Enriched JSON report generated: %s", final_json)
    except Exception as exc:
        logger.error("Failed to generate enriched JSON report: %s", exc, exc_info=True)
        # A normalized report is preferable to no JSON deliverable.
        report.flush_to_disk(str(final_json))

    try:
        from orchestrator.report_markdown import generate_report as generate_markdown
        generate_markdown(report, str(markdown_path))
    except Exception as exc:
        logger.error("Failed to generate Markdown report: %s", exc, exc_info=True)
        report.add_error("reporting", "markdown", "Markdown report generation failed: {}".format(exc))

    try:
        from orchestrator.report_html import generate_report as generate_html
        generate_html(report, str(html_path))
        logger.info("HTML report generated: %s", html_path)
    except Exception as exc:
        logger.error("Failed to generate HTML report: %s", exc, exc_info=True)
        report.add_error("reporting", "html", "HTML report generation failed: {}".format(exc))


def run_pipeline(config: Dict[str, Any], start_phase: int = 1,
                 mock_mode: bool = False, dry_run: bool = False):
    """Execute the assessment pipeline."""
    if mock_mode:
        os.environ["ASSESSMENT_MOCK_MODE"] = "1"
        logger.info("╔══════════════════════════════════════════════╗")
        logger.info("║  MOCK MODE — No real scans will be executed  ║")
        logger.info("╚══════════════════════════════════════════════╝")

    apply_scan_profile(config)
    stealth_cfg = config.get("stealth", {})
    output_dir = get_output_dir(config)
    state_file = output_dir / "assessment_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)

    if start_phase > 1 and state_file.exists():
        logger.info("Resuming from Phase %s — loading state from %s", start_phase, state_file)
        with open(state_file, "r", encoding="utf-8") as handle:
            report = AssessmentReport.from_dict(json.load(handle))
    else:
        target = config.get("assessment", {}).get("target", {})
        report = AssessmentReport(
            metadata=AssessmentMetadata(
                target_primary=target.get("ip", ""),
                target_hostname=target.get("hostname", ""),
            )
        )

    report.metadata.scan_profile = config.get("scan_profile", {}).get("active_profile", "thorough")
    report.metadata.framework_version = "2.2.0"
    config["_dry_run"] = dry_run

    phases = [
        Phase0Update(stealth_cfg),
        Phase1Init(stealth_cfg),
        FullCoverageDiscovery(stealth_cfg),
        FullCoverageServiceEnum(stealth_cfg),
        FullCoverageCrypto(stealth_cfg),
        FullCoverageWeb(stealth_cfg),
        FullCoverageVulnScan(stealth_cfg),
        Phase7Delta(stealth_cfg),
    ]

    # A value of zero disables the overall runtime ceiling. Per-command and
    # per-host timeouts still prevent an individual external process from hanging.
    max_runtime = int(stealth_cfg.get("general", {}).get("max_runtime_s", 0) or 0)
    pipeline_start = time.time()

    for phase in phases:
        if not is_phase_enabled(config, phase.phase_number):
            logger.info("Skipping Phase %s (%s) - disabled in config", phase.phase_number, phase.name)
            continue
        if phase.phase_number < start_phase:
            logger.info("Skipping Phase %s (%s) — resuming from %s", phase.phase_number, phase.name, start_phase)
            continue
        if dry_run and phase.phase_number > 1:
            logger.info("Dry-run complete. Exiting after Phase 1.")
            break

        elapsed = time.time() - pipeline_start
        if max_runtime > 0 and elapsed > max_runtime:
            logger.error("Max runtime (%ss) exceeded. Aborting at Phase %s.", max_runtime, phase.phase_number)
            report.add_error(
                "phase{}_{}".format(phase.phase_number, phase.name.lower()),
                "orchestrator",
                "Pipeline aborted — max runtime exceeded ({:.0f}s > {}s)".format(elapsed, max_runtime),
            )
            break

        logger.info("Starting Phase %s: %s", phase.phase_number, phase.name)
        try:
            phase.run(report, config)
        except Exception as exc:
            logger.critical(
                "FATAL: Phase %s (%s) crashed: %s", phase.phase_number, phase.name, exc,
                exc_info=True,
            )
            report.add_error(
                "phase{}_{}".format(phase.phase_number, phase.name.lower()),
                "orchestrator", "Unrecoverable crash: {}".format(exc),
            )

        report.flush_to_disk(str(state_file))
        logger.debug("State checkpoint saved to %s", state_file)

    if not dry_run:
        report.set_finished()
        report.flush_to_disk(str(state_file))
        _generate_final_reports(report, output_dir)
        # Persist reporting errors, if any, after report generation.
        report.flush_to_disk(str(state_file))

    total_time = time.time() - pipeline_start
    logger.info("Pipeline completed in %.1fs (%.1fm)", total_time, total_time / 60)

    if mock_mode:
        os.environ.pop("ASSESSMENT_MOCK_MODE", None)
    return report
