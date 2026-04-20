"""
Central Orchestrator — Phase-Driven Execution Engine (v2.1.0)

Runs all 8 phases in strict sequential order:
  Phase 0: Self-Update
  Phase 1: Initialization & Scoping
  Phase 2: Stealth Discovery (nmap)
  Phase 3: Service Enumeration
  Phase 4: Crypto Analysis (testssl.sh / SSL Labs / Python ssl)
  Phase 5: Web Assessment (curl probes / nikto)
  Phase 6: Vulnerability Scanning (nuclei)
  Phase 7: Delta Analysis & Archiving

Design decisions:
- Sequential execution — stealth over speed
- State persistence after each phase (crash recovery)
- CyberArk-aware audit logging at every phase boundary
- Single JSON output and HTML report as the final deliverables
"""

import os
import sys
import time
import json
import logging
import yaml
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Ensure project root is in PYTHONPATH
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.models import AssessmentReport, AssessmentMetadata
from orchestrator.phase0_update import Phase0Update
from orchestrator.phase1_init import Phase1Init
from orchestrator.phase2_discovery import Phase2Discovery
from orchestrator.phase3_enum import Phase3Enum
from orchestrator.phase4_crypto import Phase4Crypto
from orchestrator.phase5_web import Phase5Web
from orchestrator.phase6_vulnscan import Phase6VulnScan
from orchestrator.phase7_delta import Phase7Delta

logger = logging.getLogger(__name__)


def setup_logging(log_dir: Path):
    """Configure dual logging: file + console."""
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"assessment_{timestamp}.log"

    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # File handler (DEBUG level — everything)
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    root.addHandler(fh)

    # Console handler (INFO level — clean output)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    logger.info(f"Logging initialized: {log_file}")
    return log_file


def load_config(config_dir: Path) -> Dict[str, Any]:
    """Load and merge all YAML config files."""
    config = {}

    expected_files = ["assessment.yaml", "stealth_profile.yaml", "scan_profile.yaml"]
    for config_file in expected_files:
        path = config_dir / config_file
        if not path.exists():
            logger.error(f"Config file not found: {path}")
            sys.exit(1)

        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}

        # Namespace configs
        if config_file == "assessment.yaml":
            config["assessment"] = data
        elif config_file == "stealth_profile.yaml":
            config["stealth"] = data
        elif config_file == "scan_profile.yaml":
            config["scan_profile"] = data

    return config


def run_pipeline(config: Dict[str, Any],
                 start_phase: int = 1,
                 mock_mode: bool = False,
                 dry_run: bool = False):
    """
    Execute the assessment pipeline.

    Args:
        config: Merged configuration dict
        start_phase: Resume from this phase (0-7)
        mock_mode: If True, generate synthetic data instead of real scans
        dry_run: If True, validate config and check tools only (Phase 1)
    """
    if mock_mode:
        os.environ["ASSESSMENT_MOCK_MODE"] = "1"
        logger.info("╔══════════════════════════════════════════════╗")
        logger.info("║  MOCK MODE — No real scans will be executed  ║")
        logger.info("╚══════════════════════════════════════════════╝")

    stealth_cfg = config.get("stealth", {})

    # --- Initialize the report model ---
    state_file = Path("output") / "assessment_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)

    if start_phase > 1 and state_file.exists():
        logger.info(f"Resuming from Phase {start_phase} — loading state from {state_file}")
        with open(state_file, 'r', encoding='utf-8') as f:
            report = AssessmentReport.from_dict(json.load(f))
    else:
        target = config.get("assessment", {}).get("target", {})
        report = AssessmentReport(
            metadata=AssessmentMetadata(
                target_primary=target.get("ip", ""),
                target_hostname=target.get("hostname", ""),
            )
        )

    # --- Build phase pipeline ---
    phases = [
        Phase0Update(stealth_cfg),
        Phase1Init(stealth_cfg),
        Phase2Discovery(stealth_cfg),
        Phase3Enum(stealth_cfg),
        Phase4Crypto(stealth_cfg),
        Phase5Web(stealth_cfg),
        Phase6VulnScan(stealth_cfg),
        Phase7Delta(stealth_cfg),
    ]

    # --- Safety: max runtime ---
    max_runtime = stealth_cfg.get("general", {}).get("max_runtime_s", 28800) # Increased to 8h for thorough scans
    pipeline_start = time.time()

    # --- Execute phases ---
    for phase in phases:
        if phase.phase_number < start_phase:
            logger.info(f"Skipping Phase {phase.phase_number} ({phase.name}) — resuming from {start_phase}")
            continue

        if dry_run and phase.phase_number > 1:
            logger.info("Dry-run complete. Exiting after Phase 1.")
            break

        # Runtime safety check
        elapsed = time.time() - pipeline_start
        if elapsed > max_runtime:
            logger.error(f"Max runtime ({max_runtime}s) exceeded. Aborting at Phase {phase.phase_number}.")
            report.add_error(
                f"phase{phase.phase_number}_{phase.name.lower()}",
                "orchestrator",
                f"Pipeline aborted — max runtime exceeded ({elapsed:.0f}s > {max_runtime}s)"
            )
            break

        logger.info(f"Starting Phase {phase.phase_number}: {phase.name}")
        try:
            phase.run(report, config)
        except Exception as e:
            logger.critical(f"FATAL: Phase {phase.phase_number} ({phase.name}) crashed: {e}",
                            exc_info=True)
            report.add_error(
                f"phase{phase.phase_number}_{phase.name.lower()}",
                "orchestrator",
                f"Unrecoverable crash: {e}"
            )

        # Flush state after each phase for crash recovery
        report.flush_to_disk(str(state_file))
        logger.debug(f"State checkpoint saved to {state_file}")

    # --- Final Generation ---
    if not dry_run:
        try:
            from orchestrator.report_html import generate_report
            html_path = Path("output") / "assessment_report.html"
            generate_report(report, str(html_path))
            logger.info(f"HTML Report generated: {html_path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    total_time = time.time() - pipeline_start
    logger.info(f"Pipeline completed in {total_time:.1f}s ({total_time/60:.1f}m)")

    if mock_mode:
        os.environ.pop("ASSESSMENT_MOCK_MODE", None)

    return report
