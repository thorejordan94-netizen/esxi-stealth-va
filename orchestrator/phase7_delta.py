"""
Phase 7: Delta Comparison & Aggregation

Responsibilities:
- Compare the current assessment results with the previous week's report
- Identify new, resolved, and changed findings (infra, crypto, web, vulns)
- Generate a DeltaReport entry in the AssessmentReport
- Archive the current report to the history directory
- Perform cleanup of old history files (configurable retention)

Design:
- Looks for previous report in config-defined history_dir
- Uses host:port:id triples for finding identity to ensure stable comparison
- Final stage of the pipeline before completion
"""

import json
import logging
import os
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import (
    AssessmentReport, DeltaReport, DeltaEntry
)

logger = logging.getLogger(__name__)


class Phase7Delta(PhasePlugin):

    @property
    def name(self) -> str:
        return "Delta Analysis & Archive"

    @property
    def phase_number(self) -> int:
        return 7

    def _get_history_dir(self, config: Dict[str, Any]) -> Path:
        """Get path to history directory from config."""
        d_cfg = config.get("assessment", {}).get("delta", {})
        return Path(d_cfg.get("history_dir", "output/history"))

    def _find_previous_report(self, history_dir: Path) -> Optional[AssessmentReport]:
        """
        Locate the most recent previous report in the history directory.
        Checks all subdirectories for assessment_report.json.
        """
        if not history_dir.exists():
            # Check if there is an existing report in the main output dir (start of history)
            main_report = Path("output/assessment_report.json")
            if main_report.exists():
                try:
                    with open(main_report, 'r', encoding='utf-8') as f:
                        return AssessmentReport.from_dict(json.load(f))
                except Exception: pass
            return None

        # Find all JSON reports in subdirs, sort by modification time or folder name
        reports = []
        for path in history_dir.rglob("assessment_report.json"):
            reports.append(path)

        if not reports:
            return None

        # Sort by mtime descending (most recent first)
        reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        latest_path = reports[0]
        logger.info(f"Found previous report for delta comparison: {latest_path}")
        
        try:
            with open(latest_path, 'r', encoding='utf-8') as f:
                return AssessmentReport.from_dict(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load previous report {latest_path}: {e}")
            return None

    # --- Comparison Logic ---

    def _compare_infra(self, current: AssessmentReport, previous: AssessmentReport, delta: DeltaReport):
        """Compare infrastructure nodes and ports."""
        prev_hosts = {h.host: h for h in previous.findings_infrastructure}
        curr_hosts = {h.host: h for h in current.findings_infrastructure}

        # New Hosts
        for ip in curr_hosts:
            if ip not in prev_hosts:
                delta.add_entry(DeltaEntry("new", "infrastructure", f"New host discovered: {ip}", "Info", {"ip": ip}))

        # Gone Hosts
        for ip in prev_hosts:
            if ip not in curr_hosts:
                delta.add_entry(DeltaEntry("resolved", "infrastructure", f"Host no longer responding: {ip}", "Info", {"ip": ip}))

        # Port Changes on existing hosts
        for ip, host in curr_hosts.items():
            if ip in prev_hosts:
                prev_host = prev_hosts[ip]
                curr_ports = {p.port: p for p in host.ports}
                prev_ports = {p.port: p for p in prev_host.ports}

                for p in curr_ports:
                    if p not in prev_ports:
                        delta.add_entry(DeltaEntry("new", "infrastructure", f"New open port on {ip}: {p}", "Medium", {"ip": ip, "port": p}))
                
                for p in prev_ports:
                    if p not in curr_ports:
                        delta.add_entry(DeltaEntry("resolved", "infrastructure", f"Port closed on {ip}: {p}", "Info", {"ip": ip, "port": p}))

    def _compare_crypto(self, current: AssessmentReport, previous: AssessmentReport, delta: DeltaReport):
        """Compare TLS grades and vulnerabilities."""
        prev_crypto = {(c.host, c.port): c for c in previous.findings_crypto}
        curr_crypto = {(c.host, c.port): c for c in current.findings_crypto}

        for key, curr in curr_crypto.items():
            if key in prev_crypto:
                prev = prev_crypto[key]
                if curr.grade != prev.grade:
                    severity = "Medium" if curr.grade < prev.grade else "Info"
                    delta.add_entry(DeltaEntry("changed", "crypto", 
                        f"TLS Grade changed for {key[0]}:{key[1]}: {prev.grade} → {curr.grade}", 
                        severity, {"host": key[0], "port": key[1], "old_grade": prev.grade, "new_grade": curr.grade}))

    def _compare_vulns(self, current: AssessmentReport, previous: AssessmentReport, delta: DeltaReport):
        """Compare vulnerability scanner results."""
        # Use (host, port, template_id) as unique ID
        def get_id(v): return (v.host, v.port, v.template_id)
        
        prev_vulns = {get_id(v): v for v in previous.findings_vulns}
        curr_vulns = {get_id(v): v for v in current.findings_vulns}

        for vid, v in curr_vulns.items():
            if vid not in prev_vulns:
                delta.add_entry(DeltaEntry("new", "vulnerability", 
                    f"New vulnerability found: {v.name} ({v.template_id}) on {v.host}", 
                    v.severity.capitalize(), {"host": v.host, "id": v.template_id}))

        for vid, v in prev_vulns.items():
            if vid not in curr_vulns:
                delta.add_entry(DeltaEntry("resolved", "vulnerability", 
                    f"Vulnerability resolved: {v.name} ({v.template_id}) on {v.host}", 
                    "Info", {"host": v.host, "id": v.template_id}))

    def _archive_report(self, report: AssessmentReport, history_dir: Path):
        """Archive the current report to a week-based subdirectory."""
        week_str = report.metadata.scan_week # e.g. 2024-W16
        archive_path = history_dir / week_str
        archive_path.mkdir(parents=True, exist_ok=True)
        
        target_file = archive_path / "assessment_report.json"
        
        # Save to archive
        report.flush_to_disk(str(target_file))
        logger.info(f"Report archived to {target_file}")
        
        # Also symlink or copy to the main output file for easiest access
        main_report = Path("output/assessment_report.json")
        try:
            shutil.copy2(target_file, main_report)
            logger.debug(f"Updated main report at {main_report}")
        except Exception as e:
            logger.warning(f"Failed to update main report pointer: {e}")

    def _cleanup_history(self, history_dir: Path, keep_weeks: int):
        """Remove old history folders."""
        if not history_dir.exists(): return
        
        try:
            folders = [f for f in history_dir.iterdir() if f.is_dir()]
            # Sort by name (YYYY-WXX sorts chronologically)
            folders.sort(key=lambda x: x.name, reverse=True)
            
            if len(folders) > keep_weeks:
                to_delete = folders[keep_weeks:]
                for folder in to_delete:
                    logger.info(f"Cleaning up old history: {folder.name}")
                    shutil.rmtree(folder)
        except Exception as e:
            logger.warning(f"History cleanup failed: {e}")

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        delta_cfg = config.get("assessment", {}).get("delta", {})
        if not delta_cfg.get("enabled", True):
            logger.info("Delta reporting disabled.")
            return

        history_dir = self._get_history_dir(config)
        previous = self._find_previous_report(history_dir)
        
        if previous:
            delta = DeltaReport(
                previous_run_id=previous.metadata.run_id,
                previous_scan_week=previous.metadata.scan_week,
                current_run_id=report.metadata.run_id,
                current_scan_week=report.metadata.scan_week
            )
            
            logger.info("Performing delta comparison...")
            self._compare_infra(report, previous, delta)
            self._compare_crypto(report, previous, delta)
            self._compare_vulns(report, previous, delta)
            
            report.delta = delta
            logger.info(f"Delta analysis complete. "
                       f"New: {delta.summary['new']}, Resolved: {delta.summary['resolved']}")
        else:
            logger.info("No previous report found. Initializing history baseline.")
            report.delta = DeltaReport(current_run_id=report.metadata.run_id, current_scan_week=report.metadata.scan_week)

        # Finalize and archive
        report.set_finished()
        self._archive_report(report, history_dir)
        self._cleanup_history(history_dir, delta_cfg.get("keep_weeks", 12))

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Generate a mock delta report."""
        logger.info("[MOCK] Phase 7: Generating synthetic delta report...")
        
        delta = DeltaReport(
            previous_run_id="historical-uuid-123",
            previous_scan_week="2024-W15",
            current_run_id=report.metadata.run_id,
            current_scan_week=report.metadata.scan_week
        )
        
        delta.add_entry(DeltaEntry("new", "infrastructure", "New host discovered: 10.251.2.99", "Info"))
        delta.add_entry(DeltaEntry("resolved", "vulnerability", "Resolved: CVE-2021-44228 Log4Shell on 10.251.2.28", "High"))
        delta.add_entry(DeltaEntry("changed", "crypto", "TLS Grade improved for 10.251.2.28: B → A", "Info"))
        
        report.delta = delta
        report.set_finished()
        
        # In mock mode, we still want to archive to test the reporting logic
        history_dir = self._get_history_dir(config)
        self._archive_report(report, history_dir)
        
        logger.info(f"[MOCK] Phase 7 complete. Summary: {delta.summary}")
