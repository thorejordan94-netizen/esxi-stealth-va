"""
Phase 5: Aggregation & Report Finalization

Responsibilities:
- Read all raw outputs from output/ directory
- Finalize the AssessmentReport model
- Validate the JSON structure against the schema
- Write the final assessment_report.json
- Generate a summary table of findings
- Log final statistics
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport

logger = logging.getLogger(__name__)


class Phase5Aggregation(PhasePlugin):

    @property
    def name(self) -> str:
        return "Aggregation"

    @property
    def phase_number(self) -> int:
        return 5

    def _validate_schema(self, report_dict: dict) -> list:
        """
        Validate the report structure against the required schema.
        Returns a list of validation errors (empty = valid).
        """
        errors = []

        required_sections = [
            "metadata", "findings_infrastructure",
            "findings_crypto", "findings_web", "execution_errors"
        ]

        for section in required_sections:
            if section not in report_dict:
                errors.append(f"Missing required section: {section}")

        # Validate metadata fields
        meta = report_dict.get("metadata", {})
        meta_required = [
            "target_primary", "target_hostname", "assessment_type",
            "environment", "run_id", "started_at"
        ]
        for field in meta_required:
            if not meta.get(field):
                errors.append(f"metadata.{field} is missing or empty")

        # Validate infrastructure findings structure
        for i, host in enumerate(report_dict.get("findings_infrastructure", [])):
            if not host.get("host"):
                errors.append(f"findings_infrastructure[{i}].host is missing")
            for j, port in enumerate(host.get("ports", [])):
                if "port" not in port:
                    errors.append(f"findings_infrastructure[{i}].ports[{j}].port is missing")

        # Validate crypto findings structure
        for i, crypto in enumerate(report_dict.get("findings_crypto", [])):
            if not crypto.get("host"):
                errors.append(f"findings_crypto[{i}].host is missing")

        # Validate web findings structure
        for i, web in enumerate(report_dict.get("findings_web", [])):
            if not web.get("host"):
                errors.append(f"findings_web[{i}].host is missing")
            for j, finding in enumerate(web.get("findings", [])):
                for field in ("id", "title", "severity"):
                    if not finding.get(field):
                        errors.append(f"findings_web[{i}].findings[{j}].{field} is missing")

        # Validate execution_errors structure
        for i, err in enumerate(report_dict.get("execution_errors", [])):
            for field in ("phase", "module", "error"):
                if not err.get(field):
                    errors.append(f"execution_errors[{i}].{field} is missing")

        return errors

    def _print_summary(self, report: AssessmentReport):
        """Log a formatted summary table to the console."""
        summary = report.summary()

        logger.info("")
        logger.info("=" * 70)
        logger.info("  ASSESSMENT SUMMARY")
        logger.info("=" * 70)
        logger.info(f"  Target:          {report.metadata.target_primary}")
        logger.info(f"  Hostname:        {report.metadata.target_hostname}")
        logger.info(f"  Environment:     {report.metadata.environment}")
        logger.info(f"  Run ID:          {report.metadata.run_id}")
        logger.info(f"  Started:         {report.metadata.started_at}")
        logger.info(f"  Finished:        {report.metadata.finished_at}")
        logger.info("-" * 70)
        logger.info(f"  Hosts discovered:     {summary['total_hosts']}")
        logger.info(f"  Open ports:           {summary['total_open_ports']}")
        logger.info(f"  VMs found:            {report.metadata.vm_count}")
        logger.info(f"  Crypto findings:      {summary['total_crypto_findings']}")
        logger.info(f"  Web findings:         {summary['total_web_findings']}")
        logger.info(f"  Execution errors:     {summary['total_errors']}")
        logger.info("-" * 70)
        logger.info("  Severity Distribution:")
        for sev, count in summary["severity_distribution"].items():
            bar = "█" * count
            logger.info(f"    {sev:10s}  {count:3d}  {bar}")
        logger.info("=" * 70)
        logger.info("")

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        self.log_for_cyberark("Aggregating findings and generating final report")

        output_dir = Path("output")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Finalize timestamps
        report.set_finished()

        # Serialize to dict
        report_dict = report.to_dict()

        # Validate schema
        logger.info("Validating report schema...")
        validation_errors = self._validate_schema(report_dict)
        if validation_errors:
            for err in validation_errors:
                logger.warning(f"  Schema validation: {err}")
            report.add_error("phase5_aggregation", "schema_validator",
                f"{len(validation_errors)} schema validation warnings")
            # Re-serialize after adding the error
            report_dict = report.to_dict()
        else:
            logger.info("  Schema validation passed ✓")

        # Write final report JSON
        report_path = output_dir / "assessment_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        logger.info(f"Final report written to: {report_path.absolute()}")

        # Also write summary JSON
        summary_path = output_dir / "assessment_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(report.summary(), f, indent=2)
        logger.info(f"Summary written to: {summary_path.absolute()}")

        # Print summary to console/log
        self._print_summary(report)

        self.log_for_cyberark("Assessment complete. Report finalized.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Same as execute — aggregation doesn't need mocking."""
        self.execute(report, config)
