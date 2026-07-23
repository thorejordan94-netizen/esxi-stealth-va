"""Build and write the final context-enriched JSON report."""

import json
from typing import Any, Dict

from orchestrator.finding_knowledge import build_contextual_analysis
from orchestrator.reporting_policy import calibrate_analysis


def build_enriched_report(report) -> Dict[str, Any]:
    payload = report.to_dict()
    payload["report_summary"] = report.summary()
    payload["contextual_analysis"] = calibrate_analysis(build_contextual_analysis(report))
    payload["schema_version"] = "2.2-contextual"
    return payload


def write_enriched_json(report, filepath: str, indent: int = 2):
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(build_enriched_report(report), handle, indent=indent, ensure_ascii=False)
        handle.write("\n")
