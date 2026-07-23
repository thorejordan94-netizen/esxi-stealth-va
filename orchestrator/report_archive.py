"""Archive final JSON, Markdown, and HTML reports together."""

import logging
import shutil
from pathlib import Path
from typing import Any, Dict


logger = logging.getLogger(__name__)


def _history_dir(config: Dict[str, Any], output_dir: Path) -> Path:
    delta_cfg = config.get("assessment", {}).get("delta", {})
    configured = str(delta_cfg.get("history_dir", "output/history"))
    if configured in ("output/history", "history"):
        return output_dir / "history"
    path = Path(configured).expanduser()
    if path.is_absolute():
        return path
    project_root = Path(__file__).resolve().parent.parent
    return project_root / path


def archive_final_reports(report, config: Dict[str, Any], output_dir: Path):
    """Copy every generated final report into the run's weekly archive."""
    delta_cfg = config.get("assessment", {}).get("delta", {})
    if not delta_cfg.get("enabled", True):
        return

    archive_dir = _history_dir(config, output_dir) / report.metadata.scan_week
    archive_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("assessment_report.json", "assessment_report.md", "assessment_report.html"):
        source = output_dir / filename
        if not source.exists():
            logger.warning("Final report not available for archive: %s", source)
            continue
        destination = archive_dir / filename
        shutil.copy2(str(source), str(destination))
        logger.info("Archived final report: %s", destination)
