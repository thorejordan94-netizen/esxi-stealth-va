"""
Base plugin class for all assessment phase modules.

Provides:
- Stealth-aware execution wrapper with configurable delays
- CyberArk audit-trail logging
- Mock execution support for dry-run / testing
- OS compatibility checking
"""

import abc
import os
import time
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class PhasePlugin(abc.ABC):
    """
    Abstract base class for all assessment phase plugins.

    Each plugin represents one phase of the vulnerability assessment pipeline.
    The plugin system enforces stealth delays between operations and provides
    a consistent interface for real and mock execution.
    """

    def __init__(self, stealth_config: Dict[str, Any] = None):
        self._stealth = stealth_config or {}

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name of this phase (e.g., 'Discovery')."""
        pass

    @property
    @abc.abstractmethod
    def phase_number(self) -> int:
        """Numeric phase identifier (1-5)."""
        pass

    @property
    def supported_os(self) -> List[str]:
        """List of supported operating systems. Defaults to all."""
        return ['linux', 'windows', 'macos']

    def check_os_compatibility(self) -> bool:
        """Returns True if the current host OS is supported by this plugin."""
        host_os = 'windows' if os.name == 'nt' else 'linux'
        return host_os in self.supported_os

    def stealth_delay(self, category: str = "general"):
        """
        Enforce a stealth delay between operations.
        
        Categories map to stealth_profile.yaml sections:
        - 'network': inter_phase_delay_s from network section
        - 'http': request_delay_s from http section
        - 'general': inter_phase_delay_s from general section
        """
        delay_map = {
            "network": self._stealth.get("network", {}).get("scan_delay_ms", 50) / 1000.0,
            "http": self._stealth.get("http", {}).get("request_delay_s", 2.0),
            "general": self._stealth.get("general", {}).get("inter_phase_delay_s", 5),
        }
        delay = delay_map.get(category, 1.0)
        if delay > 0:
            logger.debug(f"Stealth delay: {delay:.2f}s ({category})")
            time.sleep(delay)

    def log_for_cyberark(self, message: str):
        """
        Write a sanitized audit-trail entry visible to CyberArk recording.
        
        These log lines are intentionally verbose and human-readable so that
        CyberArk session recordings show clear, authorized activity.
        """
        banner = f"[AUTHORIZED-ASSESSMENT] Phase {self.phase_number} ({self.name}): {message}"
        logger.info(banner)

    def run(self, report, config: Dict[str, Any]):
        """
        Main entrypoint. Wraps execution with OS checking, stealth delays,
        and CyberArk audit logging.
        """
        self.log_for_cyberark(f"Starting phase")
        logger.info(f"{'='*60}")
        logger.info(f"  Phase {self.phase_number}: {self.name}")
        logger.info(f"{'='*60}")

        if not self.check_os_compatibility():
            host_os = 'windows' if os.name == 'nt' else 'linux'
            msg = f"Host OS '{host_os}' not in supported list {self.supported_os}"
            logger.warning(f"Phase {self.name} skipped: {msg}")
            report.add_error(f"phase{self.phase_number}_{self.name.lower()}", self.name, msg)
            return

        mock_mode = os.environ.get("ASSESSMENT_MOCK_MODE") == "1"

        try:
            if mock_mode:
                logger.info(f"MOCK MODE: Simulating {self.name}...")
                self.mock_execute(report, config)
            else:
                self.execute(report, config)
        except Exception as e:
            logger.error(f"Phase {self.name} failed: {e}", exc_info=True)
            report.add_error(
                f"phase{self.phase_number}_{self.name.lower()}",
                self.name,
                f"Unhandled exception: {e}"
            )

        self.log_for_cyberark(f"Phase completed")
        # Cool-down between phases
        self.stealth_delay("general")

    @abc.abstractmethod
    def execute(self, report, config: Dict[str, Any]):
        """Concrete execution logic. Must be implemented by subclasses."""
        pass

    def mock_execute(self, report, config: Dict[str, Any]):
        """Override to provide mock data generation for testing."""
        logger.warning(f"{self.name} has no mock_execute defined. Skipping.")
