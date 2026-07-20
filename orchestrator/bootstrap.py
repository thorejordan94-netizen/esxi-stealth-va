"""Non-interactive prerequisite bootstrap used before network discovery."""

import logging
import shutil
import subprocess
from typing import Dict, List, Optional

from orchestrator.runtime import get_privilege_prefix, run_command


logger = logging.getLogger(__name__)


PACKAGE_NAMES = {
    "apt-get": {"ip": "iproute2", "nmap": "nmap"},
    "apt": {"ip": "iproute2", "nmap": "nmap"},
    "zypper": {"ip": "iproute2", "nmap": "nmap"},
    "dnf": {"ip": "iproute", "nmap": "nmap"},
    "yum": {"ip": "iproute", "nmap": "nmap"},
    "apk": {"ip": "iproute2", "nmap": "nmap"},
}


def _package_manager() -> Optional[str]:
    for manager in ("apt-get", "apt", "zypper", "dnf", "yum", "apk"):
        if shutil.which(manager):
            return manager
    return None


def _install_command(manager: str, prefix: List[str], packages: List[str]) -> List[str]:
    if manager == "zypper":
        return prefix + [manager, "--non-interactive", "install", "-y"] + packages
    if manager == "apk":
        return prefix + [manager, "add", "--no-progress"] + packages
    return prefix + [manager, "install", "-y"] + packages


def ensure_discovery_prerequisites(auto_install: bool = True) -> Dict[str, bool]:
    """Ensure interface discovery and Nmap are available before auto-scope."""
    status = {name: shutil.which(name) is not None for name in ("ip", "nmap")}
    missing = [name for name, available in status.items() if not available]
    if not missing or not auto_install:
        return status

    manager = _package_manager()
    prefix = get_privilege_prefix()
    if not manager or prefix is None:
        logger.warning(
            "Cannot automatically install discovery tools (%s): package manager or privileges unavailable.",
            ", ".join(missing),
        )
        return status

    packages = []
    for command_name in missing:
        package_name = PACKAGE_NAMES[manager][command_name]
        if package_name not in packages:
            packages.append(package_name)

    logger.info("Installing discovery prerequisites: %s", ", ".join(packages))
    try:
        if manager in ("apt-get", "apt"):
            run_command(
                prefix + [manager, "update"],
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
        elif manager == "zypper":
            run_command(
                prefix + [manager, "--non-interactive", "refresh"],
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
        run_command(
            _install_command(manager, prefix, packages),
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Automatic discovery-tool installation failed: %s", exc)

    return {name: shutil.which(name) is not None for name in ("ip", "nmap")}
