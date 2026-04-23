"""
Phase 0: Self-Update Mechanism

Responsibilities:
- Update framework code from git remote (if .git present)
- Update Nuclei templates (online or offline tarball)
- Optionally update system tools via the local package manager
- Log all update actions for CyberArk audit trail
"""

import shutil
import tarfile
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport
from orchestrator.runtime import get_privilege_prefix, run_command

logger = logging.getLogger(__name__)


class Phase0Update(PhasePlugin):

    @property
    def name(self) -> str:
        return "Self-Update"

    @property
    def phase_number(self) -> int:
        return 0

    def _run_cmd(self, cmd: list, timeout: int = 120, cwd: str = None) -> tuple:
        """Run a shell command and return (success, stdout, stderr)."""
        try:
            result = run_command(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                cwd=cwd,
            )
            return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
        except FileNotFoundError:
            return False, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return False, "", str(e)

    def _git_pull(self, project_root: Path) -> bool:
        """Pull latest framework code from git remote."""
        if not (project_root / ".git").exists():
            logger.info("No .git directory found - skipping git pull")
            return True

        logger.info("Pulling latest framework code from git remote...")
        self.log_for_cyberark("Updating framework via git pull")

        success, stdout, stderr = self._run_cmd(
            ["git", "pull", "--ff-only"],
            cwd=str(project_root),
        )

        if success:
            if "Already up to date" in stdout:
                logger.info("  Framework is already up to date")
            else:
                logger.info(f"  Framework updated: {stdout[:200]}")
        else:
            logger.warning(f"  Git pull failed (non-fatal): {stderr[:200]}")

        return success

    def _update_nuclei_templates_online(self) -> bool:
        """Update Nuclei templates via 'nuclei -ut'."""
        if not shutil.which("nuclei"):
            logger.info("Nuclei not installed - skipping template update")
            return False

        logger.info("Updating Nuclei templates (online)...")
        self.log_for_cyberark("Updating Nuclei vulnerability templates")

        success, stdout, stderr = self._run_cmd(
            ["nuclei", "-ut", "-silent"],
            timeout=300,
        )

        if success:
            logger.info(f"  Nuclei templates updated: {stdout[:200]}")
        else:
            logger.warning(f"  Nuclei template update failed: {stderr[:200]}")

        return success

    def _update_nuclei_templates_offline(self, tarball_path: str, templates_dir: str) -> bool:
        """Update Nuclei templates from a pre-downloaded tarball."""
        tarball = Path(tarball_path)
        if not tarball.exists():
            logger.info(f"Offline template tarball not found at {tarball_path} - skipping")
            return False

        logger.info(f"Updating Nuclei templates from offline tarball: {tarball_path}")
        self.log_for_cyberark(f"Offline template update from {tarball.name}")

        target_dir = Path(templates_dir) if templates_dir else Path.home() / ".local" / "nuclei-templates"

        try:
            if target_dir.exists():
                backup_name = f"{target_dir.name}.bak.{datetime.now().strftime('%Y%m%d')}"
                backup_path = target_dir.parent / backup_name
                if backup_path.exists():
                    shutil.rmtree(backup_path)
                target_dir.rename(backup_path)
                logger.info(f"  Backed up existing templates to {backup_path}")

            with tarfile.open(str(tarball), "r:gz") as tar:
                tar.extractall(path=str(target_dir.parent))
            logger.info(f"  Templates extracted to {target_dir}")
            return True

        except Exception as e:
            logger.error(f"  Offline template update failed: {e}")
            return False

    def _update_system_tools(self) -> bool:
        """Update system tools via apt-get or zypper."""
        privilege_prefix = get_privilege_prefix()
        if privilege_prefix is None:
            logger.info("No root privileges available - skipping system tool updates")
            return False

        if shutil.which("apt-get"):
            pkg_mgr = "apt-get"
        elif shutil.which("zypper"):
            pkg_mgr = "zypper"
        else:
            logger.info("No supported package manager found - skipping system tool updates")
            return False

        logger.info(f"Updating system tools via {pkg_mgr}...")
        self.log_for_cyberark(f"Updating system tools (nmap, nikto) via {pkg_mgr}")

        if pkg_mgr == "apt-get":
            success, _, stderr = self._run_cmd(
                privilege_prefix + ["apt-get", "update", "-qq"],
                timeout=120,
            )
            if not success:
                logger.warning(f"  apt update failed: {stderr[:200]}")
                return False

            for tool in ["nmap", "nikto", "curl"]:
                success, stdout, stderr = self._run_cmd(
                    privilege_prefix + ["apt-get", "install", "-y", "--only-upgrade", tool],
                    timeout=120,
                )
                if success:
                    logger.info(f"  {tool} updated")
                else:
                    logger.debug(f"  {tool}: {stderr[:100]}")

        elif pkg_mgr == "zypper":
            for tool in ["nmap", "nikto", "curl"]:
                success, stdout, stderr = self._run_cmd(
                    privilege_prefix + ["zypper", "install", "-y", tool],
                    timeout=120,
                )
                if success:
                    logger.info(f"  {tool} updated")
                else:
                    logger.debug(f"  {tool}: {stderr[:100]}")

        return True

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        update_cfg = config.get("assessment", {}).get("update", {})
        nuclei_cfg = config.get("assessment", {}).get("nuclei", {})
        project_root = Path(__file__).resolve().parent.parent

        update_results = {}

        if update_cfg.get("git_pull", True):
            update_results["git_pull"] = self._git_pull(project_root)
        else:
            logger.info("Git pull disabled in config - skipping")

        if update_cfg.get("nuclei_templates", True):
            offline_tarball = update_cfg.get("offline_templates_tarball", "")
            templates_dir = nuclei_cfg.get("templates_dir", "")

            if offline_tarball:
                update_results["nuclei_templates"] = self._update_nuclei_templates_offline(
                    offline_tarball,
                    templates_dir,
                )
            else:
                update_results["nuclei_templates"] = self._update_nuclei_templates_online()
        else:
            logger.info("Nuclei template updates disabled - skipping")

        if update_cfg.get("system_tools", False):
            update_results["system_tools"] = self._update_system_tools()
        else:
            logger.info("System tool updates disabled (opt-in required) - skipping")

        logger.info("Update summary:")
        for key, success in update_results.items():
            status = "OK" if success else "skipped/failed"
            logger.info(f"  {key}: {status}")

        logger.info("Phase 0 complete. Self-update finished.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Mock update - just log what would happen."""
        logger.info("[MOCK] Phase 0: Would perform the following updates:")
        logger.info("[MOCK]   - git pull (framework code)")
        logger.info("[MOCK]   - nuclei -ut (vulnerability templates)")
        logger.info("[MOCK]   - apt upgrade nmap nikto (system tools, if enabled)")
        logger.info("[MOCK] Phase 0 complete.")
