"""
Phase 1: Initialization & Scoping

Responsibilities:
- Validate configuration files
- Check external tool availability (nmap, testssl.sh, curl)
- Bootstrap the AssessmentReport data model with metadata
- Create output directories
- Log authorized assessment banner for CyberArk recording
"""

import shutil
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, AssessmentMetadata
from orchestrator.runtime import get_privilege_prefix, run_command

logger = logging.getLogger(__name__)

PKG_INSTALL_TIMEOUT_SECONDS = 180
PKG_UPDATE_TIMEOUT_SECONDS = 120


class Phase1Init(PhasePlugin):

    @property
    def name(self) -> str:
        return "Initialization"

    @property
    def phase_number(self) -> int:
        return 1

    def _get_tool_path(self, tool_name: str, config: Dict[str, Any]) -> str:
        """Get the full path to a tool, preferring config over PATH."""
        # Check for a manually configured path in assessment.yaml
        tool_paths = config.get("tool_paths", {})
        if tool_name in tool_paths and tool_paths[tool_name]:
            path = Path(tool_paths[tool_name])
            if path.is_file() and path.stat().st_mode & 0o111:
                logger.info(f"  ✓ {tool_name} found via configured path: {path}")
                return str(path)
            else:
                logger.warning(f"  ✗ Configured path for {tool_name} is not a valid executable file: {path}")

        # Fallback to shutil.which (native PATH)
        found_path = shutil.which(tool_name)
        if found_path:
            logger.info(f"  ✓ {tool_name} found in PATH: {found_path}")
            return found_path

        return ""

    def _check_tool(self, tool_name: str, config: Dict[str, Any], test_args: list = None) -> bool:
        """Check if an external tool is available from config, PATH, or via WSL."""
        if self._get_tool_path(tool_name, config):
            return True

        # Check via WSL (Windows Subsystem for Linux)
        if shutil.which("wsl"):
            try:
                result = run_command(
                    ["wsl", "which", tool_name],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    logger.info(f"  ✓ {tool_name} found via WSL")
                    return True
            except Exception:
                pass

        # Check via Git Bash
        git_bash = shutil.which("bash")
        if git_bash:
            try:
                result = run_command(
                    [git_bash, "-c", f"which {tool_name}"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    logger.info(f"  ✓ {tool_name} found via Git Bash")
                    return True
            except Exception:
                pass

        logger.warning(f"  ✗ {tool_name} not found")
        return False

    def _install_missing_tools(self, tools: Dict[str, bool], config: Dict[str, Any]) -> Dict[str, bool]:
        """Attempt to install missing tools automatically on Linux systems."""
        import platform
        if platform.system() != "Linux":
            logger.warning("Automatic tool installation only supported on Linux. Please install tools manually.")
            return {tool: False for tool in tools}

        privilege_prefix = get_privilege_prefix()
        if privilege_prefix is None:
            logger.warning("No root privileges available. Cannot install tools automatically.")
            return {tool: False for tool in tools}

        pkg_mgr = None
        if shutil.which("apt-get"):
            pkg_mgr = "apt-get"
        elif shutil.which("apt"):
            pkg_mgr = "apt"
        elif shutil.which("zypper"):
            pkg_mgr = "zypper"
        elif shutil.which("yum"):
            pkg_mgr = "yum"

        logger.info("Attempting automatic installation of missing tools...")
        install_env = {
            "DEBIAN_FRONTEND": "noninteractive",
            "APT_LISTCHANGES_FRONTEND": "none",
        }

        pkg_install_flags = ["install", "-y"]
        if pkg_mgr == "zypper":
            pkg_install_flags = ["--non-interactive", "install", "-y"]
        elif pkg_mgr == "yum":
            pkg_install_flags = ["install", "-y"]

        if pkg_mgr in ("apt-get", "apt"):
            try:
                run_command(
                    privilege_prefix + [pkg_mgr, "update"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=PKG_UPDATE_TIMEOUT_SECONDS,
                    env=install_env,
                )
            except Exception as e:
                logger.warning(f"Package metadata update failed via {pkg_mgr}: {e}")
        elif pkg_mgr == "zypper":
            try:
                run_command(
                    privilege_prefix + ["zypper", "--non-interactive", "refresh"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=PKG_UPDATE_TIMEOUT_SECONDS,
                    env=install_env,
                )
            except Exception as e:
                logger.warning(f"Package metadata refresh failed via zypper: {e}")

        installed = {}
        for tool in tools:
            if self._check_tool(tool, config):
                installed[tool] = True
                continue

            logger.info(f"Installing {tool}...")
            try:
                package_names = self._get_package_names(tool, pkg_mgr) if pkg_mgr else []
                if pkg_mgr and package_names:
                    install_success = False
                    last_error = None
                    for package_name in package_names:
                        try:
                            logger.info(f"Installing {tool} via package manager package '{package_name}'...")
                            run_command(
                                privilege_prefix + [pkg_mgr] + pkg_install_flags + [package_name],
                                check=True,
                                capture_output=True,
                                text=True,
                                timeout=PKG_INSTALL_TIMEOUT_SECONDS,
                                env=install_env,
                            )
                            install_success = True
                            break
                        except subprocess.CalledProcessError as e:
                            last_error = e
                            logger.warning(f"Package install failed for {package_name}: exit {e.returncode}")

                    if not install_success:
                        if last_error:
                            raise last_error
                        raise RuntimeError(f"No package names succeeded for {tool}")
                elif tool == "nuclei":
                    self._install_nuclei_binary(privilege_prefix)
                elif tool == "testssl.sh":
                    self._install_testssl_script(privilege_prefix)
                elif tool == "nikto":
                    self._install_nikto_script(privilege_prefix)
                else:
                    raise RuntimeError(f"No installation strategy available for {tool}")

                # Re-check after installation
                if self._check_tool(tool, config):
                    logger.info(f"  ✓ {tool} installed successfully")
                    installed[tool] = True
                elif tool == "testssl.sh":
                    logger.info(f"Package install for {tool} did not provide an executable; falling back to manual download/install.")
                    self._install_testssl_script(privilege_prefix)
                    installed[tool] = self._check_tool(tool, config)
                    if installed[tool]:
                        logger.info(f"  ✓ {tool} installed successfully via fallback")
                    else:
                        logger.error(f"  ✗ Failed to install {tool}")
                elif tool == "nuclei":
                    logger.info(f"Package install for {tool} did not provide an executable; falling back to direct download/install.")
                    self._install_nuclei_binary(privilege_prefix)
                    installed[tool] = self._check_tool(tool, config)
                    if installed[tool]:
                        logger.info(f"  ✓ {tool} installed successfully via fallback")
                    else:
                        logger.error(f"  ✗ Failed to install {tool}")
                else:
                    logger.error(f"  ✗ Failed to install {tool}")
                    installed[tool] = False

            except subprocess.CalledProcessError as e:
                if tool in ("nuclei", "testssl.sh", "nikto"):
                    logger.warning(f"  ✗ Optional tool package install failed for {tool} (exit {e.returncode}); attempting fallback installation.")
                    try:
                        if tool == "nuclei":
                            self._install_nuclei_binary(privilege_prefix)
                        elif tool == "testssl.sh":
                            self._install_testssl_script(privilege_prefix)
                        else:
                            self._install_nikto_script(privilege_prefix)
                        installed[tool] = self._check_tool(tool, config)
                        if installed[tool]:
                            logger.info(f"  ✓ {tool} installed successfully via fallback")
                        else:
                            logger.warning(f"  ✗ Optional tool {tool} could not be installed via fallback; continuing without it.")
                    except Exception as fallback_error:
                        logger.warning(f"  ✗ Fallback installation of optional tool {tool} failed: {fallback_error}; continuing without it.")
                        installed[tool] = False
                else:
                    logger.error(f"  ✗ Required tool installation failed: {tool} returned {e.returncode}. Install it manually or add it to PATH.")
                    installed[tool] = False
            except subprocess.TimeoutExpired as e:
                logger.error(f"  ✗ Installation of {tool} timed out after {e.timeout}s")
                installed[tool] = False
            except Exception as e:
                logger.error(f"  ✗ Unexpected error installing {tool}: {e}")
                installed[tool] = False

        return installed

    def _get_package_names(self, tool: str, pkg_mgr: str) -> list:
        if pkg_mgr in ("apt-get", "apt"):
            if tool == "testssl.sh":
                return ["testssl", "testssl.sh"]
            return [tool]

        if pkg_mgr == "yum":
            if tool == "testssl.sh":
                return ["testssl"]
            return [tool]

        if pkg_mgr == "zypper":
            # Avoid failing openSUSE optional tool installs with zypper package errors.
            if tool in ("nikto", "testssl.sh", "nuclei"):
                return []
            return [tool]

        return [tool]

    def _install_nuclei_binary(self, privilege_prefix: list):
        import urllib.request
        import tempfile
        import platform
        arch = "amd64" if platform.machine() == "x86_64" else "386"
        url = f"https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_{arch}.zip"
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "nuclei.zip"
            urllib.request.urlretrieve(url, zip_path)
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)
            run_command(privilege_prefix + ["cp", f"{tmpdir}/nuclei", "/usr/local/bin/nuclei"], check=True)
            run_command(privilege_prefix + ["chmod", "+x", "/usr/local/bin/nuclei"], check=True)

    def _install_testssl_script(self, privilege_prefix: list):
        import tempfile
        import zipfile
        import urllib.request

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "testssl.zip"
            urllib.request.urlretrieve("https://github.com/drwetter/testssl.sh/archive/refs/heads/master.zip", zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)
            extracted_dirs = [d for d in Path(tmpdir).iterdir() if d.is_dir() and d.name.startswith("testssl.sh")]
            if not extracted_dirs:
                raise FileNotFoundError("Could not find extracted testssl.sh directory")
            extracted_dir = extracted_dirs[0]
            script_path = extracted_dir / "testssl.sh"
            install_path = Path("/usr/local/bin/testssl.sh")
            run_command(privilege_prefix + ["cp", str(script_path), str(install_path)], check=True)
            run_command(privilege_prefix + ["chmod", "+x", str(install_path)], check=True)

    def _install_nikto_script(self, privilege_prefix: list):
        import tempfile
        import zipfile
        import urllib.request

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "nikto.zip"
            urllib.request.urlretrieve("https://github.com/sullo/nikto/archive/refs/heads/master.zip", zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)
            extracted_dirs = [d for d in Path(tmpdir).iterdir() if d.is_dir() and d.name.startswith("nikto")]
            if not extracted_dirs:
                raise FileNotFoundError("Could not find extracted nikto directory")
            extracted_dir = extracted_dirs[0]
            script_path = extracted_dir / "program" / "nikto.pl"
            if not script_path.exists():
                raise FileNotFoundError("Nikto script not found in downloaded archive")
            install_path = Path("/usr/local/bin/nikto")
            run_command(privilege_prefix + ["cp", str(script_path), str(install_path)], check=True)
            run_command(privilege_prefix + ["chmod", "+x", str(install_path)], check=True)

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})
        dry_run = bool(config.get("_dry_run", False))

        # --- CyberArk Audit Banner ---
        cr = assessment_cfg.get("environment", {}).get("change_request", "N/A")
        self.log_for_cyberark(
            f"Authorized Vulnerability Assessment starting. "
            f"Change Request: {cr}. "
            f"Target: {assessment_cfg.get('target', {}).get('ip', 'unknown')}"
        )

        # --- Create Output Directories ---
        output_dir = Path("output")
        for subdir in ["nmap", "crypto", "web", "sweep"]:
            (output_dir / subdir).mkdir(parents=True, exist_ok=True)
        logger.info("Output directories created.")

        # --- Populate Metadata ---
        target = assessment_cfg.get("target", {})
        env = assessment_cfg.get("environment", {})
        vm_disc = assessment_cfg.get("vm_discovery", {})

        report.metadata.target_primary = target.get("ip", "")
        report.metadata.target_hostname = target.get("hostname", "")
        report.metadata.executor = target.get("executor", "root")
        report.metadata.assessment_type = env.get("assessment_type", "Assume-Breach Internal VA")
        report.metadata.environment = env.get("classification", "Internal / CyberArk-monitored")
        report.metadata.change_request = env.get("change_request", "")
        report.metadata.notes = env.get("notes", "")
        report.metadata.started_at = datetime.now(timezone.utc).isoformat()
        report.metadata.scan_profile = config.get("scan_profile", {}).get("active_profile", "standard")
        report.metadata.framework_version = "2.1.0"

        # VM count from known_vms list or will be updated after sweep
        known_vms = vm_disc.get("known_vms", [])
        report.metadata.vm_count = len(known_vms) if known_vms else 0

        logger.info(f"Target: {report.metadata.target_primary} ({report.metadata.target_hostname})")
        logger.info(f"Environment: {report.metadata.environment}")
        logger.info(f"Run ID: {report.metadata.run_id}")

        # --- Check Tool Availability ---
        logger.info("Checking external tool availability...")
        tools = {
            "nmap": True,        # Required
            "curl": True,        # Required
            "nuclei": True,      # Required for vuln scanning
            "testssl.sh": False, # Optional (Python fallback exists)
            "nikto": False,      # Optional
        }

        tool_status = {}
        missing_required = []
        missing_optional = []
        for tool, required in tools.items():
            available = self._check_tool(tool, config)
            tool_status[tool] = available
            if not available:
                if required:
                    missing_required.append(tool)
                else:
                    missing_optional.append(tool)

        # Attempt automatic installation of missing required tools
        if missing_required:
            if dry_run:
                logger.info("Dry-run enabled; skipping automatic tool installation and keeping tool availability as-is.")
                for tool in missing_required:
                    logger.warning(f"Required tool '{tool}' is unavailable; dry-run will continue without installation.")
            else:
                logger.info(f"Required tools missing: {', '.join(missing_required)}. Attempting automatic installation...")
                install_results = self._install_missing_tools({tool: True for tool in missing_required}, config)
                for tool, success in install_results.items():
                    tool_status[tool] = success
                    if not success:
                        report.add_error("phase1_init", self.name,
                            f"Required tool '{tool}' not found and automatic installation failed. Install it manually or add to PATH.")

        # Attempt automatic installation of missing optional tools
        if missing_optional:
            if dry_run:
                for tool in missing_optional:
                    logger.info(f"Optional tool '{tool}' is unavailable; skipping installation during dry-run.")
            else:
                logger.info(f"Optional tools missing: {', '.join(missing_optional)}. Attempting automatic installation...")
                install_results = self._install_missing_tools({tool: False for tool in missing_optional}, config)
                for tool, success in install_results.items():
                    tool_status[tool] = success
                    if success:
                        logger.info(f"Optional tool '{tool}' installed successfully.")
                    else:
                        logger.warning(f"Optional tool '{tool}' could not be installed automatically.")

        # Store tool availability for downstream phases
        config["_tool_status"] = tool_status

        # --- Log Stealth Profile ---
        net = stealth_cfg.get("network", {})
        http = stealth_cfg.get("http", {})
        logger.info("Stealth profile loaded:")
        logger.info(f"  Max rate: {net.get('max_rate_pps', 100)} pps")
        logger.info(f"  Scan delay: {net.get('scan_delay_ms', 50)} ms")
        logger.info(f"  HTTP delay: {http.get('request_delay_s', 2.0)} s")
        logger.info(f"  Timing template: T{net.get('timing_template', 2)}")
        logger.info(f"  User-Agent: {http.get('user_agent', 'default')[:60]}...")

        logger.info("Phase 1 complete. Assessment initialized.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Mock init — populate metadata without checking tools."""
        assessment_cfg = config.get("assessment", {})
        target = assessment_cfg.get("target", {})
        env = assessment_cfg.get("environment", {})

        report.metadata.target_primary = target.get("ip", "10.251.2.28")
        report.metadata.target_hostname = target.get("hostname", "sl001983.de.internal.net")
        report.metadata.executor = "root"
        report.metadata.assessment_type = env.get("assessment_type", "Assume-Breach Internal VA")
        report.metadata.environment = env.get("classification", "Internal / CyberArk-monitored")
        report.metadata.started_at = datetime.now(timezone.utc).isoformat()
        report.metadata.vm_count = 31

        config["_tool_status"] = {
            "nmap": True, "curl": True, "nuclei": True, "testssl.sh": True, "nikto": False
        }

        logger.info("[MOCK] Phase 1 complete. Metadata populated with defaults.")
