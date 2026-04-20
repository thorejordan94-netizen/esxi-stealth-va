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

logger = logging.getLogger(__name__)


class Phase1Init(PhasePlugin):

    @property
    def name(self) -> str:
        return "Initialization"

    @property
    def phase_number(self) -> int:
        return 1

    def _check_tool(self, tool_name: str, test_args: list = None) -> bool:
        """Check if an external tool is available in PATH or via WSL."""
        # First check native PATH
        if shutil.which(tool_name):
            logger.info(f"  ✓ {tool_name} found in PATH")
            return True

        # Check via WSL (Windows Subsystem for Linux)
        if shutil.which("wsl"):
            try:
                result = subprocess.run(
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
                result = subprocess.run(
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

    def _install_missing_tools(self, tools: Dict[str, bool]) -> Dict[str, bool]:
        """Attempt to install missing tools automatically on Linux systems."""
        import platform
        if platform.system() != "Linux":
            logger.warning("Automatic tool installation only supported on Linux. Please install tools manually.")
            return {tool: False for tool in tools}

        # Check if we have sudo
        if not shutil.which("sudo"):
            logger.warning("sudo not found. Cannot install tools automatically. Please install manually or run as root.")
            return {tool: False for tool in tools}

        logger.info("Attempting automatic installation of missing tools...")

        installed = {}
        for tool, required in tools.items():
            if self._check_tool(tool):
                installed[tool] = True
                continue

            logger.info(f"Installing {tool}...")
            try:
                if tool == "nmap":
                    subprocess.run(["sudo", "apt", "update"], check=True, capture_output=True)
                    subprocess.run(["sudo", "apt", "install", "-y", "nmap"], check=True, capture_output=True)
                elif tool == "curl":
                    subprocess.run(["sudo", "apt", "install", "-y", "curl"], check=True, capture_output=True)
                elif tool == "nikto":
                    subprocess.run(["sudo", "apt", "install", "-y", "nikto"], check=True, capture_output=True)
                elif tool == "testssl.sh":
                    # Download and install testssl.sh
                    import tempfile
                    import zipfile
                    import urllib.request

                    with tempfile.TemporaryDirectory() as tmpdir:
                        zip_path = Path(tmpdir) / "testssl.zip"
                        urllib.request.urlretrieve("https://github.com/drwetter/testssl.sh/archive/refs/heads/master.zip", zip_path)
                        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                            zip_ref.extractall(tmpdir)
                        # Find the extracted directory (it might be testssl.sh-master or testssl.sh-3.3dev)
                        extracted_dirs = [d for d in Path(tmpdir).iterdir() if d.is_dir() and d.name.startswith("testssl.sh")]
                        if not extracted_dirs:
                            raise FileNotFoundError("Could not find extracted testssl.sh directory")
                        extracted_dir = extracted_dirs[0]
                        script_path = extracted_dir / "testssl.sh"
                        install_path = Path("/usr/local/bin/testssl.sh")
                        subprocess.run(["sudo", "cp", str(script_path), str(install_path)], check=True)
                        subprocess.run(["sudo", "chmod", "+x", str(install_path)], check=True)

                # Re-check after installation
                if self._check_tool(tool):
                    logger.info(f"  ✓ {tool} installed successfully")
                    installed[tool] = True
                else:
                    logger.error(f"  ✗ Failed to install {tool}")
                    installed[tool] = False

            except subprocess.CalledProcessError as e:
                logger.error(f"  ✗ Installation of {tool} failed: {e}")
                installed[tool] = False
            except Exception as e:
                logger.error(f"  ✗ Unexpected error installing {tool}: {e}")
                installed[tool] = False

        return installed

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})

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
            "testssl.sh": False, # Optional (Python fallback exists)
            "nikto": False,      # Optional
        }

        tool_status = {}
        missing_required = []
        missing_optional = []
        for tool, required in tools.items():
            available = self._check_tool(tool)
            tool_status[tool] = available
            if not available:
                if required:
                    missing_required.append(tool)
                else:
                    missing_optional.append(tool)

        # Attempt automatic installation of missing required tools
        if missing_required:
            logger.info(f"Required tools missing: {', '.join(missing_required)}. Attempting automatic installation...")
            install_results = self._install_missing_tools({tool: True for tool in missing_required})
            for tool, success in install_results.items():
                tool_status[tool] = success
                if not success:
                    report.add_error("phase1_init", self.name,
                        f"Required tool '{tool}' not found and automatic installation failed. Install it manually or add to PATH.")

        # Attempt automatic installation of missing optional tools
        if missing_optional:
            logger.info(f"Optional tools missing: {', '.join(missing_optional)}. Attempting automatic installation...")
            install_results = self._install_missing_tools({tool: False for tool in missing_optional})
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
            "nmap": True, "curl": True, "testssl.sh": True, "nikto": False
        }

        logger.info("[MOCK] Phase 1 complete. Metadata populated with defaults.")
