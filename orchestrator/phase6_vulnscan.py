"""
Phase 6: Vulnerability Scanning (Nuclei)

Responsibilities:
- Run Nuclei vulnerability scanner against all discovered web targets
- Support both online and offline template usage
- Parse Nuclei JSONL output into VulnerabilityFinding model objects
- Apply severity and tag filters based on configuration
- Respect stealth/rate-limiting parameters

Design:
- Generates a temporary targets list for Nuclei
- Uses -jsonl for easy parsing
- Includes specific ESXi and infrastructure tags by default
"""

import subprocess
import json
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, VulnerabilityFinding

logger = logging.getLogger(__name__)


class Phase6VulnScan(PhasePlugin):

    @property
    def name(self) -> str:
        return "Vulnerability Scanning"

    @property
    def phase_number(self) -> int:
        return 6

    def _get_nuclei_cmd(self) -> Optional[str]:
        """Find nuclei binary."""
        return shutil.which("nuclei")

    def _prepare_targets(self, report: AssessmentReport) -> Optional[Path]:
        """Create a temporary file containing all web targets for Nuclei."""
        web_hosts = report.get_web_hosts()
        if not web_hosts:
            return None

        targets = []
        for host in web_hosts:
            # We use the schemes determined in Phase 5 or defaults
            for p in host.ports:
                if p.port in (443, 8443, 9443):
                    targets.append(f"https://{host.host}:{p.port}")
                elif p.port in (80, 8080, 9080):
                    targets.append(f"http://{host.host}:{p.port}")

        if not targets:
            return None

        target_file = Path("output/nuclei_targets.txt")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        with open(target_file, 'w') as f:
            f.write("\n".join(set(targets)))
        
        return target_file

    def _parse_nuclei_jsonl(self, jsonl_file: Path) -> List[VulnerabilityFinding]:
        """Parse Nuclei's JSONL output into model objects."""
        findings = []
        if not jsonl_file.exists():
            return findings

        try:
            with open(jsonl_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line)
                    
                    # Map Nuclei fields to our model
                    info = data.get("info", {})
                    host_val = data.get("host", "")
                    # Extract port if possible
                    port = 0
                    if ":" in host_val.replace("://", ""):
                        try: port = int(host_val.split(":")[-1].split("/")[0])
                        except: pass

                    findings.append(VulnerabilityFinding(
                        host=data.get("ip", host_val),
                        port=port,
                        url=data.get("matched-at", host_val),
                        template_id=data.get("template-id", ""),
                        name=info.get("name", ""),
                        severity=info.get("severity", "info").lower(),
                        description=info.get("description", ""),
                        matcher_name=data.get("matcher-name", ""),
                        evidence=data.get("extracted-results", [data.get("response", "")[:200]])[0],
                        reference=info.get("reference", []),
                        tags=info.get("tags", []),
                        curl_command=data.get("curl-command", ""),
                        scanner="nuclei",
                        timestamp=data.get("timestamp", "")
                    ))
        except Exception as e:
            logger.error(f"Failed to parse Nuclei JSONL: {e}")

        return findings

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        n_cfg = config.get("assessment", {}).get("nuclei", {})
        if not n_cfg.get("enabled", True):
            logger.info("Nuclei scanning disabled in config.")
            return

        nuclei_bin = self._get_nuclei_cmd()
        if not nuclei_bin:
            report.add_error("phase6_vulnscan", "nuclei", "Nuclei binary not found in PATH")
            return

        target_file = self._prepare_targets(report)
        if not target_file:
            logger.info("No web targets found for Nuclei scanning.")
            return

        output_file = Path("output/nuclei_findings.jsonl")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Build command
        cmd = [
            nuclei_bin,
            "-l", str(target_file),
            "-jsonl",
            "-o", str(output_file),
            "-rl", str(n_cfg.get("rate_limit", 50)),
            "-c", str(n_cfg.get("concurrency", 10)),
            "-timeout", str(n_cfg.get("timeout", 10)),
            "-severity", n_cfg.get("severity_filter", "critical,high,medium"),
            "-silent"
        ]

        # Add templates dir if specified
        if n_cfg.get("templates_dir"):
            cmd.extend(["-t", n_cfg.get("templates_dir")])
        
        # Add tags
        if n_cfg.get("tags"):
            cmd.extend(["-tags", ",".join(n_cfg.get("tags"))])
        
        # Add exclusions
        if n_cfg.get("exclude_tags"):
            cmd.extend(["-etags", ",".join(n_cfg.get("exclude_tags"))])

        # Extra args
        cmd.extend(n_cfg.get("extra_args", []))

        logger.info(f"Running Nuclei against {target_file.name}...")
        self.log_for_cyberark("Starting Nuclei vulnerability scan")

        try:
            # We don't use check=True because Nuclei might exit with non-zero if findings found (depending on version)
            # or if some templates fail. We rely on the output file.
            subprocess.run(cmd, capture_output=True, timeout=3600) # 1 hour timeout
            
            findings = self._parse_nuclei_jsonl(output_file)
            for f in findings:
                report.add_vuln(f)
            
            logger.info(f"Nuclei completed. Found {len(findings)} vulnerabilities.")

        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out.")
            report.add_error("phase6_vulnscan", "nuclei", "Nuclei scan timed out")
        except Exception as e:
            logger.error(f"Nuclei execution failed: {e}")
            report.add_error("phase6_vulnscan", "nuclei", f"Execution failed: {e}")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Generate mock Nuclei findings."""
        logger.info("[MOCK] Generating synthetic Nuclei findings...")
        
        # Take a web host if available
        host = "10.251.2.28"
        web_hosts = report.get_web_hosts()
        if web_hosts: host = web_hosts[0].host

        mock_findings = [
            VulnerabilityFinding(
                host=host, port=443, url=f"https://{host}/ui/",
                template_id="ssl-deprecated-protocols", name="Deprecated TLS Protocol",
                severity="medium", description="The server supports deprecated TLS 1.0/1.1",
                evidence="TLS 1.0 is offered", tags=["tls", "ssl", "misconfig"], scanner="nuclei"
            ),
            VulnerabilityFinding(
                host=host, port=443, url=f"https://{host}/",
                template_id="http-missing-security-headers", name="HTTP Missing Security Headers",
                severity="low", description="Several security headers are missing",
                evidence="X-Content-Type-Options missing", tags=["headers", "misconfig"], scanner="nuclei"
            )
        ]
        
        for f in mock_findings:
            report.add_vuln(f)
            
        logger.info(f"[MOCK] Phase 6 complete. Added {len(mock_findings)} findings.")
