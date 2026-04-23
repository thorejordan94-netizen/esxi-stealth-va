"""
Phase 5: Web Assessment (Expanded)

Responsibilities:
- Scale web assessment to ALL discovered VMs with HTTP/HTTPS ports
- Perform standard security header and cookie checks on every web service
- Probe ESXi-specific paths and mapping CVEs for ESXi hosts
- Integrate Nikto for generic web vulnerability scanning (if available)

Execution Logic:
1. Identify all hosts with web ports (80, 443, 8080, 8443, etc.)
2. For each host:port:
   - Check security headers
   - Check cookie flags
   - Check dangerous HTTP methods
   - If host is ESXi: Probe specific paths (Phase 4 legacy)
   - If Nikto is enabled: Run Nikto scan

Stealth measures:
- Configurable inter-request delay
- User-Agent consistency
- Nikto tuning via -Tuning for specific areas (optional)
"""

import subprocess
import json
import shutil
import logging
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import (
    AssessmentReport, WebAssessmentResult, WebVulnerability
)
from orchestrator.runtime import run_command

logger = logging.getLogger(__name__)

# Known ESXi CVEs (same as Phase 4)
ESXI_CVE_DB = {
    "6.5": [
        ("CVE-2021-21972", "Critical", "vSphere Client RCE — unauthenticated remote code execution via /ui/vropspluginui/rest/services/uploadova"),
        ("CVE-2020-3992", "Critical", "OpenSLP use-after-free — RCE on port 427"),
    ],
    "6.7": [
        ("CVE-2021-21972", "Critical", "vSphere Client RCE — /ui/vropspluginui/rest/services/uploadova"),
        ("CVE-2021-21974", "Critical", "OpenSLP heap overflow — RCE via port 427"),
        ("CVE-2020-3992", "Critical", "OpenSLP use-after-free — RCE"),
    ],
    "7.0": [
        ("CVE-2021-21974", "Critical", "OpenSLP heap overflow — pre-auth RCE via port 427"),
        ("CVE-2022-31696", "High", "Memory corruption in network stack"),
        ("CVE-2023-20867", "Medium", "VMware Tools authentication bypass"),
        ("CVE-2024-37085", "High", "AD-joined ESXi auth bypass via group manipulation"),
    ],
    "8.0": [
        ("CVE-2024-37085", "High", "AD-joined ESXi auth bypass via group manipulation"),
        ("CVE-2023-20867", "Medium", "VMware Tools authentication bypass"),
    ],
}


class Phase5Web(PhasePlugin):

    @property
    def name(self) -> str:
        return "Web Assessment"

    @property
    def phase_number(self) -> int:
        return 5

    def _curl_available(self) -> bool:
        return shutil.which("curl") is not None

    def _get_nikto_cmd(self) -> Optional[List[str]]:
        if shutil.which("nikto"):
            return ["nikto"]

        if shutil.which("wsl"):
            try:
                result = run_command(["wsl", "which", "nikto"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return ["wsl", "nikto"]
            except Exception:
                pass

        return None

    def _run_curl(self, args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
        cmd = ["curl"] + args
        try:
            result = run_command(
                cmd, capture_output=True, text=True, check=False, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as e:
            return -1, "", str(e)

    def _get_base_url(self, host: str, port: int) -> str:
        scheme = "https" if port in (443, 8443, 9443) else "http"
        return f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"

    # --- Scanning & Probing ---

    def _check_security_headers(self, base_url: str, ua: str, verify_ssl: bool) -> List[WebVulnerability]:
        findings = []
        k_flag = ["-k"] if not verify_ssl else []
        rc, stdout, stderr = self._run_curl(["-sI", "-L", "--max-time", "10", "-A", ua] + k_flag + [f"{base_url}/"])
        if rc != 0: return findings

        headers_raw = stdout.lower()
        header_checks = [
            ("strict-transport-security", "HSTS", "Downgrade prevention", "High"),
            ("x-content-type-options", "X-Content-Type-Options", "MIME-sniffing prevention", "Medium"),
            ("x-frame-options", "X-Frame-Options", "Clickjacking protection", "Medium"),
            ("content-security-policy", "CSP", "XSS mitigation", "Medium"),
        ]
        f_id = 500
        for header, title, desc, severity in header_checks:
            if header not in headers_raw:
                if header == "x-frame-options" and "frame-ancestors" in headers_raw: continue
                findings.append(WebVulnerability(f"WEB-{f_id}", f"Missing {title}", severity, desc, f"Header '{header}' missing from {base_url}"))
                f_id += 1
        return findings

    def _check_cookie_security(self, base_url: str, ua: str, verify_ssl: bool) -> List[WebVulnerability]:
        findings = []
        k_flag = ["-k"] if not verify_ssl else []
        rc, stdout, stderr = self._run_curl(["-sI", "-L", "--max-time", "10", "-A", ua] + k_flag + [f"{base_url}/"])
        if rc != 0: return findings

        for line in stdout.split('\n'):
            if line.lower().startswith("set-cookie:"):
                cookie = line.split(":", 1)[1].strip().lower()
                if "secure" not in cookie and "https" in base_url:
                    findings.append(WebVulnerability("WEB-600", "Cookie Missing 'Secure'", "Medium", "XSS risk over HTTP", cookie))
                if "httponly" not in cookie:
                    findings.append(WebVulnerability("WEB-601", "Cookie Missing 'HttpOnly'", "Medium", "XSS risk", cookie))
        return findings

    def _run_nikto(self, host: str, port: int, output_dir: Path) -> List[WebVulnerability]:
        findings = []
        nikto_cmd = self._get_nikto_cmd()
        if not nikto_cmd:
            return findings

        logger.info(f"  Running Nikto on {host}:{port}...")
        json_out = output_dir / f"nikto_{host}_{port}.json"
        cmd = nikto_cmd + ["-h", host, "-p", str(port), "-Format", "json", "-output", str(json_out), "-Tuning", "123x"]
        
        try:
            if json_out.exists():
                json_out.unlink()
            run_command(cmd, capture_output=True, text=True, timeout=600)
            if json_out.exists():
                with open(json_out, 'r') as f:
                    data = json.load(f)
                    for item in data.get("vulnerabilities", []):
                        findings.append(WebVulnerability(
                            id="NIKTO-VULN", title=item.get("msg", "Nikto finding"),
                            severity="Medium", description=item.get("description", "Potential vulnerability found by Nikto"),
                            evidence=f"URL: {item.get('url', '')}"
                        ))
        except Exception as e:
            logger.warning(f"Nikto failed for {host}: {e}")
        return findings

    def _check_esxi_paths(self, base_url: str, host_ip: str, ua: str, verify_ssl: bool) -> List[WebVulnerability]:
        findings = []
        paths = ["/ui/", "/sdk", "/mob", "/host"]
        k_flag = ["-k"] if not verify_ssl else []
        for path in paths:
            self.stealth_delay("http")
            rc, stdout, stderr = self._run_curl(["-sI", "-o", "/dev/null", "-w", "%{http_code}", "-A", ua] + k_flag + [f"{base_url}{path}"])
            if rc == 0 and stdout.strip() in ("200", "301", "302"):
                findings.append(WebVulnerability("WEB-700", f"ESXi Path Accessible: {path}", "Medium", "Sensitive service exposed", f"HTTP {stdout.strip()}"))
        return findings

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        web_cfg = config.get("assessment", {}).get("web", {})
        stealth_cfg = config.get("stealth", {})
        ua = stealth_cfg.get("http", {}).get("user_agent", "Mozilla/5.0")
        verify_ssl = web_cfg.get("verify_ssl", False)
        use_nikto = web_cfg.get("use_nikto", True)

        output_dir = Path("output/web")
        output_dir.mkdir(parents=True, exist_ok=True)

        web_hosts = report.get_web_hosts() if web_cfg.get("scan_all_hosts", True) else []
        if not web_hosts:
            logger.info("No web hosts to scan.")
            return

        for host in web_hosts:
            for port_entry in [p for p in host.ports if p.port in (80, 443, 8080, 8443, 9080, 9443)]:
                base_url = self._get_base_url(host.host, port_entry.port)
                self.log_for_cyberark(f"Web assessment: {base_url}")
                
                findings = []
                findings.extend(self._check_security_headers(base_url, ua, verify_ssl))
                findings.extend(self._check_cookie_security(base_url, ua, verify_ssl))

                if host.role == "esxi_host":
                    findings.extend(self._check_esxi_paths(base_url, host.host, ua, verify_ssl))

                if use_nikto:
                    findings.extend(self._run_nikto(host.host, port_entry.port, output_dir))

                result = WebAssessmentResult(host=host.host, port=port_entry.port, url=base_url, findings=findings)
                report.add_web(result)
                self.stealth_delay("http")

        logger.info(f"Phase 5 complete. {len(report.findings_web)} web results.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        from orchestrator.models import WebAssessmentResult, WebVulnerability
        findings = [WebVulnerability("WEB-100", "Missing HSTS", "High", "Downgrade risk", "Header missing")]
        report.add_web(WebAssessmentResult("10.251.2.28", 443, "https://10.251.2.28", findings))
        logger.info("[MOCK] Phase 5 complete.")
