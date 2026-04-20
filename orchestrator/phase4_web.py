"""
Phase 4: Web Assessment

Responsibilities:
- Probe the ESXi Host Client web interface at https://10.251.2.28
- Check HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- Check HTTP methods (OPTIONS probe for TRACE, PUT, DELETE)
- Probe known ESXi paths (/ui/, /sdk, /mob, /host)
- Check cookie security flags
- Verify HTTP→HTTPS redirect
- Map service version to known CVEs (version-based, no exploitation)

Stealth measures:
- 2-second delay between HTTP requests (configurable)
- User-Agent matching the launch laptop's Chrome
- No directory brute-forcing, fuzzing, or injection testing
- Only targeted, known-safe GET/HEAD/OPTIONS requests
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

logger = logging.getLogger(__name__)

# Known ESXi CVEs mapped by version substring
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


class Phase4Web(PhasePlugin):

    @property
    def name(self) -> str:
        return "Web Assessment"

    @property
    def phase_number(self) -> int:
        return 4

    def _curl_available(self) -> bool:
        """Check if curl is available."""
        return shutil.which("curl") is not None

    def _run_curl(self, args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
        """Run a curl command and return (returncode, stdout, stderr)."""
        cmd = ["curl"] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except FileNotFoundError:
            return -1, "", "curl not found"

    def _check_security_headers(self, base_url: str, ua: str,
                                  verify_ssl: bool) -> List[WebVulnerability]:
        """Check for missing HTTP security headers."""
        findings = []
        k_flag = ["-k"] if not verify_ssl else []

        # Get response headers
        rc, stdout, stderr = self._run_curl(
            ["-sI", "-L", "--max-time", "10", "-A", ua] + k_flag + [f"{base_url}/ui/"]
        )

        if rc != 0:
            logger.warning(f"curl failed getting headers: {stderr}")
            return findings

        headers_raw = stdout.lower()
        finding_id = 100

        # Required headers check
        header_checks = [
            ("strict-transport-security", "HTTP Strict Transport Security (HSTS)",
             "Missing HSTS header allows downgrade attacks and cookie hijacking.",
             "High"),
            ("x-content-type-options", "X-Content-Type-Options",
             "Missing header allows MIME-type sniffing attacks.",
             "Medium"),
            ("x-frame-options", "X-Frame-Options / frame-ancestors",
             "Missing clickjacking protection. ESXi login could be framed.",
             "Medium"),
            ("content-security-policy", "Content-Security-Policy",
             "No CSP header. XSS mitigation is weakened.",
             "Medium"),
            ("x-xss-protection", "X-XSS-Protection",
             "Legacy XSS filter header missing. While deprecated, still useful for older browsers.",
             "Low"),
            ("referrer-policy", "Referrer-Policy",
             "No Referrer-Policy set. Internal URLs may leak in Referer headers.",
             "Low"),
            ("permissions-policy", "Permissions-Policy",
             "No Permissions-Policy header restricting browser features.",
             "Info"),
        ]

        for header_name, title, desc, severity in header_checks:
            if header_name not in headers_raw:
                # Check for CSP frame-ancestors as alternative to X-Frame-Options
                if header_name == "x-frame-options" and "frame-ancestors" in headers_raw:
                    continue

                findings.append(WebVulnerability(
                    id=f"WEB-{finding_id:03d}",
                    title=f"Missing {title}",
                    severity=severity,
                    description=desc,
                    evidence=f"Header '{header_name}' not present in response to {base_url}/ui/",
                ))
                finding_id += 1

        # Check for server information disclosure
        for line in stdout.split('\n'):
            if line.lower().startswith("server:"):
                server_val = line.split(":", 1)[1].strip()
                if server_val and server_val.lower() not in ("", "nginx", "apache"):
                    findings.append(WebVulnerability(
                        id=f"WEB-{finding_id:03d}",
                        title="Server Version Disclosure",
                        severity="Low",
                        description=f"The Server header exposes detailed version information.",
                        evidence=f"Server: {server_val}",
                    ))
                    finding_id += 1

        return findings

    def _check_http_methods(self, base_url: str, ua: str,
                             verify_ssl: bool) -> List[WebVulnerability]:
        """Check for dangerous HTTP methods via OPTIONS request."""
        findings = []
        k_flag = ["-k"] if not verify_ssl else []

        rc, stdout, stderr = self._run_curl(
            ["-sI", "-X", "OPTIONS", "--max-time", "10", "-A", ua] + k_flag + [f"{base_url}/"]
        )

        if rc != 0:
            return findings

        dangerous_methods = ["TRACE", "PUT", "DELETE", "MOVE", "COPY"]
        allow_header = ""

        for line in stdout.split('\n'):
            if line.lower().startswith("allow:"):
                allow_header = line.split(":", 1)[1].strip().upper()
                break

        if allow_header:
            for method in dangerous_methods:
                if method in allow_header:
                    findings.append(WebVulnerability(
                        id="WEB-200",
                        title=f"Dangerous HTTP Method Enabled: {method}",
                        severity="High" if method == "TRACE" else "Medium",
                        description=f"HTTP method {method} is enabled. "
                                    f"TRACE enables Cross-Site Tracing (XST) attacks.",
                        evidence=f"Allow: {allow_header}",
                    ))

        return findings

    def _check_known_paths(self, base_url: str, ua: str,
                            paths: List[str], verify_ssl: bool) -> List[WebVulnerability]:
        """Probe known ESXi paths for accessibility and information disclosure."""
        findings = []
        k_flag = ["-k"] if not verify_ssl else []

        sensitive_paths = {
            "/mob": ("VMware Managed Object Browser", "High",
                     "Exposes internal ESXi object model. Should be disabled in production."),
            "/sdk": ("VMware SDK Endpoint", "Medium",
                     "SOAP API endpoint exposed. Can be used for programmatic access."),
            "/host": ("ESXi Host Page", "Info",
                     "Host information page accessible."),
        }

        for path in paths:
            self.stealth_delay("http")

            url = f"{base_url}{path}"
            rc, stdout, stderr = self._run_curl(
                ["-sI", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "-A", ua]
                + k_flag + [url]
            )

            if rc != 0:
                continue

            status_code = stdout.strip()
            logger.debug(f"  {path} → HTTP {status_code}")

            # Check for accessible sensitive paths
            if status_code in ("200", "301", "302") and path in sensitive_paths:
                title, severity, desc = sensitive_paths[path]
                findings.append(WebVulnerability(
                    id=f"WEB-3{paths.index(path):02d}",
                    title=f"Accessible: {title}",
                    severity=severity,
                    description=desc,
                    evidence=f"GET {url} → HTTP {status_code}",
                ))

        return findings

    def _check_cookie_security(self, base_url: str, ua: str,
                                verify_ssl: bool) -> List[WebVulnerability]:
        """Check Set-Cookie headers for security flags."""
        findings = []
        k_flag = ["-k"] if not verify_ssl else []

        rc, stdout, stderr = self._run_curl(
            ["-sI", "-L", "--max-time", "10", "-A", ua] + k_flag + [f"{base_url}/ui/"]
        )

        if rc != 0:
            return findings

        for line in stdout.split('\n'):
            if line.lower().startswith("set-cookie:"):
                cookie_str = line.split(":", 1)[1].strip()
                cookie_lower = cookie_str.lower()

                if "secure" not in cookie_lower:
                    findings.append(WebVulnerability(
                        id="WEB-400",
                        title="Cookie Missing 'Secure' Flag",
                        severity="Medium",
                        description="Cookie transmitted over unencrypted connections.",
                        evidence=f"Set-Cookie: {cookie_str[:80]}...",
                    ))

                if "httponly" not in cookie_lower:
                    findings.append(WebVulnerability(
                        id="WEB-401",
                        title="Cookie Missing 'HttpOnly' Flag",
                        severity="Medium",
                        description="Cookie accessible via JavaScript (XSS risk).",
                        evidence=f"Set-Cookie: {cookie_str[:80]}...",
                    ))

                if "samesite" not in cookie_lower:
                    findings.append(WebVulnerability(
                        id="WEB-402",
                        title="Cookie Missing 'SameSite' Attribute",
                        severity="Low",
                        description="Cookie may be sent in cross-site requests (CSRF risk).",
                        evidence=f"Set-Cookie: {cookie_str[:80]}...",
                    ))

        return findings

    def _check_https_redirect(self, base_url: str, ua: str) -> List[WebVulnerability]:
        """Check if HTTP redirects to HTTPS."""
        findings = []
        # Only test if base_url is HTTPS — check the HTTP equivalent
        http_url = base_url.replace("https://", "http://")

        rc, stdout, stderr = self._run_curl(
            ["-sI", "-o", "/dev/null", "-w", "%{http_code}:%{redirect_url}",
             "--max-time", "10", "--max-redirs", "0", "-A", ua, http_url]
        )

        if rc == -1:
            return findings

        parts = stdout.strip().split(":", 1)
        status = parts[0] if parts else ""
        redirect_url = parts[1] if len(parts) > 1 else ""

        if status not in ("301", "302", "307", "308"):
            findings.append(WebVulnerability(
                id="WEB-500",
                title="No HTTP to HTTPS Redirect",
                severity="Medium",
                description="HTTP port does not redirect to HTTPS. "
                            "Users connecting via HTTP are not automatically secured.",
                evidence=f"GET {http_url} → HTTP {status} (no redirect to HTTPS)",
            ))
        elif redirect_url and "https" not in redirect_url.lower():
            findings.append(WebVulnerability(
                id="WEB-501",
                title="HTTP Redirect Does Not Point to HTTPS",
                severity="Medium",
                description="HTTP redirects, but not to an HTTPS URL.",
                evidence=f"GET {http_url} → {status} → {redirect_url}",
            ))

        return findings

    def _check_version_cves(self, report: AssessmentReport) -> List[WebVulnerability]:
        """Cross-reference discovered ESXi version with known CVEs."""
        findings = []

        for host in report.findings_infrastructure:
            if host.role != "esxi_host":
                continue
            for port in host.ports:
                version_str = port.version.lower()
                for ver_key, cves in ESXI_CVE_DB.items():
                    if ver_key in version_str or ver_key in host.os_fingerprint.lower():
                        for cve_id, severity, desc in cves:
                            findings.append(WebVulnerability(
                                id=cve_id,
                                title=f"{cve_id} — Potential Vulnerability",
                                severity=severity,
                                description=desc,
                                evidence=f"Detected version: {port.version or host.os_fingerprint}",
                            ))
                        break  # Only match first version key

        return findings

    def _run_ssl_labs_scan(self, domain: str) -> Optional[Dict[str, Any]]:
        """Run an SSL Labs scan for the given domain."""
        import requests
        api_url = "https://api.ssllabs.com/api/v3/analyze"
        params = {
            "host": domain,
            "publish": "off",
            "startNew": "on",
            "all": "done",
            "ignoreMismatch": "on"
        }

        try:
            response = requests.get(api_url, params=params, timeout=300)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"SSL Labs scan failed for {domain}: {e}")
            return None

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})
        web_cfg = assessment_cfg.get("web", {})
        http_cfg = stealth_cfg.get("http", {})

        base_url = web_cfg.get("base_url", "https://10.251.2.28")
        paths = web_cfg.get("paths", ["/ui/", "/sdk", "/mob", "/host", "/"])
        verify_ssl = web_cfg.get("verify_ssl", False)
        ua = http_cfg.get("user_agent", "Mozilla/5.0")

        self.log_for_cyberark(f"Web assessment of {base_url}")

        if not self._curl_available():
            report.add_error("phase4_web", "curl", "curl not found in PATH")
            return

        all_findings: List[WebVulnerability] = []

        # 1. Security Headers
        logger.info("Checking HTTP security headers...")
        all_findings.extend(self._check_security_headers(base_url, ua, verify_ssl))
        self.stealth_delay("http")

        # 2. HTTP Methods
        logger.info("Checking HTTP methods...")
        all_findings.extend(self._check_http_methods(base_url, ua, verify_ssl))
        self.stealth_delay("http")

        # 3. Known Paths
        logger.info("Probing known ESXi paths...")
        all_findings.extend(self._check_known_paths(base_url, ua, paths, verify_ssl))
        self.stealth_delay("http")

        # 4. Cookie Security
        logger.info("Checking cookie security...")
        all_findings.extend(self._check_cookie_security(base_url, ua, verify_ssl))
        self.stealth_delay("http")

        # 5. HTTPS Redirect
        logger.info("Checking HTTP→HTTPS redirect...")
        all_findings.extend(self._check_https_redirect(base_url, ua))
        self.stealth_delay("http")

        # 6. Version-based CVE lookup
        logger.info("Cross-referencing ESXi version with CVE database...")
        all_findings.extend(self._check_version_cves(report))

        # Save raw curl output for evidence
        output_dir = Path("output/web")
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_out = output_dir / "web_findings_raw.json"
        with open(raw_out, 'w', encoding='utf-8') as f:
            json.dump([v.__dict__ for v in all_findings], f, indent=2)

        # Add to report
        target_ip = assessment_cfg.get("target", {}).get("ip", "")
        web_result = WebAssessmentResult(
            host=target_ip,
            port=443,
            url=f"{base_url}/ui/",
            findings=all_findings,
        )
        report.add_web(web_result)

        logger.info(f"Phase 4 complete. {len(all_findings)} web findings.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Generate realistic mock web findings for ESXi Host Client."""
        findings = [
            WebVulnerability(
                id="WEB-100",
                title="Missing HTTP Strict Transport Security",
                severity="High",
                description="HSTS header not set. Allows protocol downgrade.",
                evidence="Header 'Strict-Transport-Security' not in response",
            ),
            WebVulnerability(
                id="WEB-101",
                title="Missing X-Content-Type-Options",
                severity="Medium",
                description="MIME-type sniffing not prevented.",
                evidence="Header 'X-Content-Type-Options' not in response",
            ),
            WebVulnerability(
                id="WEB-102",
                title="Missing Content-Security-Policy",
                severity="Medium",
                description="No CSP header present.",
                evidence="Header 'Content-Security-Policy' not in response",
            ),
            WebVulnerability(
                id="WEB-300",
                title="Accessible: VMware Managed Object Browser",
                severity="High",
                description="Exposes internal ESXi object model.",
                evidence="GET https://10.251.2.28/mob → HTTP 200",
            ),
            WebVulnerability(
                id="WEB-301",
                title="Accessible: VMware SDK Endpoint",
                severity="Medium",
                description="SOAP API endpoint exposed.",
                evidence="GET https://10.251.2.28/sdk → HTTP 200",
            ),
            WebVulnerability(
                id="WEB-400",
                title="Cookie Missing 'Secure' Flag",
                severity="Medium",
                description="Session cookie without Secure flag.",
                evidence="Set-Cookie: vmware_client_l10n=en; Path=/",
            ),
            WebVulnerability(
                id="CVE-2021-21974",
                title="CVE-2021-21974 — Potential Vulnerability",
                severity="Critical",
                description="OpenSLP heap overflow — pre-auth RCE via port 427",
                evidence="Detected version: VMware ESXi 7.0.3",
            ),
        ]

        report.add_web(WebAssessmentResult(
            host="10.251.2.28",
            port=443,
            url="https://10.251.2.28/ui/",
            findings=findings,
        ))
        logger.info(f"[MOCK] Phase 4 complete. {len(findings)} mock web findings.")
