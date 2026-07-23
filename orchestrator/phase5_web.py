"""Phase 5: HTTP/HTTPS security assessment."""

import json
import logging
import shutil
import subprocess
from pathlib import Path

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, WebAssessmentResult, WebVulnerability
from orchestrator.runtime import get_output_dir, run_command


logger = logging.getLogger(__name__)


ESXI_CVE_DB = {
    "6.5": [
        ("CVE-2021-21972", "Critical", "vSphere Client unauthenticated RCE"),
        ("CVE-2020-3992", "Critical", "OpenSLP use-after-free RCE"),
    ],
    "6.7": [
        ("CVE-2021-21972", "Critical", "vSphere Client unauthenticated RCE"),
        ("CVE-2021-21974", "Critical", "OpenSLP heap-overflow RCE"),
        ("CVE-2020-3992", "Critical", "OpenSLP use-after-free RCE"),
    ],
    "7.0": [
        ("CVE-2021-21974", "Critical", "OpenSLP heap-overflow pre-authentication RCE"),
        ("CVE-2022-31696", "High", "Network stack memory corruption"),
        ("CVE-2023-20867", "Medium", "VMware Tools authentication bypass"),
        ("CVE-2024-37085", "High", "AD-joined ESXi authentication bypass"),
    ],
    "8.0": [
        ("CVE-2024-37085", "High", "AD-joined ESXi authentication bypass"),
        ("CVE-2023-20867", "Medium", "VMware Tools authentication bypass"),
    ],
}


class Phase5Web(PhasePlugin):

    @property
    def name(self):
        return "Web Assessment"

    @property
    def phase_number(self):
        return 5

    @staticmethod
    def _curl_available():
        return shutil.which("curl") is not None

    def _get_nikto_cmd(self, config=None):
        configured = (config or {}).get("assessment", {}).get("tool_paths", {}).get("nikto", "")
        if configured and Path(str(configured)).is_file():
            return [str(configured)]
        native = shutil.which("nikto")
        if native:
            return [native]
        if shutil.which("wsl"):
            try:
                result = run_command(
                    ["wsl", "which", "nikto"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return ["wsl", "nikto"]
            except Exception:
                pass
        return None

    @staticmethod
    def _run_curl(args, timeout=15):
        try:
            result = run_command(
                ["curl"] + list(args),
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                strip_proxy=True,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as exc:
            return -1, "", str(exc)

    @staticmethod
    def _get_base_url(host, port):
        scheme = "https" if port in (443, 8443, 9443) else "http"
        if (scheme, port) in (("http", 80), ("https", 443)):
            return "{}://{}".format(scheme, host)
        return "{}://{}:{}".format(scheme, host, port)

    def _check_security_headers(self, base_url, user_agent, verify_ssl):
        findings = []
        insecure_flag = ["-k"] if not verify_ssl else []
        result_code, stdout, _stderr = self._run_curl(
            ["-sI", "-L", "--max-time", "15", "-A", user_agent] + insecure_flag + [base_url + "/"]
        )
        if result_code != 0:
            return findings

        headers = stdout.lower()
        checks = [
            ("x-content-type-options", "X-Content-Type-Options", "MIME-sniffing prevention", "Medium"),
            ("x-frame-options", "X-Frame-Options", "Clickjacking protection", "Medium"),
            ("content-security-policy", "CSP", "Browser content restrictions", "Medium"),
        ]
        if base_url.lower().startswith("https://"):
            checks.insert(0, (
                "strict-transport-security", "HSTS", "HTTPS downgrade prevention", "High"
            ))

        finding_number = 500
        for header, title, description, severity in checks:
            if header in headers:
                continue
            if header == "x-frame-options" and "frame-ancestors" in headers:
                continue
            findings.append(WebVulnerability(
                "WEB-{}".format(finding_number),
                "Missing {}".format(title),
                severity,
                description,
                "Header '{}' missing from {}".format(header, base_url),
            ))
            finding_number += 1
        return findings

    def _check_cookie_security(self, base_url, user_agent, verify_ssl):
        findings = []
        insecure_flag = ["-k"] if not verify_ssl else []
        result_code, stdout, _stderr = self._run_curl(
            ["-sI", "-L", "--max-time", "15", "-A", user_agent] + insecure_flag + [base_url + "/"]
        )
        if result_code != 0:
            return findings

        for line in stdout.splitlines():
            if not line.lower().startswith("set-cookie:"):
                continue
            cookie = line.split(":", 1)[1].strip().lower()
            if "secure" not in cookie and base_url.lower().startswith("https://"):
                findings.append(WebVulnerability(
                    "WEB-600", "Cookie Missing 'Secure'", "Medium",
                    "The cookie may be transmitted without TLS if a client is redirected or misconfigured.", cookie,
                ))
            if "httponly" not in cookie:
                findings.append(WebVulnerability(
                    "WEB-601", "Cookie Missing 'HttpOnly'", "Medium",
                    "Client-side script can access the cookie if script execution is achieved.", cookie,
                ))
            if "samesite" not in cookie:
                findings.append(WebVulnerability(
                    "WEB-602", "Cookie Missing 'SameSite'", "Low",
                    "Cross-site request protections are weaker without an explicit SameSite policy.", cookie,
                ))
        return findings

    def _run_nikto(self, host, port, output_dir, config=None):
        """Run the complete Nikto test set unless explicit tuning is configured."""
        findings = []
        nikto_cmd = self._get_nikto_cmd(config)
        if not nikto_cmd:
            return findings

        web_config = (config or {}).get("assessment", {}).get("web", {})
        timeout = int(web_config.get("nikto_timeout_s", 3600))
        tuning = str(web_config.get("nikto_tuning", "")).strip()
        json_output = output_dir / "nikto_{}_{}.json".format(host.replace(":", "_"), port)
        command = nikto_cmd + [
            "-h", host,
            "-p", str(port),
            "-Format", "json",
            "-output", str(json_output),
        ]
        if tuning:
            command.extend(["-Tuning", tuning])

        logger.info("Running full Nikto assessment on %s:%s", host, port)
        try:
            if json_output.exists():
                json_output.unlink()
            result = run_command(
                command,
                capture_output=True,
                text=True,
                timeout=None if timeout <= 0 else timeout,
                strip_proxy=True,
            )
            if result.returncode not in (0, 1) and not json_output.exists():
                logger.warning("Nikto failed for %s:%s: %s", host, port, (result.stderr or "")[:300])
                return findings
            if not json_output.exists():
                return findings

            with json_output.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else data
            for item in vulnerabilities or []:
                if not isinstance(item, dict):
                    continue
                findings.append(WebVulnerability(
                    id="NIKTO-{}".format(item.get("id") or "VULN"),
                    title=item.get("msg") or item.get("message") or "Nikto finding",
                    severity=item.get("severity") or "Medium",
                    description=item.get("description") or item.get("msg") or "Potential issue found by Nikto",
                    evidence="URL: {} | Method: {}".format(item.get("url", ""), item.get("method", "")),
                ))
        except subprocess.TimeoutExpired:
            logger.warning("Nikto timed out for %s:%s after %s seconds", host, port, timeout)
        except Exception as exc:
            logger.warning("Nikto failed for %s:%s: %s", host, port, exc)
        return findings

    def _check_esxi_paths(self, base_url, host_ip, user_agent, verify_ssl):
        findings = []
        paths = ["/ui/", "/sdk", "/mob", "/host"]
        insecure_flag = ["-k"] if not verify_ssl else []
        for path in paths:
            self.stealth_delay("http")
            result_code, stdout, _stderr = self._run_curl(
                ["-sI", "-o", "/dev/null", "-w", "%{http_code}", "-A", user_agent]
                + insecure_flag + [base_url + path]
            )
            if result_code == 0 and stdout.strip() in ("200", "301", "302", "401", "403"):
                findings.append(WebVulnerability(
                    "WEB-700-{}".format(path.strip("/").replace("/", "-") or "root"),
                    "ESXi Management Path Reachable: {}".format(path),
                    "Low",
                    "An ESXi management endpoint is reachable from the assessment network; authentication may still be required.",
                    "HTTP {}".format(stdout.strip()),
                ))
        return findings

    def execute(self, report, config):
        web_config = config.get("assessment", {}).get("web", {})
        stealth_config = config.get("stealth", {})
        user_agent = stealth_config.get("http", {}).get("user_agent", "Mozilla/5.0")
        verify_ssl = web_config.get("verify_ssl", False)
        use_nikto = web_config.get("use_nikto", True)
        output_dir = get_output_dir(config) / "web"
        output_dir.mkdir(parents=True, exist_ok=True)

        web_hosts = report.get_web_hosts() if web_config.get("scan_all_hosts", True) else []
        if not web_hosts:
            logger.info("No web hosts to scan.")
            return

        for host in web_hosts:
            for port_entry in [
                port for port in host.ports if port.port in (80, 443, 8080, 8443, 9080, 9443)
            ]:
                base_url = self._get_base_url(host.host, port_entry.port)
                self.log_for_cyberark("Web assessment: {}".format(base_url))
                findings = []
                findings.extend(self._check_security_headers(base_url, user_agent, verify_ssl))
                findings.extend(self._check_cookie_security(base_url, user_agent, verify_ssl))
                if host.role == "esxi_host":
                    findings.extend(self._check_esxi_paths(base_url, host.host, user_agent, verify_ssl))
                if use_nikto:
                    findings.extend(self._run_nikto(host.host, port_entry.port, output_dir, config))
                report.add_web(WebAssessmentResult(
                    host=host.host,
                    port=port_entry.port,
                    url=base_url,
                    findings=findings,
                ))
                self.stealth_delay("http")
        logger.info("Phase 5 complete. %s web results.", len(report.findings_web))

    def mock_execute(self, report, config):
        findings = [
            WebVulnerability("WEB-100", "Missing HSTS", "High", "Downgrade risk", "Header missing")
        ]
        report.add_web(WebAssessmentResult(
            "10.251.2.28", 443, "https://10.251.2.28", findings
        ))
        logger.info("[MOCK] Phase 5 complete.")
