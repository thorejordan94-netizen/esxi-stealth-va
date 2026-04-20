"""
Phase 4: TLS/Crypto Analysis (Expanded)

Responsibilities:
- Analyze TLS/SSL on ALL discovered HTTPS hosts (not just ESXi primary)
- Three execution paths (auto-detected, ordered by preference):
    Path A: testssl.sh (preferred — most comprehensive, fully offline)
    Path B: SSL Labs API v3 (optional, semi-online, async polling)
    Path C: Python ssl module (fallback — always available)
- Parse certificate details, TLS versions, vulnerabilities
- Grade each host's TLS configuration (A-F scale)

SSL Labs API Integration:
- The API is asynchronous: submit → poll → results
- Handles rate limiting (429), DNS resolution, IN_PROGRESS states
- Only usable if target is reachable from SSL Labs servers (NOT air-gapped)
- Configured via ssllabs section in assessment.yaml

Stealth measures:
- testssl.sh --sneaky mode
- Single connection per check via Python fallback
- No repeated handshakes or fuzzing
"""

import json
import ssl
import socket
import subprocess
import shutil
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import (
    AssessmentReport, CryptoFinding, CertificateInfo, SSLLabsResult
)

logger = logging.getLogger(__name__)


class SSLLabsClient:
    """
    SSL Labs API v3 client with asynchronous polling and rate limiting.

    API Documentation: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md

    The API works asynchronously:
    1. Submit analysis: GET /analyze?host=X&startNew=on
    2. Poll for status: GET /analyze?host=X (returns status: DNS, IN_PROGRESS, READY, ERROR)
    3. Retrieve results when status == READY

    Rate limiting:
    - Max 25 concurrent assessments
    - 1 new assessment per second per client IP
    - Respect 429 responses with exponential backoff
    """

    def __init__(self, api_url: str = "https://api.ssllabs.com/api/v3",
                 poll_interval: int = 30, max_attempts: int = 40,
                 max_age: int = 24, publish: str = "off"):
        self.api_url = api_url.rstrip("/")
        self.poll_interval = poll_interval
        self.max_attempts = max_attempts
        self.max_age = max_age
        self.publish = publish
        self._session = None

    def _get_session(self):
        """Lazy-init requests session."""
        if self._session is None:
            try:
                import requests
                self._session = requests.Session()
                self._session.headers.update({
                    "User-Agent": "ESXi-Pentest-Framework/2.0"
                })
            except ImportError:
                raise ImportError(
                    "The 'requests' library is required for SSL Labs API. "
                    "Install via: pip install requests"
                )
        return self._session

    def check_availability(self) -> bool:
        """Check if the SSL Labs API is reachable."""
        try:
            session = self._get_session()
            resp = session.get(f"{self.api_url}/info", timeout=10)
            if resp.status_code == 200:
                info = resp.json()
                logger.info(f"SSL Labs API available. "
                           f"Engine: {info.get('engineVersion', 'unknown')}, "
                           f"Max assessments: {info.get('maxAssessments', 'unknown')}")
                return True
            return False
        except Exception as e:
            logger.warning(f"SSL Labs API not reachable: {e}")
            return False

    def analyze(self, host: str) -> Optional[dict]:
        """
        Submit a host for analysis and poll until complete.

        Returns the full API response dict or None on failure.
        """
        session = self._get_session()

        # Step 1: Submit new analysis
        params = {
            "host": host,
            "publish": self.publish,
            "startNew": "on",
            "all": "done",
            "ignoreMismatch": "on",
        }
        if self.max_age:
            params["maxAge"] = str(self.max_age)

        logger.info(f"SSL Labs: Submitting analysis for {host}...")

        try:
            resp = session.get(f"{self.api_url}/analyze", params=params, timeout=30)

            if resp.status_code == 429:
                logger.warning("SSL Labs rate limit hit. Waiting 60s...")
                time.sleep(60)
                resp = session.get(f"{self.api_url}/analyze", params=params, timeout=30)

            if resp.status_code != 200:
                logger.error(f"SSL Labs API error: HTTP {resp.status_code}")
                return None

            data = resp.json()

        except Exception as e:
            logger.error(f"SSL Labs API request failed: {e}")
            return None

        # Step 2: Poll until READY or ERROR
        return self._poll_until_ready(host, data)

    def _poll_until_ready(self, host: str, initial_data: dict) -> Optional[dict]:
        """Poll the API until the scan completes."""
        session = self._get_session()
        data = initial_data

        for attempt in range(self.max_attempts):
            status = data.get("status", "UNKNOWN")
            logger.debug(f"SSL Labs poll #{attempt+1}: {host} → {status}")

            if status == "READY":
                logger.info(f"SSL Labs: Analysis complete for {host}")
                return data
            elif status == "ERROR":
                msg = data.get("statusMessage", "Unknown error")
                logger.error(f"SSL Labs: Analysis failed for {host}: {msg}")
                return None
            elif status in ("DNS", "IN_PROGRESS"):
                # Wait and poll again
                time.sleep(self.poll_interval)
                try:
                    params = {"host": host, "all": "done"}
                    resp = session.get(f"{self.api_url}/analyze", params=params, timeout=30)

                    if resp.status_code == 429:
                        logger.warning("SSL Labs rate limit — backing off 60s")
                        time.sleep(60)
                        resp = session.get(f"{self.api_url}/analyze", params=params, timeout=30)

                    if resp.status_code == 200:
                        data = resp.json()
                    else:
                        logger.warning(f"SSL Labs poll returned HTTP {resp.status_code}")
                except Exception as e:
                    logger.warning(f"SSL Labs poll error: {e}")
            else:
                logger.warning(f"SSL Labs: Unexpected status '{status}' for {host}")
                time.sleep(self.poll_interval)

        logger.error(f"SSL Labs: Timeout after {self.max_attempts} attempts for {host}")
        return None

    def parse_result(self, data: dict, host: str, port: int = 443) -> CryptoFinding:
        """Parse SSL Labs API response into a CryptoFinding."""
        endpoints = data.get("endpoints", [])
        if not endpoints:
            return CryptoFinding(host=host, port=port, scan_method="ssllabs")

        ep = endpoints[0]  # Primary endpoint

        ssllabs = SSLLabsResult(
            grade=ep.get("grade", "N/A"),
            grade_trust_ignored=ep.get("gradeTrIgnored", "N/A"),
            has_warnings=ep.get("hasWarnings", False),
            is_exceptional=ep.get("isExceptional", False),
            delegation=ep.get("delegation", 0),
            details_url=f"https://www.ssllabs.com/ssltest/analyze.html?d={host}",
        )

        # Extract certificate info from details
        cert_info = CertificateInfo()
        details = ep.get("details", {})
        certs = details.get("certChains", [{}])
        if certs:
            first_chain = certs[0]
            cert_list = first_chain.get("certIds", [])
            # The cert details are in the details section
            for cert_data in details.get("certs", []):
                if cert_data.get("subject"):
                    cert_info.subject = cert_data.get("subject", "")
                    cert_info.issuer = cert_data.get("issuerSubject", "")
                    cert_info.key_size = cert_data.get("keySize", 0)
                    cert_info.signature_algorithm = cert_data.get("sigAlg", "")
                    san_list = cert_data.get("altNames", [])
                    cert_info.san = san_list if isinstance(san_list, list) else []
                    # Check self-signed
                    if cert_info.subject == cert_info.issuer:
                        cert_info.self_signed = True
                    break

        # Extract protocol support
        tls_versions = {"TLS_1.0": False, "TLS_1.1": False, "TLS_1.2": False, "TLS_1.3": False}
        for proto in details.get("protocols", []):
            name = proto.get("name", "")
            version = proto.get("version", "")
            key = f"{name}_{version}".replace(".", "_").replace(" ", "_")
            tls_key = f"TLS_{version}"
            if tls_key in tls_versions:
                tls_versions[tls_key] = True

        # Vulnerabilities from details
        vulns = []
        vuln_checks = {
            "heartbleed": "Heartbleed",
            "poodle": "POODLE",
            "freak": "FREAK",
            "logjam": "Logjam",
            "drownVulnerable": "DROWN",
        }
        for key, name in vuln_checks.items():
            if details.get(key):
                vulns.append(f"{name} vulnerability detected")

        if tls_versions.get("TLS_1.0"):
            vulns.append("TLS 1.0 supported (deprecated)")
        if tls_versions.get("TLS_1.1"):
            vulns.append("TLS 1.1 supported (deprecated)")

        grade = ssllabs.grade
        severity = self._grade_to_severity(grade)

        return CryptoFinding(
            host=host, port=port,
            certificate=cert_info,
            tls_versions=tls_versions,
            vulnerabilities=vulns,
            grade=grade,
            severity=severity,
            scan_method="ssllabs",
            ssllabs_result=ssllabs,
        )

    @staticmethod
    def _grade_to_severity(grade: str) -> str:
        return {
            "A+": "Info", "A": "Info", "A-": "Low",
            "B": "Medium", "C": "High", "D": "High",
            "F": "Critical", "T": "Critical",
        }.get(grade, "Medium")


class Phase4Crypto(PhasePlugin):

    @property
    def name(self) -> str:
        return "Crypto Analysis"

    @property
    def phase_number(self) -> int:
        return 4

    def _find_testssl(self) -> Optional[str]:
        """Find testssl.sh — native, WSL, or Git Bash."""
        if shutil.which("testssl.sh"):
            return "testssl.sh"
        if shutil.which("testssl"):
            return "testssl"
        if shutil.which("wsl"):
            try:
                r = subprocess.run(["wsl", "which", "testssl.sh"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    return "wsl testssl.sh"
                r = subprocess.run(["wsl", "which", "testssl"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    return "wsl testssl"
            except Exception:
                pass
        git_bash = shutil.which("bash")
        if git_bash:
            try:
                r = subprocess.run([git_bash, "-c", "which testssl.sh"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    return f"{git_bash} -c testssl.sh"
            except Exception:
                pass
        return None

    # =========================================================================
    # Path A: testssl.sh
    # =========================================================================

    def _run_testssl(self, host: str, port: int, stealth_cfg: Dict[str, Any],
                     output_dir: Path) -> Optional[CryptoFinding]:
        """Run testssl.sh and parse its JSON output."""
        testssl_cmd = self._find_testssl()
        if not testssl_cmd:
            return None

        tls_cfg = stealth_cfg.get("tls", {})
        json_out = output_dir / f"testssl_{host.replace('.', '_')}_{port}.json"

        cmd_parts = testssl_cmd.split() + [
            "--quiet",
            "--severity", "LOW",
            "--jsonfile", str(json_out),
            tls_cfg.get("testssl_mode", "--sneaky"),
            "--connect-timeout", str(tls_cfg.get("connect_timeout_s", 5)),
            "--openssl-timeout", str(tls_cfg.get("openssl_timeout_s", 5)),
            f"{host}:{port}",
        ]

        logger.info(f"Running testssl.sh against {host}:{port}...")
        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True, text=True, check=False, timeout=300
            )
        except FileNotFoundError:
            logger.warning("testssl.sh invocation failed — falling back")
            return None
        except subprocess.TimeoutExpired:
            logger.error("testssl.sh timed out after 5 minutes")
            return None

        if not json_out.exists():
            logger.warning(f"testssl.sh did not produce JSON output at {json_out}")
            return None

        return self._parse_testssl_json(json_out, host, port)

    def _parse_testssl_json(self, json_path: Path, host: str, port: int) -> CryptoFinding:
        """Parse testssl.sh JSON output into a CryptoFinding."""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cert_info = CertificateInfo()
        tls_versions = {"TLS_1.0": False, "TLS_1.1": False, "TLS_1.2": False, "TLS_1.3": False}
        vulnerabilities = []
        cipher_suites = []

        entries = data if isinstance(data, list) else data.get("scanResult", [{}])[0].get("findings", [])

        for entry in entries:
            eid = entry.get("id", "")
            finding_val = entry.get("finding", "")
            severity = entry.get("severity", "INFO")

            # Certificate fields
            if eid in ("cert_commonName", "cert_CN"):
                cert_info.subject = f"CN={finding_val}"
            elif eid in ("cert_caIssuers", "cert_issuer"):
                cert_info.issuer = finding_val
            elif eid == "cert_notBefore":
                cert_info.valid_from = finding_val
            elif eid == "cert_notAfter":
                cert_info.valid_to = finding_val
            elif eid == "cert_keySize":
                try:
                    cert_info.key_size = int(''.join(filter(str.isdigit, finding_val)))
                except ValueError:
                    pass
            elif eid in ("cert_signatureAlgorithm", "cert_sigAlg"):
                cert_info.signature_algorithm = finding_val
            elif eid == "cert_trust":
                if "self" in finding_val.lower() or "not trusted" in finding_val.lower():
                    cert_info.self_signed = True
            elif eid == "cert_subjectAltName":
                cert_info.san = [s.strip() for s in finding_val.split(",") if s.strip()]

            # TLS versions
            elif "protocol" in eid.lower() or eid.startswith("SSLv") or eid.startswith("TLS"):
                if "offered" in finding_val.lower() or "yes" in finding_val.lower():
                    if "1.0" in eid or "1_0" in eid:
                        tls_versions["TLS_1.0"] = True
                    elif "1.1" in eid or "1_1" in eid:
                        tls_versions["TLS_1.1"] = True
                    elif "1.2" in eid or "1_2" in eid:
                        tls_versions["TLS_1.2"] = True
                    elif "1.3" in eid or "1_3" in eid:
                        tls_versions["TLS_1.3"] = True

            # Vulnerabilities
            elif severity in ("CRITICAL", "HIGH", "MEDIUM", "WARN"):
                if "vuln" in eid.lower() or any(v in eid.upper() for v in
                        ["HEARTBLEED", "POODLE", "BEAST", "BREACH", "CRIME",
                         "DROWN", "LOGJAM", "FREAK", "SWEET32", "ROBOT",
                         "TICKETBLEED", "CCS", "LUCKY13"]):
                    vulnerabilities.append(f"{eid}: {finding_val}")

            # Ciphers
            elif "cipher" in eid.lower() and severity in ("CRITICAL", "HIGH", "MEDIUM"):
                cipher_suites.append(finding_val)

        grade = self._calculate_grade(cert_info, tls_versions, vulnerabilities)
        severity_level = self._grade_to_severity(grade)

        return CryptoFinding(
            host=host, port=port,
            certificate=cert_info,
            tls_versions=tls_versions,
            vulnerabilities=vulnerabilities,
            cipher_suites=cipher_suites,
            grade=grade,
            severity=severity_level,
            scan_method="testssl",
        )

    # =========================================================================
    # Path C: Python ssl fallback
    # =========================================================================

    def _python_ssl_check(self, host: str, port: int) -> CryptoFinding:
        """Fallback TLS analysis using Python's ssl and socket modules."""
        logger.info(f"Python SSL fallback: analyzing {host}:{port}...")

        cert_info = CertificateInfo()
        tls_versions = {"TLS_1.0": False, "TLS_1.1": False, "TLS_1.2": False, "TLS_1.3": False}
        vulnerabilities = []

        # --- Get certificate ---
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    peer_cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    logger.info(f"Connected: {protocol}, cipher: {cipher}")

            if peer_cert:
                subject = dict(x[0] for x in peer_cert.get("subject", ()))
                issuer = dict(x[0] for x in peer_cert.get("issuer", ()))
                cert_info.subject = f"CN={subject.get('commonName', 'unknown')}"
                cert_info.issuer = f"CN={issuer.get('commonName', 'unknown')}"
                cert_info.valid_from = peer_cert.get("notBefore", "")
                cert_info.valid_to = peer_cert.get("notAfter", "")
                sans = peer_cert.get("subjectAltName", ())
                cert_info.san = [v for _, v in sans]
                if subject == issuer:
                    cert_info.self_signed = True
                    vulnerabilities.append("Self-signed certificate")

            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                parsed = x509.load_der_x509_certificate(der_cert, default_backend())
                cert_info.key_size = parsed.public_key().key_size
                cert_info.signature_algorithm = parsed.signature_algorithm_oid._name
            except ImportError:
                logger.debug("cryptography library not available — key size unavailable")
            except Exception as e:
                logger.debug(f"Could not parse DER cert: {e}")

        except Exception as e:
            logger.error(f"SSL connection to {host}:{port} failed: {e}")
            vulnerabilities.append(f"Connection error: {e}")

        # --- Check TLS protocol versions ---
        protocol_map = {
            "TLS_1.0": getattr(ssl.TLSVersion, 'TLSv1', None),
            "TLS_1.1": getattr(ssl.TLSVersion, 'TLSv1_1', None),
            "TLS_1.2": ssl.TLSVersion.TLSv1_2,
            "TLS_1.3": ssl.TLSVersion.TLSv1_3,
        }

        for ver_name, ver_const in protocol_map.items():
            if ver_const is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver_const
                ctx.maximum_version = ver_const
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        tls_versions[ver_name] = True
                self.stealth_delay("network")
            except (ssl.SSLError, ConnectionError, OSError):
                tls_versions[ver_name] = False
            except Exception:
                pass

        if tls_versions.get("TLS_1.0"):
            vulnerabilities.append("TLS 1.0 supported (deprecated)")
        if tls_versions.get("TLS_1.1"):
            vulnerabilities.append("TLS 1.1 supported (deprecated)")
        if not tls_versions.get("TLS_1.2") and not tls_versions.get("TLS_1.3"):
            vulnerabilities.append("No modern TLS version (1.2/1.3) supported")

        grade = self._calculate_grade(cert_info, tls_versions, vulnerabilities)

        return CryptoFinding(
            host=host, port=port,
            certificate=cert_info,
            tls_versions=tls_versions,
            vulnerabilities=vulnerabilities,
            grade=grade,
            severity=self._grade_to_severity(grade),
            scan_method="python_ssl",
        )

    # =========================================================================
    # Grading Logic
    # =========================================================================

    def _calculate_grade(self, cert: CertificateInfo,
                         tls_versions: Dict[str, bool],
                         vulns: List[str]) -> str:
        """Calculate an A-F grade based on findings."""
        score = 100

        if cert.self_signed:
            score -= 20
        if cert.key_size and cert.key_size < 2048:
            score -= 30
        elif cert.key_size and cert.key_size < 4096:
            score -= 5

        if cert.valid_to:
            try:
                for fmt in ["%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S",
                            "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y"]:
                    try:
                        expiry = datetime.strptime(cert.valid_to, fmt)
                        if expiry < datetime.now():
                            score -= 40
                            vulns.append("Certificate expired")
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        if tls_versions.get("TLS_1.0"):
            score -= 15
        if tls_versions.get("TLS_1.1"):
            score -= 10
        if not tls_versions.get("TLS_1.2") and not tls_versions.get("TLS_1.3"):
            score -= 30

        critical_vulns = [v for v in vulns if any(k in v.upper() for k in
            ["HEARTBLEED", "DROWN", "POODLE", "EXPIRED"])]
        score -= len(critical_vulns) * 20
        score -= max(0, len(vulns) - len(critical_vulns)) * 5

        if score >= 95: return "A+"
        elif score >= 85: return "A"
        elif score >= 75: return "A-"
        elif score >= 65: return "B"
        elif score >= 50: return "C"
        elif score >= 35: return "D"
        else: return "F"

    @staticmethod
    def _grade_to_severity(grade: str) -> str:
        return {
            "A+": "Info", "A": "Info", "A-": "Low",
            "B": "Medium", "C": "High", "D": "High",
            "F": "Critical",
        }.get(grade, "Medium")

    # =========================================================================
    # Main Execution
    # =========================================================================

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})
        crypto_cfg = assessment_cfg.get("crypto", {})
        ssllabs_cfg = assessment_cfg.get("ssllabs", {})

        prefer_testssl = crypto_cfg.get("prefer_testssl", True)
        scan_all_hosts = crypto_cfg.get("scan_all_hosts", True)
        output_dir = Path("output/crypto")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build list of hosts:ports to scan
        targets: List[Tuple[str, int]] = []

        if scan_all_hosts:
            # Scan ALL discovered hosts that have HTTPS ports
            targets = report.get_https_hosts()
            if not targets:
                logger.info("No HTTPS hosts found in discovery results")
        else:
            # Legacy mode: only scan primary target
            target_ip = assessment_cfg.get("target", {}).get("ip", "")
            tls_ports = crypto_cfg.get("tls_ports", [443])
            targets = [(target_ip, p) for p in tls_ports]

        if not targets:
            logger.info("No TLS targets to scan — skipping Phase 4")
            return

        logger.info(f"TLS analysis on {len(targets)} endpoint(s)...")

        # Initialize SSL Labs client if enabled
        ssllabs_client = None
        if ssllabs_cfg.get("enabled", False):
            ssllabs_client = SSLLabsClient(
                api_url=ssllabs_cfg.get("api_url", "https://api.ssllabs.com/api/v3"),
                poll_interval=ssllabs_cfg.get("poll_interval_s", 30),
                max_attempts=ssllabs_cfg.get("max_poll_attempts", 40),
                max_age=ssllabs_cfg.get("max_age_hours", 24),
                publish=ssllabs_cfg.get("publish", "off"),
            )
            if not ssllabs_client.check_availability():
                logger.warning("SSL Labs API not available — falling back to local tools")
                ssllabs_client = None

        for host, port in targets:
            self.log_for_cyberark(f"TLS analysis on {host}:{port}")
            finding = None

            # Priority 1: testssl.sh (offline, most comprehensive)
            if prefer_testssl:
                finding = self._run_testssl(host, port, stealth_cfg, output_dir)
                if finding:
                    finding.scan_method = "testssl"

            # Priority 2: SSL Labs API (if enabled and available)
            if finding is None and ssllabs_client:
                try:
                    result_data = ssllabs_client.analyze(host)
                    if result_data:
                        finding = ssllabs_client.parse_result(result_data, host, port)
                except Exception as e:
                    logger.warning(f"SSL Labs analysis failed for {host}:{port}: {e}")

            # Priority 3: Python ssl fallback (always available)
            if finding is None:
                logger.info("Using Python SSL fallback...")
                try:
                    finding = self._python_ssl_check(host, port)
                except Exception as e:
                    report.add_error("phase4_crypto", "python_ssl",
                        f"Python SSL check failed for {host}:{port}: {e}")
                    continue

            if finding:
                report.add_crypto(finding)
                logger.info(f"  {host}:{port} → Grade: {finding.grade} "
                           f"({finding.severity}) via {finding.scan_method}")

            self.stealth_delay("network")

        logger.info(f"Phase 4 complete. {len(report.findings_crypto)} crypto findings.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Generate realistic mock crypto data for multiple hosts."""
        mock_hosts = [
            ("10.251.2.28", 443, "sl001983.de.internal.net", True, "B"),
            ("10.251.2.31", 443, "va011", True, "C"),
            ("10.251.2.34", 443, "va014", True, "A-"),
            ("10.251.2.35", 8443, "va015", True, "D"),
            ("10.251.2.38", 443, "va018", True, "B"),
        ]

        for ip, port, hostname, self_signed, grade in mock_hosts:
            cert = CertificateInfo(
                subject=f"CN={hostname}",
                issuer=f"CN={hostname}" if self_signed else "CN=Internal CA",
                valid_from="2024-01-15T00:00:00",
                valid_to="2027-01-15T00:00:00",
                self_signed=self_signed,
                key_size=2048,
                signature_algorithm="sha256WithRSAEncryption",
                san=[hostname, ip],
            )

            tls_versions = {
                "TLS_1.0": grade in ("D", "F"),
                "TLS_1.1": grade in ("C", "D", "F"),
                "TLS_1.2": True,
                "TLS_1.3": grade in ("A+", "A", "A-"),
            }

            vulns = []
            if self_signed:
                vulns.append("Self-signed certificate")
            if tls_versions["TLS_1.0"]:
                vulns.append("TLS 1.0 supported (deprecated)")
            if tls_versions["TLS_1.1"]:
                vulns.append("TLS 1.1 supported (deprecated)")

            finding = CryptoFinding(
                host=ip, port=port,
                certificate=cert,
                tls_versions=tls_versions,
                vulnerabilities=vulns,
                grade=grade,
                severity=self._grade_to_severity(grade),
                scan_method="testssl",
            )
            report.add_crypto(finding)

        logger.info(f"[MOCK] Phase 4 complete. {len(mock_hosts)} mock crypto findings.")
