"""
Phase 3: Crypto Analysis

Responsibilities:
- Analyze TLS/SSL configuration of the ESXi host (port 443)
- Parse certificate details (subject, issuer, validity, key size, self-signed status)
- Determine TLS protocol version support (1.0/1.1/1.2/1.3)
- Identify known TLS vulnerabilities
- Grade the TLS configuration (A-F scale)

Execution paths (auto-detected):
  Path A: testssl.sh via WSL/Git Bash (preferred — most comprehensive)
  Path B: Python ssl + cryptography module (fallback — limited checks)

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
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import (
    AssessmentReport, CryptoFinding, CertificateInfo
)

logger = logging.getLogger(__name__)


class Phase3Crypto(PhasePlugin):

    @property
    def name(self) -> str:
        return "Crypto Analysis"

    @property
    def phase_number(self) -> int:
        return 3

    def _find_testssl(self) -> Optional[str]:
        """Find testssl.sh — native, WSL, or Git Bash."""
        # Native
        if shutil.which("testssl.sh"):
            return "testssl.sh"
        if shutil.which("testssl"):
            return "testssl"

        # WSL
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

        # Git Bash
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
                capture_output=True, text=True, check=False,
                timeout=300  # 5 min max
            )
        except FileNotFoundError:
            logger.warning("testssl.sh invocation failed — falling back to Python")
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
        tls_versions = {
            "TLS_1.0": False,
            "TLS_1.1": False,
            "TLS_1.2": False,
            "TLS_1.3": False,
        }
        vulnerabilities = []
        cipher_suites = []

        # testssl.sh JSON is an array of finding objects
        entries = data if isinstance(data, list) else data.get("scanResult", [{}])[0].get("findings", [])

        for entry in entries:
            eid = entry.get("id", "")
            finding_val = entry.get("finding", "")
            severity = entry.get("severity", "INFO")

            # Certificate fields
            if eid == "cert_commonName" or eid == "cert_CN":
                cert_info.subject = f"CN={finding_val}"
            elif eid == "cert_caIssuers" or eid == "cert_issuer":
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
            elif eid == "cert_signatureAlgorithm" or eid == "cert_sigAlg":
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

        # Calculate grade
        grade = self._calculate_grade(cert_info, tls_versions, vulnerabilities)
        severity = self._grade_to_severity(grade)

        return CryptoFinding(
            host=host, port=port,
            certificate=cert_info,
            tls_versions=tls_versions,
            vulnerabilities=vulnerabilities,
            cipher_suites=cipher_suites,
            grade=grade,
            severity=severity,
        )

    # =========================================================================
    # Path B: Python ssl fallback
    # =========================================================================

    def _python_ssl_check(self, host: str, port: int) -> CryptoFinding:
        """Fallback TLS analysis using Python's ssl and socket modules."""
        logger.info(f"Python SSL fallback: analyzing {host}:{port}...")

        cert_info = CertificateInfo()
        tls_versions = {
            "TLS_1.0": False,
            "TLS_1.1": False,
            "TLS_1.2": False,
            "TLS_1.3": False,
        }
        vulnerabilities = []

        # --- Get certificate ---
        try:
            # Use a permissive context to connect to self-signed certs
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get DER cert and parse
                    der_cert = ssock.getpeercert(binary_form=True)
                    peer_cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    logger.info(f"Connected: {protocol}, cipher: {cipher}")

            # Parse peer cert dict
            if peer_cert:
                subject = dict(x[0] for x in peer_cert.get("subject", ()))
                issuer = dict(x[0] for x in peer_cert.get("issuer", ()))
                cert_info.subject = f"CN={subject.get('commonName', 'unknown')}"
                cert_info.issuer = f"CN={issuer.get('commonName', 'unknown')}"
                cert_info.valid_from = peer_cert.get("notBefore", "")
                cert_info.valid_to = peer_cert.get("notAfter", "")

                # SAN
                sans = peer_cert.get("subjectAltName", ())
                cert_info.san = [v for _, v in sans]

                # Self-signed check
                if subject == issuer:
                    cert_info.self_signed = True
                    vulnerabilities.append("Self-signed certificate")

            # Try to get key size from DER cert using cryptography lib
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
            "TLS_1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None,
            "TLS_1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None,
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
                        logger.debug(f"  {ver_name}: supported")

                self.stealth_delay("network")  # Small delay between version probes

            except (ssl.SSLError, ConnectionError, OSError):
                tls_versions[ver_name] = False
                logger.debug(f"  {ver_name}: not supported")
            except Exception:
                pass

        # Flag deprecated protocols
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
        )

    # =========================================================================
    # Grading Logic
    # =========================================================================

    def _calculate_grade(self, cert: CertificateInfo,
                         tls_versions: Dict[str, bool],
                         vulns: List[str]) -> str:
        """Calculate an A-F grade based on findings."""
        score = 100  # Start at A+

        # Certificate issues
        if cert.self_signed:
            score -= 20
        if cert.key_size and cert.key_size < 2048:
            score -= 30
        elif cert.key_size and cert.key_size < 4096:
            score -= 5

        # Check expiry
        if cert.valid_to:
            try:
                # Try multiple formats
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

        # TLS version issues
        if tls_versions.get("TLS_1.0"):
            score -= 15
        if tls_versions.get("TLS_1.1"):
            score -= 10
        if not tls_versions.get("TLS_1.2") and not tls_versions.get("TLS_1.3"):
            score -= 30

        # Vulnerability count
        critical_vulns = [v for v in vulns if any(k in v.upper() for k in
            ["HEARTBLEED", "DROWN", "POODLE", "expired"])]
        score -= len(critical_vulns) * 20
        score -= max(0, len(vulns) - len(critical_vulns)) * 5

        # Map score to grade
        if score >= 95:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 75:
            return "A-"
        elif score >= 65:
            return "B"
        elif score >= 50:
            return "C"
        elif score >= 35:
            return "D"
        else:
            return "F"

    def _grade_to_severity(self, grade: str) -> str:
        """Map letter grade to severity level."""
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

        target_ip = assessment_cfg.get("target", {}).get("ip", "")
        tls_ports = crypto_cfg.get("tls_ports", [443])
        prefer_testssl = crypto_cfg.get("prefer_testssl", True)
        output_dir = Path("output/crypto")
        output_dir.mkdir(parents=True, exist_ok=True)

        for port in tls_ports:
            self.log_for_cyberark(f"TLS analysis on {target_ip}:{port}")

            finding = None

            # Try testssl.sh first (if preferred and available)
            if prefer_testssl:
                finding = self._run_testssl(target_ip, port, stealth_cfg, output_dir)

            # Fallback to Python
            if finding is None:
                logger.info("Using Python SSL fallback...")
                try:
                    finding = self._python_ssl_check(target_ip, port)
                except Exception as e:
                    report.add_error("phase3_crypto", "python_ssl",
                        f"Python SSL check failed for {target_ip}:{port}: {e}")
                    continue

            if finding:
                report.add_crypto(finding)
                logger.info(f"  TLS Grade: {finding.grade} ({finding.severity})")
                logger.info(f"  Self-signed: {finding.certificate.self_signed if finding.certificate else 'N/A'}")
                logger.info(f"  Vulnerabilities: {len(finding.vulnerabilities)}")

            self.stealth_delay("network")

        logger.info(f"Phase 3 complete. {len(report.findings_crypto)} crypto findings.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Generate realistic mock crypto data for the ESXi self-signed cert."""
        cert = CertificateInfo(
            subject="CN=sl001983.de.internal.net",
            issuer="CN=sl001983.de.internal.net",
            valid_from="2024-01-15T00:00:00",
            valid_to="2027-01-15T00:00:00",
            self_signed=True,
            key_size=2048,
            signature_algorithm="sha256WithRSAEncryption",
            san=["sl001983.de.internal.net", "10.251.2.28"],
        )

        finding = CryptoFinding(
            host="10.251.2.28",
            port=443,
            certificate=cert,
            tls_versions={
                "TLS_1.0": False,
                "TLS_1.1": False,
                "TLS_1.2": True,
                "TLS_1.3": False,
            },
            vulnerabilities=[
                "Self-signed certificate",
                "TLS 1.3 not supported",
            ],
            cipher_suites=[
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ],
            grade="B",
            severity="Medium",
        )

        report.add_crypto(finding)
        logger.info("[MOCK] Phase 3 complete. Mock crypto finding generated.")
