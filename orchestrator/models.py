"""
Data models for the ESXi Penetration Testing Framework.

Produces a single normalized JSON document with these top-level sections:
  - metadata
  - findings_infrastructure
  - findings_crypto
  - findings_web
  - findings_vulns        (NEW — Nuclei/scanner results)
  - delta                 (NEW — week-over-week comparison)
  - execution_errors

All models use dataclasses with explicit to_dict()/from_dict() serialization
to avoid external dependencies (no pydantic needed).
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ============================================================================
# Metadata
# ============================================================================

@dataclass
class AssessmentMetadata:
    """Top-level metadata for the assessment run."""
    target_primary: str
    target_hostname: str
    assessment_type: str = "Automated Weekly Pentest"
    environment: str = "Internal / Isolated ESXi Network"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    executor: str = "root"
    vm_count: int = 0
    change_request: str = ""
    notes: str = ""
    scan_profile: str = "standard"
    framework_version: str = "2.0.0"
    scan_week: str = field(default_factory=lambda: datetime.now().strftime("%Y-W%W"))

    def to_dict(self) -> dict:
        return {
            "target_primary": self.target_primary,
            "target_hostname": self.target_hostname,
            "assessment_type": self.assessment_type,
            "environment": self.environment,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "run_id": self.run_id,
            "executor": self.executor,
            "vm_count": self.vm_count,
            "change_request": self.change_request,
            "notes": self.notes,
            "scan_profile": self.scan_profile,
            "framework_version": self.framework_version,
            "scan_week": self.scan_week,
        }


# ============================================================================
# Infrastructure Findings
# ============================================================================

@dataclass
class PortEntry:
    """A single discovered port on a host."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
        }


@dataclass
class HostFinding:
    """Infrastructure finding for a single host."""
    host: str
    hostname: str = ""
    ports: List[PortEntry] = field(default_factory=list)
    os_fingerprint: str = ""
    role: str = ""  # "esxi_host", "vm", "unknown"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "hostname": self.hostname,
            "ports": [p.to_dict() for p in self.ports],
            "os_fingerprint": self.os_fingerprint,
            "role": self.role,
        }

    def has_web_ports(self) -> bool:
        """Check if host has any HTTP/HTTPS ports open."""
        web_ports = {80, 443, 8080, 8443, 9080, 9443}
        return any(p.port in web_ports for p in self.ports)

    def get_https_ports(self) -> List[int]:
        """Return list of ports likely running HTTPS."""
        https_ports = {443, 8443, 9443}
        return [p.port for p in self.ports if p.port in https_ports or 'ssl' in p.service.lower() or 'https' in p.service.lower()]

    def get_http_ports(self) -> List[int]:
        """Return list of ports likely running HTTP (non-TLS)."""
        http_ports = {80, 8080, 9080}
        return [p.port for p in self.ports if p.port in http_ports or (p.service == 'http' and p.port not in {443, 8443, 9443})]


# ============================================================================
# Crypto Findings
# ============================================================================

@dataclass
class CertificateInfo:
    """Parsed certificate metadata."""
    subject: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    self_signed: bool = False
    key_size: int = 0
    signature_algorithm: str = ""
    san: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "self_signed": self.self_signed,
            "key_size": self.key_size,
            "signature_algorithm": self.signature_algorithm,
            "san": self.san,
        }


@dataclass
class SSLLabsResult:
    """SSL Labs API v3 result for a single endpoint."""
    grade: str = "N/A"
    grade_trust_ignored: str = "N/A"
    has_warnings: bool = False
    is_exceptional: bool = False
    delegation: int = 0
    details_url: str = ""

    def to_dict(self) -> dict:
        return {
            "grade": self.grade,
            "grade_trust_ignored": self.grade_trust_ignored,
            "has_warnings": self.has_warnings,
            "is_exceptional": self.is_exceptional,
            "delegation": self.delegation,
            "details_url": self.details_url,
        }


@dataclass
class CryptoFinding:
    """TLS/SSL assessment result for a single host:port."""
    host: str
    port: int = 443
    certificate: Optional[CertificateInfo] = None
    tls_versions: Dict[str, bool] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    cipher_suites: List[str] = field(default_factory=list)
    grade: str = "N/A"
    severity: str = "Info"
    scan_method: str = "python_ssl"  # "testssl", "python_ssl", "ssllabs"
    ssllabs_result: Optional[SSLLabsResult] = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "tls_versions": self.tls_versions,
            "vulnerabilities": self.vulnerabilities,
            "cipher_suites": self.cipher_suites,
            "grade": self.grade,
            "severity": self.severity,
            "scan_method": self.scan_method,
            "ssllabs_result": self.ssllabs_result.to_dict() if self.ssllabs_result else None,
        }


# ============================================================================
# Web Findings
# ============================================================================

@dataclass
class WebVulnerability:
    """A single web vulnerability or misconfiguration."""
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class WebAssessmentResult:
    """Web assessment results for a single host:port."""
    host: str
    port: int = 443
    url: str = ""
    findings: List[WebVulnerability] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "findings": [f.to_dict() for f in self.findings],
        }


# ============================================================================
# Vulnerability Findings (Nuclei / Scanner Results)
# ============================================================================

@dataclass
class VulnerabilityFinding:
    """
    A vulnerability finding from Nuclei or other automated scanners.

    Separates scanner-detected vulnerabilities from manual web checks
    to maintain provenance and allow independent filtering.
    """
    host: str
    port: int = 0
    url: str = ""
    template_id: str = ""       # Nuclei template ID, e.g., "CVE-2021-44228"
    name: str = ""
    severity: str = "info"      # critical, high, medium, low, info
    description: str = ""
    matcher_name: str = ""
    evidence: str = ""
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    curl_command: str = ""
    scanner: str = "nuclei"     # Source scanner name
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "matcher_name": self.matcher_name,
            "evidence": self.evidence,
            "reference": self.reference,
            "tags": self.tags,
            "curl_command": self.curl_command,
            "scanner": self.scanner,
            "timestamp": self.timestamp,
        }


# ============================================================================
# Delta Report (Week-over-Week Comparison)
# ============================================================================

@dataclass
class DeltaEntry:
    """
    A single delta entry representing a change between two assessment runs.

    change_type: "new" | "resolved" | "unchanged" | "changed"
    category:    "infrastructure" | "crypto" | "web" | "vulnerability"
    """
    change_type: str
    category: str
    summary: str
    severity: str = "Info"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "change_type": self.change_type,
            "category": self.category,
            "summary": self.summary,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class DeltaReport:
    """Aggregated delta between current and previous assessment."""
    previous_run_id: str = ""
    previous_scan_week: str = ""
    current_run_id: str = ""
    current_scan_week: str = ""
    entries: List[DeltaEntry] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=lambda: {
        "new": 0, "resolved": 0, "changed": 0, "unchanged": 0
    })

    def add_entry(self, entry: DeltaEntry):
        self.entries.append(entry)
        if entry.change_type in self.summary:
            self.summary[entry.change_type] += 1

    def to_dict(self) -> dict:
        return {
            "previous_run_id": self.previous_run_id,
            "previous_scan_week": self.previous_scan_week,
            "current_run_id": self.current_run_id,
            "current_scan_week": self.current_scan_week,
            "entries": [e.to_dict() for e in self.entries],
            "summary": self.summary,
        }


# ============================================================================
# Execution Errors
# ============================================================================

@dataclass
class ExecutionError:
    """A logged error from any phase."""
    phase: str
    module: str
    error: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "module": self.module,
            "error": self.error,
            "timestamp": self.timestamp,
        }


# ============================================================================
# Top-Level Assessment Report
# ============================================================================

@dataclass
class AssessmentReport:
    """
    The master report object. Serializes to a single JSON document
    with the required schema sections.
    """
    metadata: AssessmentMetadata
    findings_infrastructure: List[HostFinding] = field(default_factory=list)
    findings_crypto: List[CryptoFinding] = field(default_factory=list)
    findings_web: List[WebAssessmentResult] = field(default_factory=list)
    findings_vulns: List[VulnerabilityFinding] = field(default_factory=list)
    delta: Optional[DeltaReport] = None
    execution_errors: List[ExecutionError] = field(default_factory=list)

    # --- Convenience Methods ---

    def add_host(self, host_finding: HostFinding):
        """Add an infrastructure host finding."""
        self.findings_infrastructure.append(host_finding)

    def add_crypto(self, crypto_finding: CryptoFinding):
        """Add a crypto/TLS finding."""
        self.findings_crypto.append(crypto_finding)

    def add_web(self, web_result: WebAssessmentResult):
        """Add a web assessment result."""
        self.findings_web.append(web_result)

    def add_vuln(self, vuln: VulnerabilityFinding):
        """Add a vulnerability scanner finding."""
        self.findings_vulns.append(vuln)

    def add_error(self, phase: str, module: str, error_msg: str):
        """Log an execution error."""
        logger.error(f"[{phase}/{module}] {error_msg}")
        self.execution_errors.append(ExecutionError(
            phase=phase, module=module, error=error_msg
        ))

    def set_finished(self):
        """Mark the assessment as completed."""
        self.metadata.finished_at = datetime.now(timezone.utc).isoformat()

    def get_web_hosts(self) -> List[HostFinding]:
        """Return all hosts that have HTTP/HTTPS ports open."""
        return [h for h in self.findings_infrastructure if h.has_web_ports()]

    def get_https_hosts(self) -> List[tuple]:
        """Return list of (host_ip, port) tuples for all HTTPS services."""
        results = []
        for h in self.findings_infrastructure:
            for port in h.get_https_ports():
                results.append((h.host, port))
        return results

    # --- Serialization ---

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata.to_dict(),
            "findings_infrastructure": [h.to_dict() for h in self.findings_infrastructure],
            "findings_crypto": [c.to_dict() for c in self.findings_crypto],
            "findings_web": [w.to_dict() for w in self.findings_web],
            "findings_vulns": [v.to_dict() for v in self.findings_vulns],
            "delta": self.delta.to_dict() if self.delta else None,
            "execution_errors": [e.to_dict() for e in self.execution_errors],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the full report to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def flush_to_disk(self, filepath: str):
        """Persist the current report state to disk as JSON."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self.to_json())
            logger.debug(f"Report state flushed to {filepath}")
        except Exception as e:
            logger.error(f"Failed to flush report to {filepath}: {e}")

    @classmethod
    def from_dict(cls, data: dict) -> 'AssessmentReport':
        """Deserialize an AssessmentReport from a dict (for crash recovery / delta)."""
        meta_data = data.get("metadata", {})
        meta = AssessmentMetadata(
            target_primary=meta_data.get("target_primary", ""),
            target_hostname=meta_data.get("target_hostname", ""),
            assessment_type=meta_data.get("assessment_type", ""),
            environment=meta_data.get("environment", ""),
            started_at=meta_data.get("started_at"),
            finished_at=meta_data.get("finished_at"),
            run_id=meta_data.get("run_id", str(uuid.uuid4())),
            executor=meta_data.get("executor", "root"),
            vm_count=meta_data.get("vm_count", 0),
            scan_profile=meta_data.get("scan_profile", "standard"),
            framework_version=meta_data.get("framework_version", "2.0.0"),
            scan_week=meta_data.get("scan_week", ""),
        )

        report = cls(metadata=meta)

        # Infrastructure findings
        for h in data.get("findings_infrastructure", []):
            ports = [PortEntry(**p) for p in h.get("ports", [])]
            report.findings_infrastructure.append(HostFinding(
                host=h["host"],
                hostname=h.get("hostname", ""),
                ports=ports,
                os_fingerprint=h.get("os_fingerprint", ""),
                role=h.get("role", ""),
            ))

        # Crypto findings
        for c in data.get("findings_crypto", []):
            cert_data = c.get("certificate")
            cert = CertificateInfo(**cert_data) if cert_data else None
            ssllabs_data = c.get("ssllabs_result")
            ssllabs = SSLLabsResult(**ssllabs_data) if ssllabs_data else None
            report.findings_crypto.append(CryptoFinding(
                host=c["host"],
                port=c.get("port", 443),
                certificate=cert,
                tls_versions=c.get("tls_versions", {}),
                vulnerabilities=c.get("vulnerabilities", []),
                cipher_suites=c.get("cipher_suites", []),
                grade=c.get("grade", "N/A"),
                severity=c.get("severity", "Info"),
                scan_method=c.get("scan_method", "python_ssl"),
                ssllabs_result=ssllabs,
            ))

        # Web findings
        for w in data.get("findings_web", []):
            vulns = [WebVulnerability(**v) for v in w.get("findings", [])]
            report.findings_web.append(WebAssessmentResult(
                host=w["host"],
                port=w.get("port", 443),
                url=w.get("url", ""),
                findings=vulns,
            ))

        # Vulnerability findings
        for v in data.get("findings_vulns", []):
            report.findings_vulns.append(VulnerabilityFinding(
                host=v["host"],
                port=v.get("port", 0),
                url=v.get("url", ""),
                template_id=v.get("template_id", ""),
                name=v.get("name", ""),
                severity=v.get("severity", "info"),
                description=v.get("description", ""),
                matcher_name=v.get("matcher_name", ""),
                evidence=v.get("evidence", ""),
                reference=v.get("reference", []),
                tags=v.get("tags", []),
                curl_command=v.get("curl_command", ""),
                scanner=v.get("scanner", "nuclei"),
                timestamp=v.get("timestamp", ""),
            ))

        # Execution errors
        for e in data.get("execution_errors", []):
            report.execution_errors.append(ExecutionError(**e))

        return report

    # --- Summary ---

    def summary(self) -> Dict[str, Any]:
        """Generate a statistical summary of the report."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for c in self.findings_crypto:
            sev = c.severity
            if sev in severity_counts:
                severity_counts[sev] += 1

        for w in self.findings_web:
            for v in w.findings:
                sev = v.severity
                if sev in severity_counts:
                    severity_counts[sev] += 1

        # Nuclei vulnerability findings (lowercase → capitalized mapping)
        sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
                    "low": "Low", "info": "Info"}
        for v in self.findings_vulns:
            mapped = sev_map.get(v.severity.lower(), "Info")
            if mapped in severity_counts:
                severity_counts[mapped] += 1

        # Delta summary
        delta_summary = {}
        if self.delta:
            delta_summary = self.delta.summary

        return {
            "total_hosts": len(self.findings_infrastructure),
            "total_open_ports": sum(len(h.ports) for h in self.findings_infrastructure),
            "total_crypto_findings": len(self.findings_crypto),
            "total_web_findings": sum(len(w.findings) for w in self.findings_web),
            "total_vuln_findings": len(self.findings_vulns),
            "total_errors": len(self.execution_errors),
            "severity_distribution": severity_counts,
            "delta": delta_summary,
        }
