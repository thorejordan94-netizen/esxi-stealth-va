"""
Data models for the ESXi Vulnerability Assessment Framework.

Produces a single normalized JSON document with these top-level sections:
  - metadata
  - findings_infrastructure
  - findings_crypto
  - findings_web
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
    assessment_type: str = "Assume-Breach Internal VA"
    environment: str = "Internal / CyberArk-monitored"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    executor: str = "root"
    vm_count: int = 0
    change_request: str = ""
    notes: str = ""

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

    def add_error(self, phase: str, module: str, error_msg: str):
        """Log an execution error."""
        logger.error(f"[{phase}/{module}] {error_msg}")
        self.execution_errors.append(ExecutionError(
            phase=phase, module=module, error=error_msg
        ))

    def set_finished(self):
        """Mark the assessment as completed."""
        self.metadata.finished_at = datetime.now(timezone.utc).isoformat()

    # --- Serialization ---

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata.to_dict(),
            "findings_infrastructure": [h.to_dict() for h in self.findings_infrastructure],
            "findings_crypto": [c.to_dict() for c in self.findings_crypto],
            "findings_web": [w.to_dict() for w in self.findings_web],
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
        """Deserialize an AssessmentReport from a dict (for crash recovery)."""
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
        )

        report = cls(metadata=meta)

        for h in data.get("findings_infrastructure", []):
            ports = [PortEntry(**p) for p in h.get("ports", [])]
            report.findings_infrastructure.append(HostFinding(
                host=h["host"],
                hostname=h.get("hostname", ""),
                ports=ports,
                os_fingerprint=h.get("os_fingerprint", ""),
                role=h.get("role", ""),
            ))

        for c in data.get("findings_crypto", []):
            cert_data = c.get("certificate")
            cert = CertificateInfo(**cert_data) if cert_data else None
            report.findings_crypto.append(CryptoFinding(
                host=c["host"],
                port=c.get("port", 443),
                certificate=cert,
                tls_versions=c.get("tls_versions", {}),
                vulnerabilities=c.get("vulnerabilities", []),
                cipher_suites=c.get("cipher_suites", []),
                grade=c.get("grade", "N/A"),
                severity=c.get("severity", "Info"),
            ))

        for w in data.get("findings_web", []):
            vulns = [WebVulnerability(**v) for v in w.get("findings", [])]
            report.findings_web.append(WebAssessmentResult(
                host=w["host"],
                port=w.get("port", 443),
                url=w.get("url", ""),
                findings=vulns,
            ))

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

        return {
            "total_hosts": len(self.findings_infrastructure),
            "total_open_ports": sum(len(h.ports) for h in self.findings_infrastructure),
            "total_crypto_findings": len(self.findings_crypto),
            "total_web_findings": sum(len(w.findings) for w in self.findings_web),
            "total_errors": len(self.execution_errors),
            "severity_distribution": severity_counts,
        }
