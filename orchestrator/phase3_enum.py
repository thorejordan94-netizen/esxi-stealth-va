"""
Phase 3: Focused Service Enumeration

Responsibilities:
- Perform deeper service version detection on interesting ports
- Enrich HostFinding entries with more detailed version strings
- Run nmap NSE scripts for service identification (safe scripts only)
- Focus on HTTP/HTTPS ports for downstream phases

This phase sits between Discovery (Phase 2) and Crypto (Phase 4) to ensure
that the crypto and web phases have the best possible service information.

Stealth measures:
- Only probes ports already identified as open in Phase 2
- Uses --version-intensity from scan profile
- No new host discovery — works with existing findings only
"""

import subprocess
import shutil
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, HostFinding, PortEntry
from orchestrator.runtime import run_command

logger = logging.getLogger(__name__)


class Phase3Enum(PhasePlugin):

    @property
    def name(self) -> str:
        return "Service Enumeration"

    @property
    def phase_number(self) -> int:
        return 3

    def _get_nmap_cmd(self) -> str:
        """Determine how to invoke nmap (native or WSL)."""
        if shutil.which("nmap"):
            return "nmap"
        if shutil.which("wsl"):
            return "wsl nmap"
        return "nmap"

    def _deep_service_scan(self, host: str, ports: List[int],
                           stealth_cfg: Dict[str, Any],
                           version_intensity: int,
                           output_dir: Path) -> List[PortEntry]:
        """
        Perform focused version detection on specific ports.
        Returns enriched PortEntry objects.
        """
        if not ports:
            return []

        nmap_base = self._get_nmap_cmd()
        net_cfg = stealth_cfg.get("network", {})

        port_str = ",".join(str(p) for p in ports)
        xml_out = output_dir / f"enum_{host.replace('.', '_')}.xml"

        cmd_parts = nmap_base.split() + [
            "-sT",
            "-sV",
            f"--version-intensity", str(version_intensity),
            f"--max-rate", str(net_cfg.get("max_rate_pps", 100)),
            f"--scan-delay", f"{net_cfg.get('scan_delay_ms', 50)}ms",
            f"-T{net_cfg.get('timing_template', 2)}",
            "--open",
            # Safe NSE scripts for service identification
            "--script", "banner,http-title,ssl-cert",
            "-p", port_str,
            "-oX", str(xml_out),
            host,
        ]

        logger.info(f"Deep enum: {host} ports [{port_str}]")
        try:
            result = run_command(
                cmd_parts, capture_output=True, text=True,
                check=False, timeout=300
            )
            if result.returncode != 0 and not xml_out.exists():
                logger.warning(f"Enum scan failed for {host}: {result.stderr[:200]}")
                return []
        except FileNotFoundError:
            logger.error("nmap not found")
            return []
        except subprocess.TimeoutExpired:
            logger.error(f"Enum scan timed out for {host}")
            return []

        # Parse results
        return self._parse_enum_xml(xml_out)

    def _parse_enum_xml(self, xml_path: Path) -> List[PortEntry]:
        """Parse nmap XML output into enriched PortEntry objects."""
        entries = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host_elem in root.findall("host"):
                for port_elem in host_elem.findall("ports/port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    service_elem = port_elem.find("service")
                    service_name = ""
                    service_version = ""
                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        extra = service_elem.get("extrainfo", "")
                        service_version = f"{product} {version} {extra}".strip()

                    entries.append(PortEntry(
                        port=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", "tcp"),
                        state="open",
                        service=service_name,
                        version=service_version,
                    ))
        except Exception as e:
            logger.error(f"Failed to parse enum XML {xml_path}: {e}")

        return entries

    def _enrich_host(self, host_finding: HostFinding, enriched_ports: List[PortEntry]):
        """
        Merge enriched port data back into the existing HostFinding.
        Only updates fields that are more detailed than existing data.
        """
        enriched_map = {p.port: p for p in enriched_ports}

        for port in host_finding.ports:
            if port.port in enriched_map:
                enriched = enriched_map[port.port]
                # Only overwrite if we got better data
                if enriched.service and (not port.service or port.service == "tcp"):
                    port.service = enriched.service
                if enriched.version and len(enriched.version) > len(port.version):
                    port.version = enriched.version

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})

        # Get version intensity from scan profile or default
        scan_profile = config.get("scan_profile", {})
        active_name = scan_profile.get("active_profile", "standard")
        profile = scan_profile.get("profiles", {}).get(active_name, {})
        version_intensity = profile.get("version_intensity",
                                          assessment_cfg.get("scan", {}).get("version_intensity", 2))

        output_dir = Path("output/nmap")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Enumerate hosts that have web-relevant ports for downstream phases
        web_ports = {80, 443, 8080, 8443, 9080, 9443, 902, 5989}
        hosts_to_enum = []

        for host in report.findings_infrastructure:
            interesting_ports = [p.port for p in host.ports if p.port in web_ports]
            if interesting_ports:
                hosts_to_enum.append((host, interesting_ports))

        if not hosts_to_enum:
            logger.info("No hosts with web-relevant ports found — skipping deep enumeration")
            return

        logger.info(f"Deep enumeration of {len(hosts_to_enum)} hosts with web ports...")

        for host_finding, ports in hosts_to_enum:
            self.log_for_cyberark(f"Deep enum: {host_finding.host}")

            enriched = self._deep_service_scan(
                host_finding.host, ports,
                stealth_cfg, version_intensity, output_dir
            )

            if enriched:
                self._enrich_host(host_finding, enriched)
                logger.info(f"  {host_finding.host}: enriched {len(enriched)} ports")

            self.stealth_delay("network")

        logger.info(f"Phase 3 complete. {len(hosts_to_enum)} hosts enriched.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Mock enumeration — enrich mock data with realistic version strings."""
        service_map = {
            80: ("http", "Apache httpd 2.4.57"),
            443: ("https", "VMware ESXi 7.0.3 Host Client"),
            8080: ("http-proxy", "Apache Tomcat/9.0.65"),
            8443: ("https-alt", "Jetty 9.4.44"),
            902: ("ssl/vmware-auth", "VMware Authentication Daemon 1.10"),
            5989: ("ssl/wbem-https", "OpenPegasus WBEM CIM Server"),
            22: ("ssh", "OpenSSH 8.9p1 Ubuntu 3"),
            3306: ("mysql", "MySQL 8.0.32"),
            5432: ("postgresql", "PostgreSQL 14.7"),
            25: ("smtp", "Postfix smtpd"),
            9090: ("http", "Cockpit web service"),
        }

        enriched_count = 0
        for host in report.findings_infrastructure:
            for port in host.ports:
                if port.port in service_map:
                    svc, ver = service_map[port.port]
                    if not port.version or port.version == "tcp":
                        port.service = svc
                        port.version = ver
                        enriched_count += 1

        logger.info(f"[MOCK] Phase 3 complete. {enriched_count} port entries enriched.")
