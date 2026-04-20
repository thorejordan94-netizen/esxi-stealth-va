"""
Phase 2: Stealth Discovery

Responsibilities:
- Subnet sweep to discover live VMs (gentle ARP/ping)
- Port scan ESXi host with stealth-tuned nmap
- Port scan discovered VMs with rate limiting
- Parse nmap XML output into findings_infrastructure[]
- All scans use full TCP connect (-sT) to avoid IDS SYN-flood signatures

Stealth measures:
- nmap -sT (no raw packets)
- --max-rate from stealth profile (default: 100 pps)
- --scan-delay from stealth profile (default: 50ms)
- -T2 (polite timing template)
- Sequential scanning with inter-host delay
"""

import subprocess
import shutil
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, HostFinding, PortEntry

logger = logging.getLogger(__name__)


class Phase2Discovery(PhasePlugin):

    @property
    def name(self) -> str:
        return "Discovery"

    @property
    def phase_number(self) -> int:
        return 2

    def _get_nmap_cmd(self) -> str:
        """Determine how to invoke nmap (native or WSL)."""
        if shutil.which("nmap"):
            return "nmap"
        # Try WSL
        if shutil.which("wsl"):
            return "wsl nmap"
        return "nmap"  # Will fail gracefully

    def _run_nmap(self, args: List[str], output_xml: Path, timeout: int = 600) -> bool:
        """Execute an nmap command and capture XML output."""
        nmap_base = self._get_nmap_cmd()
        cmd_parts = nmap_base.split() + args + ["-oX", str(output_xml)]

        logger.info(f"Running: {' '.join(cmd_parts)}")
        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True, text=True, check=False,
                timeout=timeout
            )
            if result.returncode != 0 and not output_xml.exists():
                logger.error(f"nmap failed: {result.stderr}")
                return False
            return True
        except FileNotFoundError:
            logger.error("nmap executable not found.")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"nmap timed out after {timeout}s")
            return False

    def _parse_nmap_xml(self, xml_path: Path) -> List[HostFinding]:
        """Parse nmap XML output into HostFinding objects."""
        findings = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host_elem in root.findall("host"):
                # Get IP address
                addr_elem = host_elem.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    continue
                ip = addr_elem.get("addr", "")

                # Get hostname if available
                hostname = ""
                hostnames_elem = host_elem.find("hostnames/hostname")
                if hostnames_elem is not None:
                    hostname = hostnames_elem.get("name", "")

                # Get OS fingerprint
                os_fp = ""
                osmatch = host_elem.find("os/osmatch")
                if osmatch is not None:
                    os_fp = osmatch.get("name", "")

                # Check if host is up
                status = host_elem.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # Parse ports
                ports = []
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
                        service_version = f"{product} {version}".strip()

                    ports.append(PortEntry(
                        port=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", "tcp"),
                        state="open",
                        service=service_name,
                        version=service_version,
                    ))

                findings.append(HostFinding(
                    host=ip,
                    hostname=hostname,
                    ports=ports,
                    os_fingerprint=os_fp,
                ))

        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML {xml_path}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing {xml_path}: {e}")

        return findings

    def _sweep_subnet(self, subnet: str, exclude_ips: List[str],
                      stealth: Dict[str, Any], output_dir: Path) -> List[str]:
        """
        Perform a gentle host discovery sweep on a subnet.
        Returns list of discovered live IPs.
        """
        sweep_cfg = stealth.get("sweep", {})
        xml_out = output_dir / f"sweep_{subnet.replace('/', '_')}.xml"

        # ARP scan is Layer 2 only — nearly invisible to IDS
        # Falls back to ICMP ping if ARP is not possible (different subnet)
        args = [
            "-sn",  # Ping scan — no port scanning
            "--max-rate", str(stealth.get("network", {}).get("max_rate_pps", 100)),
            "-T2",  # Polite timing
            subnet,
        ]

        # Exclude IPs
        if exclude_ips:
            args.extend(["--exclude", ",".join(exclude_ips)])

        logger.info(f"Sweeping subnet {subnet} for live hosts...")
        if not self._run_nmap(args, xml_out, timeout=300):
            return []

        # Parse discovered hosts
        live_ips = []
        try:
            tree = ET.parse(xml_out)
            for host_elem in tree.getroot().findall("host"):
                status = host_elem.find("status")
                if status is not None and status.get("state") == "up":
                    addr = host_elem.find("address[@addrtype='ipv4']")
                    if addr is not None:
                        live_ips.append(addr.get("addr"))
        except Exception as e:
            logger.error(f"Failed to parse sweep results: {e}")

        logger.info(f"Subnet sweep found {len(live_ips)} live hosts in {subnet}")
        return live_ips

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})
        net_cfg = stealth_cfg.get("network", {})
        scan_cfg = assessment_cfg.get("scan", {})

        output_dir = Path("output")
        target_ip = assessment_cfg.get("target", {}).get("ip", "")
        target_hostname = assessment_cfg.get("target", {}).get("hostname", "")

        # --- Build common nmap flags ---
        common_flags = [
            "-sT",  # Full TCP connect (no raw packets → no IDS SYN signature)
            f"--max-rate", str(net_cfg.get("max_rate_pps", 100)),
            f"--scan-delay", f"{net_cfg.get('scan_delay_ms', 50)}ms",
            f"-T{net_cfg.get('timing_template', 2)}",
            "-sV",  # Service version detection
            f"--version-intensity", str(scan_cfg.get("version_intensity", 2)),
            "--open",  # Only show open ports
        ]

        ports_spec = scan_cfg.get("ports", "top-1000")
        esxi_ports = scan_cfg.get("esxi_ports", "")

        # =====================================================================
        # STEP 1: Scan primary ESXi host
        # =====================================================================
        self.log_for_cyberark(f"Scanning primary target: {target_ip}")
        logger.info(f"Scanning ESXi host: {target_ip} ({target_hostname})")

        esxi_xml = output_dir / "nmap" / "esxi_host.xml"
        esxi_args = common_flags + [
            "-p", f"{esxi_ports},{ports_spec}" if esxi_ports else ports_spec,
            "-O",  # OS detection (gentle with -T2)
            target_ip,
        ]

        if self._run_nmap(esxi_args, esxi_xml, timeout=900):
            hosts = self._parse_nmap_xml(esxi_xml)
            for h in hosts:
                h.hostname = target_hostname
                h.role = "esxi_host"
                report.add_host(h)
                logger.info(f"  ESXi host: {h.host} — {len(h.ports)} open ports")
        else:
            report.add_error("phase2_discovery", "nmap",
                f"Failed to scan primary target {target_ip}")

        self.stealth_delay("network")

        # =====================================================================
        # STEP 2: Subnet sweep for VM discovery
        # =====================================================================
        vm_disc = assessment_cfg.get("vm_discovery", {})
        discovered_ips = []

        if vm_disc.get("method") == "sweep":
            subnets = vm_disc.get("subnets", [])
            exclude = vm_disc.get("exclude_ips", [])

            for subnet in subnets:
                ips = self._sweep_subnet(subnet, exclude, stealth_cfg,
                                          output_dir / "sweep")
                discovered_ips.extend(ips)
                self.stealth_delay("network")

        elif vm_disc.get("method") == "static":
            discovered_ips = vm_disc.get("static_ips", [])

        # Update VM count in metadata
        report.metadata.vm_count = len(discovered_ips)
        logger.info(f"Total VMs discovered: {len(discovered_ips)}")

        # =====================================================================
        # STEP 3: Scan each discovered VM (sequential, rate-limited)
        # =====================================================================
        max_parallel = net_cfg.get("parallel_hosts", 3)
        # For stealth, we scan sequentially despite the parallel option
        for i, vm_ip in enumerate(discovered_ips):
            self.log_for_cyberark(f"Scanning VM {i+1}/{len(discovered_ips)}: {vm_ip}")
            logger.info(f"Scanning VM [{i+1}/{len(discovered_ips)}]: {vm_ip}")

            vm_xml = output_dir / "nmap" / f"vm_{vm_ip.replace('.', '_')}.xml"
            vm_args = common_flags + [
                "-p", ports_spec,
                vm_ip,
            ]

            if self._run_nmap(vm_args, vm_xml, timeout=600):
                hosts = self._parse_nmap_xml(vm_xml)
                for h in hosts:
                    h.role = "vm"
                    report.add_host(h)
                    logger.info(f"  VM {vm_ip}: {len(h.ports)} open ports")
            else:
                report.add_error("phase2_discovery", "nmap",
                    f"Failed to scan VM {vm_ip}")

            # Inter-host stealth delay
            self.stealth_delay("network")

        total_ports = sum(len(h.ports) for h in report.findings_infrastructure)
        logger.info(f"Phase 2 complete. {len(report.findings_infrastructure)} hosts, "
                     f"{total_ports} open ports discovered.")

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        """Generate realistic mock discovery data."""
        # Mock ESXi host
        esxi = HostFinding(
            host="10.251.2.28",
            hostname="sl001983.de.internal.net",
            role="esxi_host",
            os_fingerprint="VMware ESXi 7.0.3",
            ports=[
                PortEntry(port=80, service="http", version="VMware ESXi redirect"),
                PortEntry(port=443, service="https", version="VMware ESXi 7.0.3 Host Client"),
                PortEntry(port=902, service="ssl/vmware-auth", version="VMware Authentication Daemon 1.10"),
                PortEntry(port=5989, service="ssl/wbem-https", version="CIM Server"),
                PortEntry(port=8000, service="http-alt", version="vMotion"),
            ],
        )
        report.add_host(esxi)

        # Mock discovered VMs
        mock_vms = [
            ("10.251.2.30", "va010", "SUSE openSUSE 15.4", [22, 80]),
            ("10.251.2.31", "va011", "CentOS 7.9", [22, 443, 8080]),
            ("10.251.2.32", "va012", "CentOS 7.9", [22]),
            ("10.251.2.33", "va013", "Debian GNU/Linux 11", [22, 80, 3306]),
            ("10.251.2.34", "va014", "SUSE openSUSE 15.4", [22, 443]),
            ("10.251.2.35", "va015", "CentOS 6.10", [22, 80, 8443]),
            ("10.251.2.36", "va016", "Debian GNU/Linux 11", [22, 25, 80]),
            ("10.251.2.37", "va017", "CentOS 7.9", [22, 5432]),
            ("10.251.2.38", "va018", "SUSE openSUSE 15.4", [22, 80, 443]),
            ("10.251.2.39", "va019-ansible", "CentOS 7.9", [22, 80, 8080, 9090]),
            ("10.251.2.40", "v268tmp", "Debian GNU/Linux 11", [22, 80]),
        ]

        for ip, name, os_fp, ports in mock_vms:
            vm = HostFinding(
                host=ip,
                hostname=name,
                role="vm",
                os_fingerprint=os_fp,
                ports=[PortEntry(port=p, service="tcp") for p in ports],
            )
            report.add_host(vm)

        report.metadata.vm_count = len(mock_vms)
        logger.info(f"[MOCK] Phase 2 complete. 1 ESXi host + {len(mock_vms)} VMs mocked.")
