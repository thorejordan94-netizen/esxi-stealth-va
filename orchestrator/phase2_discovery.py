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
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, HostFinding, PortEntry
from orchestrator.runtime import run_command

logger = logging.getLogger(__name__)


class Phase2Discovery(PhasePlugin):
    def _interface_exists(self, interface: str) -> bool:
        """Return True when the requested network interface exists."""
        if shutil.which("ip"):
            result = run_command(
                ["ip", "link", "show", interface],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0

        if shutil.which("ifconfig"):
            result = run_command(
                ["ifconfig", interface],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0

        logger.warning(
            "Cannot validate interface '%s' because neither 'ip' nor 'ifconfig' is available.",
            interface
        )
        return True

    def _detect_interface_for_destination(self, destination: str) -> Optional[str]:
        """Autodetect interface using route lookup for destination IP."""
        if not shutil.which("ip"):
            logger.warning("Route-based interface autodetection unavailable: 'ip' not found.")
            return None

        result = run_command(
            ["ip", "route", "get", destination],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(
                "Failed route lookup for %s (rc=%s): %s",
                destination,
                result.returncode,
                (result.stderr or "").strip(),
            )
            return None

        tokens = (result.stdout or "").split()
        if "dev" not in tokens:
            logger.warning("Route lookup did not include an interface for %s.", destination)
            return None

        dev_idx = tokens.index("dev")
        if dev_idx + 1 >= len(tokens):
            logger.warning("Route lookup output malformed for %s: %s", destination, result.stdout)
            return None
        return tokens[dev_idx + 1]

    def _resolve_interface(self, explicit_interface: Optional[str], destination: str) -> Optional[str]:
        """
        Determine which interface to pass to nmap.
        Preference:
        1) Explicit configured interface (validated)
        2) Route-based autodetected interface
        """
        if explicit_interface:
            if self._interface_exists(explicit_interface):
                logger.info("Using configured scan interface: %s", explicit_interface)
                return explicit_interface
            logger.error("Configured interface '%s' does not exist.", explicit_interface)
            return None

        # Let Nmap handle its own routing instead of trying to guess
        logger.info("No explicit scan interface configured for %s; nmap will use OS default routing.", destination)
        return None

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
            result = run_command(
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

    def _parse_sweep_results(self, xml_out: Path) -> List[str]:
        """Parse nmap sweep XML into a list of live IPv4 addresses."""
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
        return live_ips

    def _sweep_subnet(self, subnet: str, exclude_ips: List[str],
                      stealth: Dict[str, Any], output_dir: Path,
                      explicit_interface: Optional[str] = None,
                      vm_discovery_cfg: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Perform a gentle host discovery sweep on a subnet.
        Returns list of discovered live IPs.
        """
        sweep_cfg = stealth.get("sweep", {})
        vm_discovery_cfg = vm_discovery_cfg or {}
        probe_cfg = vm_discovery_cfg.get("discovery_probes", {})
        xml_out = output_dir / f"sweep_{subnet.replace('/', '_')}.xml"
        xml_out_probe = output_dir / f"sweep_{subnet.replace('/', '_')}_probe.xml"

        # ARP scan is Layer 2 only — nearly invisible to IDS
        # Falls back to ICMP ping if ARP is not possible (different subnet)
        base_args = [
            "-sn",  # Ping scan — no port scanning
            "--max-rate", str(stealth.get("network", {}).get("max_rate_pps", 100)),
            "-T2",  # Polite timing
            subnet,
        ]
        try:
            destination = str(ipaddress.ip_network(subnet, strict=False).network_address + 1)
        except ValueError:
            logger.warning("Invalid subnet '%s' for interface autodetection; using target subnet literal.", subnet)
            destination = subnet.split("/", 1)[0]

        sweep_interface = self._resolve_interface(explicit_interface, destination)
        if sweep_interface:
            base_args[1:1] = ["-e", sweep_interface]

        # Exclude IPs
        if exclude_ips:
            base_args.extend(["--exclude", ",".join(exclude_ips)])

        probe_enabled = bool(probe_cfg.get("enabled", False))
        probe_mode = str(probe_cfg.get("mode", "fallback")).lower()
        ps_ports = str(probe_cfg.get("ps_ports", "")).strip()
        pa_ports = str(probe_cfg.get("pa_ports", "")).strip()

        def run_sweep(args: List[str], out_file: Path, strategy: str) -> List[str]:
            logger.info(f"Sweeping subnet {subnet} for live hosts (strategy={strategy})...")
            if not self._run_nmap(args, out_file, timeout=300):
                return []
            return self._parse_sweep_results(out_file)

        # Conservative default remains pure ping discovery.
        live_ips = run_sweep(base_args, xml_out, "ping")
        strategy_used = "ping"

        should_try_probe = probe_enabled and probe_mode in {"fallback", "always"} and (probe_mode == "always" or not live_ips)
        if should_try_probe and (ps_ports or pa_ports):
            probe_args = list(base_args[:-1])  # all flags except target
            if ps_ports:
                probe_args.extend([f"-PS{ps_ports}"])
            if pa_ports:
                probe_args.extend([f"-PA{pa_ports}"])
            probe_args.append(subnet)

            probe_strategy_parts = ["probe"]
            if ps_ports:
                probe_strategy_parts.append(f"PS:{ps_ports}")
            if pa_ports:
                probe_strategy_parts.append(f"PA:{pa_ports}")
            probe_strategy = "+".join(probe_strategy_parts)
            probe_live_ips = run_sweep(probe_args, xml_out_probe, probe_strategy)

            if probe_mode == "always":
                live_ips = sorted(set(live_ips + probe_live_ips))
                strategy_used = f"ping+{probe_strategy}"
            elif probe_live_ips:
                live_ips = probe_live_ips
                strategy_used = probe_strategy

        logger.info(
            "Subnet sweep found %s live hosts in %s (strategy_used=%s, probes_enabled=%s, mode=%s)",
            len(live_ips), subnet, strategy_used, probe_enabled, probe_mode
        )
        return live_ips

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})
        net_cfg = stealth_cfg.get("network", {})
        net_override_cfg = assessment_cfg.get("stealth", {}).get("network", {})
        scan_cfg = assessment_cfg.get("scan", {})

        output_dir = Path("output")
        target_ip = assessment_cfg.get("target", {}).get("ip", "")
        target_hostname = assessment_cfg.get("target", {}).get("hostname", "")

        configured_interface = net_override_cfg.get("interface", net_cfg.get("interface", ""))
        interface = self._resolve_interface(configured_interface, target_ip) if target_ip else None

        # --- Build common nmap flags ---
        common_flags = [
            "-sT",  # Full TCP connect (no raw packets → no IDS SYN signature)
            "-Pn",  # Treat all hosts as online (bypasses firewall dropping ping)
            f"--max-rate", str(net_cfg.get("max_rate_pps", 100)),
            f"--scan-delay", f"{net_cfg.get('scan_delay_ms', 50)}ms",
            f"-T{net_cfg.get('timing_template', 2)}",
            "-sV",  # Service version detection
            f"--version-intensity", str(scan_cfg.get("version_intensity", 2)),
            "--open",  # Only show open ports
        ]
        if interface:
            common_flags[2:2] = ["-e", interface]

        ports_spec = scan_cfg.get("ports", "top-1000")
        esxi_ports = scan_cfg.get("esxi_ports", "")

        def build_port_args(p_spec: str, e_ports: str) -> List[str]:
            if not p_spec or p_spec.lower() == "none":
                p_spec = ""
            
            if p_spec.startswith("top-"):
                num = p_spec.split("-")[1]
                if e_ports:
                    return ["-p", e_ports, "--top-ports", num]
                return ["--top-ports", num]
            
            combined = f"{e_ports},{p_spec}" if e_ports and p_spec else e_ports or p_spec
            return ["-p", combined] if combined else []

        # =====================================================================
        # STEP 1: Scan primary ESXi host
        # =====================================================================
        self.log_for_cyberark(f"Scanning primary target: {target_ip}")
        logger.info(f"Scanning ESXi host: {target_ip} ({target_hostname})")

        esxi_xml = output_dir / "nmap" / "esxi_host.xml"
        esxi_args = common_flags + build_port_args(ports_spec, esxi_ports) + [target_ip]

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
                                          output_dir / "sweep",
                                          explicit_interface=configured_interface,
                                          vm_discovery_cfg=vm_disc)
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
            vm_args = common_flags + build_port_args(ports_spec, "") + [vm_ip]

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
