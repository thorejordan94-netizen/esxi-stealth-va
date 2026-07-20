"""Phase 2: scoped host discovery and rate-limited TCP service scanning."""

import ipaddress
import logging
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, HostFinding, PortEntry
from orchestrator.runtime import get_output_dir, run_command, run_command_with_progress


logger = logging.getLogger(__name__)


class Phase2Discovery(PhasePlugin):
    _TOP_PORTS_PATTERN = re.compile(r"^\s*top-(\d+)\s*$", re.IGNORECASE)
    _PORT_LIST_PATTERN = re.compile(r"^[0-9,\-\s]+$")

    def __init__(self, stealth_config: Optional[Dict[str, Any]] = None):
        super().__init__(stealth_config)
        self._last_nmap_error = ""
        self._last_nmap_command = ""

    @property
    def name(self) -> str:
        return "Discovery"

    @property
    def phase_number(self) -> int:
        return 2

    def _interface_exists(self, interface: str) -> bool:
        if not interface:
            return False
        if shutil.which("ip"):
            result = run_command(
                ["ip", "link", "show", interface],
                capture_output=True,
                text=True,
                check=False,
                strip_proxy=True,
            )
            return result.returncode == 0
        if shutil.which("ifconfig"):
            result = run_command(
                ["ifconfig", interface],
                capture_output=True,
                text=True,
                check=False,
                strip_proxy=True,
            )
            return result.returncode == 0
        return True

    def _resolve_interface(self, explicit_interface: Optional[str], destination: str) -> Optional[str]:
        if explicit_interface:
            if self._interface_exists(explicit_interface):
                logger.info("Using configured scan interface %s for %s", explicit_interface, destination)
                return explicit_interface
            logger.warning("Configured interface '%s' does not exist; using OS routing.", explicit_interface)
        return None

    def _get_tool_path(self, tool_name: str, config: Dict[str, Any]) -> str:
        assessment = config.get("assessment", {})
        configured = assessment.get("tool_paths", {}).get(tool_name, "")
        if configured:
            path = Path(configured)
            if path.is_file() and path.stat().st_mode & 0o111:
                return str(path)
            logger.warning("Configured %s path is not executable: %s", tool_name, configured)
        return shutil.which(tool_name) or ""

    def _get_nmap_cmd(self, config: Dict[str, Any]) -> List[str]:
        native = self._get_tool_path("nmap", config)
        if native:
            return [native]
        if shutil.which("wsl"):
            return ["wsl", "nmap"]
        return ["nmap"]

    def _run_nmap(self, args: List[str], output_xml: Path,
                  config: Dict[str, Any], timeout: int = 600) -> bool:
        output_xml.parent.mkdir(parents=True, exist_ok=True)
        if output_xml.exists():
            output_xml.unlink()

        command = self._get_nmap_cmd(config) + ["-oX", str(output_xml)] + list(args)
        display = " ".join(shlex.quote(part) for part in command)
        self._last_nmap_command = display
        self._last_nmap_error = ""
        logger.info("Running Nmap: %s", display)
        try:
            result = run_command_with_progress(
                command,
                timeout=timeout,
                progress_interval=int(config.get("assessment", {}).get("scan", {}).get("progress_interval_s", 15)),
                description="Nmap scan",
                logger=logger,
                strip_proxy=True,
            )
        except FileNotFoundError:
            self._last_nmap_error = "Nmap executable not found"
            logger.error("%s: %s", self._last_nmap_error, display)
            return False
        except subprocess.TimeoutExpired:
            self._last_nmap_error = "Nmap timed out after {}s".format(timeout)
            logger.error("%s: %s", self._last_nmap_error, display)
            return False
        except OSError as exc:
            self._last_nmap_error = "Nmap could not start: {}".format(exc)
            logger.error("%s", self._last_nmap_error)
            return False

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            self._last_nmap_error = "Nmap failed with rc={}: {}".format(
                result.returncode, stderr[:500] or "no stderr"
            )
            logger.error("%s", self._last_nmap_error)
            return False
        if not output_xml.exists():
            self._last_nmap_error = "Nmap returned success but produced no XML output"
            logger.error("%s", self._last_nmap_error)
            return False
        try:
            ET.parse(str(output_xml))
        except (ET.ParseError, OSError) as exc:
            self._last_nmap_error = "Nmap produced invalid XML: {}".format(exc)
            logger.error("%s", self._last_nmap_error)
            return False
        return True

    def _parse_nmap_xml(self, xml_path: Path) -> List[HostFinding]:
        findings = []  # type: List[HostFinding]
        try:
            root = ET.parse(str(xml_path)).getroot()
        except (ET.ParseError, OSError) as exc:
            logger.error("Failed to parse Nmap XML %s: %s", xml_path, exc)
            return findings

        for host_element in root.findall("host"):
            status = host_element.find("status")
            if status is not None and status.get("state") != "up":
                continue
            address_element = host_element.find("address[@addrtype='ipv4']")
            if address_element is None:
                continue
            hostname_element = host_element.find("hostnames/hostname")
            os_element = host_element.find("os/osmatch")
            ports = []  # type: List[PortEntry]
            for port_element in host_element.findall("ports/port"):
                state = port_element.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_element.find("service")
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                extra = service.get("extrainfo", "") if service is not None else ""
                ports.append(PortEntry(
                    port=int(port_element.get("portid", "0")),
                    protocol=port_element.get("protocol", "tcp"),
                    state="open",
                    service=service.get("name", "") if service is not None else "",
                    version=" ".join(value for value in (product, version, extra) if value).strip(),
                ))
            findings.append(HostFinding(
                host=address_element.get("addr", ""),
                hostname=hostname_element.get("name", "") if hostname_element is not None else "",
                ports=ports,
                os_fingerprint=os_element.get("name", "") if os_element is not None else "",
            ))
        return findings

    def _parse_sweep_results(self, xml_path: Path) -> List[str]:
        addresses = []  # type: List[str]
        for finding in self._parse_nmap_xml(xml_path):
            if finding.host:
                addresses.append(finding.host)
        try:
            return sorted(set(addresses), key=ipaddress.ip_address)
        except ValueError:
            return sorted(set(addresses))

    def _build_port_args(self, configured_value: str) -> List[str]:
        value = str(configured_value or "").strip() or "top-1000"
        top_match = self._TOP_PORTS_PATTERN.fullmatch(value)
        if top_match:
            count = max(1, min(65535, int(top_match.group(1))))
            return ["--top-ports", str(count)]
        if self._PORT_LIST_PATTERN.fullmatch(value):
            return ["-p", "".join(value.split())]
        logger.warning("Unsupported port expression '%s'; using top-1000.", configured_value)
        return ["--top-ports", "1000"]

    @staticmethod
    def _combine_explicit_ports(first: str, second: str) -> str:
        values = []
        for expression in (first, second):
            for value in str(expression or "").replace(" ", "").split(","):
                if value and value not in values:
                    values.append(value)
        return ",".join(values)

    @staticmethod
    def _merge_host_findings(findings: List[HostFinding]) -> List[HostFinding]:
        merged = {}  # type: Dict[str, HostFinding]
        for finding in findings:
            existing = merged.get(finding.host)
            if existing is None:
                merged[finding.host] = finding
                continue
            if not existing.hostname:
                existing.hostname = finding.hostname
            if not existing.os_fingerprint:
                existing.os_fingerprint = finding.os_fingerprint
            known = {(port.protocol, port.port): port for port in existing.ports}
            for port in finding.ports:
                key = (port.protocol, port.port)
                if key not in known:
                    existing.ports.append(port)
                elif len(port.version or "") > len(known[key].version or ""):
                    known[key].service = port.service
                    known[key].version = port.version
        for finding in merged.values():
            finding.ports.sort(key=lambda port: (port.protocol, port.port))
        return list(merged.values())

    @staticmethod
    def _looks_like_esxi(finding: HostFinding) -> bool:
        details = " ".join(
            [finding.os_fingerprint] +
            ["{} {}".format(port.service, port.version) for port in finding.ports]
        ).lower()
        ports = {port.port for port in finding.ports}
        return any(value in details for value in ("esxi", "vmware", "vcenter", "vsphere")) or bool(ports & {902, 5989})

    def _sweep_subnet(self, subnet: str, exclude_ips: List[str],
                      stealth: Dict[str, Any], output_dir: Path,
                      config: Dict[str, Any],
                      explicit_interface: Optional[str] = None,
                      vm_discovery_cfg: Optional[Dict[str, Any]] = None) -> Optional[List[str]]:
        vm_discovery_cfg = vm_discovery_cfg or {}
        probe_cfg = vm_discovery_cfg.get("discovery_probes", {})
        sweep_cfg = stealth.get("sweep", {})
        network_cfg = stealth.get("network", {})
        output_dir.mkdir(parents=True, exist_ok=True)
        token = subnet.replace("/", "_").replace(":", "_")
        ping_xml = output_dir / "sweep_{}.xml".format(token)
        probe_xml = output_dir / "sweep_{}_probe.xml".format(token)

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            logger.error("Invalid subnet in discovery configuration: %s", subnet)
            return None
        allow_public = bool(config.get("assessment", {}).get("auto_network", {}).get("allow_public_subnets", False))
        if not allow_public and not network.is_private:
            logger.error("Refusing automatic discovery of non-private subnet: %s", network)
            return None

        interface = self._resolve_interface(explicit_interface, str(network.network_address))
        common = [
            "-sn", "-n", "--max-retries", str(sweep_cfg.get("max_retries", 1)),
            "--max-rate", str(sweep_cfg.get("max_rate_pps", 2000)),
            "-T{}".format(sweep_cfg.get("timing_template", 4)),
        ]
        if interface:
            common.extend(["-e", interface])
        if exclude_ips:
            common.extend(["--exclude", ",".join(str(value) for value in exclude_ips)])
        timeout = int(sweep_cfg.get("timeout_s", 180))

        logger.info("Discovering live hosts in %s", subnet)
        if not self._run_nmap(common + [subnet], ping_xml, config, timeout=timeout):
            return None
        live = self._parse_sweep_results(ping_xml)

        probe_enabled = bool(probe_cfg.get("enabled", True))
        probe_mode = str(probe_cfg.get("mode", "fallback")).lower()
        if probe_enabled and probe_mode in ("fallback", "always") and (probe_mode == "always" or not live):
            probe_args = list(common)
            ps_ports = str(probe_cfg.get("ps_ports", "22,80,443,902,5989")).strip()
            pa_ports = str(probe_cfg.get("pa_ports", "80,443")).strip()
            if ps_ports:
                probe_args.append("-PS{}".format(ps_ports))
            if pa_ports:
                probe_args.append("-PA{}".format(pa_ports))
            if self._run_nmap(probe_args + [subnet], probe_xml, config, timeout=timeout):
                probe_live = self._parse_sweep_results(probe_xml)
                live = sorted(set(live + probe_live), key=ipaddress.ip_address)

        excluded = set(str(value) for value in exclude_ips)
        live = [address for address in live if address not in excluded]
        logger.info("Discovery complete for %s: %s live target(s)", subnet, len(live))
        return live

    def _scan_primary(self, target_ip: str, target_hostname: str,
                      common_flags: List[str], ports_spec: str, esxi_ports: str,
                      output_dir: Path, config: Dict[str, Any], timeout: int) -> List[HostFinding]:
        selected = self._build_port_args(ports_spec)
        findings = []  # type: List[HostFinding]
        if esxi_ports and selected[:1] == ["--top-ports"]:
            passes = [
                (common_flags + ["-p", self._combine_explicit_ports(esxi_ports, ""), target_ip], output_dir / "esxi_host_explicit.xml"),
                (common_flags + selected + [target_ip], output_dir / "esxi_host.xml"),
            ]
        elif selected[:1] == ["-p"]:
            passes = [(
                common_flags + ["-p", self._combine_explicit_ports(esxi_ports, selected[1]), target_ip],
                output_dir / "esxi_host.xml",
            )]
        else:
            passes = [(common_flags + selected + [target_ip], output_dir / "esxi_host.xml")]

        for arguments, xml_path in passes:
            if self._run_nmap(arguments, xml_path, config, timeout=timeout):
                findings.extend(self._parse_nmap_xml(xml_path))
            else:
                logger.warning("Primary-target scan pass failed: %s", self._last_nmap_error)
        for finding in self._merge_host_findings(findings):
            finding.hostname = target_hostname or finding.hostname
            finding.role = "esxi_host"
        return self._merge_host_findings(findings)

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment = config.get("assessment", {})
        stealth = config.get("stealth", {})
        network_cfg = stealth.get("network", {})
        scan_cfg = assessment.get("scan", {})
        discovery_cfg = assessment.get("vm_discovery", {})
        output_dir = get_output_dir(config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)

        target_ip = assessment.get("target", {}).get("ip", "")
        target_hostname = assessment.get("target", {}).get("hostname", "")
        configured_interface = assessment.get("stealth", {}).get("network", {}).get(
            "interface", network_cfg.get("interface", "")
        )
        common_flags = [
            "-sT", "-Pn", "-n", "-sV",
            "--version-intensity", str(scan_cfg.get("version_intensity", 2)),
            "--max-rate", str(network_cfg.get("max_rate_pps", 100)),
            "--scan-delay", "{}ms".format(network_cfg.get("scan_delay_ms", 50)),
            "--max-retries", str(scan_cfg.get("max_retries", 1)),
            "--host-timeout", str(scan_cfg.get("nmap_host_timeout", "15m")),
            "-T{}".format(network_cfg.get("timing_template", 2)), "--open",
        ]
        target_interface = self._resolve_interface(configured_interface, target_ip) if target_ip else None
        target_flags = list(common_flags)
        if target_interface:
            target_flags.extend(["-e", target_interface])

        scanned = set()  # type: set
        if target_ip:
            logger.info("Scanning primary ESXi target %s", target_ip)
            primary = self._scan_primary(
                target_ip, target_hostname, target_flags,
                scan_cfg.get("ports", "top-1000"), scan_cfg.get("esxi_ports", ""),
                output_dir, config, int(scan_cfg.get("esxi_timeout_s", 900)),
            )
            if primary:
                for finding in primary:
                    report.add_host(finding)
                    scanned.add(finding.host)
            else:
                report.add_error("phase2_discovery", "nmap", "Primary target scan failed: {}".format(self._last_nmap_error))
        else:
            logger.info("No primary ESXi target was preselected; live hosts will be classified after scanning.")

        discovered = []  # type: List[str]
        if discovery_cfg.get("method", "sweep") == "sweep":
            interfaces = discovery_cfg.get("subnet_interfaces", {})
            for subnet in discovery_cfg.get("subnets", []):
                interface = interfaces.get(subnet, configured_interface)
                addresses = self._sweep_subnet(
                    subnet, discovery_cfg.get("exclude_ips", []), stealth,
                    get_output_dir(config) / "sweep", config,
                    explicit_interface=interface,
                    vm_discovery_cfg=discovery_cfg,
                )
                if addresses is None:
                    report.add_error("phase2_discovery", "nmap_sweep", "Subnet sweep failed for {}: {}".format(subnet, self._last_nmap_error))
                    continue
                discovered.extend(addresses)
        else:
            discovered.extend(discovery_cfg.get("static_ips", []))

        discovered = sorted(set(discovered), key=ipaddress.ip_address)
        maximum = int(discovery_cfg.get("max_hosts", 0))
        if maximum > 0 and len(discovered) > maximum:
            logger.warning("Limiting service scans to %s of %s discovered hosts by configuration.", maximum, len(discovered))
            discovered = discovered[:maximum]
        report.metadata.vm_count = len(discovered)
        logger.info("Service scanning %s discovered host(s).", len(discovered))

        host_timeout = int(scan_cfg.get("host_timeout_s", 600))
        port_args = self._build_port_args(scan_cfg.get("ports", "top-1000"))
        for index, address in enumerate(discovered, 1):
            if address in scanned:
                continue
            logger.info("Scanning discovered host %s/%s: %s", index, len(discovered), address)
            interface = None
            for subnet, subnet_interface in discovery_cfg.get("subnet_interfaces", {}).items():
                try:
                    if ipaddress.ip_address(address) in ipaddress.ip_network(subnet, strict=False):
                        interface = subnet_interface
                        break
                except ValueError:
                    continue
            host_flags = list(common_flags)
            resolved_interface = self._resolve_interface(interface or configured_interface, address)
            if resolved_interface:
                host_flags.extend(["-e", resolved_interface])
            xml_path = output_dir / "host_{}.xml".format(address.replace(".", "_"))
            if not self._run_nmap(host_flags + port_args + [address], xml_path, config, timeout=host_timeout):
                report.add_error("phase2_discovery", "nmap", "Host scan failed for {}: {}".format(address, self._last_nmap_error))
                continue
            for finding in self._parse_nmap_xml(xml_path):
                finding.role = "esxi_host" if self._looks_like_esxi(finding) else "vm"
                if finding.role == "esxi_host" and not report.metadata.target_primary:
                    report.metadata.target_primary = finding.host
                    report.metadata.target_hostname = finding.hostname
                report.add_host(finding)
            self.stealth_delay("network")

        total_ports = sum(len(host.ports) for host in report.findings_infrastructure)
        logger.info("Phase 2 complete: %s hosts with %s open services.", len(report.findings_infrastructure), total_ports)

    def mock_execute(self, report: AssessmentReport, config: Dict[str, Any]):
        esxi = HostFinding(
            host="10.251.2.28", hostname="sl001983.de.internal.net", role="esxi_host",
            os_fingerprint="VMware ESXi 7.0.3",
            ports=[
                PortEntry(port=80, service="http", version="VMware ESXi redirect"),
                PortEntry(port=443, service="https", version="VMware ESXi 7.0.3 Host Client"),
                PortEntry(port=902, service="ssl/vmware-auth", version="VMware Authentication Daemon"),
            ],
        )
        report.add_host(esxi)
        for address, name, ports in [
            ("10.251.2.30", "va010", [22, 80]),
            ("10.251.2.31", "va011", [22, 443, 8080]),
            ("10.251.2.32", "va012", [22, 445]),
        ]:
            report.add_host(HostFinding(
                host=address, hostname=name, role="vm",
                ports=[PortEntry(port=port, service="tcp") for port in ports],
            ))
        report.metadata.vm_count = 3
        logger.info("[MOCK] Phase 2 complete. One ESXi host and three VMs generated.")
