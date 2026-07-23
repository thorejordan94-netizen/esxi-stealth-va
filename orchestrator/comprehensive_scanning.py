"""Comprehensive scan phases with complete port coverage and bounded parallelism.

The quality-preserving speed optimization is a two-stage TCP workflow:
Phase 2 discovers every open TCP port without expensive version probes; Phase 3
runs version detection and safe NSE checks only against ports confirmed open.
Independent hosts are processed concurrently, while every result remains tied to
its source asset and port.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from orchestrator.expanded_internal_assessment import ExpandedDiscovery, ExpandedServiceEnum
from orchestrator.models import AssessmentReport, HostFinding, PortEntry, WebAssessmentResult
from orchestrator.phase5_web import Phase5Web
from orchestrator.phase6_vulnscan import Phase6VulnScan
from orchestrator.runtime import get_output_dir


logger = logging.getLogger(__name__)


def _chunks(values: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    size = max(1, int(size))
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _is_web_service(port: PortEntry) -> bool:
    service = str(port.service or "").lower()
    version = str(port.version or "").lower()
    combined = "{} {}".format(service, version)
    return (
        "http" in combined
        or service in {"https", "ssl/http", "http-proxy", "http-alt", "https-alt"}
        or port.port in {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9080, 9090, 9443, 10443}
    )


def _is_tls_web_service(port: PortEntry) -> bool:
    service = str(port.service or "").lower()
    version = str(port.version or "").lower()
    return (
        "https" in service
        or service.startswith("ssl/")
        or " ssl" in " {}".format(version)
        or "tls" in version
        or port.port in {443, 8443, 9443, 10443}
    )


class ComprehensiveDiscovery(ExpandedDiscovery):
    """Discover every host in configured private scopes and every TCP/UDP port."""

    def _validate_private_subnet(self, subnet: str, config: Dict[str, Any]):
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            logger.error("Invalid subnet in discovery scope: %s", subnet)
            return None
        if network.version != 4:
            logger.warning("Skipping non-IPv4 subnet: %s", network)
            return None
        allow_public = bool(config.get("assessment", {}).get("expanded_discovery", {}).get("allow_public_subnets", False))
        if not allow_public and not network.is_private:
            logger.error("Refusing public subnet in automatic scope: %s", network)
            return None
        return network

    def _udp_scan(self, host: str, config: Dict[str, Any], output_dir: Path):
        expanded = config.get("assessment", {}).get("expanded_discovery", {})
        udp_cfg = expanded.get("udp", {})
        if not udp_cfg.get("enabled", True):
            return []

        port_expression = str(udp_cfg.get("ports", "1-65535") or "1-65535").strip().lower()
        net_cfg = config.get("stealth", {}).get("network", {})
        output_xml = output_dir / "udp_{}.xml".format(host.replace(".", "_"))
        args = [
            "-sU", "-Pn", "-n", "-sV",
            "--version-intensity", str(udp_cfg.get("version_intensity", 2)),
            "--open", "--max-retries", str(udp_cfg.get("max_retries", 1)),
            "--max-rate", str(udp_cfg.get("max_rate_pps", net_cfg.get("max_rate_pps", 1000))),
            "-T{}".format(udp_cfg.get("timing_template", net_cfg.get("timing_template", 4))),
        ]
        scan_delay = int(udp_cfg.get("scan_delay_ms", 0))
        if scan_delay > 0:
            args.extend(["--scan-delay", "{}ms".format(scan_delay)])
        if port_expression in {"all", "full", "-", "1-65535"}:
            args.extend(["-p", "1-65535"])
        elif port_expression.startswith("top-"):
            args.extend(["--top-ports", port_expression.split("-", 1)[1]])
        else:
            args.extend(["-p", port_expression])
        args.append(host)

        timeout = int(udp_cfg.get("timeout", 7200))
        if not self._run_nmap(args, output_xml, config, timeout=timeout):
            return []
        parsed = self._parse_nmap_xml(output_xml)
        return parsed[0].ports if parsed else []

    def _scan_host(self, address: str, config: Dict[str, Any], common_flags: List[str],
                   port_args: List[str], interface: str, configured_interface: str,
                   output_dir: Path, host_timeout: int):
        scanner = ComprehensiveDiscovery(self.stealth_config)
        host_flags = list(common_flags)
        resolved_interface = scanner._resolve_interface(interface or configured_interface, address)
        if resolved_interface:
            host_flags.extend(["-e", resolved_interface])
        xml_path = output_dir / "host_{}.xml".format(address.replace(".", "_"))
        if not scanner._run_nmap(host_flags + port_args + [address], xml_path, config, timeout=host_timeout):
            return address, [], scanner._last_nmap_error

        findings = scanner._parse_nmap_xml(xml_path)
        for finding in findings:
            finding.role = "esxi_host" if scanner._looks_like_esxi(finding) else "vm"
            udp_ports = scanner._udp_scan(address, config, output_dir)
            if udp_ports:
                scanner._merge_ports(finding, udp_ports)
        return address, findings, ""

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        runtime_config = copy.deepcopy(config)
        assessment = runtime_config.setdefault("assessment", {})
        stealth = runtime_config.get("stealth", {})
        network_cfg = stealth.get("network", {})
        scan_cfg = assessment.setdefault("scan", {})
        discovery_cfg = assessment.get("vm_discovery", {})
        expanded = assessment.get("expanded_discovery", {})
        output_dir = get_output_dir(runtime_config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)

        scan_cfg["ports"] = str(expanded.get("tcp_ports") or scan_cfg.get("ports") or "1-65535")
        scan_cfg["esxi_ports"] = str(expanded.get("esxi_ports") or scan_cfg.get("esxi_ports") or "")

        target = assessment.get("target", {})
        target_ip = target.get("ip", "")
        target_hostname = target.get("hostname", "")
        configured_interface = assessment.get("stealth", {}).get("network", {}).get(
            "interface", network_cfg.get("interface", "")
        )

        # Stage 1 intentionally omits -sV. Version detection is performed only
        # on confirmed-open ports in ComprehensiveServiceEnum.
        common_flags = [
            "-sT", "-Pn", "-n",
            "--max-rate", str(scan_cfg.get("discovery_max_rate_pps", network_cfg.get("max_rate_pps", 1000))),
            "--max-retries", str(scan_cfg.get("max_retries", 2)),
            "--host-timeout", str(scan_cfg.get("nmap_host_timeout", "30m")),
            "-T{}".format(scan_cfg.get("timing_template", network_cfg.get("timing_template", 4))),
            "--open",
        ]
        scan_delay = int(scan_cfg.get("scan_delay_ms", network_cfg.get("scan_delay_ms", 0)))
        if scan_delay > 0:
            common_flags.extend(["--scan-delay", "{}ms".format(scan_delay)])

        scanned = set()
        if target_ip:
            target_flags = list(common_flags)
            target_interface = self._resolve_interface(configured_interface, target_ip)
            if target_interface:
                target_flags.extend(["-e", target_interface])
            logger.info("Comprehensive TCP discovery of primary target %s", target_ip)
            primary = self._scan_primary(
                target_ip, target_hostname, target_flags,
                scan_cfg["ports"], scan_cfg["esxi_ports"],
                output_dir, runtime_config, int(scan_cfg.get("esxi_timeout_s", 7200)),
            )
            for finding in primary:
                udp_ports = self._udp_scan(finding.host, runtime_config, output_dir)
                if udp_ports:
                    self._merge_ports(finding, udp_ports)
                report.add_host(finding)
                scanned.add(finding.host)

        discovered = []
        if discovery_cfg.get("method", "sweep") == "sweep":
            interfaces = discovery_cfg.get("subnet_interfaces", {})
            for subnet in discovery_cfg.get("subnets", []):
                addresses = self._sweep_subnet(
                    subnet,
                    discovery_cfg.get("exclude_ips", []),
                    stealth,
                    get_output_dir(runtime_config) / "sweep",
                    runtime_config,
                    explicit_interface=interfaces.get(subnet, configured_interface),
                    vm_discovery_cfg=discovery_cfg,
                )
                if addresses is None:
                    report.add_error("phase2_discovery", "nmap_sweep", "Subnet sweep failed for {}".format(subnet))
                else:
                    discovered.extend(addresses)
        else:
            discovered.extend(discovery_cfg.get("static_ips", []))

        try:
            discovered = sorted(set(discovered), key=ipaddress.ip_address)
        except ValueError:
            discovered = sorted(set(discovered))
        report.metadata.vm_count = len([address for address in discovered if address != target_ip])

        port_args = self._build_port_args(scan_cfg["ports"])
        host_timeout = int(scan_cfg.get("host_timeout_s", 7200))
        parallel_hosts = max(1, int(scan_cfg.get("parallel_hosts", network_cfg.get("parallel_hosts", 4))))
        interfaces = discovery_cfg.get("subnet_interfaces", {})
        pending = []
        for address in discovered:
            if address in scanned:
                continue
            interface = ""
            for subnet, subnet_interface in interfaces.items():
                try:
                    if ipaddress.ip_address(address) in ipaddress.ip_network(subnet, strict=False):
                        interface = subnet_interface
                        break
                except ValueError:
                    continue
            pending.append((address, interface))

        logger.info(
            "Comprehensive scanning of %s discovered hosts with %s parallel worker(s).",
            len(pending), parallel_hosts,
        )
        with ThreadPoolExecutor(max_workers=parallel_hosts) as executor:
            futures = {
                executor.submit(
                    self._scan_host, address, runtime_config, common_flags, port_args,
                    interface, configured_interface, output_dir, host_timeout,
                ): address
                for address, interface in pending
            }
            for future in as_completed(futures):
                address = futures[future]
                try:
                    _, findings, error = future.result()
                except Exception as exc:
                    report.add_error("phase2_discovery", "parallel_scan", "Host scan failed for {}: {}".format(address, exc))
                    continue
                if error:
                    report.add_error("phase2_discovery", "nmap", "Host scan failed for {}: {}".format(address, error))
                    continue
                for finding in findings:
                    if finding.role == "esxi_host" and not report.metadata.target_primary:
                        report.metadata.target_primary = finding.host
                        report.metadata.target_hostname = finding.hostname
                    report.add_host(finding)

        total_ports = sum(len(host.ports) for host in report.findings_infrastructure)
        logger.info("Comprehensive discovery complete: %s hosts, %s open services.", len(report.findings_infrastructure), total_ports)


class ComprehensiveServiceEnum(ExpandedServiceEnum):
    """Enumerate every confirmed-open service without truncating per-host ports."""

    def _enumerate_host(self, host: HostFinding, config: Dict[str, Any], output_dir: Path,
                        version_intensity: int, chunk_size: int):
        scanner = ComprehensiveServiceEnum(self.stealth_config)
        findings = []
        selected = sorted(host.ports, key=lambda item: (item.protocol, item.port))
        for protocol in ("tcp", "udp"):
            protocol_ports = [item for item in selected if item.protocol == protocol]
            for port_chunk in _chunks(protocol_ports, chunk_size):
                if protocol == "tcp":
                    enriched = scanner._deep_service_scan(
                        host.host, [item.port for item in port_chunk],
                        config.get("stealth", {}), version_intensity, output_dir, config,
                    )
                    scanner._enrich_host(host, enriched)
                results = scanner._run_safe_nse(host.host, list(port_chunk), protocol, config, output_dir)
                findings.extend(scanner._derive_findings(host.host, results))
        return findings

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        security_cfg = config.get("assessment", {}).get("security_tests", {})
        if not security_cfg.get("enabled", True):
            return

        scan_cfg = config.get("assessment", {}).get("scan", {})
        version_intensity = int(scan_cfg.get("version_intensity", 5))
        output_dir = get_output_dir(config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)
        parallel_hosts = max(1, int(security_cfg.get("parallel_hosts", scan_cfg.get("parallel_hosts", 4))))
        chunk_size = max(1, int(security_cfg.get("ports_per_batch", 256)))
        seen = {(item.host, item.port, item.template_id) for item in report.findings_vulns}

        hosts = [host for host in report.findings_infrastructure if host.ports]
        logger.info(
            "Enumerating every open service on %s hosts with %s parallel worker(s).",
            len(hosts), parallel_hosts,
        )
        with ThreadPoolExecutor(max_workers=parallel_hosts) as executor:
            futures = {
                executor.submit(self._enumerate_host, host, config, output_dir, version_intensity, chunk_size): host.host
                for host in hosts
            }
            for future in as_completed(futures):
                host = futures[future]
                try:
                    derived = future.result()
                except Exception as exc:
                    report.add_error("phase3_enum", "parallel_enum", "Enumeration failed for {}: {}".format(host, exc))
                    continue
                for finding in derived:
                    key = (finding.host, finding.port, finding.template_id)
                    if key not in seen:
                        seen.add(key)
                        report.add_vuln(finding)
        logger.info("Comprehensive service enumeration completed for %s hosts.", len(hosts))


class ComprehensiveWeb(Phase5Web):
    """Assess every service identified as HTTP or HTTPS, regardless of port number."""

    def _base_url_for_entry(self, host: str, port: PortEntry) -> str:
        scheme = "https" if _is_tls_web_service(port) else "http"
        if (scheme, port.port) in {("http", 80), ("https", 443)}:
            return "{}://{}".format(scheme, host)
        return "{}://{}:{}".format(scheme, host, port.port)

    def _assess_target(self, host: HostFinding, port: PortEntry, config: Dict[str, Any], output_dir: Path):
        web_cfg = config.get("assessment", {}).get("web", {})
        stealth_cfg = config.get("stealth", {})
        ua = stealth_cfg.get("http", {}).get("user_agent", "Mozilla/5.0")
        verify_ssl = web_cfg.get("verify_ssl", False)
        base_url = self._base_url_for_entry(host.host, port)
        findings = []
        findings.extend(self._check_security_headers(base_url, ua, verify_ssl))
        findings.extend(self._check_cookie_security(base_url, ua, verify_ssl))
        if host.role == "esxi_host":
            findings.extend(self._check_esxi_paths(base_url, host.host, ua, verify_ssl))
        if web_cfg.get("use_nikto", True):
            findings.extend(self._run_nikto(host.host, port.port, output_dir))
        return WebAssessmentResult(host=host.host, port=port.port, url=base_url, findings=findings)

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        output_dir = get_output_dir(config) / "web"
        output_dir.mkdir(parents=True, exist_ok=True)
        targets = [
            (host, port)
            for host in report.findings_infrastructure
            for port in host.ports
            if port.protocol == "tcp" and _is_web_service(port)
        ]
        if not targets:
            logger.info("No HTTP/HTTPS services identified for web assessment.")
            return
        parallel_targets = max(1, int(config.get("assessment", {}).get("web", {}).get("parallel_targets", 4)))
        with ThreadPoolExecutor(max_workers=parallel_targets) as executor:
            futures = {
                executor.submit(self._assess_target, host, port, config, output_dir): (host.host, port.port)
                for host, port in targets
            }
            for future in as_completed(futures):
                host, port = futures[future]
                try:
                    report.add_web(future.result())
                except Exception as exc:
                    report.add_error("phase5_web", "web_target", "Assessment failed for {}:{}: {}".format(host, port, exc))
        logger.info("Comprehensive web assessment completed for %s endpoints.", len(targets))


class ComprehensiveVulnScan(Phase6VulnScan):
    """Feed Nuclei every discovered endpoint, including non-standard web ports."""

    def _prepare_targets(self, report: AssessmentReport, config: Dict[str, Any]) -> Optional[Path]:
        targets = set()
        for host in report.findings_infrastructure:
            if host.host:
                targets.add(host.host)
            for port in host.ports:
                if port.protocol != "tcp":
                    targets.add("{}:{}".format(host.host, port.port))
                elif _is_web_service(port):
                    scheme = "https" if _is_tls_web_service(port) else "http"
                    targets.add("{}://{}:{}".format(scheme, host.host, port.port))
                else:
                    targets.add("{}:{}".format(host.host, port.port))
        if not targets:
            return None
        target_file = get_output_dir(config) / "nuclei_targets.txt"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("\n".join(sorted(targets)) + "\n", encoding="utf-8")
        return target_file
