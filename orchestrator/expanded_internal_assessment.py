"""Expanded private-network discovery and safe internal service checks.

This module extends the existing Phase 2 and Phase 3 implementations without
changing their public interfaces. It broadens bounded private-network coverage,
adds neighbor-cache and UDP discovery, enumerates every discovered open service,
and converts deterministic safe NSE results into normalized findings.
"""

import copy
import ipaddress
import logging
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

from orchestrator.models import PortEntry, VulnerabilityFinding
from orchestrator.phase2_discovery import Phase2Discovery
from orchestrator.phase3_enum import Phase3Enum
from orchestrator.runtime import get_output_dir, run_command

logger = logging.getLogger(__name__)


class ExpandedDiscovery(Phase2Discovery):
    """Phase 2 with bounded private scope, neighbor correlation, and UDP coverage."""

    def _validate_private_subnet(self, subnet: str, config: Dict[str, Any]):
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            logger.error("Invalid subnet in discovery scope: %s", subnet)
            return None
        if network.version != 4:
            logger.warning("Skipping non-IPv4 subnet: %s", network)
            return None
        expanded = config.get("assessment", {}).get("expanded_discovery", {})
        if not expanded.get("allow_public_subnets", False) and not network.is_private:
            logger.error("Refusing public subnet in automatic scope: %s", network)
            return None
        maximum = int(expanded.get("max_addresses_per_subnet", 65536))
        if network.num_addresses > maximum:
            logger.error(
                "Refusing subnet %s with %s addresses; split it into scoped networks (max=%s).",
                network,
                network.num_addresses,
                maximum,
            )
            return None
        return network

    def _scope_chunks(self, network, config: Dict[str, Any]):
        """Split broad accepted scopes into bounded sweeps with visible progress."""
        expanded = config.get("assessment", {}).get("expanded_discovery", {})
        maximum = max(4, int(expanded.get("max_addresses_per_sweep", 4096)))
        if network.num_addresses <= maximum:
            return [network]
        prefix = network.prefixlen
        while prefix < network.max_prefixlen and (2 ** (network.max_prefixlen - prefix)) > maximum:
            prefix += 1
        return list(network.subnets(new_prefix=prefix))

    def _neighbor_cache_ips(self, subnet: str) -> List[str]:
        if not shutil.which("ip"):
            return []
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return []
        result = run_command(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            check=False,
            strip_proxy=True,
        )
        if result.returncode != 0:
            return []
        accepted = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
        addresses: Set[str] = set()
        for line in (result.stdout or "").splitlines():
            tokens = line.split()
            if not tokens or not any(state in tokens for state in accepted):
                continue
            try:
                address = ipaddress.ip_address(tokens[0])
            except ValueError:
                continue
            if address.version == 4 and address in network:
                addresses.add(str(address))
        return sorted(addresses, key=ipaddress.ip_address)

    def _sweep_subnet(self, subnet, exclude_ips, stealth, output_dir, config,
                      explicit_interface=None, vm_discovery_cfg=None):
        network = self._validate_private_subnet(subnet, config)
        if network is None:
            return []
        chunks = self._scope_chunks(network, config)
        discovered = set()
        for index, chunk in enumerate(chunks, 1):
            if len(chunks) > 1:
                logger.info("Broad-scope discovery chunk %s/%s: %s", index, len(chunks), chunk)
            chunk_result = super()._sweep_subnet(
                str(chunk),
                exclude_ips,
                stealth,
                output_dir,
                config,
                explicit_interface=explicit_interface,
                vm_discovery_cfg=vm_discovery_cfg,
            )
            if chunk_result is not None:
                discovered.update(chunk_result)
        expanded = config.get("assessment", {}).get("expanded_discovery", {})
        if expanded.get("neighbor_cache", True):
            discovered.update(self._neighbor_cache_ips(subnet))
        discovered.difference_update(str(value) for value in exclude_ips)
        return sorted(discovered, key=ipaddress.ip_address)

    @staticmethod
    def _merge_ports(host, ports: Iterable[PortEntry]):
        current = {(entry.protocol, entry.port): entry for entry in host.ports}
        for entry in ports:
            key = (entry.protocol, entry.port)
            existing = current.get(key)
            if existing is None:
                current[key] = entry
            else:
                if entry.service and not existing.service:
                    existing.service = entry.service
                if len(entry.version or "") > len(existing.version or ""):
                    existing.version = entry.version
        host.ports = sorted(current.values(), key=lambda item: (item.protocol, item.port))

    def _udp_scan(self, host: str, config: Dict[str, Any], output_dir: Path):
        expanded = config.get("assessment", {}).get("expanded_discovery", {})
        udp_cfg = expanded.get("udp", {})
        if not udp_cfg.get("enabled", True):
            return []
        top_ports = int(udp_cfg.get("top_ports", 20))
        if top_ports <= 0:
            return []
        net_cfg = config.get("stealth", {}).get("network", {})
        output_xml = output_dir / "udp_{}.xml".format(host.replace(".", "_"))
        args = [
            "-sU", "-Pn", "-sV", "--version-intensity", str(udp_cfg.get("version_intensity", 1)),
            "--top-ports", str(top_ports), "--open", "--max-retries", str(udp_cfg.get("max_retries", 1)),
            "--max-rate", str(net_cfg.get("max_rate_pps", 100)),
            "--scan-delay", "{}ms".format(net_cfg.get("scan_delay_ms", 50)),
            "-T{}".format(net_cfg.get("timing_template", 2)), host,
        ]
        if not self._run_nmap(args, output_xml, config, timeout=int(udp_cfg.get("timeout", 900))):
            return []
        parsed = self._parse_nmap_xml(output_xml)
        return parsed[0].ports if parsed else []

    def execute(self, report, config: Dict[str, Any]):
        expanded = config.get("assessment", {}).get("expanded_discovery", {})
        runtime_config = copy.deepcopy(config)
        scan_cfg = runtime_config.setdefault("assessment", {}).setdefault("scan", {})
        if expanded.get("tcp_ports"):
            scan_cfg["ports"] = expanded["tcp_ports"]
        scan_cfg["esxi_ports"] = expanded.get(
            "esxi_ports",
            "22,80,443,427,902,5988,5989,8000,8080,9080,9443",
        )
        super().execute(report, runtime_config)

        output_dir = get_output_dir(runtime_config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)
        for host in report.findings_infrastructure:
            udp_ports = self._udp_scan(host.host, runtime_config, output_dir)
            if udp_ports:
                self._merge_ports(host, udp_ports)
                logger.info("UDP discovery: %s gained %s open UDP services", host.host, len(udp_ports))
            self.stealth_delay("network")


class ExpandedServiceEnum(Phase3Enum):
    """Phase 3 that enumerates all open services and runs bounded safe NSE checks."""

    TLS_PORTS = {443, 465, 636, 853, 993, 995, 2376, 5986, 6443, 7443, 8443, 9443, 10443}

    @staticmethod
    def _scripts_for_port(port: PortEntry) -> Set[str]:
        service = (port.service or "").lower()
        scripts = {"banner"}
        if "http" in service or port.port in {80, 443, 8000, 8080, 8081, 8443, 8888, 9080, 9090, 9443}:
            scripts.update({"http-title", "http-headers", "http-methods", "http-security-headers"})
        if port.port in ExpandedServiceEnum.TLS_PORTS or "https" in service or service.startswith("ssl/"):
            scripts.add("ssl-cert")
        if port.port == 22 or "ssh" in service:
            scripts.update({"ssh-hostkey", "ssh2-enum-algos"})
        if port.port in {139, 445} or "smb" in service or "microsoft-ds" in service:
            scripts.update({"smb-protocols", "smb2-security-mode", "smb-os-discovery"})
        if port.port == 3389 or "rdp" in service or "ms-wbt" in service:
            scripts.update({"rdp-enum-encryption", "rdp-ntlm-info"})
        if port.port == 21 or service.startswith("ftp"):
            scripts.update({"ftp-anon", "ftp-syst"})
        if port.port == 53 or service in {"domain", "dns"}:
            scripts.add("dns-recursion")
        if port.port == 111 or "rpcbind" in service:
            scripts.add("rpcinfo")
        if port.port == 3306 or "mysql" in service:
            scripts.add("mysql-info")
        if port.port == 6379 or "redis" in service:
            scripts.add("redis-info")
        if port.port == 11211 or "memcached" in service:
            scripts.add("memcached-info")
        if port.protocol == "udp" and (port.port == 161 or "snmp" in service):
            scripts.add("snmp-info")
        if port.protocol == "udp" and (port.port == 123 or "ntp" in service):
            scripts.add("ntp-info")
        return scripts

    @staticmethod
    def _script_output(element: ET.Element) -> str:
        output = element.get("output", "").strip()
        if output:
            return output
        values = []
        for child in element.iter():
            if child is element:
                continue
            text = (child.text or "").strip()
            if text:
                values.append(text)
        return "\n".join(values)

    def _parse_safe_nse(self, path: Path):
        results: Dict[Tuple[str, int], Dict[str, str]] = {}
        try:
            root = ET.parse(path).getroot()
            for port_elem in root.findall("host/ports/port"):
                key = (port_elem.get("protocol", "tcp"), int(port_elem.get("portid", 0)))
                scripts = {}
                for script in port_elem.findall("script"):
                    script_id = script.get("id", "")
                    if script_id:
                        scripts[script_id] = self._script_output(script)
                if scripts:
                    results[key] = scripts
        except Exception as exc:
            logger.error("Failed to parse safe NSE output %s: %s", path, exc)
        return results

    def _run_safe_nse(self, host, ports, protocol, config, output_dir):
        if not ports:
            return {}
        security_cfg = config.get("assessment", {}).get("security_tests", {})
        scripts: Set[str] = set()
        for port in ports:
            scripts.update(self._scripts_for_port(port))
        scripts.update(str(value) for value in security_cfg.get("additional_safe_scripts", []) if value)
        port_list = ",".join(str(port.port) for port in ports)
        output = output_dir / "safe_nse_{}_{}.xml".format(host.replace(".", "_"), protocol)
        net_cfg = config.get("stealth", {}).get("network", {})
        command = self._get_nmap_cmd(config) + [
            "-sU" if protocol == "udp" else "-sT", "-Pn", "-sV", "--version-intensity", "2",
            "--max-rate", str(net_cfg.get("max_rate_pps", 100)),
            "--scan-delay", "{}ms".format(net_cfg.get("scan_delay_ms", 50)),
            "-T{}".format(net_cfg.get("timing_template", 2)), "--max-retries", "1",
            "--script-timeout", str(security_cfg.get("script_timeout", "45s")),
            "--host-timeout", str(security_cfg.get("host_timeout", "20m")),
            "--script", ",".join(sorted(scripts)), "-p",
            "U:{}".format(port_list) if protocol == "udp" else port_list,
            "-oX", str(output), host,
        ]
        try:
            result = run_command(command, capture_output=True, text=True, check=False,
                                 timeout=int(security_cfg.get("timeout", 1200)),
                                 strip_proxy=True)
            if result.returncode != 0 and not output.exists():
                logger.warning("Safe NSE scan failed for %s/%s: %s", host, protocol, (result.stderr or "")[:250])
                return {}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Safe NSE scan failed for %s/%s: %s", host, protocol, exc)
            return {}
        return self._parse_safe_nse(output)

    @staticmethod
    def _finding(host, port, finding_id, name, severity, description, evidence, tags):
        return VulnerabilityFinding(
            host=host, port=port, template_id=finding_id, name=name, severity=severity,
            description=description, evidence=evidence[:4000], tags=tags, scanner="nmap-safe-nse",
        )

    def _derive_findings(self, host: str, results):
        findings = []
        for (_, port), scripts in results.items():
            lowered = {key: value.lower() for key, value in scripts.items()}
            ftp = lowered.get("ftp-anon", "")
            if "anonymous ftp login allowed" in ftp:
                findings.append(self._finding(host, port, "NMAP-FTP-ANON", "Anonymous FTP Login Allowed", "medium",
                                              "The FTP service accepts anonymous authentication.", scripts["ftp-anon"], ["ftp", "misconfig"]))
            smb = lowered.get("smb-protocols", "")
            if "nt lm 0.12" in smb or re.search(r"\bsmbv?1\b", smb):
                findings.append(self._finding(host, port, "NMAP-SMB1", "SMBv1 Protocol Enabled", "high",
                                              "The host advertises obsolete SMBv1.", scripts["smb-protocols"], ["smb", "legacy"]))
            signing = lowered.get("smb2-security-mode", "")
            if "not required" in signing or "signing disabled" in signing:
                findings.append(self._finding(host, port, "NMAP-SMB-SIGNING", "SMB Signing Not Required", "medium",
                                              "SMB signing is not enforced.", scripts["smb2-security-mode"], ["smb", "misconfig"]))
            methods = lowered.get("http-methods", "")
            dangerous = sorted(method.upper() for method in ("put", "delete", "trace", "connect") if method in methods)
            if dangerous:
                findings.append(self._finding(host, port, "NMAP-HTTP-METHODS", "Potentially Dangerous HTTP Methods", "medium",
                                              "The service advertises methods requiring explicit justification.",
                                              "{}\n{}".format(", ".join(dangerous), scripts["http-methods"]), ["http", "misconfig"]))
            ssh = lowered.get("ssh2-enum-algos", "")
            weak = [value for value in ("diffie-hellman-group1-sha1", "ssh-dss", "3des-cbc", "arcfour", "hmac-md5") if value in ssh]
            if weak:
                findings.append(self._finding(host, port, "NMAP-SSH-WEAK-ALGO", "Weak SSH Algorithms Enabled", "medium",
                                              "The SSH service offers weak algorithms.", scripts["ssh2-enum-algos"], ["ssh", "crypto"]))
            rdp = lowered.get("rdp-enum-encryption", "")
            if "credssp (nla): failure" in rdp or "network level authentication: not supported" in rdp:
                findings.append(self._finding(host, port, "NMAP-RDP-NLA", "RDP NLA Not Enforced", "medium",
                                              "RDP does not appear to require Network Level Authentication.",
                                              scripts["rdp-enum-encryption"], ["rdp", "misconfig"]))
            dns = lowered.get("dns-recursion", "")
            if "recursion appears to be enabled" in dns:
                findings.append(self._finding(host, port, "NMAP-DNS-RECURSION", "DNS Recursion Enabled", "low",
                                              "Recursive DNS queries are accepted from the assessment network.",
                                              scripts["dns-recursion"], ["dns", "exposure"]))
            for script_id, finding_id, name in (
                ("redis-info", "NMAP-REDIS-INFO", "Unauthenticated Redis Information Access"),
                ("memcached-info", "NMAP-MEMCACHED-INFO", "Unauthenticated Memcached Information Access"),
                ("snmp-info", "NMAP-SNMP-INFO", "SNMP Service Information Exposed"),
            ):
                output = lowered.get(script_id, "")
                if output and "error" not in output and "failed" not in output:
                    findings.append(self._finding(host, port, finding_id, name, "low" if script_id == "snmp-info" else "medium",
                                                  "Service information was retrieved without application credentials.",
                                                  scripts[script_id], [script_id.split("-")[0], "exposure"]))
        return findings

    def execute(self, report, config: Dict[str, Any]):
        security_cfg = config.get("assessment", {}).get("security_tests", {})
        if not security_cfg.get("enabled", True):
            return super().execute(report, config)

        stealth_cfg = config.get("stealth", {})
        version_intensity = int(config.get("assessment", {}).get("scan", {}).get("version_intensity", 2))
        output_dir = get_output_dir(config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)
        maximum = int(security_cfg.get("max_ports_per_host", 128))
        seen = {(item.host, item.port, item.template_id) for item in report.findings_vulns}

        for host in report.findings_infrastructure:
            selected = sorted(host.ports, key=lambda item: (item.protocol, item.port))[:maximum]
            for protocol in ("tcp", "udp"):
                protocol_ports = [item for item in selected if item.protocol == protocol]
                if not protocol_ports:
                    continue
                if protocol == "tcp":
                    enriched = self._deep_service_scan(
                        host.host, [item.port for item in protocol_ports], stealth_cfg,
                        version_intensity, output_dir, config,
                    )
                    self._enrich_host(host, enriched)
                results = self._run_safe_nse(host.host, protocol_ports, protocol, config, output_dir)
                for finding in self._derive_findings(host.host, results):
                    key = (finding.host, finding.port, finding.template_id)
                    if key not in seen:
                        seen.add(key)
                        report.add_vuln(finding)
            self.stealth_delay("network")
        logger.info("Expanded safe service enumeration completed for %s hosts.", len(report.findings_infrastructure))
