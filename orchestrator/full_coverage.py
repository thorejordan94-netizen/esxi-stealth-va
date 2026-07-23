"""Full-coverage phase implementations with bounded parallel execution.

The classes in this module preserve the existing phase interfaces while:
- removing host and service-enumeration caps when configured as zero;
- scanning all TCP ports and the configured UDP range;
- probing every discovered TCP service for HTTP/HTTPS;
- feeding every open endpoint to Nuclei, not only common web ports; and
- parallelizing independent hosts/endpoints without skipping checks.

Public-network and intrusive/DoS/fuzz protections remain configuration gates.
"""

import copy
import ipaddress
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from orchestrator.expanded_internal_assessment import ExpandedDiscovery, ExpandedServiceEnum
from orchestrator.models import AssessmentReport, PortEntry, WebAssessmentResult
from orchestrator.phase2_discovery import Phase2Discovery
from orchestrator.phase4_crypto import Phase4Crypto, SSLLabsClient, _valid_scan_host
from orchestrator.phase5_web import Phase5Web
from orchestrator.phase6_vulnscan import Phase6VulnScan
from orchestrator.runtime import get_output_dir


logger = logging.getLogger(__name__)

TLS_PORTS = {
    443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 2083,
    2087, 2376, 5986, 6443, 7443, 8443, 8834, 9443, 10443,
}
WEB_PORTS = {
    80, 81, 3000, 5000, 5601, 7001, 7002, 8000, 8008, 8080, 8081,
    8088, 8181, 8443, 8888, 9000, 9080, 9090, 9200, 9443, 10000,
}


def _workers(config: Dict[str, Any], key: str, default: int) -> int:
    performance = config.get("assessment", {}).get("performance", {})
    value = int(performance.get(key, default) or default)
    return max(1, min(64, value))


def _is_tls_port(port: PortEntry) -> bool:
    service = (port.service or "").lower()
    return (
        port.port in TLS_PORTS
        or "https" in service
        or "ssl" in service
        or "tls" in service
        or service in ("imaps", "pop3s", "smtps", "ldaps")
    )


def _is_web_port(port: PortEntry) -> bool:
    service = (port.service or "").lower()
    return port.port in WEB_PORTS or "http" in service or "web" in service


def _base_url(host: str, port: int, scheme: str) -> str:
    if (scheme, port) in (("http", 80), ("https", 443)):
        return "{}://{}".format(scheme, host)
    return "{}://{}:{}".format(scheme, host, port)


class FullCoverageDiscovery(ExpandedDiscovery):
    """Discover all in-scope hosts and scan complete configured port ranges."""

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
        maximum = int(expanded.get("max_addresses_per_subnet", 0) or 0)
        if maximum > 0 and network.num_addresses > maximum:
            logger.error(
                "Refusing subnet %s with %s addresses; split it into scoped networks (max=%s).",
                network, network.num_addresses, maximum,
            )
            return None
        return network

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        runtime_config = copy.deepcopy(config)
        assessment = runtime_config.setdefault("assessment", {})
        expanded = assessment.setdefault("expanded_discovery", {})
        scan_cfg = assessment.setdefault("scan", {})
        discovery_cfg = assessment.setdefault("vm_discovery", {})

        # Empty/zero limits mean unlimited.  Complete TCP coverage is the default
        # in this full-coverage phase; an explicit CLI profile can still override.
        scan_cfg["ports"] = str(expanded.get("tcp_ports") or scan_cfg.get("ports") or "1-65535")
        scan_cfg["esxi_ports"] = expanded.get(
            "esxi_ports", "22,80,443,427,902,5988,5989,8000,8080,9080,9443",
        )
        discovery_cfg["max_hosts"] = 0

        # Phase2Discovery.execute dynamically dispatches to the expanded subnet
        # sweep implementation above, while avoiding the parent's sequential UDP
        # post-pass so it can be executed concurrently below.
        Phase2Discovery.execute(self, report, runtime_config)

        output_dir = get_output_dir(runtime_config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)
        hosts = list(report.findings_infrastructure)
        worker_count = _workers(runtime_config, "udp_workers", 4)

        def scan_udp(host_finding):
            return host_finding, self._udp_scan(host_finding.host, runtime_config, output_dir)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(scan_udp, host) for host in hosts]
            for future in as_completed(futures):
                host, ports = future.result()
                if ports:
                    self._merge_ports(host, ports)
                    logger.info("UDP discovery: %s gained %s open UDP services", host.host, len(ports))

        total_ports = sum(len(host.ports) for host in report.findings_infrastructure)
        logger.info(
            "Full-coverage discovery complete: %s hosts and %s open TCP/UDP services.",
            len(report.findings_infrastructure), total_ports,
        )


class FullCoverageServiceEnum(ExpandedServiceEnum):
    """Enumerate every discovered open service using parallel host workers."""

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        security_cfg = config.get("assessment", {}).get("security_tests", {})
        if not security_cfg.get("enabled", True):
            return super().execute(report, config)

        stealth_cfg = config.get("stealth", {})
        version_intensity = int(config.get("assessment", {}).get("scan", {}).get("version_intensity", 2))
        output_dir = get_output_dir(config) / "nmap"
        output_dir.mkdir(parents=True, exist_ok=True)
        maximum = int(security_cfg.get("max_ports_per_host", 0) or 0)
        seen = {(item.host, item.port, item.template_id) for item in report.findings_vulns}
        worker_count = _workers(config, "service_workers", 4)

        def enumerate_host(host):
            ordered = sorted(host.ports, key=lambda item: (item.protocol, item.port))
            selected = ordered if maximum <= 0 else ordered[:maximum]
            derived = []
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
                derived.extend(self._derive_findings(host.host, results))
            self.stealth_delay("network")
            return host.host, len(selected), derived

        hosts = list(report.findings_infrastructure)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(enumerate_host, host) for host in hosts]
            for future in as_completed(futures):
                host_address, selected_count, findings = future.result()
                logger.info("Service enumeration completed for %s (%s open services).", host_address, selected_count)
                for finding in findings:
                    key = (finding.host, finding.port, finding.template_id)
                    if key not in seen:
                        seen.add(key)
                        report.add_vuln(finding)

        logger.info("Full safe service enumeration completed for %s hosts.", len(hosts))


class FullCoverageCrypto(Phase4Crypto):
    """Analyze every discovered TLS-like endpoint using parallel local workers."""

    def _targets(self, report: AssessmentReport, config: Dict[str, Any]) -> List[Tuple[str, int]]:
        crypto_cfg = config.get("assessment", {}).get("crypto", {})
        explicit_ports = set()
        for value in crypto_cfg.get("tls_ports", []):
            try:
                explicit_ports.add(int(value))
            except (TypeError, ValueError):
                continue
        targets = set()
        for host in report.findings_infrastructure:
            if not _valid_scan_host(host.host):
                continue
            for port in host.ports:
                if port.protocol == "tcp" and (_is_tls_port(port) or port.port in explicit_ports):
                    targets.add((host.host, port.port))
        return sorted(targets, key=lambda item: (ipaddress.ip_address(item[0]) if _is_ip(item[0]) else item[0], item[1]))

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        assessment_cfg = config.get("assessment", {})
        stealth_cfg = config.get("stealth", {})
        crypto_cfg = assessment_cfg.get("crypto", {})
        ssllabs_cfg = assessment_cfg.get("ssllabs", {})
        prefer_testssl = crypto_cfg.get("prefer_testssl", True)
        output_dir = get_output_dir(config) / "crypto"
        output_dir.mkdir(parents=True, exist_ok=True)
        targets = self._targets(report, config)
        if not targets:
            logger.info("No TLS-like endpoints found in discovery results.")
            return

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
                ssllabs_client = None

        worker_count = 1 if ssllabs_client else _workers(config, "crypto_workers", 4)

        def scan_target(target):
            host, port = target
            self.log_for_cyberark("TLS analysis on {}:{}".format(host, port))
            finding = None
            if prefer_testssl:
                finding = self._run_testssl(host, port, stealth_cfg, output_dir)
                if finding:
                    finding.scan_method = "testssl"
            if finding is None and ssllabs_client:
                try:
                    result_data = ssllabs_client.analyze(host)
                    if result_data:
                        finding = ssllabs_client.parse_result(result_data, host, port)
                except Exception as exc:
                    logger.warning("SSL Labs analysis failed for %s:%s: %s", host, port, exc)
            if finding is None:
                try:
                    finding = self._python_ssl_check(host, port)
                except Exception as exc:
                    return target, None, str(exc)
            self.stealth_delay("network")
            return target, finding, ""

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(scan_target, target) for target in targets]
            for future in as_completed(futures):
                target, finding, error = future.result()
                host, port = target
                if error:
                    report.add_error("phase4_crypto", "tls_scan", "TLS check failed for {}:{}: {}".format(host, port, error))
                elif finding:
                    report.add_crypto(finding)
                    logger.info("%s:%s -> Grade %s (%s) via %s", host, port, finding.grade, finding.severity, finding.scan_method)

        logger.info("Full TLS analysis complete for %s endpoint(s).", len(targets))


class FullCoverageWeb(Phase5Web):
    """Probe every open TCP port and fully assess each detected web endpoint."""

    def _probe_endpoint(self, host: str, port: PortEntry, verify_ssl: bool) -> Optional[str]:
        preferred = []
        if _is_tls_port(port):
            preferred.append("https")
        if _is_web_port(port) and "https" not in (port.service or "").lower():
            preferred.append("http")
        for scheme in ("http", "https"):
            if scheme not in preferred:
                preferred.append(scheme)

        for scheme in preferred:
            base_url = _base_url(host, port.port, scheme)
            args = ["-sS", "-o", os.devnull, "-w", "%{http_code}", "--max-time", "6"]
            # Discovery must not miss internal self-signed HTTPS endpoints.  The
            # certificate itself is evaluated separately by the crypto phase.
            if scheme == "https" or not verify_ssl:
                args.append("-k")
            rc, stdout, _ = self._run_curl(args + [base_url + "/"], timeout=8)
            code = (stdout or "").strip()
            if rc == 0 and code and code != "000":
                return base_url
        return None

    def execute(self, report: AssessmentReport, config: Dict[str, Any]):
        web_cfg = config.get("assessment", {}).get("web", {})
        stealth_cfg = config.get("stealth", {})
        ua = stealth_cfg.get("http", {}).get("user_agent", "Mozilla/5.0")
        verify_ssl = web_cfg.get("verify_ssl", False)
        use_nikto = web_cfg.get("use_nikto", True)
        probe_all = web_cfg.get("probe_all_open_ports", True)
        output_dir = get_output_dir(config) / "web"
        output_dir.mkdir(parents=True, exist_ok=True)

        candidates = []
        for host in report.findings_infrastructure:
            for port in host.ports:
                if port.protocol != "tcp":
                    continue
                if probe_all or _is_web_port(port) or _is_tls_port(port):
                    candidates.append((host, port))

        if not candidates:
            logger.info("No TCP endpoints available for web probing.")
            return

        probe_workers = _workers(config, "web_probe_workers", 12)
        endpoints = []
        with ThreadPoolExecutor(max_workers=probe_workers) as executor:
            future_map = {
                executor.submit(self._probe_endpoint, host.host, port, verify_ssl): (host, port)
                for host, port in candidates
            }
            for future in as_completed(future_map):
                host, port = future_map[future]
                base_url = future.result()
                if base_url:
                    endpoints.append((host, port, base_url))

        # Deduplicate by host:port; the successful probe already selected scheme.
        unique = {}
        for host, port, base_url in endpoints:
            unique[(host.host, port.port)] = (host, port, base_url)
        endpoints = list(unique.values())
        logger.info("Detected %s web endpoint(s) across %s open TCP services.", len(endpoints), len(candidates))

        def assess_endpoint(item):
            host, port, base_url = item
            self.log_for_cyberark("Web assessment: {}".format(base_url))
            findings = []
            findings.extend(self._check_security_headers(base_url, ua, verify_ssl))
            findings.extend(self._check_cookie_security(base_url, ua, verify_ssl))
            if host.role == "esxi_host":
                findings.extend(self._check_esxi_paths(base_url, host.host, ua, verify_ssl))
            if use_nikto:
                findings.extend(self._run_nikto(host.host, port.port, output_dir))
            self.stealth_delay("http")
            return WebAssessmentResult(host=host.host, port=port.port, url=base_url, findings=findings)

        worker_count = _workers(config, "web_workers", 6)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(assess_endpoint, endpoint) for endpoint in endpoints]
            for future in as_completed(futures):
                report.add_web(future.result())

        logger.info("Full web assessment complete. %s endpoints recorded.", len(report.findings_web))


class FullCoverageVulnScan(Phase6VulnScan):
    """Run safe Nuclei templates against every discovered endpoint."""

    def _prepare_targets(self, report: AssessmentReport, config: Dict[str, Any]) -> Optional[Path]:
        targets = set()
        for web in report.findings_web:
            if web.url:
                targets.add(web.url.rstrip("/"))
        for host in report.findings_infrastructure:
            if not _valid_scan_host(host.host):
                continue
            for port in host.ports:
                endpoint = "{}:{}".format(host.host, port.port)
                targets.add(endpoint)
                if port.protocol == "tcp" and (_is_web_port(port) or _is_tls_port(port)):
                    scheme = "https" if _is_tls_port(port) else "http"
                    targets.add(_base_url(host.host, port.port, scheme))
        if not targets:
            return None
        target_file = get_output_dir(config) / "nuclei_targets.txt"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(sorted(targets)))
            handle.write("\n")
        logger.info("Prepared %s unique Nuclei targets from all open endpoints.", len(targets))
        return target_file


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
