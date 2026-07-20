#!/usr/bin/env python3
"""Standalone ESXi/internal service assessment runner.

Requires: Python 3.6+ and nmap. Nuclei is used when installed.
The runner writes JSON and self-contained HTML reports without Python packages.
"""
import argparse
import concurrent.futures
import datetime as dt
import html
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "3.0.0"
SYSTEM_PACKAGES = {"nmap": "nmap", "ip": "iproute2"}
PROFILES = {
    "quick": {"ports": "top-100", "intensity": 1, "rate": 100, "concurrency": 8},
    "standard": {"ports": "top-1000", "intensity": 2, "rate": 50, "concurrency": 4},
    "thorough": {"ports": "1-65535", "intensity": 5, "rate": 25, "concurrency": 2},
}
WEB_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https", 9443: "https"}


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""


@dataclass
class Host:
    address: str
    status: str
    hostname: str = ""
    services: List[Service] = field(default_factory=list)
    web_headers: Dict[str, Dict[str, str]] = field(default_factory=dict)


class AssessmentError(RuntimeError):
    """Raised for anticipated assessment failures."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a standalone ESXi/internal service assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="IP address, hostname, or CIDR accepted by nmap; omitted to discover live hosts on local networks.")
    parser.add_argument("--profile", choices=PROFILES, default="standard", help="Scan intensity preset.")
    parser.add_argument("--ports", help="nmap port expression; overrides the selected profile.")
    parser.add_argument("--output", type=Path, default=Path("assessment-output"), help="Report directory.")
    parser.add_argument("--interface", help="Network interface passed to nmap with -e.")
    parser.add_argument("--no-install", action="store_true", help="Do not install missing system or optional tools automatically.")
    parser.add_argument("--nuclei", action="store_true", help="Run installed nuclei templates against discovered HTTP(S) services.")
    parser.add_argument("--nuclei-templates", type=Path, help="Optional local nuclei template directory.")
    parser.add_argument("--timeout", type=int, default=1800, help="Maximum seconds for the nmap process.")
    parser.add_argument("--web-timeout", type=float, default=8.0, help="Per-request HTTP header probe timeout.")
    parser.add_argument("--no-web-probes", action="store_true", help="Skip HTTP(S) response-header collection.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()
    if args.timeout <= 0 or args.web_timeout <= 0:
        parser.error("timeouts must be positive")
    if args.nuclei_templates and not args.nuclei:
        parser.error("--nuclei-templates requires --nuclei")
    return args


def install_dependencies(args: argparse.Namespace) -> None:
    """Install the small set of external tools this runner needs when absent."""
    missing = [executable for executable in SYSTEM_PACKAGES if not shutil.which(executable)]
    if not missing and (not args.nuclei or shutil.which("nuclei")):
        return
    if args.no_install:
        required = ", ".join(missing) or "nuclei"
        raise AssessmentError(f"Missing tool(s): {required}. Re-run without --no-install to install them.")

    package_manager = next((tool for tool in ("apt-get", "dnf", "yum", "apk") if shutil.which(tool)), None)
    if missing:
        if not package_manager:
            raise AssessmentError("Missing required tools and no supported package manager was found: " + ", ".join(missing))
        packages = [SYSTEM_PACKAGES[item] for item in missing]
        prefix = [] if os.geteuid() == 0 else ["sudo"]
        if prefix and not shutil.which("sudo"):
            raise AssessmentError("Installing tools requires root or sudo privileges.")
        commands = {
            "apt-get": [*prefix, "apt-get", "update"],
            "dnf": [*prefix, "dnf", "install", "-y"],
            "yum": [*prefix, "yum", "install", "-y"],
            "apk": [*prefix, "apk", "add"],
        }
        if package_manager == "apt-get":
            result = run(commands[package_manager], timeout=args.timeout)
            if result.returncode != 0:
                raise AssessmentError(f"Package index update failed: {result.stderr.strip()}")
        install_command = [*prefix, package_manager]
        if package_manager == "apt-get":
            install_command.extend(["install", "-y"])
        elif package_manager == "apk":
            install_command.append("add")
        else:
            install_command.extend(["install", "-y"])
        result = run([*install_command, *packages], timeout=args.timeout)
        if result.returncode != 0:
            raise AssessmentError(f"Could not install {', '.join(packages)}: {result.stderr.strip()}")

    if args.nuclei and not shutil.which("nuclei"):
        if not shutil.which("go"):
            raise AssessmentError("--nuclei was requested, but nuclei and Go are not installed.")
        result = run(["go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], timeout=args.timeout)
        if result.returncode != 0:
            raise AssessmentError(f"Could not install nuclei: {result.stderr.strip()}")
        if not shutil.which("nuclei"):
            raise AssessmentError("nuclei installed, but its Go bin directory is not on PATH.")


def run(command: list[str], *, timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    logging.debug("Running command: %s", " ".join(command))
    try:
        return subprocess.run(command, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd, check=False)
    except subprocess.TimeoutExpired as exc:
        raise AssessmentError(f"Command timed out after {timeout}s: {command[0]}") from exc
    except OSError as exc:
        raise AssessmentError(f"Could not run {command[0]}: {exc}") from exc


def local_networks(interface: str | None) -> list[str]:
    """Return non-loopback IPv4 networks configured on active interfaces."""
    command = ["ip", "-o", "-4", "addr", "show", "up"]
    if interface:
        command.extend(["dev", interface])
    result = run(command, timeout=30)
    if result.returncode != 0:
        raise AssessmentError(f"Could not inspect local interfaces: {result.stderr.strip()}")
    networks: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        try:
            address = fields[fields.index("inet") + 1]
            ip, prefix = address.split("/", 1)
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except (ValueError, IndexError):
            continue
        if not network.is_loopback and network.prefixlen < 32:
            networks.add(str(network))
    return sorted(networks)


def discover_targets(args: argparse.Namespace, output_dir: Path) -> tuple[list[str], list[str]]:
    """Discover live hosts on local networks, returning addresses and command."""
    networks = local_networks(args.interface)
    if not networks:
        raise AssessmentError("No non-loopback IPv4 network was found; specify targets explicitly.")
    command = ["nmap", "-sn", "-PR", "-n", "-oX", str(output_dir / "discovery.xml")]
    if args.interface:
        command.extend(["-e", args.interface])
    command.extend(networks)
    result = run(command, timeout=args.timeout)
    if result.returncode not in (0, 1):
        raise AssessmentError(f"Network discovery failed ({result.returncode}): {result.stderr.strip()}")
    discovered = parse_nmap(Path(output_dir / "discovery.xml"))
    targets = [host.address for host in discovered if host.status == "up"]
    if not targets:
        raise AssessmentError("Network discovery found no live hosts.")
    logging.info("Discovered %d live host(s) on %s", len(targets), ", ".join(networks))
    return targets, command


def build_nmap_command(args: argparse.Namespace, xml_path: Path, targets: list[str]) -> list[str]:
    profile = PROFILES[args.profile]
    command = ["nmap", "-sV", f"--version-intensity={profile['intensity']}", "-T2", "--open", "-oX", str(xml_path)]
    ports = args.ports or profile["ports"]
    if ports.startswith("top-"):
        command.extend(["--top-ports", ports[len("top-"):]])
    else:
        command.extend(["-p", ports])
    if args.interface:
        command.extend(["-e", args.interface])
    command.extend(targets)
    return command


def text(element: Optional[ET.Element], attribute: str, default: str = "") -> str:
    return element.get(attribute, default) if element is not None else default


def parse_nmap(xml_path: Path) -> List[Host]:
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise AssessmentError(f"Unable to parse nmap XML report: {exc}") from exc
    hosts = []  # type: List[Host]
    for node in root.findall("host"):
        address = text(node.find("address[@addrtype='ipv4']"), "addr") or text(node.find("address[@addrtype='ipv6']"), "addr")
        if not address:
            continue
        hostname_node = node.find("hostnames/hostname")
        host = Host(address=address, status=text(node.find("status"), "state", "unknown"), hostname=text(hostname_node, "name"))
        for port in node.findall("ports/port"):
            state = text(port.find("state"), "state")
            if state != "open":
                continue
            service = port.find("service")
            host.services.append(Service(
                port=int(port.get("portid", "0")), protocol=port.get("protocol", "tcp"), state=state,
                service=text(service, "name"), product=text(service, "product"), version=text(service, "version"), tunnel=text(service, "tunnel"),
            ))
        hosts.append(host)
    return hosts


def probe_headers(host: Tuple[Host, str], timeout: float) -> Tuple[str, Dict[str, str]]:
    url, headers = host
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": f"esxi-assessment/{VERSION}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return url, {key: value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        return url, {key: value for key, value in exc.headers.items()} if exc.headers else {"error": str(exc)}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return url, {"error": str(exc.reason) if isinstance(exc, urllib.error.URLError) else str(exc)}


def collect_web_headers(hosts: List[Host], timeout: float, workers: int) -> None:
    work = []  # type: List[Tuple[Host, str]]
    for host in hosts:
        for service in host.services:
            scheme = WEB_PORTS.get(service.port)
            if scheme:
                authority = f"[{host.address}]" if ":" in host.address else host.address
                work.append((host, f"{scheme}://{authority}:{service.port}/"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(probe_headers, item, timeout): item[0] for item in work}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                url, headers = future.result()
            except Exception as exc:  # A failed endpoint must not lose the report.
                logging.warning("Header probe failed for %s: %s", host.address, exc)
                continue
            host.web_headers[url] = headers


def run_nuclei(hosts: Iterable[Host], args: argparse.Namespace, output_dir: Path) -> List[Dict[str, Any]]:
    nuclei = shutil.which("nuclei")
    if not nuclei:
        logging.warning("nuclei was requested but is not installed; skipping vulnerability templates")
        return []
    targets = [url for host in hosts for url in host.web_headers]
    if not targets:
        logging.info("No discovered HTTP(S) services to send to nuclei")
        return []
    targets_file = output_dir / "nuclei_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    findings_file = output_dir / "nuclei_findings.jsonl"
    command = [nuclei, "-l", str(targets_file), "-jsonl", "-o", str(findings_file), "-rl", str(PROFILES[args.profile]["rate"]), "-c", str(PROFILES[args.profile]["concurrency"]), "-severity", "critical,high,medium", "-etags", "dos,fuzz,intrusive"]
    if args.nuclei_templates:
        command.extend(["-t", str(args.nuclei_templates)])
    result = run(command, timeout=args.timeout, cwd=output_dir)
    if result.returncode not in (0, 1):
        logging.warning("nuclei ended with %d: %s", result.returncode, result.stderr.strip())
    if not findings_file.exists():
        return []
    findings = []  # type: List[Dict[str, Any]]
    for line in findings_file.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            logging.warning("Ignoring malformed nuclei result")
    return findings


def render_html(report: Dict[str, Any]) -> str:
    def esc(value: Any) -> str: return html.escape(str(value))
    host_rows = []
    for host in report["hosts"]:
        services = "<br>".join(esc(f"{service['port']}/{service['protocol']} {service['service']} {service['product']} {service['version']}") for service in host["services"]) or "—"
        headers = "<br>".join(f"<b>{esc(url)}</b>: {esc(', '.join(headers.keys()))}" for url, headers in host["web_headers"].items()) or "—"
        host_rows.append(f"<tr><td>{esc(host['address'])}</td><td>{esc(host['hostname'] or '—')}</td><td>{services}</td><td>{headers}</td></tr>")
    finding_rows = "".join(f"<tr><td>{esc(item.get('info', {}).get('severity', 'unknown'))}</td><td>{esc(item.get('info', {}).get('name', 'unknown'))}</td><td>{esc(item.get('matched-at', ''))}</td></tr>" for item in report["nuclei_findings"]) or "<tr><td colspan='3'>No nuclei findings.</td></tr>"
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Assessment report</title><style>body{{font:15px system-ui;margin:2rem;color:#172033}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #cbd5e1;padding:.6rem;text-align:left;vertical-align:top}}th{{background:#e2e8f0}}code{{white-space:pre-wrap}}</style></head><body><h1>Assessment report</h1><p>Generated: {esc(report['generated_at'])} · Profile: {esc(report['profile'])}</p><h2>Discovered services</h2><table><tr><th>Host</th><th>Name</th><th>Open services</th><th>HTTP(S) headers</th></tr>{''.join(host_rows)}</table><h2>Nuclei findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Target</th></tr>{finding_rows}</table><h2>Execution</h2><code>{esc(' '.join(report['nmap_command']))}</code></body></html>"""


def main() -> int:
    args = parse_args()
    install_dependencies(args)
    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    discovery_command: list[str] = []
    targets = args.targets
    if not targets:
        targets, discovery_command = discover_targets(args, output_dir)
    with tempfile.TemporaryDirectory(prefix="esxi-assessment-", dir=output_dir) as temporary:
        xml_path = Path(temporary) / "nmap.xml"
        command = build_nmap_command(args, xml_path, targets)
        result = run(command, timeout=args.timeout)
        if result.returncode not in (0, 1):
            raise AssessmentError(f"nmap failed ({result.returncode}): {result.stderr.strip()}")
        hosts = parse_nmap(xml_path)
    if not args.no_web_probes:
        collect_web_headers(hosts, args.web_timeout, PROFILES[args.profile]["concurrency"])
    findings = run_nuclei(hosts, args, output_dir) if args.nuclei else []
    report = {"version": VERSION, "generated_at": timestamp, "profile": args.profile, "targets": targets, "discovery_command": discovery_command, "nmap_command": command, "nmap_stderr": result.stderr.strip(), "hosts": [asdict(host) for host in hosts], "nuclei_findings": findings}
    json_path = output_dir / "assessment_report.json"
    html_path = output_dir / "assessment_report.html"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    print(f"Assessment complete: {len(hosts)} hosts, {sum(len(host.services) for host in hosts)} open services")
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssessmentError as exc:
        logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(message)s")
        logging.error("%s", exc)
        raise SystemExit(2)
