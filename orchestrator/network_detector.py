"""Automatic, bounded discovery of local private networks and ESXi hosts."""

import ipaddress
import logging
import os
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from orchestrator.runtime import run_command


logger = logging.getLogger(__name__)

VIRTUAL_INTERFACE_PREFIXES = (
    "br-", "cni", "docker", "dummy", "flannel", "lxc", "podman",
    "tailscale", "tun", "tap", "veth", "virbr", "vmnet",
)
ESXI_PORTS = "443,902,5989,8000,9080,9443"


def is_virtual_interface(name: str) -> bool:
    normalized = (name or "").split("@", 1)[0].lower()
    return normalized.startswith(VIRTUAL_INTERFACE_PREFIXES)


def get_local_interfaces(include_virtual: bool = False) -> Dict[str, Dict[str, str]]:
    """Return active, globally scoped IPv4 interfaces from ``ip`` output."""
    interfaces = {}  # type: Dict[str, Dict[str, str]]
    if not shutil.which("ip"):
        logger.error("The 'ip' command is unavailable; cannot inspect interfaces.")
        return interfaces

    try:
        result = run_command(
            ["ip", "-o", "-4", "addr", "show", "up", "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            strip_proxy=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Error detecting interfaces: %s", exc)
        return interfaces

    if result.returncode != 0:
        logger.warning("Failed to inspect interfaces: %s", (result.stderr or "").strip())
        return interfaces

    for line in (result.stdout or "").splitlines():
        fields = line.split()
        if len(fields) < 4 or "inet" not in fields:
            continue
        name = fields[1].rstrip(":").split("@", 1)[0]
        if not include_virtual and is_virtual_interface(name):
            logger.info("Ignoring virtual/container interface: %s", name)
            continue
        try:
            address = fields[fields.index("inet") + 1]
            interface = ipaddress.ip_interface(address)
        except (ValueError, IndexError):
            continue
        if interface.ip.is_loopback or interface.ip.is_link_local or interface.ip.is_multicast:
            continue
        interfaces[name] = {
            "ip": str(interface.ip),
            "netmask": "/{}".format(interface.network.prefixlen),
            "network": str(interface.network),
        }
    return interfaces


def get_default_route() -> Tuple[Optional[str], Optional[str]]:
    """Return ``(gateway, interface)`` for the default IPv4 route."""
    if not shutil.which("ip"):
        return None, None
    try:
        result = run_command(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            strip_proxy=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    for line in (result.stdout or "").splitlines():
        fields = line.split()
        gateway = fields[fields.index("via") + 1] if "via" in fields else None
        interface = fields[fields.index("dev") + 1] if "dev" in fields else None
        return gateway, interface
    return None, None


def get_default_gateway() -> Optional[str]:
    """Backward-compatible gateway-only helper."""
    return get_default_route()[0]


def calculate_subnet_range(ip: str, netmask: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        network = ipaddress.ip_network("{}{}".format(ip, netmask), strict=False)
        return str(network.network_address), str(network.broadcast_address)
    except ValueError as exc:
        logger.warning("Error calculating subnet for %s%s: %s", ip, netmask, exc)
        return None, None


def _parse_grepable_up(output: str) -> List[str]:
    addresses = set()  # type: Set[str]
    for line in (output or "").splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            fields = line.split()
            if len(fields) >= 2:
                try:
                    addresses.add(str(ipaddress.ip_address(fields[1])))
                except ValueError:
                    pass
    return sorted(addresses, key=ipaddress.ip_address)


def get_active_hosts(subnet: str, timeout_sec: int = 60,
                     interface: Optional[str] = None,
                     max_rate: int = 2000) -> List[str]:
    """Run a fast discovery-only sweep; no service or vulnerability probes."""
    if not shutil.which("nmap"):
        logger.warning("Nmap is unavailable; skipping live-host discovery for %s", subnet)
        return []

    command = [
        "nmap", "-sn", "-n", "-T4", "--max-retries", "1",
        "--max-rate", str(max(1, max_rate)), "-oG", "-",
    ]
    if interface:
        command.extend(["-e", interface])
    command.append(subnet)
    logger.info("  Stage 1/2: discovering live hosts on %s (timeout=%ss)", subnet, timeout_sec)
    try:
        result = run_command(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
            strip_proxy=True,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Live-host discovery timed out after %ss on %s; continuing.", timeout_sec, subnet)
        return []
    except OSError as exc:
        logger.warning("Live-host discovery failed on %s: %s", subnet, exc)
        return []

    if result.returncode not in (0, 1):
        logger.warning("Live-host discovery failed on %s: %s", subnet, (result.stderr or "").strip())
        return []
    addresses = _parse_grepable_up(result.stdout or "")
    logger.info("  Stage 1/2 complete: %s live host(s) on %s", len(addresses), subnet)
    return addresses


def _parse_esxi_grepable(output: str) -> List[str]:
    matches = set()  # type: Set[str]
    for line in (output or "").splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        lowered = line.lower()
        vmware_signature = any(value in lowered for value in ("esxi", "vmware", "vcenter", "vsphere"))
        characteristic_port = any(value in lowered for value in ("902/open", "5989/open"))
        if vmware_signature or characteristic_port:
            matches.add(fields[1])
    return sorted(matches, key=ipaddress.ip_address)


def detect_esxi_hosts(subnet: str, timeout_sec: int = 90,
                      interface: Optional[str] = None,
                      max_candidates: int = 1024,
                      discovery_rate: int = 2000) -> List[str]:
    """Discover live hosts first, then probe only those for VMware services."""
    live_hosts = get_active_hosts(
        subnet,
        timeout_sec=max(10, int(timeout_sec * 0.6)),
        interface=interface,
        max_rate=discovery_rate,
    )
    if not live_hosts:
        return []

    candidates = live_hosts[:max(1, max_candidates)]
    if len(live_hosts) > len(candidates):
        logger.warning(
            "ESXi identification is limited to %s of %s live hosts on %s; Phase 2 still scans all discovered hosts.",
            len(candidates), len(live_hosts), subnet,
        )

    found = set()  # type: Set[str]
    chunks = [candidates[index:index + 128] for index in range(0, len(candidates), 128)]
    per_chunk_timeout = max(15, int(max(1, timeout_sec * 0.4) / max(1, len(chunks))))
    for index, chunk in enumerate(chunks, 1):
        logger.info(
            "  Stage 2/2: identifying VMware services on candidate batch %s/%s (%s hosts)",
            index, len(chunks), len(chunk),
        )
        command = [
            "nmap", "-n", "-sT", "-sV", "--version-intensity", "1",
            "--open", "--max-retries", "1", "--host-timeout", "15s",
            "-p", ESXI_PORTS, "-oG", "-",
        ]
        if interface:
            command.extend(["-e", interface])
        command.extend(chunk)
        try:
            result = run_command(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=per_chunk_timeout,
                strip_proxy=True,
            )
        except subprocess.TimeoutExpired:
            logger.warning("VMware identification batch %s/%s timed out; continuing.", index, len(chunks))
            continue
        except OSError as exc:
            logger.warning("VMware identification failed: %s", exc)
            continue
        found.update(_parse_esxi_grepable(result.stdout or ""))

    logger.info("  Stage 2/2 complete: %s ESXi/VMware host(s) identified on %s", len(found), subnet)
    return sorted(found, key=ipaddress.ip_address)


def _reverse_hostname(address: str) -> str:
    try:
        return socket.gethostbyaddr(address)[0]
    except (OSError, socket.herror):
        return ""


def auto_detect_network(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Detect usable private subnets and an optional primary ESXi target."""
    config = config or {}
    automatic = config.get("assessment", {}).get("auto_network", {})
    include_virtual = bool(automatic.get("include_virtual_interfaces", False))
    if os.environ.get("ASSESSMENT_INCLUDE_VIRTUAL_INTERFACES") == "1":
        include_virtual = True

    result = {
        "target_ip": None,
        "target_hostname": "",
        "subnets": [],
        "subnet_interfaces": {},
        "exclude_ips": set(),
        "scan_interface": None,
        "local_ip": None,
        "scanner_hostname": socket.gethostname(),
    }  # type: Dict[str, Any]

    logger.info("=" * 60)
    logger.info("AUTO-DETECTING NETWORK CONFIGURATION")
    logger.info("=" * 60)
    logger.info("[1/5] Detecting active IPv4 interfaces...")
    interfaces = get_local_interfaces(include_virtual=include_virtual)
    if not interfaces:
        logger.error("No suitable active IPv4 interfaces detected.")
        result["exclude_ips"] = []
        return result

    for name, details in interfaces.items():
        logger.info("  - %s: %s%s", name, details["ip"], details["netmask"])

    logger.info("[2/5] Detecting default route...")
    gateway, default_interface = get_default_route()
    if gateway:
        logger.info("  Default gateway: %s via %s", gateway, default_interface or "OS route")
        result["exclude_ips"].add(gateway)

    logger.info("[3/5] Building private subnet scope...")
    allow_public = bool(automatic.get("allow_public_subnets", False))
    for name, details in interfaces.items():
        network = ipaddress.ip_network(details["network"], strict=False)
        if not allow_public and not network.is_private:
            logger.warning("  Skipping non-private network %s on %s", network, name)
            continue
        subnet = str(network)
        if subnet not in result["subnets"]:
            result["subnets"].append(subnet)
            result["subnet_interfaces"][subnet] = name
        result["exclude_ips"].update(
            [details["ip"], str(network.network_address), str(network.broadcast_address)]
        )
        logger.info("  - %s via %s (%s addresses)", subnet, name, network.num_addresses)

    if not result["subnets"]:
        logger.error("No suitable private subnet detected.")
        result["exclude_ips"] = sorted(result["exclude_ips"])
        return result

    selected_interface = default_interface if default_interface in interfaces else next(iter(interfaces))
    result["scan_interface"] = selected_interface
    result["local_ip"] = interfaces[selected_interface]["ip"]

    logger.info("[4/5] Detecting ESXi/VMware hosts with two-stage discovery...")
    if shutil.which("nmap") and automatic.get("detect_esxi", True):
        all_esxi = set()  # type: Set[str]
        timeout = int(automatic.get("esxi_detection_timeout_s", 90))
        max_candidates = int(automatic.get("max_esxi_candidates", 1024))
        discovery_rate = int(automatic.get("discovery_rate_pps", 2000))
        for subnet in result["subnets"]:
            all_esxi.update(detect_esxi_hosts(
                subnet,
                timeout_sec=timeout,
                interface=result["subnet_interfaces"].get(subnet),
                max_candidates=max_candidates,
                discovery_rate=discovery_rate,
            ))
        if all_esxi:
            ordered = sorted(all_esxi, key=ipaddress.ip_address)
            result["target_ip"] = ordered[0]
            result["target_hostname"] = _reverse_hostname(ordered[0])
            result["exclude_ips"].add(ordered[0])
            logger.info("  Primary ESXi target: %s", ordered[0])
        else:
            logger.info("  No primary ESXi host identified; all live hosts will still be assessed.")
    else:
        logger.warning("  Nmap unavailable or ESXi identification disabled; deferring host classification to Phase 2.")

    logger.info("[5/5] Finalizing automatic scope...")
    result["exclude_ips"] = sorted(result["exclude_ips"], key=ipaddress.ip_address)
    logger.info("  Subnets: %s", ", ".join(result["subnets"]))
    logger.info("  Scanner: %s (%s)", result["scanner_hostname"], result["local_ip"])
    logger.info("  Primary target: %s", result["target_ip"] or "auto-classify after discovery")
    logger.info("=" * 60)
    return result


def update_config_with_detected_network(config: Dict[str, Any], detected: Dict[str, Any]) -> Dict[str, Any]:
    """Apply automatic scope without retaining stale hard-coded targets."""
    if not detected.get("subnets"):
        logger.warning("No subnets detected. Configuration was not changed.")
        return config

    assessment = config.setdefault("assessment", {})
    target = assessment.setdefault("target", {})
    discovery = assessment.setdefault("vm_discovery", {})
    web = assessment.setdefault("web", {})

    target["ip"] = detected.get("target_ip") or ""
    target["hostname"] = detected.get("target_hostname") or ""
    discovery["method"] = "sweep"
    discovery["subnets"] = list(detected["subnets"])
    discovery["subnet_interfaces"] = dict(detected.get("subnet_interfaces", {}))
    discovery["exclude_ips"] = list(detected.get("exclude_ips", []))

    unique_interfaces = set(discovery["subnet_interfaces"].values())
    interface_override = assessment.setdefault("stealth", {}).setdefault("network", {})
    interface_override["interface"] = next(iter(unique_interfaces)) if len(unique_interfaces) == 1 else ""

    web["base_url"] = (
        "https://{}".format(target["ip"]) if target["ip"] else ""
    )
    logger.info("Runtime configuration updated with automatic network scope.")
    return config


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
    print(auto_detect_network())
