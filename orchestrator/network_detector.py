"""
Network Auto-Detection Module

Automatically discovers the local network configuration and ESXi hosts
without manual configuration. Detects:
  - Local network interfaces and IP addresses
  - Default gateway and subnets
  - ESXi hosts via nmap OS detection
  - Automatically generates exclude_ips list
"""

import subprocess
import ipaddress
import logging
import socket
from typing import List, Dict, Tuple, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)


def get_local_interfaces() -> Dict[str, Dict[str, str]]:
    """
    Detect all local network interfaces using 'ip addr' command.
    
    Returns:
        Dict mapping interface name to {'ip': x.x.x.x, 'netmask': /24, 'mac': xx:xx:xx:xx:xx:xx}
    """
    interfaces = {}
    
    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode != 0:
            logger.warning("Failed to run 'ip addr show'")
            return interfaces
        
        current_interface = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            # Parse interface line: "2: eth0: <BROADCAST,RUNNING,MULTICAST> ..."
            if line and line[0].isdigit() and ':' in line:
                parts = line.split(':')
                current_interface = parts[1].strip()
                if current_interface not in interfaces:
                    interfaces[current_interface] = {}
            
            # Parse IPv4 address: "inet 10.251.2.25/24 brd 10.251.2.255 scope global eth0"
            if line.startswith('inet ') and current_interface:
                parts = line.split()
                if len(parts) >= 2:
                    addr_with_mask = parts[1]
                    if '/' in addr_with_mask:
                        ip, netmask = addr_with_mask.split('/')
                        interfaces[current_interface]['ip'] = ip
                        interfaces[current_interface]['netmask'] = f"/{netmask}"
            
            # Parse MAC address: "link/ether 02:42:0a:fb:02:19 brd ff:ff:ff:ff:ff:ff"
            if line.startswith('link/ether') and current_interface:
                parts = line.split()
                if len(parts) >= 2:
                    interfaces[current_interface]['mac'] = parts[1]
    
    except Exception as e:
        logger.warning(f"Error detecting interfaces: {e}")
    
    return interfaces


def get_default_gateway() -> Optional[str]:
    """
    Detect default gateway using 'ip route' command.
    
    Returns:
        Gateway IP address or None
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show"],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode != 0:
            return None
        
        for line in result.stdout.split('\n'):
            if line.startswith('default via'):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    
    except Exception as e:
        logger.warning(f"Error detecting default gateway: {e}")
    
    return None


def calculate_subnet_range(ip: str, netmask: str) -> Tuple[str, str]:
    """
    Calculate network address and broadcast address from IP and netmask.
    
    Args:
        ip: IP address (e.g., "10.251.2.25")
        netmask: CIDR netmask (e.g., "/24")
    
    Returns:
        Tuple of (network_address, broadcast_address) or None if invalid
    """
    try:
        network = ipaddress.ip_network(f"{ip}{netmask}", strict=False)
        return str(network.network_address), str(network.broadcast_address)
    except Exception as e:
        logger.warning(f"Error calculating subnet for {ip}{netmask}: {e}")
        return None, None


def detect_esxi_hosts(subnet: str, timeout_sec: int = 30) -> List[str]:
    """
    Detect ESXi hosts in a subnet using nmap OS detection.
    
    Looks for:
      - ESXi hypervisor signatures
      - VMware vCenter/vSphere ports (443, 902, 5989, 8000, 9080)
      - SSH with VMware banner
    
    Args:
        subnet: CIDR notation subnet (e.g., "10.251.2.0/24")
        timeout_sec: Timeout for nmap scan
    
    Returns:
        List of detected ESXi host IPs
    """
    esxi_hosts = []
    
    try:
        # Quick nmap scan for common ESXi ports
        cmd = [
            "nmap",
            "-sV", "-sC",  # Service detection + default NSE scripts
            "-p", "22,443,902,5989,8000,9080",
            "--script=smb-os-discovery,ssh-hostkey",
            "-oG", "-",  # Greppable output
            subnet
        ]
        
        logger.info(f"Running ESXi host detection on {subnet}...")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec
        )
        
        if result.returncode != 0:
            logger.debug(f"nmap scan returned code {result.returncode}")
            return esxi_hosts
        
        # Parse nmap greppable output
        for line in result.stdout.split('\n'):
            if line.startswith('Host:'):
                parts = line.split()
                if len(parts) >= 2:
                    host_ip = parts[1]
                    # Check if ESXi signatures detected
                    if any(sig in line.lower() for sig in ['esxi', 'vmware', 'vcenter', 'vsphere']):
                        esxi_hosts.append(host_ip)
                    # Also check for common ESXi ports
                    elif any(port in line for port in ['443/open', '902/open', '5989/open']):
                        esxi_hosts.append(host_ip)
    
    except FileNotFoundError:
        logger.warning("nmap not found. Install with: apt-get install nmap")
    except subprocess.TimeoutExpired:
        logger.warning(f"nmap scan timeout after {timeout_sec}s")
    except Exception as e:
        logger.warning(f"Error detecting ESXi hosts: {e}")
    
    return list(set(esxi_hosts))  # Remove duplicates


def get_active_hosts(subnet: str, timeout_sec: int = 15) -> List[str]:
    """
    Quickly ping-sweep a subnet to find active hosts.
    
    Args:
        subnet: CIDR notation subnet (e.g., "10.251.2.0/24")
        timeout_sec: Timeout for nmap ping sweep
    
    Returns:
        List of active host IPs
    """
    active_hosts = []
    
    try:
        # Fast ping sweep using nmap
        cmd = [
            "nmap",
            "-sn",  # Ping scan only
            "-T5",  # Insanely fast timing
            "-oG", "-",  # Greppable output
            subnet
        ]
        
        logger.info(f"Running host discovery ping sweep on {subnet}...")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec
        )
        
        # Parse nmap greppable output
        for line in result.stdout.split('\n'):
            if 'Up' in line and line.startswith('Host:'):
                parts = line.split()
                if len(parts) >= 2:
                    active_hosts.append(parts[1])
    
    except FileNotFoundError:
        logger.warning("nmap not found. Install with: apt-get install nmap")
    except subprocess.TimeoutExpired:
        logger.warning(f"Ping sweep timeout after {timeout_sec}s")
    except Exception as e:
        logger.warning(f"Error detecting active hosts: {e}")
    
    return active_hosts


def detect_local_hostname() -> Optional[str]:
    """Get the local machine hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return None


def detect_local_ips() -> Set[str]:
    """Get all local IP addresses assigned to this machine."""
    local_ips = set()
    
    try:
        interfaces = get_local_interfaces()
        for iface_info in interfaces.values():
            if 'ip' in iface_info:
                local_ips.add(iface_info['ip'])
    except Exception as e:
        logger.warning(f"Error detecting local IPs: {e}")
    
    return local_ips


def auto_detect_network() -> Dict[str, any]:
    """
    Automatically detect network configuration.
    
    Returns:
        Dict with keys:
          - 'target_ip': Primary ESXi host IP (or None if not found)
          - 'target_hostname': ESXi host hostname (or None)
          - 'subnets': List of detected subnets to scan
          - 'exclude_ips': List of IPs to exclude (gateway, local, broadcast, etc.)
          - 'scan_interface': Network interface to use for scanning
          - 'local_ip': Local machine's IP on the subnet
    """
    result = {
        'target_ip': None,
        'target_hostname': None,
        'subnets': [],
        'exclude_ips': set(),
        'scan_interface': None,
        'local_ip': None,
    }
    
    logger.info("\n" + "="*60)
    logger.info("AUTO-DETECTING NETWORK CONFIGURATION")
    logger.info("="*60)
    
    # Step 1: Detect local interfaces
    logger.info("\n[1/5] Detecting local network interfaces...")
    interfaces = get_local_interfaces()
    if not interfaces:
        logger.error("No network interfaces detected. Manual configuration required.")
        return result
    
    logger.info(f"Found {len(interfaces)} active interface(s):")
    for iface_name, iface_info in interfaces.items():
        if 'ip' in iface_info:
            logger.info(f"  - {iface_name}: {iface_info['ip']}{iface_info.get('netmask', '')}")
    
    # Step 2: Get default gateway
    logger.info("\n[2/5] Detecting default gateway...")
    gateway = get_default_gateway()
    if gateway:
        logger.info(f"Default gateway: {gateway}")
        result['exclude_ips'].add(gateway)
    
    # Step 3: Identify subnets and build exclude list
    logger.info("\n[3/5] Identifying subnets to scan...")
    local_ips = get_local_ips()
    result['exclude_ips'].update(local_ips)
    
    for iface_name, iface_info in interfaces.items():
        if 'ip' in iface_info and 'netmask' in iface_info:
            ip = iface_info['ip']
            netmask = iface_info['netmask']
            
            # Skip loopback
            if ip.startswith('127.'):
                continue
            
            # Calculate network and broadcast
            net_addr, bcast = calculate_subnet_range(ip, netmask)
            if net_addr and bcast:
                subnet_cidr = f"{net_addr}{netmask}"
                result['subnets'].append(subnet_cidr)
                result['exclude_ips'].add(net_addr)
                result['exclude_ips'].add(bcast)
                result['scan_interface'] = iface_name
                result['local_ip'] = ip
                
                logger.info(f"  - {subnet_cidr} (via {iface_name})")
                logger.info(f"    Network: {net_addr}, Broadcast: {bcast}")
    
    if not result['subnets']:
        logger.error("No suitable subnets detected. Manual configuration required.")
        return result
    
    # Step 4: Detect ESXi hosts
    logger.info("\n[4/5] Detecting ESXi/VMware hosts...")
    all_esxi_hosts = []
    for subnet in result['subnets']:
        esxi_in_subnet = detect_esxi_hosts(subnet, timeout_sec=20)
        if esxi_in_subnet:
            logger.info(f"Found ESXi host(s) in {subnet}: {esxi_in_subnet}")
            all_esxi_hosts.extend(esxi_in_subnet)
    
    if all_esxi_hosts:
        result['target_ip'] = all_esxi_hosts[0]  # Primary target is first ESXi host
        logger.info(f"\nPrimary target (ESXi host): {result['target_ip']}")
        result['exclude_ips'].add(result['target_ip'])
    
    # Step 5: Get hostname and verify
    logger.info("\n[5/5] Gathering additional information...")
    result['target_hostname'] = detect_local_hostname() or f"scanner-{result['local_ip'].split('.')[-1]}"
    
    logger.info(f"Local hostname: {result['target_hostname']}")
    logger.info(f"Scanner IP: {result['local_ip']}")
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("NETWORK DETECTION SUMMARY")
    logger.info("="*60)
    logger.info(f"Subnets to scan:     {', '.join(result['subnets'])}")
    logger.info(f"Primary target:      {result['target_ip'] or 'Not detected'}")
    logger.info(f"Scan interface:      {result['scan_interface']}")
    logger.info(f"Scanner IP:          {result['local_ip']}")
    logger.info(f"Exclude IPs:         {', '.join(sorted(result['exclude_ips']))}")
    logger.info("="*60 + "\n")
    
    # Convert set to list for JSON serialization
    result['exclude_ips'] = sorted(list(result['exclude_ips']))
    
    return result


def update_config_with_detected_network(config: Dict, detected: Dict) -> Dict:
    """
    Update the configuration dict with auto-detected network values.
    
    Args:
        config: Configuration dictionary from YAML
        detected: Result from auto_detect_network()
    
    Returns:
        Updated configuration dictionary
    """
    if not detected['subnets']:
        logger.warning("No subnets detected. Using configuration as-is.")
        return config
    
    # Ensure sections exist
    config.setdefault('assessment', {})
    assessment_cfg = config['assessment']
    assessment_cfg.setdefault('target', {})
    assessment_cfg.setdefault('vm_discovery', {})
    
    # Update target
    if detected['target_ip']:
        assessment_cfg['target']['ip'] = detected['target_ip']
        logger.info(f"Updated target IP: {detected['target_ip']}")
    
    # Update VM discovery
    assessment_cfg['vm_discovery']['method'] = 'sweep'
    assessment_cfg['vm_discovery']['subnets'] = detected['subnets']
    assessment_cfg['vm_discovery']['exclude_ips'] = detected['exclude_ips']
    
    # Update scan interface if detected
    if detected['scan_interface']:
        config.setdefault('stealth', {})
        config['stealth'].setdefault('network', {})
        config['stealth']['network']['interface'] = detected['scan_interface']
        logger.info(f"Updated scan interface: {detected['scan_interface']}")
    
    # Update web base_url if target detected
    if detected['target_ip']:
        assessment_cfg.setdefault('web', {})
        assessment_cfg['web']['base_url'] = f"https://{detected['target_ip']}"
        logger.info(f"Updated web base_url: {assessment_cfg['web']['base_url']}")
    
    logger.info("Configuration updated with auto-detected network values.")
    return config


if __name__ == "__main__":
    # Test the network detection
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    detected = auto_detect_network()
    print("\nDetected Configuration:")
    print(f"  Target IP: {detected['target_ip']}")
    print(f"  Subnets: {detected['subnets']}")
    print(f"  Exclude IPs: {detected['exclude_ips']}")
    print(f"  Scan Interface: {detected['scan_interface']}")
