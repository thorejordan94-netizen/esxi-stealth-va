import subprocess
import os
import logging

def scan_network_for_https(subnet="192.168.157.0/24"):
    logging.info(f"[*] Sweeping {subnet} for active HTTPS servers using Nmap...")
    
    nmap_cmd = ["nmap", "-p", "443", "--open", "-oG", "-", subnet]
    try:
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Nmap scan failed: {e}")
        return []

    live_hosts = []
    for line in result.stdout.splitlines():
        if "443/open" in line:
            ip = line.split()[1]
            live_hosts.append(ip)

    logging.info(f"[+] Discovered {len(live_hosts)} HTTPS target(s): {live_hosts}")
    return live_hosts

def execute_testssl(targets):
    if not targets:
        return

    # Strip the proxy from the environment so testssl.sh can reach local lab IPs
    clean_env = os.environ.copy()
    for proxy_var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
        clean_env.pop(proxy_var, None)

    os.makedirs("output", exist_ok=True)

    for ip in targets:
        logging.info(f"[*] Launching testssl.sh against {ip}...")
        
        csv_path = f"output/testssl_{ip}.csv"
        cmd = [
            "/usr/local/testssl.sh/testssl.sh", 
            "--fast", 
            "--csvfile", csv_path, 
            f"https://{ip}"
        ]
        
        subprocess.run(cmd, env=clean_env)
        logging.info(f"[+] Scan complete for {ip}. Results saved to {csv_path}")

def run_ssl_automation(subnet="192.168.157.0/24"):
    logging.info("--- Starting Automated SSL Phase ---")
    targets = scan_network_for_https(subnet)
    execute_testssl(targets)
    logging.info("--- SSL Phase Complete ---")