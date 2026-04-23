import os
import shutil
import logging
from pathlib import Path

from orchestrator.runtime import run_command


def find_nmap_command():
    if shutil.which("nmap"):
        return ["nmap"]

    if shutil.which("wsl"):
        try:
            result = run_command(["wsl", "which", "nmap"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return ["wsl", "nmap"]
        except Exception:
            pass

    return None


def find_testssl_command():
    if shutil.which("testssl.sh"):
        return ["testssl.sh"]
    if shutil.which("testssl"):
        return ["testssl"]

    if shutil.which("wsl"):
        try:
            result = run_command(["wsl", "which", "testssl.sh"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return ["wsl", "testssl.sh"]

            result = run_command(["wsl", "which", "testssl"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return ["wsl", "testssl"]
        except Exception:
            pass

    bundled = Path("/usr/local/testssl.sh/testssl.sh")
    if bundled.exists():
        return [str(bundled)]

    return None


def scan_network_for_https(subnet="192.168.157.0/24"):
    logging.info(f"[*] Sweeping {subnet} for active HTTPS servers using Nmap...")

    nmap_base = find_nmap_command()
    if not nmap_base:
        logging.error(f"[!] Nmap is not available. Cannot scan {subnet}.")
        return []

    nmap_cmd = nmap_base + ["-Pn", "-p", "443", "--open", "-oG", "-", subnet]
    try:
        result = run_command(
            nmap_cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception as e:
        logging.error(f"[!] Nmap scan failed for {subnet}: {e}")
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

    testssl_cmd = find_testssl_command()
    if not testssl_cmd:
        logging.error("[!] testssl.sh not found. Skipping standalone SSL automation.")
        return

    clean_env = os.environ.copy()
    for proxy_var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
        clean_env.pop(proxy_var, None)

    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)

    for ip in targets:
        logging.info(f"[*] Launching testssl.sh against {ip}...")

        csv_path = output_dir / f"testssl_{ip}.csv"
        if csv_path.exists():
            csv_path.unlink()

        cmd = testssl_cmd + [
            "--quiet",
            "--sneaky",
            "--csvfile", str(csv_path),
            f"https://{ip}",
        ]

        result = run_command(
            cmd,
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and csv_path.exists():
            logging.info(f"[+] Scan complete for {ip}. Results saved to {csv_path}")
        else:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            detail = stderr or stdout or f"exit code {result.returncode}"
            logging.error(f"[!] testssl.sh failed for {ip}: {detail}")


def run_ssl_automation(subnet=None, subnets=None):
    logging.info("--- Starting Automated SSL Phase ---")

    if subnets is None:
        subnets = [subnet] if subnet else []

    all_targets = []
    seen = set()
    for current_subnet in subnets:
        for ip in scan_network_for_https(current_subnet):
            if ip not in seen:
                seen.add(ip)
                all_targets.append(ip)

    execute_testssl(all_targets)
    logging.info("--- SSL Phase Complete ---")
