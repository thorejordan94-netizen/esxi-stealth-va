import urllib.request
import re

def get_top_tcp_ports(n=1000):
    try:
        with open('/usr/share/nmap/nmap-services', 'r') as f:
            lines = f.readlines()
    except Exception:
        return []
    
    ports = []
    for line in lines:
        if line.startswith('#') or not line.strip(): continue
        parts = line.split()
        if len(parts) >= 3 and '/tcp' in parts[1]:
            port = int(parts[1].split('/')[0])
            freq = float(parts[2])
            ports.append((freq, port))
            
    ports.sort(reverse=True, key=lambda x: x[0])
    return [str(p[1]) for p in ports[:n]]

top_ports = set(get_top_tcp_ports(1000))
esxi_ports = {"80", "443", "902", "5989", "8000", "8080", "9080"}
print("esxi ports not in top 1000:", esxi_ports - top_ports)
