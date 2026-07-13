# ESXi Stealth VA - Automatic Network Detection & Auto-Assessment

## Overview

The ESXi Stealth VA tool now includes **automatic network detection** and **dynamic assessment** capabilities. The tool can automatically:

1. **Detect local network configuration** (interfaces, IP addresses, gateways)
2. **Identify subnets** to scan
3. **Discover ESXi hosts** on the network
4. **Auto-configure** the assessment based on discovered network topology
5. **Run the complete assessment** automatically

This eliminates the need for manual network configuration in `config/assessment.yaml`.

## Quick Start

### Option 1: Using the Bash Wrapper (Easiest)

```bash
# Make the script executable
chmod +x auto_assess.sh

# Run with automatic network detection
./auto_assess.sh

# With custom profile
./auto_assess.sh --profile thorough

# Dry-run (validate configuration only)
./auto_assess.sh --dry-run
```

### Option 2: Direct Python Invocation

```bash
# Run with automatic network detection
python3 run_assessment.py --auto-network

# With scan profile
python3 run_assessment.py --auto-network --profile standard

# With mock data (testing)
python3 run_assessment.py --auto-network --mock

# Continue from specific phase
python3 run_assessment.py --auto-network --phase 3
```

## What Gets Auto-Detected

### 1. Local Network Interfaces
- Scans all active network interfaces (excluding loopback)
- Detects IP addresses and subnet masks (CIDR notation)
- Identifies the primary interface for scanning

Example output:
```
Found 2 active interface(s):
  - eth0: 10.251.2.25/24
  - docker0: 172.17.0.1/16
```

### 2. Default Gateway
- Automatically retrieves the default gateway IP
- Excludes gateway from scan targets
- Used to validate subnet membership

### 3. Network Subnets
- Calculates network and broadcast addresses
- Identifies all RFC1918 private subnets
- Determines which subnet(s) to scan

Example:
```
Identifying subnets to scan...
  - 10.251.2.0/24 (via eth0)
    Network: 10.251.2.0, Broadcast: 10.251.2.255
```

### 4. ESXi Host Detection
- Uses nmap to scan common ESXi ports (22, 443, 902, 5989, 8000, 9080)
- Looks for VMware service signatures
- Automatically sets discovered ESXi host as primary target

Example:
```
Detecting ESXi/VMware hosts...
Found ESXi host(s) in 10.251.2.0/24: ['10.251.2.28']
Primary target (ESXi host): 10.251.2.28
```

### 5. Exclude IPs List
Automatically excludes:
- Local machine's IP address(es)
- Default gateway IP
- Network address (e.g., 10.251.2.0)
- Broadcast address (e.g., 10.251.2.255)
- Primary ESXi target (scanned separately)

## Auto-Detected Configuration Update

The tool updates `assessment.yaml` settings on-the-fly with:

```yaml
# Before (manual config)
target:
  ip: "10.251.2.28"          # Hardcoded

vm_discovery:
  method: "sweep"
  subnets:
    - "10.251.2.0/24"        # Hardcoded
    - "192.168.157.0/24"     # Hardcoded
  exclude_ips:
    - "10.251.2.1"           # Hardcoded
    - "10.251.2.25"          # Hardcoded
    - "10.251.2.28"          # Hardcoded
    - "10.251.2.255"         # Hardcoded

# After (auto-detected)
target:
  ip: "10.251.2.28"          # ← Auto-detected from nmap scan

vm_discovery:
  method: "sweep"
  subnets:
    - "10.251.2.0/24"        # ← Auto-detected from local interfaces
  exclude_ips:
    - "10.251.2.1"           # ← Auto-detected gateway
    - "10.251.2.25"          # ← Auto-detected local IP
    - "10.251.2.0"           # ← Auto-calculated network address
    - "10.251.2.255"         # ← Auto-calculated broadcast
```

## Usage Examples

### Full Assessment with Auto-Detection

```bash
python3 run_assessment.py --auto-network
```

**What happens:**
1. Detects local network interfaces and IP addresses
2. Finds default gateway and calculates subnets
3. Scans for ESXi hosts using nmap
4. Updates configuration with detected values
5. Runs all 8 assessment phases (0-7)
6. Generates JSON and HTML reports

### Quick Scan (Fast Profile)

```bash
python3 run_assessment.py --auto-network --profile quick
```

**What happens:**
- Auto-detects network
- Uses "quick" scan profile (top 1000 ports)
- Completes faster than standard/thorough profiles

### Thorough Deep Scan

```bash
python3 run_assessment.py --auto-network --profile thorough
```

**What happens:**
- Auto-detects network
- Uses "thorough" scan profile (all 65535 ports)
- More comprehensive but time-consuming

### Validation Only (Dry-Run)

```bash
python3 run_assessment.py --auto-network --dry-run
```

**What happens:**
- Detects network configuration
- Validates all tools are available (nmap, curl, etc.)
- Checks assessment.yaml syntax
- Does NOT run actual scans

### Resume from Specific Phase

```bash
python3 run_assessment.py --auto-network --phase 3
```

**Phases:**
- **Phase 0:** Self-Update
- **Phase 1:** Initialization & Scoping
- **Phase 2:** Stealth Discovery (nmap)
- **Phase 3:** Service Enumeration
- **Phase 4:** Crypto Analysis
- **Phase 5:** Web Assessment
- **Phase 6:** Vulnerability Scanning (nuclei)
- **Phase 7:** Delta Analysis

### Mock Mode Testing

```bash
python3 run_assessment.py --auto-network --mock
```

**What happens:**
- Uses synthetic data instead of real scans
- Useful for testing pipeline without network scanning
- Much faster execution

## Network Detection Flow

```
┌─────────────────────────────────────────┐
│   User runs: python run_assessment.py   │
│              --auto-network             │
└────────────┬────────────────────────────┘
             │
             ▼
    ┌────────────────────┐
    │ [1] Get Interfaces │
    │ - Execute: ip addr │
    │ - Parse IPv4/IPv6  │
    └────────┬───────────┘
             │
             ▼
   ┌──────────────────────┐
   │ [2] Get Gateway      │
   │ - Execute: ip route  │
   │ - Find default route │
   └────────┬─────────────┘
            │
            ▼
   ┌──────────────────────┐
   │ [3] Calculate Subnets│
   │ - Parse CIDR mask    │
   │ - Compute broadcast  │
   └────────┬─────────────┘
            │
            ▼
   ┌───────────────────────────┐
   │ [4] Detect ESXi Hosts     │
   │ - nmap port scan (quick)  │
   │ - Look for VMware signers │
   └────────┬──────────────────┘
            │
            ▼
   ┌───────────────────────────┐
   │ [5] Update Config         │
   │ - Set target IP           │
   │ - Set subnets to scan     │
   │ - Set exclude_ips         │
   │ - Set scan interface      │
   └────────┬──────────────────┘
            │
            ▼
   ┌───────────────────────────┐
   │ Run Assessment Pipeline   │
   │ Phase 0 → Phase 7         │
   └────────┬──────────────────┘
            │
            ▼
   ┌───────────────────────────┐
   │ Generate Reports          │
   │ - assessment_report.json  │
   │ - assessment_report.html  │
   └───────────────────────────┘
```

## Output

After running with `--auto-network`, you'll get:

**Console Output:**
```
========================================================
AUTO-DETECTING NETWORK CONFIGURATION
========================================================

[1/5] Detecting local network interfaces...
Found 2 active interface(s):
  - eth0: 10.251.2.25/24
  - docker0: 172.17.0.1/16

[2/5] Detecting default gateway...
Default gateway: 10.251.2.1

[3/5] Identifying subnets to scan...
  - 10.251.2.0/24 (via eth0)
    Network: 10.251.2.0, Broadcast: 10.251.2.255

[4/5] Detecting ESXi/VMware hosts...
Found ESXi host(s) in 10.251.2.0/24: ['10.251.2.28']

[5/5] Gathering additional information...
Local hostname: scanner-host
Scanner IP: 10.251.2.25

========================================================
NETWORK DETECTION SUMMARY
========================================================
Subnets to scan:     10.251.2.0/24
Primary target:      10.251.2.28
Scan interface:      eth0
Scanner IP:          10.251.2.25
Exclude IPs:         10.251.2.0, 10.251.2.1, 10.251.2.25, 10.251.2.255, 10.251.2.28
========================================================
```

**Generated Reports:**
```
output/
├── assessment_report.json          # Complete findings in JSON
├── assessment_report.html          # Executive HTML report
└── history/
    └── 2024-W29/
        ├── assessment_report.json  # Weekly archive
        └── assessment_report.html
```

## Requirements

### System Requirements
- **OS:** Linux/macOS (Ubuntu 20.04+ recommended)
- **Python:** 3.7 or later
- **Network:** Access to local network(s) to scan

### Required Tools (Auto-Installed if Missing)
- `nmap` - Network scanning
- `curl` - Web probing
- `ip` - Network interface detection

### Optional Tools
- `testssl.sh` - SSL/TLS deep analysis
- `nuclei` - Vulnerability templates
- `nikto` - Web vulnerability scanner

## Troubleshooting

### "No network interfaces detected"
```bash
# Check if 'ip' command is available
which ip

# Install if missing
sudo apt-get install iproute2
```

### "nmap not found"
```bash
# Install nmap for ESXi host detection
sudo apt-get install nmap
```

### "Permission denied" for network scanning
```bash
# Some scans require root. Use sudo:
sudo python3 run_assessment.py --auto-network

# Or use --dry-run first to validate configuration
python3 run_assessment.py --auto-network --dry-run
```

### "Failed to detect any subnets"
```bash
# Check your network configuration
ip addr
ip route

# Or use manual configuration
python3 run_assessment.py  # Without --auto-network
```

## Advanced Usage

### Combine with Other Flags

```bash
# Auto-network + force Phase 0 update + quick profile
python3 run_assessment.py --auto-network --update --profile quick

# Auto-network + skip delta analysis
python3 run_assessment.py --auto-network --no-delta

# Auto-network + custom config directory
python3 run_assessment.py --auto-network --config-dir /custom/path/to/config
```

### Automated Scheduling

Add to crontab for weekly automated assessments:

```bash
# Edit crontab
crontab -e

# Add weekly assessment (Sunday 2 AM)
0 2 * * 0 cd /opt/esxi-stealth-va && python3 run_assessment.py --auto-network --profile standard >> logs/cron.log 2>&1
```

## Network Detection Limitations

The auto-detection works best when:
- ✅ Machine has direct network access to target subnets
- ✅ ESXi hosts respond to nmap probes
- ✅ Running on Linux (best support)
- ✅ No strict firewall blocking nmap ports

It may have issues:
- ❌ If ESXi hosts are on non-standard ports
- ❌ In heavily firewalled networks
- ❌ With multiple complex network topologies
- ❌ On non-Linux systems (macOS/Windows limited support)

In these cases, fall back to manual configuration in `config/assessment.yaml`.

## Security Considerations

- The tool performs **non-intrusive network scanning** by default
- Uses **stealth timing profiles** to avoid detection
- **Excludes** local IPs and gateways automatically
- All activities are **logged** for audit purposes
- Designed for **authorized assessments only**

## Support

For issues with auto-network detection:

1. Check the logs:
   ```bash
   tail -100 logs/assessment_latest.log
   ```

2. Run with dry-run for validation:
   ```bash
   python3 run_assessment.py --auto-network --dry-run
   ```

3. Review detected configuration:
   ```bash
   python3 -c "from orchestrator.network_detector import auto_detect_network; import logging; logging.basicConfig(level=logging.INFO); auto_detect_network()"
   ```
