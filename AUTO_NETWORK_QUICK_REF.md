# ESXi Stealth VA - Auto-Network Detection Quick Reference

## One-Liner Quick Starts

```bash
# Simplest: Auto-detect network and run full assessment
python3 run_assessment.py --auto-network

# Using the wrapper script
chmod +x auto_assess.sh && ./auto_assess.sh

# Quick scan (all enabled phases, top 1000 ports)
python3 run_assessment.py --auto-network --profile quick

# Thorough scan (all 65535 ports)
python3 run_assessment.py --auto-network --profile thorough

# Test configuration without actual scanning
python3 run_assessment.py --auto-network --dry-run

# Test with synthetic data
python3 run_assessment.py --auto-network --mock
```

## What Gets Auto-Detected

| Item | Auto-Detection Method | Example |
|------|----------------------|---------|
| **Network Interfaces** | `ip addr` command | eth0: 10.251.2.25/24 |
| **Default Gateway** | `ip route` command | 10.251.2.1 |
| **Subnets** | CIDR calculation | 10.251.2.0/24 |
| **ESXi Hosts** | nmap port scan | 10.251.2.28 |
| **Exclude IPs** | Auto-calculated | gateway, local, broadcast |
| **Scan Interface** | Primary network | eth0 |

## Command Reference

### Basic Usage
```bash
python3 run_assessment.py --auto-network
```
Auto-detects network and runs full assessment (all phases 0-7)

### With Scan Profile
```bash
# Quick scan (faster)
python3 run_assessment.py --auto-network --profile quick

# Standard scan (recommended)
python3 run_assessment.py --auto-network --profile standard

# Thorough scan (comprehensive, slower)
python3 run_assessment.py --auto-network --profile thorough
```

### Phase Control
```bash
# Force start from Phase 0 (self-update)
python3 run_assessment.py --auto-network --update

# Resume from specific phase (0-7)
python3 run_assessment.py --auto-network --phase 3

# Skip delta analysis (Phase 7)
python3 run_assessment.py --auto-network --no-delta
```

### Testing & Validation
```bash
# Validate configuration without scanning
python3 run_assessment.py --auto-network --dry-run

# Test with synthetic data (mock mode)
python3 run_assessment.py --auto-network --mock

# Combined: dry-run + thorough profile
python3 run_assessment.py --auto-network --dry-run --profile thorough
```

### Advanced Options
```bash
# Custom configuration directory
python3 run_assessment.py --auto-network --config-dir /custom/config

# Combine multiple options
python3 run_assessment.py --auto-network --update --profile standard --no-delta
```

## Expected Console Output

```
╔══════════════════════════════════════════════════════════════════╗
║     ESXi Vulnerability Assessment Framework v2.1.0               ║
║     Automated Weekly Pentest Orchestrator                        ║
║     Internal Use Only — CyberArk PSM Monitored                   ║
╚══════════════════════════════════════════════════════════════════╝

============================================================
AUTO-DETECTING NETWORK CONFIGURATION
============================================================

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
Running ESXi host detection on 10.251.2.0/24...
Found ESXi host(s) in 10.251.2.0/24: ['10.251.2.28']

[5/5] Gathering additional information...
Local hostname: scanner-host

============================================================
NETWORK DETECTION SUMMARY
============================================================
Subnets to scan:     10.251.2.0/24
Primary target:      10.251.2.28
Scan interface:      eth0
Scanner IP:          10.251.2.25
Exclude IPs:         10.251.2.0, 10.251.2.1, 10.251.2.25, 10.251.2.255, 10.251.2.28
============================================================
```

## Output Files

After successful assessment with `--auto-network`:

```
output/
├── assessment_report.json           # Complete findings (JSON)
├── assessment_report.html           # Executive report (HTML)
└── history/
    └── 2024-W29/
        ├── assessment_report.json   # Weekly backup
        └── assessment_report.html
        
logs/
└── assessment_20240715_143022.log   # Detailed audit log
```

## Troubleshooting Quick Fixes

| Problem | Solution |
|---------|----------|
| "nmap not found" | `sudo apt-get install nmap` |
| "ip command not found" | `sudo apt-get install iproute2` |
| "Permission denied" | Run with `sudo` or check firewall rules |
| "No subnets detected" | Check network connectivity: `ip addr && ip route` |
| "ESXi host not detected" | May be on non-standard ports; use manual config |

## Cron Schedule for Weekly Scans

```bash
# Add to crontab (crontab -e)
0 2 * * 0 cd /opt/esxi-stealth-va && python3 run_assessment.py --auto-network --profile standard >> logs/cron.log 2>&1
```

## Exit Codes

- `0` - Success
- `1` - Network detection failed
- `2` - Configuration error
- `130` - Interrupted by user (Ctrl+C)

## Environment Variables

```bash
# Enable mock mode globally
export ASSESSMENT_MOCK_MODE=1

# Run assessment with mock mode
python3 run_assessment.py --auto-network
```

## Network Detection Flow (Visual)

```
START
  ↓
Detect Interfaces (ip addr)
  ↓
Get Default Gateway (ip route)
  ↓
Calculate Subnets (CIDR math)
  ↓
Detect ESXi Hosts (nmap)
  ↓
Update Configuration
  ↓
Run Assessment Pipeline (Phases 0-7)
  ↓
Generate Reports (JSON/HTML)
  ↓
END
```

## Key Features

✅ **Zero Configuration** - Works out of the box  
✅ **Automatic Discovery** - Finds ESXi hosts without manual entry  
✅ **Smart Exclusions** - Auto-excludes gateway, local IP, broadcast  
✅ **Stealth Mode** - Uses conservative timing profiles  
✅ **Error Recovery** - Can resume from any phase  
✅ **Comprehensive Reports** - JSON + HTML with delta analysis  
✅ **Audit Logging** - All activities recorded for compliance  

## Security Notes

🔒 Performs **authorized security assessments only**  
🔒 Uses **stealth timing** to minimize detection  
🔒 **Excludes** critical infrastructure IPs automatically  
🔒 **Logs** all activities for CyberArk integration  
🔒 Requires **explicit** `--auto-network` flag (no accidental scans)  

## Full Documentation

See [AUTO_NETWORK_DETECTION.md](AUTO_NETWORK_DETECTION.md) for comprehensive documentation.
