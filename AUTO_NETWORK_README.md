# ESXi Stealth VA - Automatic Network Detection Feature

## 🎯 What's New

The tool now **automatically detects your network configuration** and runs the assessment **without any manual setup**. Simply run:

```bash
python3 run_assessment.py --auto-network
```

That's it! The tool will:
- 🔍 Detect local network interfaces
- 🌐 Find the default gateway and calculate subnets
- 🎯 Scan for ESXi hosts using nmap
- ⚙️ Auto-configure the assessment
- 🚀 Run the complete penetration test

## Quick Start

### Option 1: Fastest - Bash Wrapper
```bash
chmod +x auto_assess.sh
./auto_assess.sh
```

### Option 2: Direct Python
```bash
python3 run_assessment.py --auto-network
```

### Option 3: With Custom Profile
```bash
python3 run_assessment.py --auto-network --profile thorough
```

## Features

### 🚀 Zero Configuration
- No need to edit `config/assessment.yaml`
- Works immediately on any network
- Smart exclusion of local IPs and gateways

### 🎯 Intelligent Discovery
- Auto-detects ESXi hosts via nmap
- Identifies all network interfaces
- Calculates subnets automatically
- Finds primary target for assessment

### 📋 Logging & Reporting
- Comprehensive discovery logging
- JSON and HTML report generation
- Weekly archival of results
- Delta analysis (what changed)

### 🛡️ Secure & Stealthy
- Non-intrusive network scanning
- Stealth timing profiles
- Automatic excluded IPs
- Full audit logging

## What Gets Auto-Detected

| Component | Detection Method | Example |
|-----------|-----------------|---------|
| Network Interfaces | `ip addr` | eth0: 10.251.2.25/24 |
| Gateway | `ip route` | 10.251.2.1 |
| Subnets | CIDR calculation | 10.251.2.0/24 |
| ESXi Hosts | nmap scan | 10.251.2.28 |
| Exclude IPs | Auto-calculated | gateway, broadcast, local |
| Scan Interface | Primary network | eth0 |

## Complete Command Examples

### Assessment Types

```bash
# Full comprehensive assessment (all phases)
python3 run_assessment.py --auto-network

# Quick scan (faster, top 1000 ports)
python3 run_assessment.py --auto-network --profile quick

# Thorough scan (all 65535 ports)
python3 run_assessment.py --auto-network --profile thorough

# Validate configuration only
python3 run_assessment.py --auto-network --dry-run

# Test with synthetic data
python3 run_assessment.py --auto-network --mock
```

### Phase Control

```bash
# Start from Phase 0 (self-update)
python3 run_assessment.py --auto-network --update

# Resume from Phase 3 (service enumeration)
python3 run_assessment.py --auto-network --phase 3

# Skip final delta analysis
python3 run_assessment.py --auto-network --no-delta

# Combine options
python3 run_assessment.py --auto-network --update --profile standard --no-delta
```

## Output

### Console Output
```
╔══════════════════════════════════════════════════════════════════╗
║     ESXi Vulnerability Assessment Framework v2.1.0               ║
║     Automated Weekly Pentest Orchestrator                        ║
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
Exclude IPs:         10.251.2.0, 10.251.2.1, 10.251.2.25, 10.251.2.255
============================================================
```

### Generated Reports
```
output/
├── assessment_report.json          # Complete findings
├── assessment_report.html          # Executive report
└── history/
    └── 2024-W29/
        ├── assessment_report.json  # Weekly archive
        └── assessment_report.html
        
logs/
└── assessment_20240715_143022.log  # Detailed audit log
```

## Implementation Details

### New Files Added

1. **`orchestrator/network_detector.py`** (300+ lines)
   - Core network detection logic
   - Functions for interface detection, subnet calculation, ESXi discovery
   - Configuration update mechanism

2. **`auto_assess.sh`** 
   - Bash wrapper for easy execution
   - Automatic tool dependency checking
   - User-friendly output with progress indicators

3. **`AUTO_NETWORK_DETECTION.md`**
   - Comprehensive feature documentation
   - Usage examples and troubleshooting
   - Advanced configuration options

4. **`AUTO_NETWORK_QUICK_REF.md`**
   - Quick reference guide
   - Command cheat sheet
   - Common troubleshooting fixes

### Modified Files

1. **`run_assessment.py`**
   - Added import for `network_detector` module
   - Added `--auto-network` CLI flag
   - Integrated auto-detection before pipeline execution
   - Updated usage documentation

## Technical Architecture

### Network Detection Flow
```
User Command: python3 run_assessment.py --auto-network
       ↓
Load Configuration (YAML)
       ↓
If --auto-network flag:
       ↓
   [1] Get local interfaces (ip addr)
   [2] Get default gateway (ip route)
   [3] Calculate subnets (CIDR math)
   [4] Detect ESXi hosts (nmap scan)
   [5] Update configuration
       ↓
Run Assessment Pipeline (Phases 0-7)
       ↓
Generate Reports (JSON/HTML)
```

### Detection Methods

| Detection | Tool/Method | Reliability |
|-----------|-------------|-------------|
| Interfaces | Linux `ip addr` | Very High |
| Gateway | Linux `ip route` | Very High |
| Subnets | Python ipaddress | Very High |
| ESXi Hosts | nmap + signatures | High |
| Exclusions | Auto-calculated | Very High |

## Requirements

### System
- Linux/macOS (Ubuntu 20.04+ recommended)
- Python 3.7+
- Network access to target subnets

### Tools (auto-installed if missing)
- `nmap` - ESXi host discovery
- `curl` - Web probing
- `ip` - Network interface detection

### Optional
- `testssl.sh` - SSL/TLS deep analysis
- `nuclei` - Vulnerability scanning
- `nikto` - Web vulnerability scanner

## Usage Scenarios

### Scenario 1: First-Time Setup
```bash
# New to the tool? Just run this!
./auto_assess.sh

# The tool handles everything:
# - Detects your network
# - Finds ESXi hosts
# - Runs the assessment
# - Generates reports
```

### Scenario 2: Scheduled Weekly Scans
```bash
# Add to crontab (crontab -e)
0 2 * * 0 cd /opt/esxi-stealth-va && python3 run_assessment.py --auto-network >> logs/cron.log 2>&1

# Every Sunday at 2 AM, the tool:
# - Auto-detects current network state
# - Runs assessment
# - Archives reports
# - Performs delta analysis
```

### Scenario 3: Quick Network Validation
```bash
# Just check the network without scanning
python3 run_assessment.py --auto-network --dry-run

# Takes <1 minute, shows what WOULD be scanned
```

### Scenario 4: Deep Forensic Assessment
```bash
# Thorough investigation of all 65535 ports
python3 run_assessment.py --auto-network --profile thorough --update

# Starts fresh, scans everything, detailed analysis
```

## Troubleshooting

### Issue: "nmap not found"
```bash
sudo apt-get install nmap
```

### Issue: "No subnets detected"
```bash
# Check your network
ip addr
ip route

# Check if you have connectivity
ping 8.8.8.8
```

### Issue: "ESXi host not detected"
The host might be on a non-standard port. Check manually:
```bash
nmap -sV 10.251.2.0/24
```

Or use manual configuration:
```bash
# Edit config/assessment.yaml with known ESXi IP
python3 run_assessment.py
```

### Issue: "Permission denied"
Some scans need elevated privileges:
```bash
sudo python3 run_assessment.py --auto-network
```

## Migration from Manual Configuration

### Before (Manual):
```yaml
# config/assessment.yaml - Hardcoded values
target:
  ip: "10.251.2.28"

vm_discovery:
  subnets:
    - "10.251.2.0/24"
    - "192.168.157.0/24"
  exclude_ips:
    - "10.251.2.1"
    - "10.251.2.25"
    - "10.251.2.28"
    - "10.251.2.255"
```

### After (Automatic):
```bash
# One-liner, everything auto-detected
python3 run_assessment.py --auto-network
```

## Advanced Configuration

### Combine Auto-Network with Custom Profile
```bash
# Auto-detect + use quick scan profile
python3 run_assessment.py --auto-network --profile quick

# Auto-detect + use thorough scan profile
python3 run_assessment.py --auto-network --profile thorough
```

### Resume Failed Assessment
```bash
# If assessment fails at Phase 5, resume from there
python3 run_assessment.py --auto-network --phase 5

# Auto-network detection runs first, then resumes from Phase 5
```

### Dry-Run with Different Profile
```bash
# Test configuration before long scan
python3 run_assessment.py --auto-network --dry-run --profile thorough

# Validates setup without actually scanning
```

## Security & Compliance

✅ **Authorized Assessment Only** - Designed for internal security testing  
✅ **Stealth Timing** - Uses conservative scanning profiles  
✅ **Auto Exclusions** - Critical IPs excluded automatically  
✅ **Full Logging** - All activities recorded for audit  
✅ **CyberArk Integration** - Compatible with PSM monitoring  

## Performance

| Profile | Typical Duration | Ports Scanned |
|---------|------------------|---------------|
| Quick | 15-30 min | Top 1,000 |
| Standard | 30-60 min | Top 10,000 |
| Thorough | 2-4 hours | All 65,535 |

*Times vary based on network size and response times*

## Support & Documentation

- **Quick Start:** [AUTO_NETWORK_QUICK_REF.md](AUTO_NETWORK_QUICK_REF.md)
- **Full Docs:** [AUTO_NETWORK_DETECTION.md](AUTO_NETWORK_DETECTION.md)
- **Source Code:** `orchestrator/network_detector.py`
- **Integration:** `run_assessment.py --auto-network`

## Next Steps

1. **Test it out:**
   ```bash
   python3 run_assessment.py --auto-network --dry-run
   ```

2. **Run your first assessment:**
   ```bash
   python3 run_assessment.py --auto-network
   ```

3. **Review the reports:**
   ```bash
   cat output/assessment_report.json
   open output/assessment_report.html  # on macOS
   ```

4. **Schedule for production:**
   ```bash
   crontab -e
   # Add: 0 2 * * 0 cd /opt/esxi-stealth-va && python3 run_assessment.py --auto-network
   ```

---

**That's it!** The ESXi Stealth VA tool now automatically detects your network and runs comprehensive security assessments without manual configuration. 🎉
