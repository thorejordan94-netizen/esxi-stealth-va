#!/bin/bash
#
# ESXi Stealth VA - Automatic Network Detection & Assessment
# =========================================================
#
# This script automatically detects the local network and runs
# a comprehensive security assessment on ESXi hosts and VMs
# without requiring manual configuration.
#
# Usage:
#   ./auto_assess.sh                           # Full auto assessment
#   ./auto_assess.sh --profile quick           # Fast scan
#   ./auto_assess.sh --profile thorough        # Deep scan
#   ./auto_assess.sh --dry-run                 # Validate config only
#   ./auto_assess.sh --mock                    # Synthetic data (testing)
#
# Requirements:
#   - Python 3.7+
#   - nmap
#   - curl
#   - Root or sudo access (for network discovery)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ESXi Stealth VA - Automatic Network Detection & Assessment     ║"
echo "║  Initializing dynamic network detection...                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python availability
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python 3 is not installed. Please install Python 3.7+"
    exit 1
fi

# Check for required tools
MISSING_TOOLS=0
for tool in nmap curl; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${YELLOW}[WARNING]${NC} $tool not found. Some features may be limited."
        if [ "$tool" = "nmap" ]; then
            MISSING_TOOLS=1
        fi
    fi
done

if [ $MISSING_TOOLS -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}Installing missing dependencies...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y nmap curl > /dev/null 2>&1 || true
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap curl > /dev/null 2>&1 || true
    fi
fi

# Check for network interfaces
echo ""
echo -e "${BLUE}[1/3]${NC} Detecting network interfaces..."
if [ ! -x "$(command -v ip)" ]; then
    echo -e "${RED}[ERROR]${NC} 'ip' command not found. Cannot detect network."
    exit 1
fi

INTERFACES=$(ip -br addr | grep -v lo | awk '{print $1}' | head -5)
if [ -z "$INTERFACES" ]; then
    echo -e "${RED}[ERROR]${NC} No network interfaces found."
    exit 1
fi

echo -e "${GREEN}✓ Network interfaces detected:${NC}"
echo "$INTERFACES" | sed 's/^/   /'

# Run the auto-network assessment
echo ""
echo -e "${BLUE}[2/3]${NC} Running automatic network detection..."
PYTHON_CMD="python3 run_assessment.py --auto-network"

# Add any additional arguments passed to this script
if [ $# -gt 0 ]; then
    PYTHON_CMD="$PYTHON_CMD $@"
fi

echo -e "${GREEN}Command:${NC} $PYTHON_CMD"
echo ""

# Execute with proper error handling
if $PYTHON_CMD; then
    echo ""
    echo -e "${GREEN}✓ Assessment completed successfully!${NC}"
    echo ""
    
    # Display report locations
    if [ -f "output/assessment_report.json" ]; then
        echo -e "${BLUE}[3/3]${NC} Reports generated:"
        ls -lh output/assessment_report.* 2>/dev/null | awk '{print "   " $NF " (" $5 ")"}'
    fi
    
    exit 0
else
    echo ""
    echo -e "${RED}✗ Assessment failed!${NC}"
    echo -e "${YELLOW}Check logs in: logs/assessment_*.log${NC}"
    exit 1
fi
