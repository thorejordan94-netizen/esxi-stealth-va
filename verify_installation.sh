#!/bin/bash
#
# Verification Script for Auto-Network Detection Feature
# ======================================================
#
# This script validates that the auto-network detection feature
# is properly installed and functional.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Auto-Network Detection - Verification Script                   ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

TEST_PASS=0
TEST_FAIL=0

# Test function
run_test() {
    local test_name="$1"
    local test_cmd="$2"

    echo -n "Testing: $test_name... "

    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((TEST_PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((TEST_FAIL++))
    fi
}

# Verification Tests

echo ""
echo -e "${BLUE}[1/5] File Structure${NC}"
echo "─────────────────────────────────────────────────────────────"

run_test "network_detector.py exists" "[ -f orchestrator/network_detector.py ]"
run_test "auto_assess.sh exists" "[ -f auto_assess.sh ]"
run_test "auto_assess.sh is executable" "[ -x auto_assess.sh ]"
run_test "AUTO_NETWORK_README.md exists" "[ -f AUTO_NETWORK_README.md ]"
run_test "AUTO_NETWORK_DETECTION.md exists" "[ -f AUTO_NETWORK_DETECTION.md ]"
run_test "AUTO_NETWORK_QUICK_REF.md exists" "[ -f AUTO_NETWORK_QUICK_REF.md ]"
run_test "IMPLEMENTATION_SUMMARY.md exists" "[ -f IMPLEMENTATION_SUMMARY.md ]"

echo ""
echo -e "${BLUE}[2/5] Python Syntax${NC}"
echo "─────────────────────────────────────────────────────────────"

run_test "network_detector.py syntax" "python3 -m py_compile orchestrator/network_detector.py"
run_test "run_assessment.py syntax" "python3 -m py_compile run_assessment.py"

echo ""
echo -e "${BLUE}[3/5] Module Imports${NC}"
echo "─────────────────────────────────────────────────────────────"

run_test "network_detector imports" "python3 -c 'from orchestrator.network_detector import auto_detect_network, update_config_with_detected_network; print(1)'"
run_test "run_assessment imports" "python3 -c 'import run_assessment; print(1)'"

echo ""
echo -e "${BLUE}[4/5] CLI Interface${NC}"
echo "─────────────────────────────────────────────────────────────"

run_test "--auto-network flag exists" "python3 run_assessment.py --help | grep -q 'auto-network'"
run_test "--help shows new flag" "python3 run_assessment.py --help | grep -q 'Automatically detect network'"

echo ""
echo -e "${BLUE}[5/5] Tool Availability${NC}"
echo "─────────────────────────────────────────────────────────────"

run_test "Python 3 available" "command -v python3"
run_test "ip command available" "command -v ip"
run_test "curl available" "command -v curl"

if command -v nmap &> /dev/null; then
    run_test "nmap available" "command -v nmap"
else
    echo -n "Testing: nmap available... ${YELLOW}⚠ OPTIONAL${NC}"
    echo " (Not required but recommended)"
fi

# Summary
echo ""
echo "─────────────────────────────────────────────────────────────"
echo -e "Results: ${GREEN}${TEST_PASS} passed${NC}, ${RED}${TEST_FAIL} failed${NC}"
echo "─────────────────────────────────────────────────────────────"

if [ $TEST_FAIL -eq 0 ]; then
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║     ✓ All tests passed!                               ║"
    echo "║     Auto-Network Detection is ready to use!           ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo ""
    echo "Quick Start Commands:"
    echo "  python3 run_assessment.py --auto-network --dry-run"
    echo "  python3 run_assessment.py --auto-network"
    echo "  ./auto_assess.sh"
    echo ""

    exit 0
else
    echo -e "${RED}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║     ✗ Some tests failed                               ║"
    echo "║     Please check the errors above                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    exit 1
fi
