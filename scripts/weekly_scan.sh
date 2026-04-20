#!/bin/bash
# ============================================================================
# Weekly ESXi Pentest Scan — Cron Entry Point
# ============================================================================
# This script is intended to be run via a weekly cron job.
# It ensures the framework is updated (git pull / nuclei templates)
# and runs the full assessment pipeline with the 'standard' profile.
# 
# Installation:
#   crontab -e
#   0 2 * * 0 /opt/esxi-stealth-va/scripts/weekly_scan.sh
# ============================================================================

set -euo pipefail

# Get framework root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Switch to framework root
cd "$FRAMEWORK_ROOT"

TIMESTAMP=$(date +"%Y%m%d")
LOG_FILE="$FRAMEWORK_ROOT/logs/weekly_scan_$TIMESTAMP.log"

echo "[$(date)] Starting weekly ESXi security assessment..." | tee -a "$LOG_FILE"

# Ensure log directory exists
mkdir -p "$FRAMEWORK_ROOT/logs"

# Execute assessment with --update (Phase 0) and --profile standard
# We use stdbuf to disable buffering for the tee command
stdbuf -oL python3 run_assessment.py --update --profile standard 2>&1 | tee -a "$LOG_FILE"

# Check exit status
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "[$(date)] Weekly assessment completed successfully." | tee -a "$LOG_FILE"
else
    echo "[$(date)] ERROR: Weekly assessment failed. Check log: $LOG_FILE" | tee -a "$LOG_FILE"
    # Optional: Send alert email/webhook here
fi
