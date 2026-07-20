#!/bin/bash
# Compatibility launcher for the comprehensive automatic assessment.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required."
    exit 1
fi

exec python3 "$SCRIPT_DIR/master_assessment.py" "$@"
