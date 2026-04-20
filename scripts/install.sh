#!/bin/bash
# ============================================================================
# ESXi Pentest Framework — One-Shot Installer
# ============================================================================
# Installs all required system dependencies on the scanning VM.
# Supported OS: Debian, Ubuntu, Kali, RHEL, CentOS, SUSE
# ============================================================================

set -e

OFFLINE_MODE=false
if [[ "$*" == *"--offline"* ]]; then
    OFFLINE_MODE=true
fi

echo "----------------------------------------------------------------------"
echo "  ESXi Stealth VA Framework Installer $([ "$OFFLINE_MODE" = true ] && echo "[OFFLINE MODE]")"
echo "----------------------------------------------------------------------"

# 1. Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Unsupported OS"
    exit 1
fi

echo "[*] Detecting OS: $OS"

# 2. Install System Tools
if [ "$OFFLINE_MODE" = false ]; then
    case "$OS" in
        ubuntu|debian|kali)
            sudo apt-get update
            sudo apt-get install -y nmap curl python3-pip nikto git unzip
            ;;
        centos|rhel|almalinux)
            sudo yum check-update || true
            sudo yum install -y nmap curl python3-pip git unzip
            sudo yum install -y epel-release || true
            sudo yum install -y nikto || true
            ;;
        sles|opensuse*)
            sudo zypper refresh
            sudo zypper install -y nmap curl python3-pip nikto git unzip python3-devel libffi-devel libopenssl-devel
            ;;
        *)
            echo "OS $OS not explicitly supported. Install nmap, curl, nikto, nuclei manually."
            ;;
    esac
else
    echo "[!] Offline mode: Skipping system repository updates and tool installations."
    echo "[!] Ensure nmap and python3 are already installed on this system."
fi

# 3. Install Nuclei
if command -v nuclei &> /dev/null; then
    echo "[*] Nuclei already installed."
else
    if [ "$OFFLINE_MODE" = true ] && [ -f "./bin/nuclei" ]; then
        echo "[*] Installing Nuclei from local bin/..."
        sudo cp ./bin/nuclei /usr/local/bin/
        sudo chmod +x /usr/local/bin/nuclei
    elif [ "$OFFLINE_MODE" = false ]; then
        echo "[*] Downloading Nuclei..."
        ARCH=$(uname -m)
        if [ "$ARCH" = "x86_64" ]; then N_ARCH="amd64"; else N_ARCH="386"; fi
        VERSION="3.2.0"
        TEMP_DIR=$(mktemp -d)
        curl -L "https://github.com/projectdiscovery/nuclei/releases/download/v${VERSION}/nuclei_${VERSION}_linux_${N_ARCH}.zip" -o "$TEMP_DIR/nuclei.zip"
        unzip -o "$TEMP_DIR/nuclei.zip" -d "$TEMP_DIR"
        sudo mv "$TEMP_DIR/nuclei" /usr/local/bin/
        sudo chmod +x /usr/local/bin/nuclei
        rm -rf "$TEMP_DIR"
    else
        echo "[!] Error: No nuclei binary found in bin/ and offline mode is active."
        exit 1
    fi
fi

# 4. Install Python Dependencies
echo "[*] Installing Python dependencies..."
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
IS_LEGACY=$(python3 -c "import sys; print(1 if sys.version_info < (3, 7) else 0)")

REQ_FILE="requirements.txt"
WHEEL_DIR="./wheels/modern"
if [ "$IS_LEGACY" -eq 1 ]; then
    echo "[!] Legacy Python detected ($PYTHON_VERSION)."
    REQ_FILE="requirements_legacy.txt"
    WHEEL_DIR="./wheels/legacy"
fi

if [ "$OFFLINE_MODE" = true ]; then
    echo "[*] Performing offline pip install from $WHEEL_DIR..."
    pip3 install --no-index --find-links="$WHEEL_DIR" -r "$REQ_FILE"
else
    pip3 install -r "$REQ_FILE"
fi

# 5. Initialize Nuclei Templates
if [ "$OFFLINE_MODE" = true ]; then
    if [ -f "./templates/nuclei-templates.tar.gz" ]; then
        echo "[*] Offline mode: Templates will be initialized during the first run (Phase 0)."
    fi
else
    echo "[*] Initializing Nuclei templates..."
    nuclei -ut || echo "Warning: Nuclei template update failed."
fi

# 6. Create Directories
echo "[*] Creating environment..."
mkdir -p output/history logs

echo "----------------------------------------------------------------------"
echo "  Installation Complete!"
echo "----------------------------------------------------------------------"
echo "  To start a test run:"
    echo "    python3 run_assessment.py --mock"
echo "----------------------------------------------------------------------"
