#!/bin/bash
# ============================================================================
# ESXi Pentest Framework — One-Shot Installer
# ============================================================================
# Installs all required system dependencies on the scanning VM.
# Supported OS: Debian, Ubuntu, Kali, RHEL, CentOS, SUSE
# ============================================================================

set -e

echo "----------------------------------------------------------------------"
echo "  ESXi Stealth VA Framework Installer"
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
case "$OS" in
    ubuntu|debian|kali)
        sudo apt-get update
        sudo apt-get install -y nmap curl python3-pip nikto git
        ;;
    centos|rhel|almalinux)
        sudo yum check-update || true
        sudo yum install -y nmap curl python3-pip git
        # Nikto usually requires EPEL
        sudo yum install -y epel-release || true
        sudo yum install -y nikto || true
        ;;
    sles|opensuse*)
        sudo zypper refresh
        # SUSE often needs build headers for cryptography/other pip packages
        sudo zypper install -y nmap curl python3-pip nikto git unzip python3-devel libffi-devel libopenssl-devel
        ;;
    *)
        echo "OS $OS not explicitly supported. Please install nmap, curl, nikto, nuclei manually."
        ;;
esac

# 3. Install Nuclei (if not present)
if ! command -v nuclei &> /dev/null; then
    echo "[*] Installing Nuclei..."
    # We use the official install script or download binary
    # Simple binary download for stability
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then N_ARCH="amd64"; else N_ARCH="386"; fi
    VERSION="3.2.0"
    TEMP_DIR=$(mktemp -d)
    curl -L "https://github.com/projectdiscovery/nuclei/releases/download/v${VERSION}/nuclei_${VERSION}_linux_${N_ARCH}.zip" -o "$TEMP_DIR/nuclei.zip"
    unzip "$TEMP_DIR/nuclei.zip" -d "$TEMP_DIR"
    sudo mv "$TEMP_DIR/nuclei" /usr/local/bin/
    chmod +x /usr/local/bin/nuclei
    rm -rf "$TEMP_DIR"
    echo "[+] Nuclei installed."
fi

# 4. Install Python Dependencies
echo "[*] Installing Python dependencies..."
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
# Compare versions using python for portability
IS_LEGACY=$(python3 -c "import sys; print(1 if sys.version_info < (3, 7) else 0)")

if [ "$IS_LEGACY" -eq 1 ]; then
    echo "[!] Legacy Python detected ($PYTHON_VERSION). Using requirements_legacy.txt"
    pip3 install -r requirements_legacy.txt
else
    pip3 install -r requirements.txt
fi

# 5. Initialize Nuclei Templates
echo "[*] Initializing Nuclei templates..."
nuclei -ut || echo "Warning: Nuclei template update failed (offline?)."

# 6. Create Directories
echo "[*] Creating environment..."
mkdir -p output/history logs

echo "----------------------------------------------------------------------"
echo "  Installation Complete!"
echo "----------------------------------------------------------------------"
echo "  To start a test run:"
echo "    python3 run_assessment.py --mock"
echo ""
echo "  To schedule weekly scans:"
echo "    Add scripts/weekly_scan.sh to your crontab."
echo "----------------------------------------------------------------------"
