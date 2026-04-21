#!/bin/bash
# ============================================================================
# ESXi Pentest Framework — One-Shot Installer
# ============================================================================
# Installs all required system dependencies on the scanning VM.
# Supported OS: Debian, Ubuntu, Kali, RHEL, CentOS, SUSE
# ============================================================================

set -e

# Proxy Configuration
PROXY_HOST="${PROXY_HOST:-}"
PROXY_PORT="${PROXY_PORT:-}"
OFFLINE_MODE=false

if [[ "$*" == *"--offline"* ]]; then
    OFFLINE_MODE=true
fi

if [[ "$*" == *"--proxy="* ]]; then
    PROXY_HOST=$(echo "$*" | grep -oP '(?<=--proxy=)[^[:space:]]*' | head -1)
fi

if [[ "$*" == *"--proxy-port="* ]]; then
    PROXY_PORT=$(echo "$*" | grep -oP '(?<=--proxy-port=)[^[:space:]]*' | head -1)
fi

# Set proxy environment variables if configured
if [ -n "$PROXY_HOST" ]; then
    PROXY_URL="http://$PROXY_HOST${PROXY_PORT:+:$PROXY_PORT}"
    export http_proxy="$PROXY_URL"
    export https_proxy="$PROXY_URL"
    export HTTP_PROXY="$PROXY_URL"
    export HTTPS_PROXY="$PROXY_URL"
    export no_proxy="localhost,127.0.0.1"
    echo "[*] Using proxy: $PROXY_URL"
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
            if [ -n "$PROXY_URL" ]; then
                sudo apt-get -o Acquire::http::Proxy="$PROXY_URL" -o Acquire::https::Proxy="$PROXY_URL" update
                sudo apt-get -o Acquire::http::Proxy="$PROXY_URL" -o Acquire::https::Proxy="$PROXY_URL" install -y nmap curl python3-pip nikto git unzip
            else
                sudo apt-get update
                sudo apt-get install -y nmap curl python3-pip nikto git unzip
            fi
            ;;
        centos|rhel|almalinux)
            if [ -n "$PROXY_URL" ]; then
                sudo yum --httpproxy="$PROXY_URL" check-update || true
                sudo yum --httpproxy="$PROXY_URL" install -y nmap curl python3-pip git unzip
                sudo yum --httpproxy="$PROXY_URL" install -y epel-release || true
                sudo yum --httpproxy="$PROXY_URL" install -y nikto || true
            else
                sudo yum check-update || true
                sudo yum install -y nmap curl python3-pip git unzip
                sudo yum install -y epel-release || true
                sudo yum install -y nikto || true
            fi
            ;;
        sles|opensuse*)
            if [ -n "$PROXY_URL" ]; then
                echo "[*] Configuring zypper with proxy..."
                sudo zypper ar --no-gpg-check --priority 100 "https://download.opensuse.org/distribution/leap/15.6/repo/oss/" "OSS-$RANDOM" 2>/dev/null || true
                sudo zypper refresh -f -q 2>/dev/null || echo "[!] Warning: Repository refresh had issues, continuing anyway..."
                sudo zypper -p "$PROXY_URL" install -y nmap curl python3-pip nikto git unzip python3-devel libffi-devel libopenssl-devel 2>&1 || {
                    echo "[!] zypper install failed, trying with --no-gpg-check..."
                    sudo zypper --no-gpg-check -p "$PROXY_URL" install -y nmap curl python3-pip nikto git unzip python3-devel libffi-devel libopenssl-devel || true
                }
            else
                echo "[*] Refreshing zypper repositories..."
                sudo zypper refresh -f -q 2>/dev/null || echo "[!] Warning: Repository refresh had issues, continuing anyway..."
                sudo zypper install -y nmap curl python3-pip nikto git unzip python3-devel libffi-devel libopenssl-devel 2>&1 || {
                    echo "[!] zypper install failed, trying with --no-gpg-check..."
                    sudo zypper --no-gpg-check install -y nmap curl python3-pip nikto git unzip python3-devel libffi-devel libopenssl-devel || true
                }
            fi
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
        if [ -n "$PROXY_URL" ]; then
            curl -x "$PROXY_URL" -L "https://github.com/projectdiscovery/nuclei/releases/download/v${VERSION}/nuclei_${VERSION}_linux_${N_ARCH}.zip" -o "$TEMP_DIR/nuclei.zip"
        else
            curl -L "https://github.com/projectdiscovery/nuclei/releases/download/v${VERSION}/nuclei_${VERSION}_linux_${N_ARCH}.zip" -o "$TEMP_DIR/nuclei.zip"
        fi
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
    if [ -n "$PROXY_URL" ]; then
        pip3 install --proxy "[user:passwd@]proxy.server:port" -r "$REQ_FILE" || \
        pip3 install --proxy "$PROXY_URL" -r "$REQ_FILE"
    else
        pip3 install -r "$REQ_FILE"
    fi
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
