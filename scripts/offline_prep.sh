#!/bin/bash
# ============================================================================
# ESXi Pentest Framework — Offline Preparation Script
# ============================================================================
# Run this on a machine WITH internet access to download all 
# dependencies needed for an air-gapped deployment.
# ============================================================================

set -e

# Proxy Configuration
PROXY_HOST="${PROXY_HOST:-}"
PROXY_PORT="${PROXY_PORT:-}"

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
echo "  ESXi Stealth VA — Air-Gap Preparation"
echo "----------------------------------------------------------------------"

# 1. Create Transfer Bundle Directory
BUNDLE_DIR="transfer_bundle"
mkdir -p "$BUNDLE_DIR/bin"
mkdir -p "$BUNDLE_DIR/wheels"
mkdir -p "$BUNDLE_DIR/templates"

echo "[*] Bundle directory created: $BUNDLE_DIR"

# 2. Download Nuclei Binary
N_VERSION="3.2.0"
N_ARCH="amd64"
N_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${N_VERSION}/nuclei_${N_VERSION}_linux_${N_ARCH}.zip"

echo "[*] Downloading Nuclei v${N_VERSION}..."
if [ -n "$PROXY_URL" ]; then
    curl -x "$PROXY_URL" -L "$N_URL" -o "$BUNDLE_DIR/bin/nuclei.zip"
else
    curl -L "$N_URL" -o "$BUNDLE_DIR/bin/nuclei.zip"
fi
unzip -o "$BUNDLE_DIR/bin/nuclei.zip" -d "$BUNDLE_DIR/bin/"
rm "$BUNDLE_DIR/bin/nuclei.zip"
chmod +x "$BUNDLE_DIR/bin/nuclei"

# 3. Download Nuclei Templates (tarball)
# We can't easily get a release zip of templates, so we clone and tar
echo "[*] Downloading Nuclei Templates..."
rm -rf "$BUNDLE_DIR/templates/nuclei-templates"
if [ -n "$PROXY_URL" ]; then
    git config --global http.proxy "$PROXY_URL"
    git config --global https.proxy "$PROXY_URL"
fi
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$BUNDLE_DIR/templates/nuclei-templates"
tar -czf "$BUNDLE_DIR/templates/nuclei-templates.tar.gz" -C "$BUNDLE_DIR/templates" nuclei-templates
rm -rf "$BUNDLE_DIR/templates/nuclei-templates"

# 4. Download Python Wheels (Modern)
echo "[*] Downloading Python Wheels (Modern - Python 3.7+)..."
if [ -n "$PROXY_URL" ]; then
    pip download -r requirements.txt -d "$BUNDLE_DIR/wheels/modern" --platform manylinux2014_x86_64 --only-binary=:all: --proxy "$PROXY_URL"
else
    pip download -r requirements.txt -d "$BUNDLE_DIR/wheels/modern" --platform manylinux2014_x86_64 --only-binary=:all:
fi

# 5. Download Python Wheels (Legacy - Python 3.6)
echo "[*] Downloading Python Wheels (Legacy - Python 3.6)..."
if [ -n "$PROXY_URL" ]; then
    pip download -r requirements_legacy.txt -d "$BUNDLE_DIR/wheels/legacy" \
        --platform manylinux2014_x86_64 \
        --python-version 36 \
        --only-binary=:all: --proxy "$PROXY_URL" || echo "Warning: Some legacy wheels might need manual download if not available as binaries."
else
    pip download -r requirements_legacy.txt -d "$BUNDLE_DIR/wheels/legacy" \
        --platform manylinux2014_x86_64 \
        --python-version 36 \
        --only-binary=:all: || echo "Warning: Some legacy wheels might need manual download if not available as binaries."
fi

# 6. Copy Installer and Scripts
echo "[*] Packing scripts..."
cp scripts/install.sh "$BUNDLE_DIR/"
cp requirements.txt "$BUNDLE_DIR/"
cp requirements_legacy.txt "$BUNDLE_DIR/"

# 7. Final Package
echo "[*] Creating final transfer package..."
tar -czf transfer_package.tar.gz "$BUNDLE_DIR"

echo "----------------------------------------------------------------------"
echo "  Success! One file created: transfer_package.tar.gz"
echo "----------------------------------------------------------------------"
echo "  Instructions:"
echo "  1. Copy transfer_package.tar.gz to the isolated server."
echo "  2. Extract: tar -xzf transfer_package.tar.gz"
echo "  3. Change into bundle: cd $BUNDLE_DIR"
echo "  4. Run offline installer: sudo ./install.sh --offline"
echo "----------------------------------------------------------------------"
