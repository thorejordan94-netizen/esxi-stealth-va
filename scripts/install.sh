#!/usr/bin/env bash
# ESXi Stealth VA - resilient one-shot installer
set -Eeuo pipefail

cd "$(dirname "$0")/.."

OFFLINE_MODE=false
PROXY_HOST="${PROXY_HOST:-}"
PROXY_PORT="${PROXY_PORT:-}"
PROXY_URL=""

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE_MODE=true ;;
    --proxy=*) PROXY_HOST="${arg#--proxy=}" ;;
    --proxy-port=*) PROXY_PORT="${arg#--proxy-port=}" ;;
  esac
done

if [[ -n "$PROXY_HOST" ]]; then
  if [[ "$PROXY_HOST" == http://* || "$PROXY_HOST" == https://* ]]; then
    PROXY_URL="$PROXY_HOST"
  else
    PROXY_URL="http://${PROXY_HOST}${PROXY_PORT:+:$PROXY_PORT}"
  fi
  export http_proxy="$PROXY_URL" https_proxy="$PROXY_URL"
  export HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL"
  export no_proxy="localhost,127.0.0.1"
  echo "[*] Using proxy: $PROXY_URL"
fi

run_root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "[!] Administrator access is required. Run as root or install sudo."
    return 1
  fi
}

warn_optional() {
  echo "[!] Optional component unavailable: $1"
  echo "[!] Core installation will continue. You can install it later."
}

echo "----------------------------------------------------------------------"
echo "  ESXi Stealth VA Framework Installer $($OFFLINE_MODE && echo '[OFFLINE MODE]')"
echo "----------------------------------------------------------------------"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  OS="${ID:-unknown}"
else
  OS="unknown"
fi
echo "[*] Detecting OS: $OS"

install_packages() {
  $OFFLINE_MODE && {
    echo "[!] Offline mode: package downloads skipped."
    return 0
  }

  case "$OS" in
    ubuntu|debian|kali)
      run_root apt-get update
      run_root apt-get install -y nmap curl python3 python3-pip git unzip ca-certificates iproute2
      run_root apt-get install -y nikto || warn_optional "nikto"
      ;;
    fedora|rhel|centos|almalinux|rocky)
      local pm="yum"
      command -v dnf >/dev/null 2>&1 && pm="dnf"
      run_root "$pm" install -y nmap curl python3 python3-pip git unzip ca-certificates iproute
      run_root "$pm" install -y nikto || warn_optional "nikto"
      ;;
    sles|opensuse*|opensuse-leap|opensuse-tumbleweed)
      run_root zypper --non-interactive refresh || echo "[!] Repository refresh failed; using available package metadata."
      local pkg
      for pkg in nmap curl python3 python3-pip python311 python311-pip git unzip ca-certificates iproute2; do
        run_root zypper --non-interactive install "$pkg" >/dev/null 2>&1 || true
      done
      ;;
    *)
      echo "[!] Unsupported package manager. Required tools will be checked below."
      ;;
  esac
}

install_packages

for required in python3 nmap curl git; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "[ERROR] Required program is missing: $required"
    echo "Install it with your OS package manager, then run this installer again."
    exit 1
  fi
done

PYTHON_VERSION="$(python3 -c 'import sys; print("%s.%s" % sys.version_info[:2])')"
if python3 -c 'import sys; raise SystemExit(0 if sys.version_info < (3,7) else 1)'; then
  REQ_FILE="requirements_legacy.txt"
  WHEEL_DIR="./wheels/legacy"
  echo "[!] Legacy Python detected ($PYTHON_VERSION)."
else
  REQ_FILE="requirements.txt"
  WHEEL_DIR="./wheels/modern"
fi

echo "[*] Installing Python dependencies from $REQ_FILE..."
if $OFFLINE_MODE; then
  python3 -m pip install --no-index --find-links="$WHEEL_DIR" -r "$REQ_FILE" --break-system-packages 2>/dev/null \
    || python3 -m pip install --no-index --find-links="$WHEEL_DIR" -r "$REQ_FILE"
else
  PIP_ARGS=()
  [[ -n "$PROXY_URL" ]] && PIP_ARGS+=(--proxy "$PROXY_URL")
  python3 -m pip install "${PIP_ARGS[@]}" -r "$REQ_FILE" --break-system-packages 2>/dev/null \
    || python3 -m pip install "${PIP_ARGS[@]}" -r "$REQ_FILE"
fi

mkdir -p output/history logs

# Nuclei is useful but not required for discovery, enumeration, TLS, or web checks.
if command -v nuclei >/dev/null 2>&1; then
  echo "[*] Nuclei already installed."
  $OFFLINE_MODE || nuclei -ut || warn_optional "Nuclei templates"
elif $OFFLINE_MODE; then
  if [[ -x ./bin/nuclei ]]; then
    run_root cp ./bin/nuclei /usr/local/bin/nuclei
    run_root chmod +x /usr/local/bin/nuclei
  else
    warn_optional "Nuclei (no offline binary in ./bin)"
  fi
else
  echo "[*] Nuclei is not installed. Phase 1 may install it later when internet access is available."
  warn_optional "Nuclei"
fi

# testssl.sh is optional. DNS/proxy/internet failure must never abort setup.
if [[ -x scripts/optional_tools.sh ]]; then
  bash scripts/optional_tools.sh "$@" || true
elif command -v testssl.sh >/dev/null 2>&1; then
  echo "[*] testssl.sh already installed."
else
  warn_optional "testssl.sh"
fi

echo "----------------------------------------------------------------------"
echo "  Installation complete."
echo "----------------------------------------------------------------------"
echo "  Harmless test run: python3 run_assessment.py --mock"
echo "  Guided launcher:    ./easy_assessment.sh"
echo "----------------------------------------------------------------------"
