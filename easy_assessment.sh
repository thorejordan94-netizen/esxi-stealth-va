#!/usr/bin/env bash
# ESXi Stealth VA - guided setup and assessment launcher
set -Eeuo pipefail

REPO_URL="${ESXI_VA_REPO_URL:-https://github.com/thorejordan94-netizen/esxi-stealth-va.git}"
INSTALL_DIR="${ESXI_VA_INSTALL_DIR:-${HOME}/esxi-stealth-va}"
ASSUME_YES=false
OFFLINE=false
PROXY=""
PROJECT_DIR=""
LOG_FILE=""

if [[ -t 1 ]]; then
  BOLD='\033[1m'; BLUE='\033[34m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
else
  BOLD=''; BLUE=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

info() { printf "%b[INFO]%b %s\n" "$BLUE" "$RESET" "$*"; }
ok() { printf "%b[OK]%b %s\n" "$GREEN" "$RESET" "$*"; }
warn() { printf "%b[WARN]%b %s\n" "$YELLOW" "$RESET" "$*"; }
fail() { printf "%b[ERROR]%b %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }

on_error() {
  local rc=$?
  printf "\n%bSomething stopped unexpectedly.%b\n" "$RED" "$RESET" >&2
  printf "Command: %s\nExit code: %s\n" "${BASH_COMMAND:-unknown}" "$rc" >&2
  [[ -n "$LOG_FILE" ]] && printf "Log: %s\n" "$LOG_FILE" >&2
  exit "$rc"
}
trap on_error ERR

usage() {
  cat <<USAGE
Usage: bash easy_assessment.sh [options]

Options:
  --yes                 Accept safe defaults and reduce questions.
  --install-dir PATH    Project installation directory.
  --offline             Do not download packages or update the repository.
  --proxy URL           HTTP/HTTPS proxy, for example http://proxy:8080.
  --help                 Show this help.

Supports Linux distributions using apt, dnf/yum, or zypper.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) ASSUME_YES=true; shift ;;
    --offline) OFFLINE=true; shift ;;
    --install-dir) [[ $# -ge 2 ]] || fail "--install-dir requires a path"; INSTALL_DIR="$2"; shift 2 ;;
    --proxy) [[ $# -ge 2 ]] || fail "--proxy requires a URL"; PROXY="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

banner() {
  clear 2>/dev/null || true
  printf "%b" "$BOLD"
  cat <<'BANNER'
============================================================
 ESXi Stealth VA - Guided Setup and Security Assessment
============================================================
BANNER
  printf "%b" "$RESET"
  echo "This assistant installs what is missing, checks the setup,"
  echo "and guides you through a safe internal assessment."
  echo
}

pause() {
  $ASSUME_YES && return 0
  read -r -p "Press Enter to continue... " _
}

ask_yes_no() {
  local prompt="$1" default="${2:-yes}" answer
  if $ASSUME_YES; then
    [[ "$default" == "yes" ]]
    return
  fi
  if [[ "$default" == "yes" ]]; then
    read -r -p "$prompt [Y/n]: " answer
    answer="${answer:-y}"
  else
    read -r -p "$prompt [y/N]: " answer
    answer="${answer:-n}"
  fi
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

run_privileged() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "Administrator access is required, but sudo is not installed. Log in as root and run this file again."
  fi
}

set_proxy() {
  [[ -z "$PROXY" ]] && return 0
  export http_proxy="$PROXY" https_proxy="$PROXY" HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
  info "Using proxy: $PROXY"
}

package_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  elif command -v zypper >/dev/null 2>&1; then echo zypper
  else echo unknown
  fi
}

bootstrap_basics() {
  local missing=() cmd pm
  for cmd in git curl python3; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  $OFFLINE && fail "Missing required programs in offline mode: ${missing[*]}"
  pm="$(package_manager)"
  info "Installing basic programs needed to continue: ${missing[*]}"
  case "$pm" in
    apt)
      run_privileged apt-get update
      run_privileged apt-get install -y git curl python3 python3-pip sudo ca-certificates
      ;;
    dnf)
      run_privileged dnf install -y git curl python3 python3-pip sudo ca-certificates
      ;;
    yum)
      run_privileged yum install -y git curl python3 python3-pip sudo ca-certificates
      ;;
    zypper)
      run_privileged zypper --non-interactive refresh || true
      run_privileged zypper --non-interactive install git curl python3 python3-pip sudo ca-certificates
      ;;
    *) fail "No supported package manager was found. Install git, curl, and Python 3, then rerun this file." ;;
  esac
}

find_or_install_project() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/run_assessment.py" && -d "$script_dir/orchestrator" ]]; then
    PROJECT_DIR="$script_dir"
  elif [[ -f "$INSTALL_DIR/run_assessment.py" && -d "$INSTALL_DIR/.git" ]]; then
    PROJECT_DIR="$INSTALL_DIR"
  else
    $OFFLINE && fail "The project is not installed and offline mode prevents downloading it."
    info "Downloading the project into: $INSTALL_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone "$REPO_URL" "$INSTALL_DIR"
    PROJECT_DIR="$INSTALL_DIR"
  fi
}

setup_logging() {
  mkdir -p "$PROJECT_DIR/logs"
  LOG_FILE="$PROJECT_DIR/logs/easy_assessment_$(date +%Y%m%d_%H%M%S).log"
  exec > >(tee -a "$LOG_FILE") 2>&1
  info "Session log: $LOG_FILE"
}

update_project() {
  cd "$PROJECT_DIR"
  if $OFFLINE; then warn "Offline mode: repository update skipped."; return 0; fi
  if [[ ! -d .git ]]; then warn "This copy is not a Git checkout. Update skipped."; return 0; fi
  if [[ -n "$(git status --porcelain)" ]]; then
    warn "Local project files have changes. Update skipped to avoid overwriting them."
    return 0
  fi
  info "Checking for project updates..."
  git pull --ff-only
  ok "Project is current."
}

repair_installation() {
  cd "$PROJECT_DIR"
  chmod +x scripts/install.sh auto_assess.sh verify_installation.sh easy_assessment.sh 2>/dev/null || true
  local args=()
  $OFFLINE && args+=(--offline)
  if [[ -n "$PROXY" ]]; then
    local hostport host port
    hostport="${PROXY#*://}"; hostport="${hostport%%/*}"
    host="${hostport%%:*}"; port="${hostport##*:}"
    args+=("--proxy=$host")
    [[ "$port" != "$host" ]] && args+=("--proxy-port=$port")
  fi
  info "Checking and installing project requirements. Administrator approval may be requested."
  bash scripts/install.sh "${args[@]}"
  mkdir -p output/history logs
  ok "Required software is installed."
}

missing_tools() {
  local cmd missing=()
  for cmd in python3 nmap curl git; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [[ -f "$PROJECT_DIR/requirements.txt" ]] || missing+=("requirements.txt")
  printf '%s\n' "${missing[@]}"
}

ensure_ready() {
  local missing
  missing="$(missing_tools)"
  if [[ -n "$missing" ]]; then
    warn "Some required items are missing: $(echo "$missing" | tr '\n' ' ')"
    repair_installation
  else
    ok "Core requirements are present."
  fi
}

show_network_summary() {
  echo
  printf "%bDetected network connections%b\n" "$BOLD" "$RESET"
  if command -v ip >/dev/null 2>&1; then
    ip -brief -4 address show scope global 2>/dev/null || true
    echo
    ip -4 route show 2>/dev/null | sed -n '1,8p' || true
  else
    warn "The 'ip' command is unavailable; the installer should add it with network tools."
  fi
  echo
  echo "Automatic discovery is restricted to configured private networks."
  echo "Public and oversized automatic scopes are rejected by default."
}

authorization_check() {
  echo
  printf "%bPermission check%b\n" "$BOLD" "$RESET"
  echo "Only scan systems you own or have explicit permission to assess."
  echo "The scan can create network traffic and security alerts."
  if ! ask_yes_no "Do you have permission to scan the connected private network?" no; then
    warn "Assessment cancelled. Installation and demo options remain available."
    return 1
  fi
}

choose_profile() {
  local choice
  echo
  echo "Choose how thorough the scan should be:"
  echo "  1) Quick     - safest first run; common ports; lowest traffic"
  echo "  2) Standard  - balanced coverage; recommended after Quick succeeds"
  echo "  3) Thorough  - all TCP ports; may take many hours; more traffic"
  if $ASSUME_YES; then echo quick; return 0; fi
  read -r -p "Selection [1]: " choice
  case "${choice:-1}" in
    1) echo quick ;;
    2) echo standard ;;
    3) echo thorough ;;
    *) warn "Unknown selection. Using Quick."; echo quick ;;
  esac
}

run_validation() {
  cd "$PROJECT_DIR"
  ensure_ready
  info "Running configuration and tool validation..."
  python3 run_assessment.py --auto-network --dry-run
  ok "Validation completed."
}

run_demo() {
  cd "$PROJECT_DIR"
  ensure_ready
  info "Running a harmless demonstration with made-up data. No systems will be scanned."
  python3 run_assessment.py --mock --profile quick --no-delta
  ok "Demonstration completed."
  open_report
}

run_real_assessment() {
  local profile
  cd "$PROJECT_DIR"
  ensure_ready
  show_network_summary
  authorization_check || return 0
  profile="$(choose_profile)"
  echo "Selected profile: $profile"
  if [[ "$profile" == "thorough" ]]; then
    warn "Thorough mode scans every TCP port and may run for several hours."
    ask_yes_no "Continue with Thorough mode?" no || return 0
  fi
  info "Running a validation pass before the real assessment..."
  python3 run_assessment.py --auto-network --dry-run
  ask_yes_no "Validation passed. Start the authorized assessment now?" yes || return 0
  info "Starting assessment. Leave this window open."
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    python3 run_assessment.py --auto-network --profile "$profile"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -E python3 run_assessment.py --auto-network --profile "$profile"
  else
    python3 run_assessment.py --auto-network --profile "$profile"
  fi
  ok "Assessment completed."
  open_report
}

open_report() {
  local report="$PROJECT_DIR/output/assessment_report.html"
  if [[ ! -f "$report" ]]; then
    warn "No HTML report exists yet. Run the demonstration or an assessment first."
    return 0
  fi
  echo "Report: $report"
  if command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    xdg-open "$report" >/dev/null 2>&1 || true
  elif command -v wslview >/dev/null 2>&1; then
    wslview "$report" >/dev/null 2>&1 || true
  else
    echo "Open that file in a web browser to view the report."
  fi
}

first_run() {
  banner
  set_proxy
  [[ "$(uname -s)" == "Linux" ]] || fail "This guided launcher currently supports Linux and WSL only."
  bootstrap_basics
  find_or_install_project
  setup_logging
  update_project
  echo
  echo "Recommended first-time path:"
  echo "  1. Install or repair requirements"
  echo "  2. Run harmless demonstration"
  echo "  3. Validate the real network setup"
  echo "  4. Run a Quick authorized assessment"
  echo
  if $ASSUME_YES; then
    repair_installation
    run_demo
    return 0
  fi
  if ask_yes_no "Is this the first time this project is being used on this computer?" yes; then
    repair_installation
    if ask_yes_no "Run the harmless demonstration now?" yes; then run_demo; fi
    if ask_yes_no "Validate the real network setup now?" yes; then run_validation; fi
  else
    ensure_ready
  fi
}

menu() {
  local choice
  while true; do
    echo
    printf "%bMain menu%b\n" "$BOLD" "$RESET"
    echo "  1) Install or repair everything"
    echo "  2) Run harmless demonstration"
    echo "  3) Validate network and tools"
    echo "  4) Run authorized assessment"
    echo "  5) Open latest report"
    echo "  6) Update project"
    echo "  7) Show paths and status"
    echo "  8) Exit"
    read -r -p "Choose an option [4]: " choice
    case "${choice:-4}" in
      1) repair_installation ;;
      2) run_demo ;;
      3) run_validation ;;
      4) run_real_assessment ;;
      5) open_report ;;
      6) update_project ;;
      7)
        echo "Project: $PROJECT_DIR"
        echo "Log:     $LOG_FILE"
        echo "Report:  $PROJECT_DIR/output/assessment_report.html"
        missing_tools | sed '/^$/d' | sed 's/^/Missing: /' || true
        ;;
      8) ok "Finished."; return 0 ;;
      *) warn "Please choose a number from 1 to 8." ;;
    esac
    pause
  done
}

first_run
$ASSUME_YES || menu
