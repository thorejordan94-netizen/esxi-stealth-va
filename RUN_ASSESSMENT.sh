#!/usr/bin/env bash
# One-click, end-to-end ESXi Stealth VA operator.
# No menus. No interactive workflow decisions. One launch produces one report.
set -Eeuo pipefail

REPO_URL="${ESXI_VA_REPO_URL:-https://github.com/thorejordan94-netizen/esxi-stealth-va.git}"
INSTALL_DIR="${ESXI_VA_INSTALL_DIR:-${HOME}/esxi-stealth-va}"
PROFILE="${ESXI_VA_PROFILE:-standard}"
PROXY="${ESXI_VA_PROXY:-}"
FORCE_OFFLINE=false
NO_UPDATE=false
NO_OPEN=false
PROJECT_DIR=""
LOG_FILE=""
STATUS_FILE=""
ONLINE=true
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

usage() {
  cat <<'EOF'
Usage: ./RUN_ASSESSMENT.sh [options]

Runs the complete assessment automatically from setup through final report.

Options:
  --profile quick|standard|thorough   Default: standard
  --install-dir PATH                  Default: ~/esxi-stealth-va
  --proxy URL                         HTTP/HTTPS proxy
  --offline                           Never use internet access
  --no-update                         Do not update an existing checkout
  --no-open                           Do not open the HTML report
  --help                              Show this help

Environment equivalents:
  ESXI_VA_PROFILE, ESXI_VA_INSTALL_DIR, ESXI_VA_PROXY, ESXI_VA_REPO_URL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || { echo "--profile requires a value" >&2; exit 2; }
      PROFILE="$2"; shift 2 ;;
    --install-dir)
      [[ $# -ge 2 ]] || { echo "--install-dir requires a path" >&2; exit 2; }
      INSTALL_DIR="$2"; shift 2 ;;
    --proxy)
      [[ $# -ge 2 ]] || { echo "--proxy requires a URL" >&2; exit 2; }
      PROXY="$2"; shift 2 ;;
    --offline) FORCE_OFFLINE=true; shift ;;
    --no-update) NO_UPDATE=true; shift ;;
    --no-open) NO_OPEN=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$PROFILE" in
  quick|standard|thorough) ;;
  *) echo "Invalid profile: $PROFILE" >&2; exit 2 ;;
esac

if [[ -t 1 ]]; then
  BOLD='\033[1m'; BLUE='\033[34m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
else
  BOLD=''; BLUE=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

stage() { printf "\n%b== %s ==%b\n" "$BOLD$BLUE" "$*" "$RESET"; }
info()  { printf "%b[INFO]%b %s\n" "$BLUE" "$RESET" "$*"; }
ok()    { printf "%b[OK]%b %s\n" "$GREEN" "$RESET" "$*"; }
warn()  { printf "%b[WARN]%b %s\n" "$YELLOW" "$RESET" "$*"; }
fail()  { printf "%b[FAILED]%b %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }

write_status() {
  local state="$1" message="$2" finished
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [[ -n "$STATUS_FILE" ]] || return 0
  cat > "$STATUS_FILE" <<EOF
state=$state
message=$message
profile=$PROFILE
started_at=$STARTED_AT
finished_at=$finished
log=$LOG_FILE
report=${PROJECT_DIR}/output/assessment_report.html
EOF
}

on_error() {
  local rc=$? line="${BASH_LINENO[0]:-unknown}" command="${BASH_COMMAND:-unknown}"
  printf "\n%bASSESSMENT FAILED%b\n" "$RED$BOLD" "$RESET" >&2
  printf "Command: %s\nLine: %s\nExit code: %s\n" "$command" "$line" "$rc" >&2
  [[ -n "$LOG_FILE" ]] && printf "Log: %s\n" "$LOG_FILE" >&2
  write_status failed "Command failed at line $line with exit code $rc"
  exit "$rc"
}
trap on_error ERR

run_root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "Administrator access is required. Install sudo or run as root."
  fi
}

package_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  elif command -v zypper >/dev/null 2>&1; then echo zypper
  else echo unknown
  fi
}

apply_proxy() {
  [[ -n "$PROXY" ]] || return 0
  export http_proxy="$PROXY" https_proxy="$PROXY" HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
  export no_proxy="${no_proxy:-localhost,127.0.0.1}"
}

bootstrap_basics() {
  local missing=() command pm
  for command in git curl python3; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
  done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  $FORCE_OFFLINE && fail "Fresh installation requires ${missing[*]}, but --offline was specified."
  pm="$(package_manager)"
  info "Installing bootstrap requirements: ${missing[*]}"
  case "$pm" in
    apt)
      run_root apt-get update
      run_root apt-get install -y git curl python3 python3-pip sudo ca-certificates
      ;;
    dnf)
      run_root dnf install -y git curl python3 python3-pip sudo ca-certificates
      ;;
    yum)
      run_root yum install -y git curl python3 python3-pip sudo ca-certificates
      ;;
    zypper)
      run_root zypper --non-interactive refresh || true
      run_root zypper --non-interactive install git curl python3 python3-pip sudo ca-certificates
      ;;
    *) fail "No supported package manager was found." ;;
  esac
}

locate_project() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/run_assessment.py" && -d "$script_dir/orchestrator" ]]; then
    PROJECT_DIR="$script_dir"
  elif [[ -f "$INSTALL_DIR/run_assessment.py" && -d "$INSTALL_DIR/orchestrator" ]]; then
    PROJECT_DIR="$INSTALL_DIR"
  else
    $FORCE_OFFLINE && fail "Project is not installed and cannot be cloned in offline mode."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    info "Installing project at $INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
    PROJECT_DIR="$INSTALL_DIR"
  fi
}

setup_logging() {
  mkdir -p "$PROJECT_DIR/logs" "$PROJECT_DIR/output"
  LOG_FILE="$PROJECT_DIR/logs/one_click_$(date +%Y%m%d_%H%M%S).log"
  STATUS_FILE="$PROJECT_DIR/output/last_run_status.txt"
  exec > >(tee -a "$LOG_FILE") 2>&1
  write_status running "Assessment started"
}

check_connectivity() {
  if $FORCE_OFFLINE; then ONLINE=false; return 0; fi
  if curl -fsSIL --connect-timeout 5 --max-time 10 https://github.com/ >/dev/null 2>&1; then
    ONLINE=true
  else
    ONLINE=false
    warn "Internet/GitHub is unavailable. Continuing in automatic degraded mode."
  fi
}

update_project() {
  $NO_UPDATE && { info "Project update disabled."; return 0; }
  $ONLINE || { warn "Project update skipped because GitHub is unavailable."; return 0; }
  [[ -d "$PROJECT_DIR/.git" ]] || { warn "Project is not a Git checkout; update skipped."; return 0; }
  cd "$PROJECT_DIR"
  if [[ -n "$(git status --porcelain)" ]]; then
    warn "Local changes detected; automatic update skipped to preserve them."
    return 0
  fi
  if git pull --ff-only; then
    ok "Project updated."
  else
    warn "Project update failed; continuing with the installed version."
  fi
}

installer_args() {
  local result=()
  $ONLINE || result+=(--offline)
  if [[ -n "$PROXY" ]]; then
    local hostport host port
    hostport="${PROXY#*://}"; hostport="${hostport%%/*}"
    host="${hostport%%:*}"; port="${hostport##*:}"
    result+=("--proxy=$host")
    [[ "$port" != "$host" ]] && result+=("--proxy-port=$port")
  fi
  printf '%s\n' "${result[@]}"
}

repair_environment() {
  local args=()
  cd "$PROJECT_DIR"
  chmod +x scripts/install.sh RUN_ASSESSMENT.sh easy_assessment.sh 2>/dev/null || true
  while IFS= read -r argument; do [[ -n "$argument" ]] && args+=("$argument"); done < <(installer_args)
  if bash scripts/install.sh "${args[@]}"; then
    ok "Environment installation completed."
  else
    warn "Installer reported a problem. Checking whether the required core remains usable."
  fi
  local required missing=()
  for required in python3 nmap curl; do
    command -v "$required" >/dev/null 2>&1 || missing+=("$required")
  done
  [[ ${#missing[@]} -eq 0 ]] || fail "Required components are still missing: ${missing[*]}"
  python3 -c 'import yaml' >/dev/null 2>&1 || fail "Required Python module PyYAML is unavailable."
}

validate_once() {
  cd "$PROJECT_DIR"
  python3 run_assessment.py --auto-network --dry-run
}

validate_with_repair() {
  if validate_once; then
    ok "Validation passed."
    return 0
  fi
  warn "Validation failed. Running one automatic repair attempt."
  repair_environment
  validate_once
  ok "Validation passed after repair."
}

run_assessment() {
  cd "$PROJECT_DIR"
  local command=(python3 run_assessment.py --auto-network --profile "$PROFILE")
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    "${command[@]}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -E "${command[@]}"
  else
    "${command[@]}"
  fi
}

print_summary() {
  local report_json="$PROJECT_DIR/output/assessment_report.json"
  [[ -f "$report_json" ]] || return 0
  python3 - "$report_json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
hosts = data.get("findings_infrastructure", [])
vulns = data.get("findings_vulns", [])
web = sum(len(item.get("findings", [])) for item in data.get("findings_web", []))
crypto = data.get("findings_crypto", [])
counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
for item in vulns:
    severity = str(item.get("severity", "info")).lower()
    counts[severity if severity in counts else "info"] += 1
for item in data.get("findings_web", []):
    for finding in item.get("findings", []):
        severity = str(finding.get("severity", "Info")).lower()
        counts[severity if severity in counts else "info"] += 1
print("\nEXECUTIVE RUN SUMMARY")
print("---------------------")
print(f"Hosts discovered:       {len(hosts)}")
print(f"Open services:          {sum(len(h.get('ports', [])) for h in hosts)}")
print(f"Vulnerability findings: {len(vulns)}")
print(f"Web findings:           {web}")
print(f"TLS assessments:        {len(crypto)}")
print("Severity:               " + ", ".join(f"{k}={v}" for k, v in counts.items()))
PY
}

open_report() {
  $NO_OPEN && return 0
  local report="$PROJECT_DIR/output/assessment_report.html"
  [[ -f "$report" ]] || return 0
  if command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    xdg-open "$report" >/dev/null 2>&1 || true
  elif command -v wslview >/dev/null 2>&1; then
    wslview "$report" >/dev/null 2>&1 || true
  fi
}

main() {
  printf "%bESXi Stealth VA — Fully Automated Assessment%b\n" "$BOLD" "$RESET"
  printf "Profile: %s\n" "$PROFILE"
  [[ "$(uname -s)" == "Linux" ]] || fail "This runner supports Linux and WSL."
  apply_proxy

  stage "Preparing operating system"
  bootstrap_basics
  if [[ ${EUID:-$(id -u)} -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    sudo -v
  fi

  stage "Preparing assessment project"
  locate_project
  setup_logging
  check_connectivity
  update_project

  stage "Installing and repairing requirements"
  repair_environment

  stage "Validating detected environment"
  validate_with_repair

  stage "Running complete assessment"
  run_assessment

  local html="$PROJECT_DIR/output/assessment_report.html"
  local json="$PROJECT_DIR/output/assessment_report.json"
  [[ -f "$html" && -f "$json" ]] || fail "Assessment finished without producing both required reports."

  print_summary
  printf "\n%bASSESSMENT COMPLETE%b\n" "$GREEN$BOLD" "$RESET"
  printf "HTML report: %s\nJSON report: %s\nLog: %s\n" "$html" "$json" "$LOG_FILE"
  write_status success "Assessment completed successfully"
  open_report
}

main
