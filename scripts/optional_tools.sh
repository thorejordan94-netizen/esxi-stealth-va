#!/usr/bin/env bash
# Best-effort installer for optional online assessment tools.
# Core framework setup must not fail when the internet, DNS, or GitHub is unavailable.

set -u

OFFLINE_MODE=false
[[ " $* " == *" --offline "* ]] && OFFLINE_MODE=true

log() { printf '[optional-tools] %s\n' "$*"; }

if $OFFLINE_MODE; then
  log "Offline mode: skipping online optional tool downloads."
  exit 0
fi

if command -v testssl.sh >/dev/null 2>&1; then
  log "testssl.sh already available."
elif command -v git >/dev/null 2>&1; then
  log "Trying to install testssl.sh (optional)..."
  if sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /usr/local/testssl.sh 2>/dev/null; then
    sudo ln -sf /usr/local/testssl.sh/testssl.sh /usr/local/bin/testssl.sh || true
    log "testssl.sh installed."
  else
    log "Could not download testssl.sh. Continuing without it."
    log "This usually means DNS, proxy, firewall, or internet access is unavailable."
  fi
else
  log "git is unavailable; skipping optional testssl.sh installation."
fi

exit 0
