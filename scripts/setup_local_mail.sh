#!/usr/bin/env bash
# Set up a loopback-only Postfix relay and verify that it is usable by the
# assessment process. Debian/Ubuntu, RHEL/Fedora, and openSUSE/SLES are
# supported because the original assessment host can run on any of them.
set -euo pipefail

HOSTNAME_VALUE=""
DOMAIN_VALUE=""
RECIPIENT=""
FROM_ADDRESS=""
DO_SETUP=1
DO_HEALTH_CHECK=1
SEND_TEST=0

usage() {
    cat <<'EOF'
Usage: setup_local_mail.sh [options]

Options:
  --hostname NAME       Local Postfix hostname (default: detected automatically)
  --domain NAME         Mail domain (auto-generated when omitted)
  --recipient ADDRESS   Recipient for an optional end-to-end test
  --from ADDRESS        Sender for an optional end-to-end test
  --test                Send an end-to-end test message after the checks
  --health-check        Run service, configuration, and port checks (default)
  --check-only          Do not install/configure; only run health checks
  --help                Show this help
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname)
            [[ $# -ge 2 ]] || die "--hostname needs a value"
            HOSTNAME_VALUE="$2"
            shift 2
            ;;
        --recipient)
            [[ $# -ge 2 ]] || die "--recipient needs a value"
            RECIPIENT="$2"
            shift 2
            ;;
        --domain)
            [[ $# -ge 2 ]] || die "--domain needs a value"
            DOMAIN_VALUE="$2"
            shift 2
            ;;
        --from)
            [[ $# -ge 2 ]] || die "--from needs a value"
            FROM_ADDRESS="$2"
            shift 2
            ;;
        --test)
            SEND_TEST=1
            shift
            ;;
        --health-check)
            DO_HEALTH_CHECK=1
            shift
            ;;
        --check-only)
            DO_SETUP=0
            DO_HEALTH_CHECK=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

if [[ -z "$HOSTNAME_VALUE" ]]; then
    HOSTNAME_VALUE="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    if [[ "$HOSTNAME_VALUE" == "localhost" || "$HOSTNAME_VALUE" == localhost.* || -z "$HOSTNAME_VALUE" ]]; then
        HOSTNAME_VALUE="$(hostname 2>/dev/null || true)"
    fi
    HOSTNAME_VALUE="$(printf '%s' "$HOSTNAME_VALUE" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.-]/-/g; s/^[-.]\+//; s/[-.]\+$//')"
    if [[ -z "$HOSTNAME_VALUE" || "$HOSTNAME_VALUE" == "localhost" || "$HOSTNAME_VALUE" == localhost.* || "$HOSTNAME_VALUE" != *.* ]]; then
        HOSTNAME_VALUE="esxi-assessment"
    fi
fi
if [[ "$HOSTNAME_VALUE" == "localhost" || "$HOSTNAME_VALUE" == localhost.* || "$HOSTNAME_VALUE" != *.* ]]; then
    HOSTNAME_VALUE="${HOSTNAME_VALUE%%.*}.local"
fi
[[ "$HOSTNAME_VALUE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "invalid hostname: $HOSTNAME_VALUE"
if [[ -z "$DOMAIN_VALUE" ]]; then
    if [[ "$HOSTNAME_VALUE" == *.* && "$HOSTNAME_VALUE" != *.local ]]; then
        DOMAIN_VALUE="${HOSTNAME_VALUE#*.}"
    else
        DOMAIN_VALUE="$HOSTNAME_VALUE"
    fi
fi
[[ "$DOMAIN_VALUE" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "invalid mail domain: $DOMAIN_VALUE"
if [[ "$SEND_TEST" -eq 1 && -z "$RECIPIENT" ]]; then
    die "--test requires --recipient"
fi

echo "Using local mail identity: assessment@${DOMAIN_VALUE} (hostname ${HOSTNAME_VALUE})"

if [[ "$(id -u)" -eq 0 ]]; then
    ROOT_PREFIX=()
else
    command -v sudo >/dev/null 2>&1 || die "root privileges or sudo are required"
    ROOT_PREFIX=(sudo)
fi

root_run() {
    "${ROOT_PREFIX[@]}" "$@"
}

root_env_run() {
    if [[ "${#ROOT_PREFIX[@]}" -eq 0 ]]; then
        env DEBIAN_FRONTEND=noninteractive "$@"
    else
        sudo env DEBIAN_FRONTEND=noninteractive "$@"
    fi
}

install_postfix() {
    if command -v apt-get >/dev/null 2>&1; then
        root_env_run apt-get update
        root_env_run apt-get install -y postfix mailutils
    elif command -v dnf >/dev/null 2>&1; then
        root_run dnf install -y postfix mailx
    elif command -v yum >/dev/null 2>&1; then
        root_run yum install -y postfix mailx
    elif command -v zypper >/dev/null 2>&1; then
        root_run zypper --non-interactive refresh
        root_run zypper --non-interactive install -y postfix mailx
    else
        die "unsupported package manager; install Postfix and a sendmail-compatible client manually"
    fi
}

configure_postfix() {
    command -v postconf >/dev/null 2>&1 || die "postconf is unavailable after package installation"
    root_run postconf -e "myhostname = ${HOSTNAME_VALUE}"
    root_run postconf -e "mydomain = ${DOMAIN_VALUE}"
    root_run postconf -e "inet_interfaces = loopback-only"
    root_run postconf -e "inet_protocols = all"
    root_run postconf -e "mynetworks_style = host"
    root_run postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost'
    # No relayhost is forced: Postfix delivers directly using DNS, which keeps
    # the local-mail option useful on isolated networks with an approved route.
    root_run postconf -e "relayhost ="
}

systemd_running() {
    # systemctl may be installed in a container even though PID 1 is not
    # systemd. Only use it when the systemd runtime directory is present.
    [[ -d /run/systemd/system ]]
}

ensure_aliases() {
    if ! root_run test -f /etc/aliases; then
        root_run install -m 0644 /dev/null /etc/aliases
    fi
    if ! root_run grep -Eq '^root[[:space:]]*:' /etc/aliases; then
        if [[ -n "$RECIPIENT" ]]; then
            printf 'root: %s\n' "$RECIPIENT" | root_run tee -a /etc/aliases >/dev/null
        else
            printf 'root: root\n' | root_run tee -a /etc/aliases >/dev/null
        fi
    fi
    command -v newaliases >/dev/null 2>&1 && root_run newaliases
}

check_aliases() {
    root_run test -f /etc/aliases || die "/etc/aliases is missing"
    root_run grep -Eq '^root[[:space:]]*:' /etc/aliases || die "/etc/aliases has no root alias"
}

start_postfix() {
    if systemd_running && command -v systemctl >/dev/null 2>&1; then
        if root_run systemctl enable --now postfix; then
            return
        fi
        echo "WARNING: systemd could not start Postfix; trying the service command." >&2
    fi
    if command -v service >/dev/null 2>&1 && root_run service postfix start; then
        if root_run postfix status >/dev/null 2>&1; then
            return
        fi
        echo "WARNING: the service command did not leave Postfix running; using postfix start." >&2
    fi
    command -v postfix >/dev/null 2>&1 || die "no Postfix service command is available"
    root_run postfix start
}

check_postfix_service() {
    if systemd_running && command -v systemctl >/dev/null 2>&1; then
        root_run systemctl is-active --quiet postfix || die "Postfix is not active"
    elif command -v service >/dev/null 2>&1; then
        root_run service postfix status >/dev/null 2>&1 || die "Postfix service is not active"
    else
        root_run postfix status >/dev/null 2>&1 || die "Postfix is not active"
    fi
}

check_postfix_port() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltnH | awk '{print $4}' | grep -Eq '127\.0\.0\.1:25|\[::1\]:25' || die "Postfix is not listening on TCP loopback port 25"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn | awk '{print $4}' | grep -Eq '127\.0\.0\.1:25|:::25' || die "Postfix is not listening on TCP port 25"
    else
        echo "WARNING: ss/netstat unavailable; skipped the port-listener check." >&2
    fi
}

health_check() {
    command -v postconf >/dev/null 2>&1 || die "postconf is not installed"
    root_run postfix check
    check_aliases
    check_postfix_service
    check_postfix_port
    echo "Postfix health-check passed: active, configuration valid, loopback SMTP port 25 listening."
}

send_test_message() {
    local sendmail_path
    sendmail_path="$(command -v sendmail || true)"
    [[ -n "$sendmail_path" ]] || die "sendmail client is unavailable"
    [[ -n "$FROM_ADDRESS" ]] || FROM_ADDRESS="assessment@${DOMAIN_VALUE}"
    {
        echo "To: ${RECIPIENT}"
        echo "From: ${FROM_ADDRESS}"
        echo "Subject: ESXi assessment local mail health-check"
        echo
        echo "The local Postfix health-check completed successfully."
    } | root_run "$sendmail_path" -t -oi
    echo "Test message queued for ${RECIPIENT}."
}

if [[ "$DO_SETUP" -eq 1 ]]; then
    install_postfix
    configure_postfix
    ensure_aliases
    start_postfix
fi

if [[ "$DO_HEALTH_CHECK" -eq 1 ]]; then
    health_check
fi

if [[ "$SEND_TEST" -eq 1 ]]; then
    send_test_message
fi
