#!/usr/bin/env python3
"""Short interactive terminal setup for scope, scan coverage, and delivery.

The wizard deliberately has no menu dependency.  It uses the terminal's
cbreak mode so that Space toggles a checkbox and Enter confirms immediately,
including when the terminal is being used through a PSM session.
"""

from contextlib import contextmanager
import copy
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - the supported runtime is Unix
    termios = None
    tty = None

try:
    import yaml
except ImportError:  # pragma: no cover - handled by main()
    yaml = None


ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
CONFIG_FILES = (
    ("assessment", "assessment.yaml", "Assessment, scope, reports, and tool settings"),
    ("stealth", "stealth_profile.yaml", "Stealth, timing, and network behavior"),
    ("scan_profile", "scan_profile.yaml", "Quick, standard, and thorough profiles"),
)
EMAIL_SCOPE_OPTIONS = (
    "HTML report",
    "JSON report",
    "Delta summary",
    "Errors and health status",
)
EMAIL_SECRET_KEYS = {"password", "app_password", "secret"}
EMAIL_PATH = ("email",)
EMAIL_DEFAULT_SCOPE = list(EMAIL_SCOPE_OPTIONS)
SCAN_PROFILE_ORDER = ("quick", "standard", "thorough")
RECOMMENDED_DEFAULTS = {
    # Scope safety: discover private networks by default and never broaden a
    # scan to public interfaces without an explicit advanced change.
    ("assessment", ("auto_network", "include_virtual_interfaces")): False,
    ("assessment", ("auto_network", "allow_public_subnets")): False,
    ("assessment", ("auto_network", "detect_esxi")): True,
    ("assessment", ("vm_discovery", "method")): "sweep",
    ("assessment", ("vm_discovery", "discovery_probes", "enabled")): True,
    ("assessment", ("vm_discovery", "discovery_probes", "mode")): "fallback",
    # Core assessment coverage is on; duplicate or externally disclosing work
    # is opt-in for an internal ESXi environment.
    ("assessment", ("security_tests", "enabled")): True,
    ("assessment", ("crypto", "prefer_testssl")): True,
    ("assessment", ("crypto", "scan_all_hosts")): True,
    ("assessment", ("ssl_automation", "enabled")): False,
    ("assessment", ("ssllabs", "enabled")): False,
    ("assessment", ("web", "scan_all_hosts")): True,
    ("assessment", ("web", "use_nikto")): True,
    ("assessment", ("nuclei", "enabled")): True,
    ("assessment", ("delta", "enabled")): True,
    # Updating code/tools during an assessment is a meaningful change and can
    # break reproducibility. Template/tool updates remain explicit choices.
    ("assessment", ("phases", "phase0_update")): False,
    ("assessment", ("phases", "phase1_init")): True,
    ("assessment", ("phases", "phase2_discovery")): True,
    ("assessment", ("phases", "phase3_enum")): True,
    ("assessment", ("phases", "phase4_crypto")): True,
    ("assessment", ("phases", "phase5_web")): True,
    ("assessment", ("phases", "phase6_vulnscan")): True,
    ("assessment", ("phases", "phase7_delta")): True,
    ("assessment", ("update", "git_pull")): False,
    ("assessment", ("update", "nuclei_templates")): False,
    ("assessment", ("update", "system_tools")): False,
    # Email can disclose findings; require the user to opt in.
    ("assessment", ("email", "enabled")): False,
    ("scan_profile", ("active_profile",)): "standard",
    ("stealth", ("network", "max_rate_pps")): 100,
    ("stealth", ("network", "scan_delay_ms")): 50,
    ("stealth", ("sweep", "max_rate_pps")): 200,
    ("stealth", ("sweep", "timeout_s")): 90,
}
SETTING_GROUP_TITLES = {
    "target": "Primary target and identity",
    "auto_network": "Automatic network detection",
    "vm_discovery": "VM discovery and scope",
    "expanded_discovery": "Expanded discovery",
    "security_tests": "Safe service checks",
    "phases": "Assessment phases",
    "scan": "Nmap scan behavior and timeouts",
    "crypto": "TLS and cryptography",
    "ssl_automation": "Standalone SSL automation",
    "ssllabs": "SSL Labs integration",
    "web": "Web assessment",
    "nuclei": "Nuclei vulnerability scanning",
    "delta": "Delta reporting and retention",
    "update": "Framework and template updates",
    "environment": "Audit and environment metadata",
    "tool_paths": "External tool paths",
    "network": "Network stealth timing",
    "sweep": "Discovery sweep timing",
    "http": "HTTP probing timing",
    "tls": "TLS probing timing",
    "general": "General runtime safety",
    "active_profile": "Active scan profile",
    "profiles": "Scan profile presets",
}


def _clear_screen():
    # Do not emit terminal-clear escape sequences. Some VM consoles and PSM
    # sessions interpret them as a blank/black display. Keeping the previous
    # prompts visible is also useful when a setup is interrupted.
    sys.stdout.write("\n")
    sys.stdout.flush()


@contextmanager
def _cbreak_terminal():
    """Temporarily read individual keys without requiring an extra Enter."""
    if not sys.stdin.isatty() or termios is None or tty is None:
        raise RuntimeError("The setup wizard needs an interactive Unix terminal.")
    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    try:
        yield fd
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)


def _read_key(fd):
    key = os.read(fd, 1)
    if key == b"\x1b":
        # Arrow keys arrive as ESC [ A/B.  A short read is safe in cbreak mode.
        suffix = os.read(fd, 2)
        if suffix == b"[A":
            return "up"
        if suffix == b"[B":
            return "down"
        if suffix == b"[5":
            os.read(fd, 1)
            return "pageup"
        if suffix == b"[6":
            os.read(fd, 1)
            return "pagedown"
        return "escape"
    if key in (b"\r", b"\n"):
        return "enter"
    if key == b" ":
        return "space"
    if key in (b"j", b"J"):
        return "down"
    if key in (b"k", b"K"):
        return "up"
    if key == b"\x03":
        raise KeyboardInterrupt
    return key.decode("utf-8", "ignore").lower()


def choose(title, options, selected=None, single=False):
    """Render checkboxes and return selected indexes after Enter.

    ``single=True`` keeps the checkbox interaction but makes the menu behave
    like a radio group.  This prevents an ambiguous Gmail/local-mail choice.
    """
    options = list(options)
    if not options:
        return set()
    selected = set(selected or [])
    selected.intersection_update(range(len(options)))
    cursor = min(max(0, min(selected) if selected else 0), len(options) - 1)

    with _cbreak_terminal() as fd:
        while True:
            _clear_screen()
            print(title)
            print("  Space select/unselect   Enter confirm   ↑/↓ move   Ctrl-C cancel")
            print()

            height = max(4, shutil.get_terminal_size((100, 24)).lines - 6)
            start = max(0, min(cursor - height // 2, len(options) - height))
            end = min(len(options), start + height)
            if start:
                print("  ...")
            for index in range(start, end):
                marker = "x" if index in selected else " "
                pointer = ">" if index == cursor else " "
                print(" {} [{}] {}".format(pointer, marker, options[index]))
            if end < len(options):
                print("  ...")

            key = _read_key(fd)
            if key == "up":
                cursor = (cursor - 1) % len(options)
            elif key == "down":
                cursor = (cursor + 1) % len(options)
            elif key == "pageup":
                cursor = max(0, cursor - height)
            elif key == "pagedown":
                cursor = min(len(options) - 1, cursor + height)
            elif key == "space":
                if single:
                    if cursor in selected:
                        selected.remove(cursor)
                    else:
                        selected.clear()
                        selected.add(cursor)
                elif cursor in selected:
                    selected.remove(cursor)
                else:
                    selected.add(cursor)
            elif key == "enter":
                return selected
            elif key == "escape":
                raise KeyboardInterrupt


def choose_one(title, options, selected=0):
    """Return one selected index while retaining checkbox-only navigation."""
    while True:
        result = choose(title, options, [selected], single=True)
        if len(result) == 1:
            return next(iter(result))
        # An empty radio choice is not useful.  Keep the existing value and
        # allow the user to confirm it again without a line-oriented prompt.
        selected = min(max(0, selected), len(options) - 1)


def ask(prompt, default="", secret=False):
    suffix = " [{}]".format(default) if default not in (None, "") and not secret else ""
    reader = getpass.getpass if secret else input
    value = reader("{}{}: ".format(prompt, suffix))
    return value.strip() or (default if default is not None else "")


def ask_required(prompt, default="", secret=False):
    while True:
        value = ask(prompt, default=default, secret=secret)
        if value:
            return value
        print("A value is required. Press Enter to continue.")
        input()


def _ask_secret(prompt, existing=False):
    hint = " (leave blank to keep the saved credential)" if existing else ""
    value = getpass.getpass(prompt + hint + ": ").strip()
    return value or None


def _path_string(path):
    return ".".join(str(part) for part in path)


def _flatten_settings(value, prefix=()):
    """Yield every editable leaf in a YAML mapping, including lists."""
    if isinstance(value, dict) and value:
        for key, child in value.items():
            for item in _flatten_settings(child, prefix + (str(key),)):
                yield item
        return
    yield prefix, value


def _get_path(mapping, path):
    current = mapping
    for part in path:
        current = current[part]
    return current


def _set_path(mapping, path, value):
    current = mapping
    for part in path[:-1]:
        if not isinstance(current.get(part), dict):
            current[part] = {}
        current = current[part]
    current[path[-1]] = value


def _path_exists(mapping, path):
    current = mapping
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def apply_recommended_defaults(configs):
    """Fill missing values with safe, useful defaults without overwriting choices.

    This makes a fresh/custom config directory usable while keeping rerunning
    the wizard non-destructive. Risky scope expansion, external SSL Labs
    checks, automatic updates, and report delivery are opt-in defaults.
    """
    for (config_key, path), value in RECOMMENDED_DEFAULTS.items():
        config = configs.setdefault(config_key, {})
        if not _path_exists(config, path):
            _set_path(config, path, copy.deepcopy(value))
    return configs


def _is_email_setting(path):
    return path[:1] == EMAIL_PATH


def _format_value(value, redact=False):
    if redact:
        return "<saved securely>"
    if isinstance(value, str):
        return value or "<empty>"
    if isinstance(value, (list, dict)):
        return yaml.safe_dump(value, default_flow_style=True, sort_keys=False).strip()
    return str(value)


def _parse_value(raw, current):
    if isinstance(current, bool):
        lowered = raw.strip().lower()
        if lowered in ("true", "yes", "y", "1", "on", "enabled"):
            return True
        if lowered in ("false", "no", "n", "0", "off", "disabled"):
            return False
        raise ValueError("enter yes or no")
    if isinstance(current, int) and not isinstance(current, bool):
        return int(raw.strip())
    if isinstance(current, float):
        return float(raw.strip())
    if isinstance(current, list):
        parsed = yaml.safe_load(raw)
        if isinstance(parsed, list):
            return parsed
        # Convenience for common comma-separated settings such as ports/tags.
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(current, dict):
        parsed = yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError("enter a YAML mapping")
        return parsed
    if current is None:
        return yaml.safe_load(raw)
    return raw


def _edit_setting(path, current):
    label = _path_string(path)
    if isinstance(current, bool):
        choice = choose_one(
            "{}\nCurrent value: {}".format(label, _format_value(current)),
            ["Enabled", "Disabled"],
            0 if current else 1,
        )
        return choice == 0

    while True:
        kind = "YAML value" if isinstance(current, (list, dict)) or current is None else "value"
        raw = ask("{} ({}, current: {})".format(label, kind, _format_value(current)))
        try:
            return _parse_value(raw, current)
        except (TypeError, ValueError, yaml.YAMLError) as exc:
            print("Invalid value for {}: {}".format(label, exc))
            input("Press Enter to try again.")


def edit_settings(section_name, data, skip_email=True, prefix=None):
    boolean_leaves = []
    value_leaves = []
    for path, value in _flatten_settings(data):
        if not path or (skip_email and _is_email_setting(path)):
            continue
        if prefix and path[:len(prefix)] != prefix:
            continue
        redact = any(part.lower() in EMAIL_SECRET_KEYS for part in path)
        item = (path, value, redact)
        if isinstance(value, bool):
            boolean_leaves.append(item)
        else:
            value_leaves.append(item)

    if boolean_leaves:
        labels = [
            "{} = {}".format(
                _path_string(path),
                "True / Enabled" if value else "False / Disabled",
            )
            for path, value, _redact in boolean_leaves
        ]
        enabled = choose(
            "{}\nChecked [x] is the actual True/Enabled value.\n"
            "Unchecked [ ] is the actual False/Disabled value. Space toggles the value; Enter confirms.".format(section_name),
            labels,
            [index for index, (_path, value, _redact) in enumerate(boolean_leaves) if value],
        )
        for index, (path, _current, _redact) in enumerate(boolean_leaves):
            _set_path(data, path, index in enabled)

    if value_leaves:
        labels = [
            "{} (current: {})".format(_path_string(path), _format_value(value, redact))
            for path, value, redact in value_leaves
        ]
        selected = choose(
            "{}\nSelect non-boolean settings for typed value entry.\n"
            "Here [x] means selected for editing; it does not mean True.".format(section_name),
            labels,
            [],
        )
        for index, (path, _current, _redact) in enumerate(value_leaves):
            if index in selected:
                _set_path(data, path, _edit_setting(path, _get_path(data, path)))


def _setting_group_prefix(path):
    if path[:1] == ("profiles",) and len(path) >= 2:
        return path[:2]
    return path[:1]


def _setting_group_title(prefix):
    if prefix[:1] == ("profiles",) and len(prefix) == 2:
        return "Scan profile preset: {}".format(prefix[1])
    return SETTING_GROUP_TITLES.get(prefix[0], prefix[0].replace("_", " ").title())


def edit_setting_groups(section_name, data, skip_email=True):
    """Present settings hierarchically so the user never faces one giant list."""
    groups = {}
    for path, _value in _flatten_settings(data):
        if not path or (skip_email and _is_email_setting(path)):
            continue
        prefix = _setting_group_prefix(path)
        groups.setdefault(prefix, 0)
        groups[prefix] += 1
    if not groups:
        return

    prefixes = sorted(groups, key=lambda item: tuple(str(part) for part in item))
    labels = [
        "{} ({} setting{})".format(
            _setting_group_title(prefix),
            groups[prefix],
            "" if groups[prefix] == 1 else "s",
        )
        for prefix in prefixes
    ]
    # Keep the first-run path short.  These groups are the small set of
    # decisions that materially change scope, safety, or scan coverage.
    recommended = {
        "target", "auto_network", "vm_discovery", "phases", "scan",
        "crypto", "web", "nuclei", "delta", "environment", "active_profile",
    }
    recommended_indexes = [
        index for index, prefix in enumerate(prefixes)
        if prefix[:1] in {(name,) for name in recommended}
    ]
    selected = choose(
        "{}\nRecommended groups are selected. Press Enter to accept them, or use "
        "Space to add advanced settings.".format(section_name),
        labels,
        recommended_indexes,
    )
    selected_prefixes = [prefixes[index] for index in sorted(selected)]
    for position, prefix in enumerate(selected_prefixes, 1):
        edit_settings(
            "{} — group {}/{}".format(_setting_group_title(prefix), position, len(selected_prefixes)),
            data,
            skip_email=skip_email,
            prefix=prefix,
        )


def _load_yaml(path):
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_configs(config_dir=CONFIG_DIR):
    config_dir = Path(config_dir)
    return {
        key: _load_yaml(config_dir / filename)
        for key, filename, _description in CONFIG_FILES
    }


def save_configs(configs, config_dir=CONFIG_DIR):
    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    for key, filename, _description in CONFIG_FILES:
        path = config_dir / filename
        with path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(configs.get(key, {}), handle, sort_keys=False, allow_unicode=True)


def _credential_path(mail, config_dir):
    configured = mail.get("credentials_file")
    if not configured:
        return Path(config_dir) / ".email_credentials"
    path = Path(os.path.expanduser(str(configured)))
    return path if path.is_absolute() else ROOT / path


def _credential_reference(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(Path(path).resolve())


def _load_credentials(mail, config_dir):
    path = _credential_path(mail, config_dir)
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if isinstance(value, dict):
            return value
    except (OSError, ValueError):
        pass
    return {}


def _save_credentials(path, credentials):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(credentials, handle)
        handle.write("\n")
    os.chmod(str(temporary), 0o600)
    os.replace(str(temporary), str(path))
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


def _valid_email(value):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value))


def _ask_email(prompt, default=""):
    while True:
        value = ask_required(prompt, default)
        if _valid_email(value):
            return value
        print("That does not look like an email address.")
        input("Press Enter to try again.")


def configure_target(assessment):
    """Collect only the two identity values a normal setup needs."""
    target = dict(assessment.get("target") or {})
    print("\nStep 1/4 — Assessment target")
    print("Leave the address blank to let automatic private-network discovery find ESXi hosts.")
    target["ip"] = ask("Primary ESXi IP or hostname", target.get("ip", ""))
    target["hostname"] = ask("Target hostname (optional)", target.get("hostname", ""))
    assessment["target"] = target


def _profile_options(scan_profile):
    profiles = scan_profile.get("profiles") or {}
    names = [name for name in SCAN_PROFILE_ORDER if name in profiles]
    names.extend(name for name in profiles if name not in names)
    if not names:
        # This is only a fallback for a custom/empty config directory. The
        # normal repository config already contains the complete presets.
        names = ["standard"]
        scan_profile.setdefault("profiles", {})["standard"] = {
            "description": "Balanced coverage for routine internal assessments.",
        }
    labels = []
    for name in names:
        description = (profiles.get(name) or {}).get("description", "").strip()
        if not description:
            description = {
                "quick": "Fast, lower coverage",
                "standard": "Balanced coverage for routine internal assessments",
                "thorough": "All TCP ports; slow and noisy",
            }.get(name, "Custom profile")
        labels.append("{} — {}".format(name.title(), description))
    return names, labels


def configure_scan_profile(scan_profile):
    """Select one understandable scan intensity instead of raw scan knobs."""
    names, labels = _profile_options(scan_profile)
    current = scan_profile.get("active_profile", "standard")
    selected = names.index(current) if current in names else names.index("standard") if "standard" in names else 0
    print("\nStep 2/4 — Scan coverage")
    print("Standard is the recommended balance for the internal ESXi/VM assessment.")
    selected = choose_one("Choose scan coverage", labels, selected)
    scan_profile["active_profile"] = names[selected]


def _local_mail_identity():
    """Generate a stable local Postfix identity without asking for a sender."""
    candidate = (socket.getfqdn() or "").strip().lower()
    if candidate in ("", "localhost", "localhost.localdomain"):
        candidate = (socket.gethostname() or "").strip().lower()
    candidate = re.sub(r"[^a-z0-9.-]", "-", candidate).strip(".-")
    if candidate in ("", "localhost", "localhost.localdomain"):
        candidate = "esxi-assessment"
    if "." not in candidate:
        hostname = candidate + ".local"
        domain = hostname
    else:
        hostname = candidate
        domain = candidate.split(".", 1)[1]
    return {
        "hostname": hostname,
        "domain": domain,
        "sender": "assessment@{}".format(domain),
    }


def configure_email(assessment, config_dir):
    existing = dict(assessment.get("email") or {})
    backend = existing.get("backend")
    # Email is opt-in for a new setup: it can disclose assessment results and
    # local Postfix setup is a meaningful system change. Existing choices are
    # retained so rerunning the wizard is non-destructive.
    default_delivery = 1 if existing.get("enabled") and backend == "smtp" else 2 if existing.get("enabled") and backend == "local" else 0
    delivery = choose_one(
        "Step 3/4 — Report delivery\nChoose one delivery method. Email is disabled by default.",
        [
            "Disable email reports",
            "Gmail SMTP using a Google app password",
            "Local mail server using automated Postfix setup",
        ],
        default_delivery,
    )

    mail = dict(existing)
    pending_credentials = None
    setup_action = "none"
    if delivery == 0:
        mail["enabled"] = False
        for key in ("password", "app_password"):
            mail.pop(key, None)
        return mail, setup_action, pending_credentials

    recipient = _ask_email("Receiving email address", mail.get("recipient", ""))
    local_identity = _local_mail_identity() if delivery == 2 else None
    if local_identity:
        sender = local_identity["sender"]
        print("Generated local sender: {} (domain: {})".format(sender, local_identity["domain"]))
    else:
        sender = _ask_email("From email address", mail.get("sender", recipient))
    mail.update({
        "enabled": True,
        "recipient": recipient,
        "sender": sender,
        # Keep the quick path predictable. Advanced email scope and subject
        # editing remains available directly in the YAML configuration.
        "subject": mail.get("subject", "ESXi assessment report"),
        "scope": list(mail.get("scope") or EMAIL_DEFAULT_SCOPE),
    })

    if delivery == 1:
        credential_path = _credential_path(mail, config_dir)
        credentials = _load_credentials(mail, config_dir)
        username = _ask_email("Gmail account", mail.get("username", credentials.get("username", sender)))
        password = _ask_secret(
            "Gmail app password (16-character app password, not your normal password)",
            existing=bool(credentials.get("password")),
        )
        if not password and not credentials.get("password") and not mail.get("password"):
            print("A Gmail app password is required for SMTP delivery.")
            password = _ask_secret("Gmail app password", existing=False)
        mail.update({
            "backend": "smtp",
            "host": "smtp.gmail.com",
            "port": 587,
            "starttls": True,
            "username": username,
            "credentials_file": _credential_reference(credential_path),
        })
        for key in ("hostname", "domain", "setup", "health_check", "sendmail_path"):
            mail.pop(key, None)
        old_password = credentials.get("password") or mail.get("password")
        if password or old_password:
            pending_credentials = {
                "path": _credential_path(mail, config_dir),
                "username": username,
                "password": password or old_password,
            }
        mail.pop("password", None)
        mail.pop("app_password", None)
    else:
        # Local delivery gets a machine-derived identity.  There is no
        # ambiguous sender/hostname prompt to fill in manually.
        hostname = local_identity["hostname"]
        domain = local_identity["domain"]
        mail.update({
            "backend": "local",
            "host": "127.0.0.1",
            "port": 25,
            "hostname": hostname,
            "domain": domain,
            "setup": True,
            "health_check": True,
            "sendmail_path": mail.get("sendmail_path", "/usr/sbin/sendmail"),
        })
        for key in ("username", "credentials_file", "starttls", "password", "app_password"):
            mail.pop(key, None)
        print("Local delivery will run the loopback-only Postfix setup and health-check after saving.")
        setup_action = "setup"

    return mail, setup_action, pending_credentials


def _run_local_mail_action(mail, action):
    if action == "none":
        return True
    script = ROOT / "scripts" / "setup_local_mail.sh"
    command = [
        "bash", str(script), "--hostname", str(mail.get("hostname", "localhost")),
        "--domain", str(mail.get("domain", "")),
        "--health-check", "--recipient", str(mail.get("recipient", "")),
        "--from", str(mail.get("sender", "")),
    ]
    if action == "test":
        command.append("--test")
    print("\nRunning local mail setup and health-check...")
    return subprocess.call(command) == 0


def _changed_settings(original_configs, configs):
    changes = []
    missing = object()
    for key, _filename, _description in CONFIG_FILES:
        before = dict(_flatten_settings(original_configs.get(key, {})))
        after = dict(_flatten_settings(configs.get(key, {})))
        for path in sorted(set(before) | set(after)):
            old = before.get(path, missing)
            new = after.get(path, missing)
            if old == new:
                continue
            redact = any(part.lower() in EMAIL_SECRET_KEYS for part in path)
            old_display = "<not set>" if old is missing else _format_value(old, redact)
            new_display = "<not set>" if new is missing else _format_value(new, redact)
            changes.append((key, _path_string(path), old_display, new_display))
    return changes


def _summary(configs, original_configs=None):
    print("\nFinal review — ready to save")
    assessment = configs.get("assessment", {})
    target = assessment.get("target", {})
    scan_profile = configs.get("scan_profile", {}).get("active_profile", "standard")
    auto_network = assessment.get("auto_network", {})
    print("  Target: {}".format(target.get("ip") or "automatic private-network discovery"))
    if target.get("hostname"):
        print("  Hostname: {}".format(target["hostname"]))
    print("  Scan coverage: {}".format(scan_profile))
    public_scope = auto_network.get("allow_public_subnets", False) or assessment.get("expanded_discovery", {}).get("allow_public_subnets", False)
    print("  Scope guardrails: {}".format(
        "public networks allowed (advanced)" if public_scope else "private subnets only; public networks excluded"
    ))
    print("  Core checks: VM discovery, safe service checks, TLS, web, Nuclei, and delta reporting")
    print("  External SSL Labs checks: {}".format("enabled" if assessment.get("ssllabs", {}).get("enabled") else "disabled"))
    if auto_network.get("include_virtual_interfaces"):
        print("  Note: virtual interfaces are included in automatic discovery")
    mail = configs.get("assessment", {}).get("email", {})
    delivery = "disabled"
    if mail.get("enabled"):
        delivery = "{} -> {}".format(mail.get("backend", "unknown"), mail.get("recipient", "<missing>"))
    print("  Email: {}".format(delivery))
    if original_configs is not None:
        changes = _changed_settings(original_configs, configs)
        print("  Changes: {}".format(len(changes)))
        for key, path, old, new in changes[:40]:
            print("    {}.{}: {} -> {}".format(key, path, old, new))
        if len(changes) > 40:
            print("    ... {} more change(s)".format(len(changes) - 40))
    for key, _filename, description in CONFIG_FILES:
        leaves = list(_flatten_settings(configs.get(key, {})))
        print("  {}: {} setting(s) ready ({})".format(key, len(leaves), description))


def main(config_dir=CONFIG_DIR):
    if yaml is None:
        print("PyYAML is required. Install dependencies with: python3 -m pip install -r requirements.txt", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("The setup wizard needs a real interactive terminal (TTY).", file=sys.stderr)
        return 2

    config_dir = Path(config_dir)
    configs = load_configs(config_dir)
    apply_recommended_defaults(configs)
    original_configs = copy.deepcopy(configs)
    print("ESXi Assessment — quick setup")
    print("Enter the few decisions needed for a safe internal assessment.\n"
          "Press Enter to keep the shown default. Advanced settings are optional.")

    configure_target(configs.setdefault("assessment", {}))
    configure_scan_profile(configs.setdefault("scan_profile", {}))

    mail, mail_action, pending_credentials = configure_email(configs["assessment"], config_dir)
    configs["assessment"]["email"] = mail

    advanced = choose_one(
        "Step 4/4 — Optional advanced settings",
        [
            "Use recommended security defaults",
            "Edit advanced timing, tool, phase, and stealth settings",
        ],
        0,
    )
    if advanced == 1:
        areas = choose(
            "Choose advanced areas to edit. Leave all unchecked to continue.",
            ["{} — {}".format(description, key) for key, _filename, description in CONFIG_FILES],
            [],
        )
        for index, (key, _filename, description) in enumerate(CONFIG_FILES):
            if index in areas:
                edit_setting_groups(description, configs[key], skip_email=(key == "assessment"))

    _summary(configs, original_configs)
    if choose_one("Save this configuration?", ["Save configuration and continue", "Cancel without saving"], 0) == 1:
        print("Setup cancelled; no configuration files were changed.")
        return 0

    if pending_credentials:
        _save_credentials(
            pending_credentials["path"],
            {"username": pending_credentials["username"], "password": pending_credentials["password"]},
        )
    save_configs(configs, config_dir)

    if configs["assessment"].get("email", {}).get("enabled") and mail_action != "none":
        if not _run_local_mail_action(configs["assessment"]["email"], mail_action):
            print("Local mail setup or health-check failed. Configuration was saved.", file=sys.stderr)
            return 1

    print("\nSaved configuration files in {}.".format(config_dir))
    print("Run: python3 run_assessment.py")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nSetup cancelled.", file=sys.stderr)
        raise SystemExit(130)
