"""Build and send assessment reports using SMTP or a local sendmail queue."""

import json
import os
import shutil
import smtplib
import subprocess
from email.message import EmailMessage
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCOPE_HTML = "HTML report"
SCOPE_JSON = "JSON report"
SCOPE_MARKDOWN = "Markdown report"
SCOPE_DELTA = "Delta summary"
SCOPE_HEALTH = "Errors and health status"


def _credential_path(mail):
    configured = mail.get("credentials_file", "config/.email_credentials")
    path = Path(os.path.expanduser(str(configured)))
    return path if path.is_absolute() else PROJECT_ROOT / path


def _load_credentials(mail):
    path = _credential_path(mail)
    try:
        with path.open("r", encoding="utf-8") as handle:
            credentials = json.load(handle)
        if isinstance(credentials, dict):
            return credentials
    except (OSError, ValueError):
        pass
    return {}


def _report_data(output_dir):
    path = Path(output_dir) / "assessment_report.json"
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _body_for_scope(scope, output_dir, mail):
    data = _report_data(output_dir)
    metadata = data.get("metadata", {})
    contextual = data.get("contextual_analysis", {})
    lines = [
        "ESXi assessment report",
        "Target: {} ({})".format(metadata.get("target_primary", "unknown"), metadata.get("target_hostname", "unknown")),
        "Run ID: {}".format(metadata.get("run_id", "unknown")),
        "Risk: {} ({}/100)".format(contextual.get("risk_rating", "unknown"), contextual.get("risk_score", "unknown")),
        "",
    ]

    if SCOPE_DELTA in scope:
        delta = data.get("delta") or {}
        summary = delta.get("summary") or {}
        lines.extend([
            "Delta summary:",
            "  New: {}".format(summary.get("new", 0)),
            "  Resolved: {}".format(summary.get("resolved", 0)),
            "  Changed: {}".format(summary.get("changed", 0)),
            "  Unchanged: {}".format(summary.get("unchanged", 0)),
            "",
        ])

    if SCOPE_HEALTH in scope:
        errors = data.get("execution_errors") or []
        output = Path(output_dir)
        files = {
            "JSON": output / "assessment_report.json",
            "Markdown": output / "assessment_report.md",
            "HTML": output / "assessment_report.html",
        }
        lines.append("Errors and health status:")
        for label, path in files.items():
            lines.append("  Report {}: {}".format(label, "OK" if path.exists() else "MISSING"))
        lines.append("  Delivery backend: {}".format(mail.get("backend", "unknown")))
        if errors:
            lines.append("  Assessment errors: {}".format(len(errors)))
            for error in errors:
                lines.append("    - [{}/{}] {}".format(
                    error.get("phase", "unknown"),
                    error.get("module", "unknown"),
                    error.get("error", "unknown error"),
                ))
        else:
            lines.append("  Assessment errors: none")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_message(config, output_dir):
    """Build the email without sending it; useful for tests and dry checks."""
    mail = config.get("assessment", {}).get("email", {})
    if not mail.get("enabled"):
        return None

    default_scope = [SCOPE_HTML, SCOPE_JSON, SCOPE_MARKDOWN, SCOPE_DELTA, SCOPE_HEALTH]
    scope = set(mail.get("scope") or default_scope)
    message = EmailMessage()
    message["Subject"] = mail.get("subject", "ESXi assessment report")
    message["From"] = mail.get("sender") or mail["recipient"]
    message["To"] = mail["recipient"]
    message.set_content(_body_for_scope(scope, output_dir, mail))

    attachments = []
    if SCOPE_HTML in scope:
        attachments.append((Path(output_dir) / "assessment_report.html", "text", "html"))
    if SCOPE_JSON in scope:
        attachments.append((Path(output_dir) / "assessment_report.json", "application", "json"))
    if SCOPE_MARKDOWN in scope:
        attachments.append((Path(output_dir) / "assessment_report.md", "text", "markdown"))
    for path, maintype, subtype in attachments:
        if path.exists():
            message.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)
    return message


def _send_local(message, mail):
    configured = mail.get("sendmail_path", "/usr/sbin/sendmail")
    sendmail = str(configured) if Path(str(configured)).exists() else shutil.which("sendmail")
    if not sendmail:
        raise RuntimeError("sendmail was not found; run scripts/setup_local_mail.sh first")
    subprocess.run([sendmail, "-t", "-oi"], input=message.as_bytes(), check=True)


def _send_smtp(message, mail):
    credentials = _load_credentials(mail)
    username = mail.get("username") or credentials.get("username")
    password = mail.get("password") or credentials.get("password")
    if not username or not password:
        raise RuntimeError(
            "Gmail credentials are missing. Run python3 run_assessment.py --setup "
            "and provide a Gmail app password."
        )
    with smtplib.SMTP(
        mail.get("host", "smtp.gmail.com"),
        int(mail.get("port", 587)),
        timeout=int(mail.get("timeout_s", 30)),
    ) as smtp:
        if mail.get("starttls", True):
            smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(message)


def send_report(config, output_dir):
    """Send configured report artifacts and return False when disabled."""
    mail = config.get("assessment", {}).get("email", {})
    if not mail.get("enabled"):
        return False
    if not mail.get("recipient"):
        raise RuntimeError("Email delivery is enabled but no receiving address is configured")

    message = build_message(config, output_dir)
    if message is None:
        return False
    if mail.get("backend") == "local":
        _send_local(message, mail)
    else:
        _send_smtp(message, mail)
    return True
