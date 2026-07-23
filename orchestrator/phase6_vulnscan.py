"""Phase 6: vulnerability scanning with Nuclei."""

import json
import logging
import shutil
import subprocess
from pathlib import Path

from orchestrator.core.plugin import PhasePlugin
from orchestrator.models import AssessmentReport, VulnerabilityFinding
from orchestrator.runtime import get_output_dir, run_command


logger = logging.getLogger(__name__)


class Phase6VulnScan(PhasePlugin):

    @property
    def name(self):
        return "Vulnerability Scanning"

    @property
    def phase_number(self):
        return 6

    def _get_nuclei_cmd(self, config=None):
        """Find the configured, native, or WSL Nuclei binary."""
        configured = (config or {}).get("assessment", {}).get("tool_paths", {}).get("nuclei", "")
        if configured and Path(str(configured)).is_file():
            return [str(configured)]

        nuclei_path = shutil.which("nuclei")
        if nuclei_path:
            return [nuclei_path]

        if shutil.which("wsl"):
            try:
                result = run_command(
                    ["wsl", "which", "nuclei"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return ["wsl", "nuclei"]
            except Exception:
                pass
        return None

    def _prepare_targets(self, report, config):
        """Create a target file containing discovered standard web endpoints."""
        web_hosts = report.get_web_hosts()
        if not web_hosts:
            return None

        targets = []
        for host in web_hosts:
            for port in host.ports:
                if port.port in (443, 8443, 9443):
                    targets.append("https://{}:{}".format(host.host, port.port))
                elif port.port in (80, 8080, 9080):
                    targets.append("http://{}:{}".format(host.host, port.port))

        if not targets:
            return None
        target_file = get_output_dir(config) / "nuclei_targets.txt"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("\n".join(sorted(set(targets))) + "\n", encoding="utf-8")
        return target_file

    @staticmethod
    def _list_value(value):
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return []

    def _parse_nuclei_jsonl(self, jsonl_file):
        """Parse Nuclei JSONL into normalized model objects."""
        findings = []
        if not jsonl_file.exists():
            return findings

        try:
            with jsonl_file.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                    except ValueError as exc:
                        logger.warning("Ignoring invalid Nuclei JSONL line %s: %s", line_number, exc)
                        continue

                    info = data.get("info") or {}
                    host_value = str(data.get("host", ""))
                    port = 0
                    if ":" in host_value.replace("://", ""):
                        try:
                            port = int(host_value.rsplit(":", 1)[-1].split("/", 1)[0])
                        except (TypeError, ValueError):
                            port = 0

                    extracted = data.get("extracted-results") or []
                    if extracted:
                        evidence = str(extracted[0])
                    else:
                        evidence = str(data.get("response", ""))[:4000]

                    findings.append(VulnerabilityFinding(
                        host=data.get("ip") or host_value,
                        port=port,
                        url=data.get("matched-at") or host_value,
                        template_id=data.get("template-id", ""),
                        name=info.get("name", ""),
                        severity=str(info.get("severity", "info")).lower(),
                        description=info.get("description", ""),
                        matcher_name=data.get("matcher-name", ""),
                        evidence=evidence,
                        reference=self._list_value(info.get("reference", [])),
                        tags=self._list_value(info.get("tags", [])),
                        curl_command=data.get("curl-command", ""),
                        scanner="nuclei",
                        timestamp=data.get("timestamp", ""),
                    ))
        except Exception as exc:
            logger.error("Failed to parse Nuclei JSONL: %s", exc)
        return findings

    def execute(self, report, config):
        nuclei_cfg = config.get("assessment", {}).get("nuclei", {})
        if not nuclei_cfg.get("enabled", True):
            logger.info("Nuclei scanning disabled in config.")
            return

        nuclei_cmd = self._get_nuclei_cmd(config)
        if not nuclei_cmd:
            report.add_error("phase6_vulnscan", "nuclei", "Nuclei binary not found")
            return

        target_file = self._prepare_targets(report, config)
        if not target_file:
            logger.info("No targets found for Nuclei scanning.")
            return

        output_file = get_output_dir(config) / "nuclei_findings.jsonl"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        if output_file.exists():
            output_file.unlink()

        command = nuclei_cmd + [
            "-l", str(target_file),
            "-jsonl",
            "-o", str(output_file),
            "-rl", str(nuclei_cfg.get("rate_limit", 50)),
            "-c", str(nuclei_cfg.get("concurrency", 10)),
            "-timeout", str(nuclei_cfg.get("timeout", 10)),
        ]
        severity_filter = str(nuclei_cfg.get("severity_filter", "")).strip()
        if severity_filter:
            command.extend(["-severity", severity_filter])
        command.append("-silent")

        templates_dir = str(nuclei_cfg.get("templates_dir", "")).strip()
        if templates_dir:
            command.extend(["-t", templates_dir])
        tags = self._list_value(nuclei_cfg.get("tags", []))
        if tags:
            command.extend(["-tags", ",".join(tags)])
        excluded = self._list_value(nuclei_cfg.get("exclude_tags", []))
        if excluded:
            command.extend(["-etags", ",".join(excluded)])
        command.extend(self._list_value(nuclei_cfg.get("extra_args", [])))

        execution_timeout = int(nuclei_cfg.get("execution_timeout_s", 86400))
        timeout_value = None if execution_timeout <= 0 else execution_timeout
        logger.info("Running Nuclei against %s with timeout=%s", target_file.name, timeout_value or "unlimited")
        self.log_for_cyberark("Starting Nuclei vulnerability scan")

        try:
            result = run_command(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_value,
                strip_proxy=True,
            )
            if result.returncode not in (0, 1):
                message = "Nuclei exited with code {}: {}".format(
                    result.returncode, (result.stderr or "")[:500]
                )
                logger.warning(message)
                if not output_file.exists():
                    report.add_error("phase6_vulnscan", "nuclei", message)

            findings = self._parse_nuclei_jsonl(output_file)
            for finding in findings:
                report.add_vuln(finding)
            logger.info("Nuclei completed. Found %s findings.", len(findings))
        except subprocess.TimeoutExpired:
            message = "Nuclei scan timed out after {} seconds".format(execution_timeout)
            logger.error(message)
            report.add_error("phase6_vulnscan", "nuclei", message)
            for finding in self._parse_nuclei_jsonl(output_file):
                report.add_vuln(finding)
        except Exception as exc:
            logger.error("Nuclei execution failed: %s", exc)
            report.add_error("phase6_vulnscan", "nuclei", "Execution failed: {}".format(exc))

    def mock_execute(self, report, config):
        logger.info("[MOCK] Generating synthetic Nuclei findings...")
        host = "10.251.2.28"
        web_hosts = report.get_web_hosts()
        if web_hosts:
            host = web_hosts[0].host

        mock_findings = [
            VulnerabilityFinding(
                host=host,
                port=443,
                url="https://{}/ui/".format(host),
                template_id="ssl-deprecated-protocols",
                name="Deprecated TLS Protocol",
                severity="medium",
                description="The server supports deprecated TLS 1.0/1.1",
                evidence="TLS 1.0 is offered",
                tags=["tls", "ssl", "misconfig"],
                scanner="nuclei",
            ),
            VulnerabilityFinding(
                host=host,
                port=443,
                url="https://{}/".format(host),
                template_id="http-missing-security-headers",
                name="HTTP Missing Security Headers",
                severity="low",
                description="Several security headers are missing",
                evidence="X-Content-Type-Options missing",
                tags=["headers", "misconfig"],
                scanner="nuclei",
            ),
        ]
        for finding in mock_findings:
            report.add_vuln(finding)
        logger.info("[MOCK] Phase 6 complete. Added %s findings.", len(mock_findings))
