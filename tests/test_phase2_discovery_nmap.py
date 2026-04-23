import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.phase2_discovery import Phase2Discovery


MINIMAL_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="10.0.0.1" addrtype="ipv4" />
  </host>
</nmaprun>
"""


def test_run_nmap_nonzero_with_xml_present_still_fails(tmp_path, monkeypatch):
    plugin = Phase2Discovery({})
    xml_out = tmp_path / "scan.xml"
    xml_out.write_text(MINIMAL_XML, encoding="utf-8")

    monkeypatch.setattr(plugin, "_get_nmap_cmd", lambda: "nmap")

    def fake_run_command(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["nmap"],
            returncode=2,
            stdout="",
            stderr="nmap reported an error",
        )

    monkeypatch.setattr("orchestrator.phase2_discovery.run_command", fake_run_command)

    ok = plugin._run_nmap(["-sn", "10.0.0.0/24"], xml_out, timeout=10)

    assert ok is False
    assert "rc=2" in plugin._last_nmap_error
    assert "command='nmap -sn 10.0.0.0/24" in plugin._last_nmap_error
    assert "xml_present=True" in plugin._last_nmap_error


def test_run_nmap_nonzero_without_xml_fails(tmp_path, monkeypatch):
    plugin = Phase2Discovery({})
    xml_out = tmp_path / "scan.xml"

    monkeypatch.setattr(plugin, "_get_nmap_cmd", lambda: "nmap")

    def fake_run_command(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["nmap"],
            returncode=1,
            stdout="",
            stderr="fatal",
        )

    monkeypatch.setattr("orchestrator.phase2_discovery.run_command", fake_run_command)

    ok = plugin._run_nmap(["-sT", "10.0.0.1"], xml_out, timeout=10)

    assert ok is False
    assert "rc=1" in plugin._last_nmap_error
    assert "xml_present=False" in plugin._last_nmap_error


def test_run_nmap_zero_with_valid_xml_succeeds(tmp_path, monkeypatch):
    plugin = Phase2Discovery({})
    xml_out = tmp_path / "scan.xml"
    xml_out.write_text(MINIMAL_XML, encoding="utf-8")

    monkeypatch.setattr(plugin, "_get_nmap_cmd", lambda: "nmap")

    def fake_run_command(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout="done",
            stderr="",
        )

    monkeypatch.setattr("orchestrator.phase2_discovery.run_command", fake_run_command)

    ok = plugin._run_nmap(["-sV", "10.0.0.1"], xml_out, timeout=10)

    assert ok is True
    assert plugin._last_nmap_error == ""
