"""
Runtime helpers for cross-version and cross-platform command execution.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Sequence


PY37_PLUS = sys.version_info >= (3, 7)


def get_output_dir(config=None):
    """Return the absolute output directory for this assessment run."""
    configured = (config or {}).get("_output_dir")
    if configured:
        return Path(os.path.abspath(os.path.expanduser(str(configured))))
    project_root = Path(__file__).resolve().parent.parent
    return project_root / "output"


def run_command(cmd: Sequence[str], capture_output: bool = False,
                text: bool = False, strip_proxy: bool = False, **kwargs):
    """
    Compatibility wrapper for subprocess.run().

    Python 3.6 does not support capture_output= or text=, so we translate
    those flags to stdout/stderr pipes and universal_newlines.
    """
    kwargs = dict(kwargs)

    # Local scanners can explicitly request a proxy-free environment. Package
    # managers and download tools retain proxy variables by default because the
    # original environment may require a corporate proxy for installation.
    env = kwargs.get("env", os.environ).copy()
    if strip_proxy:
        for proxy_var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]:
            env.pop(proxy_var, None)
    kwargs["env"] = env

    if capture_output:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)

    if text:
        if PY37_PLUS:
            kwargs.setdefault("text", True)
        else:
            kwargs.setdefault("universal_newlines", True)

    return subprocess.run(list(cmd), **kwargs)


def run_command_with_progress(cmd: Sequence[str], timeout: int,
                              progress_interval: int = 15,
                              description: str = "command",
                              logger=None,
                              strip_proxy: bool = False,
                              cwd: Optional[str] = None):
    """Run a captured command while periodically reporting that it is active."""
    env = os.environ.copy()
    if strip_proxy:
        for proxy_var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]:
            env.pop(proxy_var, None)

    started = time.time()
    next_progress = max(1, progress_interval)
    with tempfile.TemporaryFile(mode="w+") as stdout_file, tempfile.TemporaryFile(mode="w+") as stderr_file:
        process = subprocess.Popen(
            list(cmd),
            stdout=stdout_file,
            stderr=stderr_file,
            universal_newlines=True,
            cwd=cwd,
            env=env,
        )
        while process.poll() is None:
            elapsed = time.time() - started
            if elapsed >= timeout:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(list(cmd), timeout)
            if elapsed >= next_progress:
                if logger is not None:
                    logger.info("%s still running (%ss elapsed, %ss timeout)...", description, int(elapsed), timeout)
                next_progress += max(1, progress_interval)
            time.sleep(0.25)

        stdout_file.seek(0)
        stderr_file.seek(0)
        return subprocess.CompletedProcess(
            list(cmd),
            process.returncode,
            stdout_file.read(),
            stderr_file.read(),
        )


def get_privilege_prefix() -> Optional[List[str]]:
    """
    Return the command prefix needed for privileged operations on Linux.

    - [] when already running as root
    - ["sudo", "-n"] when sudo is available (non-interactive)
    - None when elevation is unavailable
    """
    if os.name == "nt":
        return None

    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return []

    if shutil.which("sudo"):
        # Use non-interactive sudo so automation never blocks on a password
        # prompt in unattended environments.
        return ["sudo", "-n"]

    return None
