"""
Runtime helpers for cross-version and cross-platform command execution.
"""

import os
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence


PY37_PLUS = sys.version_info >= (3, 7)


def run_command(cmd: Sequence[str], capture_output: bool = False,
                text: bool = False, **kwargs):
    """
    Compatibility wrapper for subprocess.run().

    Python 3.6 does not support capture_output= or text=, so we translate
    those flags to stdout/stderr pipes and universal_newlines.
    """
    kwargs = dict(kwargs)

    if capture_output:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)

    if text:
        if PY37_PLUS:
            kwargs.setdefault("text", True)
        else:
            kwargs.setdefault("universal_newlines", True)

    return subprocess.run(list(cmd), **kwargs)


def get_privilege_prefix() -> Optional[List[str]]:
    """
    Return the command prefix needed for privileged operations on Linux.

    - [] when already running as root
    - ["sudo"] when sudo is available
    - None when elevation is unavailable
    """
    if os.name == "nt":
        return None

    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return []

    if shutil.which("sudo"):
        return ["sudo"]

    return None
