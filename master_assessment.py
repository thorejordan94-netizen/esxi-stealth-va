#!/usr/bin/env python3
"""One-command launcher for the comprehensive ESXi assessment pipeline.

This launcher stays compatible with the Python 3.6 runtime used by the original
openSUSE/SLES assessment host. With no command-line options it lets
``run_assessment.py`` use every configured subnet and target. Automatic local
network detection is used only when no scope is configured or when
``--auto-network`` is explicitly supplied.
"""

import importlib
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parent


def _missing_python_modules():
    modules = ["yaml", "requests", "jinja2", "packaging", "cryptography"]
    if sys.version_info < (3, 7):
        modules.append("dataclasses")
    missing = []
    for module_name in modules:
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(module_name)
    return missing


def _install_python_dependencies():
    missing = _missing_python_modules()
    if not missing:
        return
    if "--no-install" in sys.argv:
        raise RuntimeError(
            "Missing Python dependencies: {} (automatic installation disabled)".format(
                ", ".join(missing)
            )
        )

    requirements = PROJECT_ROOT / (
        "requirements_legacy.txt" if sys.version_info < (3, 7) else "requirements.txt"
    )
    if not requirements.exists():
        raise RuntimeError("Python requirements file is missing: {}".format(requirements))

    geteuid = getattr(os, "geteuid", None)
    is_root = callable(geteuid) and geteuid() == 0
    pip_check = subprocess.call(
        [sys.executable, "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if pip_check != 0:
        ensurepip_command = [sys.executable, "-m", "ensurepip", "--upgrade"]
        if not is_root:
            ensurepip_command.append("--user")
        subprocess.call(ensurepip_command)

    if subprocess.call(
        [sys.executable, "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) != 0:
        prefix = [] if is_root else (["sudo", "-n"] if shutil.which("sudo") else [])
        package_command = None
        if shutil.which("zypper"):
            package_command = prefix + ["zypper", "--non-interactive", "install", "-y", "python3-pip"]
        elif shutil.which("apt-get"):
            package_command = prefix + ["apt-get", "install", "-y", "python3-pip"]
        elif shutil.which("dnf"):
            package_command = prefix + ["dnf", "install", "-y", "python3-pip"]
        elif shutil.which("yum"):
            package_command = prefix + ["yum", "install", "-y", "python3-pip"]
        elif shutil.which("apk"):
            package_command = prefix + ["apk", "add", "py3-pip"]
        if package_command:
            subprocess.call(package_command)

    command = [sys.executable, "-m", "pip", "install", "-r", str(requirements)]
    if not is_root:
        command.append("--user")

    print("[*] Installing missing Python dependencies: {}".format(", ".join(missing)))
    result = subprocess.call(command)
    if result != 0 or _missing_python_modules():
        raise RuntimeError(
            "Automatic Python dependency installation failed. Run: {}".format(
                " ".join(command)
            )
        )


def main():
    runner = PROJECT_ROOT / "run_assessment.py"
    if not runner.exists():
        raise RuntimeError("Comprehensive assessment runner is missing: {}".format(runner))

    _install_python_dependencies()
    sys.argv[0] = str(runner)
    runpy.run_path(str(runner), run_name="__main__")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Assessment interrupted. Existing state is preserved in output/.")
        raise SystemExit(130)
    except Exception as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)
