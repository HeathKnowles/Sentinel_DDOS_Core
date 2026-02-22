#!/usr/bin/env python3
"""
Start a real Ryu/OS-Ken controller endpoint for Sentinel.
No fallback controller is used.
"""

import os
import shutil
import subprocess
import sys
import importlib.util
from pathlib import Path


def run(cmd):
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        return 127


def module_exists(name):
    try:
        return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError:
        return False


def main():
    project_ryu = Path(__file__).resolve().parent / ".venv-controller" / "bin" / "ryu-manager"
    if project_ryu.exists():
        os.execv(str(project_ryu), [str(project_ryu), "ryu.app.simple_switch_13", "ryu.app.ofctl_rest"])

    if shutil.which("ryu-manager"):
        os.execvp("ryu-manager", ["ryu-manager", "ryu.app.simple_switch_13", "ryu.app.ofctl_rest"])

    if shutil.which("osken-manager"):
        if module_exists("os_ken.app.ofctl_rest"):
            os.execvp("osken-manager", ["osken-manager", "os_ken.controller.ofp_handler", "os_ken.app.ofctl_rest"])

    if module_exists("ryu.cmd.manager"):
        rc = run([sys.executable, "-m", "ryu.cmd.manager", "ryu.app.simple_switch_13", "ryu.app.ofctl_rest"])
        if rc == 0:
            return 0

    if module_exists("os_ken.cmd.manager"):
        if module_exists("os_ken.app.ofctl_rest"):
            rc = run([sys.executable, "-m", "os_ken.cmd.manager", "os_ken.controller.ofp_handler", "os_ken.app.ofctl_rest"])
        else:
            rc = 1
        if rc == 0:
            return 0

    print("[FAIL] No working Ryu/OS-Ken controller runtime found.")
    if module_exists("os_ken") and not module_exists("os_ken.cmd.manager"):
        print("Detected 'os_ken' package without 'os_ken.cmd.manager'.")
        print("Install a full OS-Ken/Ryu controller distribution that provides manager entrypoints.")
    elif module_exists("os_ken") and module_exists("os_ken.cmd.manager") and not module_exists("os_ken.app.ofctl_rest"):
        print("Detected OS-Ken manager, but REST app 'os_ken.app.ofctl_rest' is unavailable.")
        print("Install a full controller package that includes REST endpoints required by Sentinel SDN integration.")
    print("Install one of the following:")
    print("  - ryu-manager (recommended)")
    print("  - python package 'ryu' with ryu.cmd.manager")
    print("  - python package 'os-ken' with os_ken.cmd.manager")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
