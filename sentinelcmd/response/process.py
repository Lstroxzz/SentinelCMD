"""Manual process termination with conservative identity and scope checks."""

from __future__ import annotations

import math
import os
from pathlib import Path

import psutil


CRITICAL_NAMES = frozenset(
    {
        "system",
        "system idle process",
        "registry",
        "secure system",
        "memory compression",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "sihost.exe",
        "explorer.exe",
        "audiodg.exe",
        "conhost.exe",
        "msmpeng.exe",
        "mssense.exe",
        "senseir.exe",
        "sentinel",
        "sentinel.exe",
        "sentinelcmd.exe",
        "init",
        "systemd",
    }
)


def _psutil_call(operation):
    """Turn disappearing/protected processes into clear, non-traceback errors."""
    try:
        return operation()
    except psutil.NoSuchProcess as exc:
        raise ValueError("Process is no longer available; termination refused.") from exc
    except psutil.ZombieProcess as exc:
        raise ValueError("Process is a zombie; termination refused.") from exc
    except psutil.AccessDenied as exc:
        raise PermissionError("Permission denied for the selected process.") from exc


def terminate_process(pid: int, expected_create_time: float) -> dict:
    """Terminate one explicitly selected, same-user process; never descendants.

    Caller must obtain and display the process identity and request a deliberate
    manual confirmation. No automatic policy may call this helper. No force-kill
    escalation occurs if the termination request times out.
    """
    if type(pid) is not int or pid <= 4 or pid in {os.getpid(), os.getppid()}:
        raise ValueError("Refusing to terminate a protected or invalid process ID.")
    if (
        not isinstance(expected_create_time, (int, float))
        or isinstance(expected_create_time, bool)
        or not math.isfinite(expected_create_time)
        or expected_create_time <= 0
    ):
        raise ValueError("A valid expected process creation time is required.")
    process = _psutil_call(lambda: psutil.Process(pid))
    if abs(_psutil_call(process.create_time) - expected_create_time) > 0.000001:
        raise ValueError("Process identity changed; termination refused.")
    name = _psutil_call(process.name)
    if name.casefold() in CRITICAL_NAMES:
        raise ValueError("Refusing to terminate a critical or protected process.")
    selected_user = _psutil_call(process.username)
    own_user = _psutil_call(lambda: psutil.Process(os.getpid()).username())
    if selected_user.casefold() != own_user.casefold():
        raise ValueError("Only processes belonging to the current user may be terminated.")
    if os.name == "nt":
        executable = _psutil_call(process.exe)
        if not executable:
            raise ValueError("Executable identity unavailable; termination refused.")
        windows = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
        resolved = Path(executable).resolve()
        if resolved == windows or windows in resolved.parents:
            raise ValueError("Windows component processes are protected.")
    # A fresh Process object avoids relying on psutil's cached create_time.
    current = _psutil_call(lambda: psutil.Process(pid))
    if abs(_psutil_call(current.create_time) - expected_create_time) > 0.000001 or not _psutil_call(current.is_running):
        raise ValueError("Process identity changed; termination refused.")
    _psutil_call(current.terminate)
    try:
        exit_code = current.wait(timeout=3)
        status = "terminated"
    except psutil.TimeoutExpired:
        status, exit_code = "termination_requested", None
    return {
        "status": status,
        "pid": pid,
        "process": name,
        "create_time": expected_create_time,
        "exit_code": exit_code,
        "action": "terminate_process",
    }
