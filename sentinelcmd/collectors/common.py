"""Small, replaceable interfaces for local operating-system collectors."""

from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def is_local_path(path: Path) -> bool:
    """Reject UNC/device paths to keep filesystem observations on this host."""
    value = os.fspath(path)
    if value.startswith(("\\\\", "//")):
        return False
    if os.name == "nt":
        drive = path.drive
        if len(drive) != 2 or drive[1] != ":":
            return False
        # A drive letter can also be a mapped network share. Querying its type
        # does not enumerate or open that share.
        try:
            import ctypes

            if ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") != 3:
                return False
        except (AttributeError, OSError):
            return False
    return True


def no_reparse_components(path: Path) -> bool:
    """Never follow a known link/junction in an explicitly configured path."""
    try:
        for component in (*reversed(path.parents), path):
            if is_reparse(component.lstat()):
                return False
        return True
    except OSError:
        return False
