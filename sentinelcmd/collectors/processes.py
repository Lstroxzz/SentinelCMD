"""Polling process inventory; short-lived processes between polls may be missed.

Command lines and account names are read once per observed process identity.
These values are sensitive: callers must redact them before persistence.
No collector hashes every process on every poll or opens remote executables.
"""

from __future__ import annotations

import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Any

import psutil

from .common import is_local_path, no_reparse_components, utc_now

_PROCESS_ERRORS = (psutil.Error, OSError, ValueError)


def _downloaded(executable: str | None) -> bool:
    """Check recent (24h) file metadata plus a bounded local Mark-of-the-Web.

    The timestamp is an estimate, not a trusted download time. Absence of this
    marker, a changed timestamp, or an inaccessible stream is inconclusive.
    """
    if os.name != "nt" or not executable:
        return False
    path = Path(executable)
    if not is_local_path(path) or not no_reparse_components(path):
        return False
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 <= time.time() - info.st_mtime <= 86400:
            return False
        with open(str(path) + ":Zone.Identifier", "rb") as stream:
            data = stream.read(4096)
        return bool(re.search(rb"(?im)^\s*ZoneId\s*=\s*[34]\s*$", data))
    except OSError:
        return False


class ProcessCollector:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self._previous: dict[tuple[int, float], dict[str, Any]] | None = None
        self._cache: dict[tuple[int, float], dict[str, Any]] = {}
        self.last_error: str | None = None
        self._lock = threading.Lock()

    def _capture(self) -> dict[tuple[int, float], dict[str, Any]]:
        current: dict[tuple[int, float], dict[str, Any]] = {}
        timestamp = utc_now()
        self.last_error = None
        try:
            for process in psutil.process_iter(
                attrs=["pid", "ppid", "name", "exe", "create_time"], ad_value=None
            ):
                try:
                    info = process.info
                    pid = int(info["pid"])
                    created = float(info.get("create_time") or 0)
                    key = (pid, created)
                    cached = self._cache.get(key)
                    if cached is None:
                        try:
                            command_line = " ".join(process.cmdline() or [])
                        except _PROCESS_ERRORS:
                            command_line = ""
                        try:
                            username = process.username() or ""
                        except _PROCESS_ERRORS:
                            username = ""
                        cached = {
                            "command_line": command_line,
                            "username": username,
                            "downloaded": _downloaded(info.get("exe")),
                        }
                    current[key] = {
                        **cached,
                        "kind": "process_started",
                        "timestamp": timestamp,
                        "pid": pid,
                        "ppid": info.get("ppid"),
                        "process_name": info.get("name") or "<inaccessible>",
                        "executable": info.get("exe") or "",
                        "process_created_at": created,
                    }
                except _PROCESS_ERRORS:
                    continue
        except _PROCESS_ERRORS as error:
            # An inventory failure must never report every process as exited.
            self.last_error = type(error).__name__
            return dict(self._cache)
        by_pid = {key[0]: record for key, record in current.items()}
        for record in current.values():
            parent = by_pid.get(record["ppid"])
            parent_created = parent["process_created_at"] if parent is not None else None
            record["parent_created_at"] = (
                parent_created
                if parent_created and record["process_created_at"] >= parent_created
                else None
            )
        self._cache = current
        return current

    def sample(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._sample()

    def _sample(self) -> list[dict[str, Any]]:
        current = self._capture()
        if self.last_error:
            return []
        if self._previous is None:
            self._previous = current
            return []
        events = [dict(record) for key, record in current.items() if key not in self._previous]
        timestamp = utc_now()
        events.extend(
            {**record, "kind": "process_exited", "timestamp": timestamp}
            for key, record in self._previous.items()
            if key not in current
        )
        self._previous = current
        return events

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._capture().values()]


def build_process_tree(processes: list[dict[str, Any]]) -> str:
    """Render all observed processes, tolerating missing parents and PID cycles."""
    by_pid = {int(item["pid"]): item for item in processes if item.get("pid") is not None}
    children: dict[int, list[int]] = {}
    roots: list[int] = []
    for pid, record in by_pid.items():
        parent = record.get("ppid")
        if parent not in by_pid or parent == pid:
            roots.append(pid)
        else:
            children.setdefault(int(parent), []).append(pid)
    for values in children.values():
        values.sort()
    visited: set[int] = set()
    lines: list[str] = []
    for root in sorted(roots) + sorted(set(by_pid) - set(roots)):
        if root in visited:
            continue
        stack = [(root, "", "")]
        while stack:
            pid, prefix, connector = stack.pop()
            if pid in visited:
                continue
            visited.add(pid)
            label = str(by_pid[pid].get("process_name") or "unknown")
            # Process names are untrusted terminal input as well.
            label = "".join(c if c.isprintable() else "?" for c in label)
            lines.append(f"{prefix}{connector}{label} [PID {pid}]")
            branch_prefix = prefix + ("    " if connector == "└── " else "│   " if connector else "")
            descendants = children.get(pid, [])
            for index in range(len(descendants) - 1, -1, -1):
                child = descendants[index]
                stack.append((child, branch_prefix, "└── " if index == len(descendants) - 1 else "├── "))
    return "\n".join(lines) or "No accessible processes."
