"""Bounded metadata polling of explicitly configured local directories.

There is no default filesystem scope. File contents are never read or hashed.
Symlinks, junctions, UNC paths, mapped network drives and reparse points are
excluded. Each scan resumes across calls and is bounded by max_files,
max_depth, max_entries and a cooperative time budget (one filesystem call may
overrun it). The entry cap bounds directory-only trees and ignored entries.
Changes are reported only when a scan cycle finishes. Deletions are suppressed
when enumeration failed or hit its file cap; previously unseen files are not
called new creations after an incomplete cycle. No PID is inferred from a
filesystem change. Very short-lived files, same-size changes preserving mtime,
renames (represented as creation/deletion), link-swap races and inaccessible
files require native audit/event facilities for stronger guarantees.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .common import is_local_path, is_reparse, no_reparse_components, utc_now


def _bounded(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


class FileCollector:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self.paths = [Path(p).absolute() for p in config.get("monitor_paths", []) if isinstance(p, str) and p]
        self.max_files = _bounded(config.get("max_files"), 2000, 1, 100000)
        self.max_depth = _bounded(config.get("max_depth"), 4, 0, 32)
        self.max_entries = _bounded(config.get("max_entries"), 10000, 1, 1000000)
        self.budget_ms = _bounded(config.get("file_scan_budget_ms"), 20, 1, 1000)
        self._known: dict[str, dict[str, Any]] = {}
        self._cycle: dict[str, dict[str, Any]] = {}
        self._iterator: Iterator[tuple[str, dict[str, Any]] | None] | None = None
        self._initialized = False
        self._previous_complete = False
        self._cycle_complete = True
        self._cycle_entries = 0
        self.status: dict[str, Any] = {
            "enabled": bool(self.paths), "scanning": False, "tracked_files": 0,
            "truncated": False, "inaccessible_entries": 0,
        }

    def _walk(self) -> Iterator[tuple[str, dict[str, Any]] | None]:
        seen_roots: set[str] = set()
        for root in self.paths:
            root_key = os.path.normcase(str(root))
            if root_key in seen_roots:
                continue
            seen_roots.add(root_key)
            yield None
            if not is_local_path(root) or not no_reparse_components(root):
                self._cycle_complete = False
                self.status["inaccessible_entries"] += 1
                yield None
                continue
            yield from self._walk_directory(root, 0)

    def _walk_directory(self, directory: Path, depth: int) -> Iterator[tuple[str, dict[str, Any]] | None]:
        try:
            info = directory.lstat()
            if is_reparse(info) or not stat.S_ISDIR(info.st_mode):
                self._cycle_complete = False
                yield None
                return
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if is_reparse(info):
                            yield None
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            yield None
                            if depth < self.max_depth:
                                yield from self._walk_directory(Path(entry.path), depth + 1)
                        elif stat.S_ISREG(info.st_mode):
                            path = str(Path(entry.path).absolute())
                            yield os.path.normcase(path), {
                                "file_path": path, "file_size": info.st_size,
                                "mtime_ns": info.st_mtime_ns,
                            }
                        else:
                            yield None
                    except OSError:
                        self._cycle_complete = False
                        self.status["inaccessible_entries"] += 1
                        yield None
        except OSError:
            self._cycle_complete = False
            self.status["inaccessible_entries"] += 1
            yield None

    def _finish(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        timestamp = utc_now()
        if self._initialized:
            for key, record in self._cycle.items():
                previous = self._known.get(key)
                kind = None
                if previous is None and self._previous_complete:
                    kind = "file_created"
                elif previous is not None and (
                    previous["file_size"], previous["mtime_ns"]
                ) != (record["file_size"], record["mtime_ns"]):
                    kind = "file_modified"
                if kind:
                    events.append({**record, "kind": kind, "timestamp": timestamp})
            if self._cycle_complete:
                events.extend(
                    {**record, "kind": "file_deleted", "timestamp": timestamp}
                    for key, record in self._known.items() if key not in self._cycle
                )
        self._known = self._cycle
        self._cycle = {}
        self._initialized = True
        self._previous_complete = self._cycle_complete
        self._iterator = None
        self.status.update(
            scanning=False, tracked_files=len(self._known),
            last_scan_at=timestamp, complete=self._cycle_complete,
        )
        return events

    def sample(self) -> list[dict[str, Any]]:
        if not self.paths:
            return []
        if self._iterator is None:
            self._cycle_complete = True
            self._cycle_entries = 0
            self.status.update(scanning=True, truncated=False, inaccessible_entries=0, scanned_entries=0)
            self._iterator = self._walk()
        deadline = time.perf_counter() + self.budget_ms / 1000
        # Always advance at least one entry so a small budget makes progress.
        while True:
            if self._cycle_entries >= self.max_entries:
                self._cycle_complete = False
                self.status["truncated"] = True
                self._iterator.close()
                return self._finish()
            try:
                item = next(self._iterator)
            except StopIteration:
                return self._finish()
            self._cycle_entries += 1
            self.status["scanned_entries"] = self._cycle_entries
            if item is not None:
                key, record = item
                if key not in self._cycle and len(self._cycle) >= self.max_files:
                    self._cycle_complete = False
                    self.status["truncated"] = True
                    self._iterator.close()
                    return self._finish()
                self._cycle[key] = record
            if time.perf_counter() >= deadline:
                return []

    def snapshot(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._known.values()]

    def close(self) -> None:
        """Release scandir handles when monitoring is stopped mid-cycle."""
        if self._iterator is not None:
            self._iterator.close()
            self._iterator = None
            self._cycle = {}
        self.status["scanning"] = False
