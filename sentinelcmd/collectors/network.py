"""Passive local socket snapshots; no packets, probes, DNS or remote requests.

UDP endpoints often have no peer, and access rights can hide socket ownership.
Polling cannot see connections that open and close entirely between snapshots.
"""

from __future__ import annotations

import socket
import threading
from typing import Any

import psutil

from .common import utc_now


def _address(value: Any) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    return str(value[0]), int(value[1])


class NetworkCollector:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self._previous: set[tuple[Any, ...]] | None = None
        self._current: list[dict[str, Any]] = []
        self.last_error: str | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _identity(record: dict[str, Any]) -> tuple[Any, ...]:
        # State changes (e.g. ESTABLISHED -> TIME_WAIT) are not new connections.
        return tuple(record[key] for key in (
            "pid", "process_created_at", "protocol", "local_ip", "local_port", "remote_ip", "remote_port"
        ))

    def _capture(self) -> list[dict[str, Any]]:
        self.last_error = None
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError) as error:
            self.last_error = type(error).__name__
            return [dict(record) for record in self._current]
        processes: dict[int, tuple[str, float | None]] = {}
        records = []
        seen = set()
        timestamp = utc_now()
        for connection in connections:
            pid = connection.pid
            if pid is not None and pid not in processes:
                try:
                    process = psutil.Process(pid)
                    with process.oneshot():
                        processes[pid] = (process.name(), process.create_time())
                except (psutil.Error, OSError):
                    processes[pid] = ("<inaccessible>", None)
            name, created_at = processes.get(pid, ("<unavailable>", None))
            local_ip, local_port = _address(connection.laddr)
            remote_ip, remote_port = _address(connection.raddr)
            record = {
                "kind": "network_connection", "timestamp": timestamp,
                "pid": pid, "process_name": name, "process_created_at": created_at,
                "local_ip": local_ip, "local_port": local_port,
                "remote_ip": remote_ip, "remote_port": remote_port,
                "protocol": "TCP" if connection.type == socket.SOCK_STREAM else "UDP",
                "state": connection.status or "NONE",
            }
            key = self._identity(record)
            if key not in seen:
                records.append(record)
                seen.add(key)
        self._current = records
        return records

    def sample(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._sample()

    def _sample(self) -> list[dict[str, Any]]:
        current = self._capture()
        if self.last_error:
            return []
        identities = {self._identity(record) for record in current}
        events = [] if self._previous is None else [
            dict(record) for record in current if self._identity(record) not in self._previous
        ]
        self._previous = identities
        return events

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._capture()]
