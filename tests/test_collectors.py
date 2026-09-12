"""Collector tests use fabricated processes/sockets and temporary user files."""

from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

import psutil

from sentinelcmd.collectors import (
    FileCollector,
    NetworkCollector,
    ProcessCollector,
    SystemInspector,
    build_process_tree,
)
from sentinelcmd.collectors.processes import _downloaded


def process(pid: int, created: float = 10, ppid: int = 0) -> MagicMock:
    item = MagicMock()
    item.info = {"pid": pid, "ppid": ppid, "name": "example.exe", "exe": "", "create_time": created}
    item.cmdline.return_value = ["example.exe", "--example"]
    item.username.return_value = "test-user"
    return item


def connection(pid: int | None = None, port: int = 443, state: str = "ESTABLISHED", udp: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        pid=pid, laddr=("127.0.0.1", 50000), raddr=() if udp else ("192.0.2.4", port),
        type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM, status=state,
    )


def cycle(collector: FileCollector) -> list[dict]:
    events = []
    for _ in range(1000):
        events.extend(collector.sample())
        if not collector.status["scanning"]:
            return events
    raise AssertionError("File scan did not finish in the configured bounds")


class ProcessTests(unittest.TestCase):
    def test_download_marker_requires_recent_file_metadata(self) -> None:
        fake_path = MagicMock()
        fake_path.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_mtime=99900)
        with (
            patch("sentinelcmd.collectors.processes.os.name", "nt"),
            patch("sentinelcmd.collectors.processes.Path", return_value=fake_path),
            patch("sentinelcmd.collectors.processes.is_local_path", return_value=True),
            patch("sentinelcmd.collectors.processes.no_reparse_components", return_value=True),
            patch("sentinelcmd.collectors.processes.time.time", return_value=100000),
            patch("builtins.open", mock_open(read_data=b"[ZoneTransfer]\r\nZoneId=3\r\n")) as stream,
        ):
            self.assertTrue(_downloaded("example.exe"))
            stream().read.assert_called_with(4096)
            fake_path.lstat.return_value.st_mtime = 1
            self.assertFalse(_downloaded("example.exe"))

    @patch("sentinelcmd.collectors.processes.psutil.process_iter")
    def test_baseline_lifecycle_and_pid_reuse(self, iterate: MagicMock) -> None:
        first = process(5)
        iterate.return_value = [first]
        collector = ProcessCollector({})
        self.assertEqual(collector.sample(), [])
        self.assertEqual(collector.sample(), [])
        first.cmdline.assert_called_once()
        first.username.assert_called_once()
        iterate.return_value = [process(5, created=20)]
        events = collector.sample()
        self.assertEqual([event["kind"] for event in events], ["process_started", "process_exited"])
        self.assertEqual(events[0]["process_created_at"], 20)
        self.assertEqual(events[1]["process_created_at"], 10)

    @patch("sentinelcmd.collectors.processes.psutil.process_iter")
    def test_denied_inventory_does_not_report_mass_exit(self, iterate: MagicMock) -> None:
        iterate.return_value = [process(5)]
        collector = ProcessCollector({})
        collector.sample()
        iterate.side_effect = psutil.AccessDenied()
        self.assertEqual(collector.sample(), [])
        self.assertEqual(collector.last_error, "AccessDenied")
        iterate.side_effect = None
        iterate.return_value = [process(5)]
        self.assertEqual(collector.sample(), [])

    @patch("sentinelcmd.collectors.processes.psutil.process_iter")
    def test_inaccessible_details_and_snapshot_independence(self, iterate: MagicMock) -> None:
        first = process(5)
        first.cmdline.side_effect = psutil.AccessDenied()
        first.username.side_effect = psutil.AccessDenied()
        iterate.return_value = [first]
        collector = ProcessCollector({})
        snapshot = collector.snapshot()
        self.assertEqual(snapshot[0]["command_line"], "")
        snapshot[0]["process_name"] = "modified"
        self.assertEqual(collector.sample(), [])
        iterate.return_value = [first, process(7)]
        collector.snapshot()
        self.assertEqual(collector.sample()[0]["pid"], 7)

    def test_tree_includes_orphans_and_cycles_once(self) -> None:
        records = [
            {"pid": 1, "ppid": 999, "process_name": "root"},
            {"pid": 2, "ppid": 1, "process_name": "child"},
            {"pid": 3, "ppid": 4, "process_name": "cycleA"},
            {"pid": 4, "ppid": 3, "process_name": "cycleB\x1b"},
        ]
        rendered = build_process_tree(records)
        self.assertEqual(len(rendered.splitlines()), 4)
        self.assertIn("└── child [PID 2]", rendered)
        self.assertNotIn("\x1b", rendered)

    @patch("sentinelcmd.collectors.processes.psutil.process_iter")
    def test_parent_identity_rejects_reused_parent_pid(self, iterate: MagicMock) -> None:
        iterate.return_value = [process(1, created=10), process(2, created=20, ppid=1)]
        collector = ProcessCollector({})
        records = {row["pid"]: row for row in collector.snapshot()}
        self.assertEqual(records[2]["parent_created_at"], 10)
        iterate.return_value = [process(1, created=30), process(2, created=20, ppid=1)]
        records = {row["pid"]: row for row in collector.snapshot()}
        self.assertIsNone(records[2]["parent_created_at"])


class NetworkTests(unittest.TestCase):
    @patch("sentinelcmd.collectors.network.psutil.net_connections")
    def test_baseline_new_connections_and_udp_unknown_peer(self, connections: MagicMock) -> None:
        connections.return_value = [connection()]
        collector = NetworkCollector({})
        self.assertEqual(collector.sample(), [])
        connections.return_value = [connection(state="TIME_WAIT"), connection(udp=True)]
        events = collector.sample()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["protocol"], "UDP")
        self.assertIsNone(events[0]["remote_ip"])
        self.assertIsNone(events[0]["remote_port"])

    @patch("sentinelcmd.collectors.network.psutil.net_connections")
    def test_snapshot_does_not_swallow_new_connections(self, connections: MagicMock) -> None:
        connections.return_value = []
        collector = NetworkCollector({})
        collector.sample()
        connections.return_value = [connection()]
        collector.snapshot()
        self.assertEqual(len(collector.sample()), 1)

    @patch("sentinelcmd.collectors.network.psutil.net_connections")
    def test_access_denied_retains_baseline(self, connections: MagicMock) -> None:
        connections.return_value = [connection()]
        collector = NetworkCollector({})
        collector.sample()
        connections.side_effect = psutil.AccessDenied()
        self.assertEqual(collector.sample(), [])
        connections.side_effect = None
        self.assertEqual(collector.sample(), [])


class FileTests(unittest.TestCase):
    def test_no_implicit_monitor_scope(self) -> None:
        collector = FileCollector({})
        self.assertEqual(collector.sample(), [])
        self.assertFalse(collector.status["enabled"])

    def test_baseline_created_modified_deleted_without_pid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "existing.txt"
            original.write_text("initial", encoding="utf-8")
            collector = FileCollector({"monitor_paths": [directory], "file_scan_budget_ms": 1000})
            self.assertEqual(cycle(collector), [])
            original.write_text("changed length", encoding="utf-8")
            added = root / "new.txt"
            added.write_text("new", encoding="utf-8")
            events = cycle(collector)
            self.assertEqual({event["kind"] for event in events}, {"file_created", "file_modified"})
            self.assertTrue(all("pid" not in event for event in events))
            added.unlink()
            events = cycle(collector)
            self.assertEqual([event["kind"] for event in events], ["file_deleted"])
            self.assertEqual(events[0]["file_path"], str(added))

    def test_max_depth_and_file_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(5):
                (root / f"file-{index}.txt").write_text("data", encoding="utf-8")
            (root / "child").mkdir()
            (root / "child" / "deep.txt").write_text("deep", encoding="utf-8")
            collector = FileCollector({"monitor_paths": [directory], "max_files": 2, "max_depth": 0})
            self.assertEqual(cycle(collector), [])
            self.assertEqual(len(collector.snapshot()), 2)
            self.assertTrue(collector.status["truncated"])
            self.assertFalse(collector.status["complete"])
            self.assertTrue(all("deep.txt" not in row["file_path"] for row in collector.snapshot()))

    def test_inaccessible_cycle_does_not_invent_deletions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "file.txt").write_text("data", encoding="utf-8")
            collector = FileCollector({"monitor_paths": [directory]})
            cycle(collector)
            with patch("sentinelcmd.collectors.files.os.scandir", side_effect=PermissionError()):
                self.assertEqual(cycle(collector), [])
            self.assertFalse(collector.status["complete"])
            self.assertEqual(cycle(collector), [])

    def test_directory_only_tree_is_bounded_by_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for index in range(50):
                (Path(directory) / str(index)).mkdir()
            collector = FileCollector({"monitor_paths": [directory], "max_entries": 5})
            cycle(collector)
            self.assertTrue(collector.status["truncated"])
            self.assertLessEqual(collector.status["scanned_entries"], 5)
            self.assertEqual(collector.snapshot(), [])

    def test_links_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as other:
            target = Path(other) / "external.txt"
            target.write_text("outside monitor scope", encoding="utf-8")
            try:
                os.symlink(other, Path(directory) / "link", target_is_directory=True)
            except OSError:
                self.skipTest("Creating symlinks is not permitted on this Windows host")
            collector = FileCollector({"monitor_paths": [directory]})
            cycle(collector)
            self.assertEqual(collector.snapshot(), [])


class SystemTests(unittest.TestCase):
    @patch("sentinelcmd.collectors.system.platform.system", return_value="Linux")
    @patch("sentinelcmd.collectors.system.subprocess.run")
    def test_unsupported_platform_never_executes_powershell(self, run: MagicMock, platform: MagicMock) -> None:
        self.assertFalse(SystemInspector().inspect()["supported"])
        run.assert_not_called()

    @patch("sentinelcmd.collectors.system.platform.system", return_value="Windows")
    @patch("sentinelcmd.collectors.system.subprocess.run")
    def test_windows_query_is_bounded_and_read_only(self, run: MagicMock, platform: MagicMock) -> None:
        run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps({"defender": {"available": False}}))
        result = SystemInspector().inspect()
        self.assertFalse(result["checks"]["defender"]["available"])
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertNotIn("shell", run.call_args.kwargs)
        command = run.call_args.args[0]
        self.assertIn("-NonInteractive", command)
        self.assertNotIn("Set-MpPreference", command[-1])


if __name__ == "__main__":
    unittest.main()
