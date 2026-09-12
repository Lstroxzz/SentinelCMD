"""Orchestration regression tests with fake host collectors and fake responses.

Only a temporary SQLite journal/log is real. No test inventories the host, reads
its process command lines, hashes host executables, or changes firewall rules.
"""

from __future__ import annotations

import copy
import threading
from types import SimpleNamespace

import pytest

from sentinelcmd import monitor as module
from sentinelcmd.config import validate_config
from sentinelcmd.storage import EventStore


GOOD_HASH = "a" * 64
BAD_HASH = "b" * 64
PUBLIC_IP = "8.8.8.8"  # Test data only: no socket calls are made.


def process(**updates):
    return {
        "kind": "process_started", "pid": 100, "ppid": 50,
        "process_created_at": 1700000000.0,
        "process_name": "app.exe", "executable": r"C:\Program Files\Vendor\app.exe",
        "command_line": "app.exe", "username": "TEST\\Alice", **updates,
    }


def connection(**updates):
    return {
        "kind": "network_connection", "pid": 100,
        "process_created_at": 1700000000.0, "process_name": "app.exe",
        "local_ip": "192.0.2.2", "local_port": 50000,
        "remote_ip": PUBLIC_IP, "remote_port": 443, "protocol": "TCP",
        "state": "ESTABLISHED", **updates,
    }


class FakeFirewall:
    def __init__(self):
        self.calls = []
        self.result = {"status": "blocked", "created": True}
        self.error = None

    def block_ip(self, address, *, reason):
        self.calls.append((address, reason))
        if self.error:
            raise self.error
        return dict(self.result)


class FakeHashes:
    def __init__(self, _limit):
        self.calls = []
        self.result = GOOD_HASH

    def get(self, path):
        self.calls.append(path)
        return self.result


class FakeLock:
    def __init__(self, _directory):
        self.held = False
        self.acquisitions = 0

    def acquire(self):
        if self.held:
            raise RuntimeError("Already held")
        self.held = True
        self.acquisitions += 1

    def release(self):
        self.held = False


@pytest.fixture
def harness(monkeypatch, tmp_path):
    state = SimpleNamespace(
        snapshots={"processes": [], "network": [], "files": []},
        failures={}, ready=threading.Event(), monitors=[], stores=[],
    )

    class FakeCollector:
        def __init__(self, name):
            self.name = name
            self.last_error = None
            self.closed = 0
            self.status = {"truncated": False, "inaccessible_entries": 0}
            self._current = []

        def sample(self):
            if self.name in state.failures:
                raise state.failures[self.name]
            if self.name == "files":
                state.ready.set()
            return []

        def snapshot(self):
            self._current = copy.deepcopy(state.snapshots[self.name])
            return copy.deepcopy(self._current)

        def close(self):
            self.closed += 1

    class FakeSelf:
        def cpu_percent(self, _interval):
            return 0.25

        def memory_info(self):
            return SimpleNamespace(rss=32 * 1024 * 1024)

    monkeypatch.setattr(module, "ProcessCollector", lambda config: FakeCollector("processes"))
    monkeypatch.setattr(module, "NetworkCollector", lambda config: FakeCollector("network"))
    monkeypatch.setattr(module, "FileCollector", lambda config: FakeCollector("files"))
    monkeypatch.setattr(module, "FirewallManager", FakeFirewall)
    monkeypatch.setattr(module, "HashCache", FakeHashes)
    monkeypatch.setattr(module, "MonitorLock", FakeLock)
    monkeypatch.setattr(module.psutil, "Process", FakeSelf)

    def create(**overrides):
        config = validate_config(overrides)
        directory = tmp_path / f"case_{len(state.monitors)}"
        store = EventStore(directory, config)
        monitor = module.Monitor(config, directory, store)
        state.monitors.append(monitor)
        state.stores.append(store)
        return monitor

    state.create = create
    yield state
    for monitor in state.monitors:
        monitor.close()
    for store in state.stores:
        store.close()


@pytest.mark.parametrize(("enabled", "listed", "score", "expected_calls"), [
    (False, True, 100, 0), (True, False, 100, 0),
    (True, True, 79, 0), (True, True, 80, 1),
])
def test_auto_response_requires_opt_in_exact_indicator_and_critical_score(harness, enabled, listed, score, expected_calls):
    monitor = harness.create(auto_block_ips=enabled, blocked_ips=[PUBLIC_IP] if listed else [])
    action = monitor._respond(connection(), {"score": score})
    assert len(monitor.firewall.calls) == expected_calls
    assert action == ("firewall_blocked" if expected_calls else "alerted")


@pytest.mark.parametrize("address", ["127.0.0.1", "192.168.1.1", "10.0.0.1", "::1", "169.254.169.254"])
def test_automatic_response_does_not_block_local_or_private_addresses(harness, address):
    monitor = harness.create(auto_block_ips=True, blocked_ips=[address])
    assert monitor._respond(connection(remote_ip=address), {"score": 100}) == "alerted_auto_block_ineligible"
    assert not monitor.firewall.calls


def test_auto_response_matches_equivalent_ipv6_notation(harness):
    address = "2606:4700:4700::1111"
    monitor = harness.create(auto_block_ips=True, blocked_ips=[address])
    result = monitor._process([connection(remote_ip="2606:4700:4700:0:0:0:0:1111")])
    assert result[0]["action"] == "firewall_blocked"
    assert monitor.firewall.calls[0][0] == address


def test_block_counter_counts_created_rules_not_cooldown_or_existing_rules(harness):
    monitor = harness.create(auto_block_ips=True, blocked_ips=[PUBLIC_IP])
    initial = monitor._process([connection()])
    assert initial[0]["action"] == "firewall_blocked"
    monitor._process([connection()])
    assert len(monitor.firewall.calls) == 1
    assert monitor.store.query(1)[0]["action"] == "alerted_auto_block_cooldown"
    monitor._auto_attempts.clear()
    monitor.firewall.result["created"] = False
    monitor._process([connection()])
    assert monitor.store.query(1)[0]["action"] == "firewall_already_blocked"
    assert monitor.store.counts()["blocked_today_utc"] == 1


@pytest.mark.parametrize("error", [OSError("denied"), ValueError("invalid"), RuntimeError("unavailable")])
def test_failed_response_is_logged_as_failure_not_blocked(harness, error):
    monitor = harness.create(auto_block_ips=True, blocked_ips=[PUBLIC_IP])
    monitor.firewall.error = error
    result = monitor._process([connection()])
    assert result[0]["action"] == "auto_block_failed"
    assert monitor.store.counts()["blocked_today_utc"] == 0


def test_unconfirmed_response_is_not_counted_as_blocked(harness):
    monitor = harness.create(auto_block_ips=True, blocked_ips=[PUBLIC_IP])
    monitor.firewall.result = {"status": "unconfirmed", "created": False}
    result = monitor._process([connection()])
    assert result[0]["action"] == "auto_block_unconfirmed"
    assert monitor.store.counts()["blocked_today_utc"] == 0


def test_start_stop_lifecycle_resets_collectors_and_releases_lock(harness):
    monitor = harness.create()
    initial_collector = monitor.processes
    assert monitor.status()["status"] == "STOPPED"
    assert monitor.start() is True
    assert harness.ready.wait(2), "Fake file collector did not receive a worker poll"
    assert monitor.processes is not initial_collector
    assert monitor.start() is False
    assert monitor.status()["status"] == "MONITORING"
    assert monitor.status()["ram_mb"] == 32
    assert monitor.stop() is True
    assert monitor.stop() is False
    assert not monitor.running
    assert not monitor._lock.held
    assert monitor.files.closed >= 1
    actions = {event["action"] for event in monitor.store.query()}
    assert {"monitoring_started", "monitoring_stopped"} <= actions


def test_worker_failure_is_visible_and_cannot_claim_monitoring(harness):
    harness.failures["processes"] = RuntimeError("simulated collector failure")
    monitor = harness.create()
    assert monitor.start()
    monitor._thread.join(timeout=2)
    assert not monitor.running
    assert monitor.status()["status"] == "STOPPED"
    assert monitor.status()["health"]["worker"] == "RuntimeError"
    assert not monitor._lock.held
    assert monitor.store.query(1)[0]["kind"] == "monitor_stopped"


def test_start_setup_failure_does_not_leave_monitor_lock_held(harness, monkeypatch):
    monitor = harness.create()

    def fail_reload(_config):
        raise ValueError("simulated invalid config")

    monkeypatch.setattr(monitor.engine, "reload", fail_reload)
    with pytest.raises(ValueError, match="simulated"):
        monitor.start()
    assert not monitor._lock.held
    assert not monitor.running


def test_scan_is_read_only_even_when_automatic_response_is_enabled(harness):
    harness.snapshots["network"] = [connection()]
    harness.snapshots["processes"] = [process()]
    monitor = harness.create(auto_block_ips=True, blocked_ips=[PUBLIC_IP])
    result = monitor.scan()
    assert result["processes_scanned"] == 1
    assert result["connections_scanned"] == 1
    assert result["alerts"][0]["action"] == "alerted"
    assert not monitor.firewall.calls
    assert not monitor._auto_attempts
    assert not monitor.running


def test_every_scan_reports_current_findings_despite_live_alert_deduplication(harness):
    harness.snapshots["network"] = [connection()]
    monitor = harness.create(blocked_ips=[PUBLIC_IP])
    assert len(monitor._process([connection()])) == 1
    assert len(monitor.scan()["alerts"]) == 1
    assert len(monitor.scan()["alerts"]) == 1


def test_network_enrichment_requires_matching_pid_and_creation_time(harness):
    monitor = harness.create()
    monitor._refresh_process_records([process(command_line="app.exe --token sensitive", username="TEST\\Alice")])
    same = monitor._enrich(connection())
    assert same["username"] == "TEST\\Alice"
    assert same["executable"] == process()["executable"]
    assert "username" not in monitor._enrich(connection(process_created_at=1700000001.0))
    assert "username" not in monitor._enrich(connection(process_created_at=None))
    assert "username" not in monitor._enrich(connection(pid=101))


def test_hash_budget_caps_attempts_and_marks_uncomputed_records(harness):
    monitor = harness.create(hashes_per_cycle=2)
    records = [process(pid=100 + n, executable=rf"C:\Temp\app{n}.exe") for n in range(5)]
    assert len(monitor._process(records)) == 5
    assert len(monitor.hashes.calls) == 2
    stored = monitor.store.query()
    assert sum(e["hash_status"] == "computed" for e in stored) == 2
    assert sum(e["hash_status"] == "not_computed" for e in stored) == 3


def test_hash_budget_zero_never_hashes_and_failed_hash_is_explicit(harness):
    disabled = harness.create(hashes_per_cycle=0)
    disabled._process([process(executable=r"C:\Temp\app.exe")])
    assert not disabled.hashes.calls
    assert disabled.store.query(1)[0]["hash_status"] == "not_computed"
    limited = harness.create()
    limited.hashes.result = None
    limited._process([process(executable=r"C:\Temp\app.exe")])
    stored = limited.store.query(1)[0]
    assert stored["hash_status"] == "unavailable_or_budget_exceeded"
    assert stored["sha256"] is None
    assert stored["score"] > 0


def test_normal_process_not_hashed_without_explicit_hash_indicators(harness):
    monitor = harness.create()
    monitor._process([process()])
    assert not monitor.hashes.calls
    indicator = harness.create(blocked_hashes=[BAD_HASH])
    indicator.hashes.result = BAD_HASH
    result = indicator._process([process()])
    assert len(indicator.hashes.calls) == 1
    assert result[0]["rule_ids"] == ["blocked_hash"]


def test_lazy_hash_allowlist_suppresses_provisional_heuristic_alert(harness):
    monitor = harness.create(allowed_hashes=[GOOD_HASH])
    assert monitor._process([process(executable=r"C:\Temp\app.exe")]) == []
    assert monitor.store.query(1)[0]["risk"] == "info"
    assert not monitor.engine._evidence


def test_command_lines_are_available_for_detection_but_private_by_default(harness):
    monitor = harness.create()
    command = "powershell.exe -EncodedCommand YWJj --token top-secret-value"
    result = monitor._process([process(process_name="powershell.exe", command_line=command)])
    assert "encoded_command" in result[0]["rule_ids"]
    assert result[0]["command_line"] is None
    assert "top-secret-value" not in str(monitor.store.query())
    assert command == "powershell.exe -EncodedCommand YWJj --token top-secret-value"


def test_opted_in_command_line_storage_redacts_common_secret_flags(harness):
    monitor = harness.create(store_command_lines=True)
    monitor._process([process(command_line="app.exe --token top-secret-value password=other-secret")])
    stored = monitor.store.query(1)[0]["command_line"]
    assert "top-secret-value" not in stored
    assert "other-secret" not in stored
    assert stored.count("[REDACTED]") == 2


def test_disabled_connection_logging_retains_alerts_only(harness):
    monitor = harness.create(log_connections=False, blocked_ips=[PUBLIC_IP])
    monitor._process([connection(remote_ip="1.1.1.1"), connection()])
    assert len(monitor.store.query()) == 1
    assert monitor.store.query(1)[0]["remote_ip"] == PUBLIC_IP


def test_coverage_health_records_change_once_and_recovers(harness):
    monitor = harness.create()
    monitor.processes.last_error = "AccessDenied"
    monitor._record_health("processes", monitor.processes)
    monitor._record_health("processes", monitor.processes)
    assert len(monitor.store.query()) == 1
    assert monitor.status()["health"]["processes"] == "AccessDenied"
    monitor.processes.last_error = None
    monitor._record_health("processes", monitor.processes)
    assert "processes" not in monitor.status()["health"]
    monitor.files.status["truncated"] = True
    monitor._record_health("files", monitor.files)
    assert "files" in monitor.status()["health"]
