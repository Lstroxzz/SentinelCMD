"""Storage, configuration and privacy tests stay inside temporary directories."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import pytest

from sentinelcmd.config import ConfigManager, validate_config
from sentinelcmd.privacy import command_line_for_storage, csv_cell, safe_text
from sentinelcmd.storage import EventStore


def test_default_config_is_validated_and_round_trips_atomically(tmp_path):
    manager = ConfigManager(tmp_path)
    config = manager.load()
    assert config["rules_enabled"] is True
    assert config["max_entries"] == 10000
    saved = manager.save({**config, "max_entries": 25, "blocked_ips": ["2001:0db8::1"]})
    assert saved["max_entries"] == 25
    assert manager.load()["blocked_ips"] == ["2001:db8::1"]
    assert not list(tmp_path.glob(".sentinel-*.tmp"))


@pytest.mark.parametrize("raw", [
    {"max_events": 0}, {"max_entries": 1_000_001}, {"monitor_paths": ["relative"]},
    {"blocked_ips": ["not-an-ip"]}, {"blocked_hashes": ["a"]},
    {"store_command_lines": "true"}, {"unknown": 1},
])
def test_config_rejects_unsafe_or_unknown_values(raw):
    with pytest.raises(ValueError):
        validate_config(raw)


def test_event_store_retains_schema_and_counts_actions(tmp_path):
    config = validate_config({"max_events": 100})
    store = EventStore(tmp_path, config)
    try:
        first = store.append({"kind": "process_started", "pid": 4}, {"score": 80, "risk": "critical"}, "alerted")
        store.append({"kind": "network_connection", "remote_ip": "8.8.8.8"}, {"score": 100, "risk": "critical"}, "firewall_blocked")
        assert first["id"]
        assert store.counts()["suspicious_today_utc"] == 2
        assert store.counts()["blocked_today_utc"] == 1
        assert store.query(pid=4)[0]["kind"] == "process_started"
    finally:
        store.close()


def test_event_store_prunes_old_and_excess_events(tmp_path):
    config = validate_config({"max_events": 100, "retention_days": 1})
    store = EventStore(tmp_path, config)
    try:
        old = store.append({"kind": "old"})
        old_time = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        store._db.execute("UPDATE events SET timestamp=? WHERE id=?", (old_time, old["id"]))
        store._db.commit()
        for index in range(101):
            store.append({"kind": f"new-{index}"})
        store.prune()
        events = store.query(limit=1000)
        assert len(events) == 100
        assert all(item["kind"].startswith("new-") for item in events)
    finally:
        store.close()


def test_exports_are_explicit_and_csv_cells_are_safe(tmp_path):
    config = validate_config({"store_command_lines": True})
    store = EventStore(tmp_path, config)
    try:
        store.append({"kind": "manual", "command_line": "app --token secret-value", "process_name": "=FORMULA"})
        json_path = tmp_path / "report.json"
        csv_path = tmp_path / "report.csv"
        assert store.export(json_path, "json")["events"] == 1
        assert json.loads(json_path.read_text(encoding="utf-8"))["schema_version"] == 1
        store.export(csv_path, "csv")
        csv_text = csv_path.read_text(encoding="utf-8")
        assert "secret-value" not in csv_text
        assert "'=FORMULA" in csv_text
        with pytest.raises(FileExistsError):
            store.export(json_path, "json")
    finally:
        store.close()


def test_privacy_redacts_flags_and_terminal_controls():
    raw = "powershell.exe\x1b[31m --token top-secret password=other-secret"
    assert command_line_for_storage(raw, False) is None
    clean = command_line_for_storage(raw, True)
    assert "top-secret" not in clean and "other-secret" not in clean
    assert "\x1b" not in clean
    assert "\x1b" not in safe_text(raw)
    assert csv_cell("=1+1").startswith("'=")
    assert "secret-value" not in command_line_for_storage(["app", "--token", "secret-value"], True)
