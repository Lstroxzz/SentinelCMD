"""Response tests use disposable bytes and mocked firewall/process operations."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import psutil
import pytest

from sentinelcmd.response import FirewallManager, QuarantineManager, terminate_process
from sentinelcmd.response.firewall import RULE_GROUP, RULE_PREFIX, validate_public_ip
from sentinelcmd.response import quarantine as quarantine_module


@pytest.fixture
def sandbox():
    # System temp is deliberately outside the protected project directory.
    with tempfile.TemporaryDirectory(prefix="sentinelcmd-response-test-") as directory:
        yield Path(directory)


@pytest.fixture
def manager(sandbox):
    return QuarantineManager(sandbox / "data")


def test_quarantine_restore_round_trip_and_no_overwrite(manager, sandbox):
    source = sandbox / "harmless.txt"
    payload = b"SentinelCMD harmless fixture\x00\x01\xff"
    source.write_bytes(payload)
    item = manager.quarantine(
        source, reason="explicit test", expected_sha256=hashlib.sha256(payload).hexdigest()
    )
    assert item["status"] == "quarantined"
    assert item["source_removed"] is True
    assert not source.exists()
    assert manager.list_items()[0]["sha256"] == hashlib.sha256(payload).hexdigest()
    blob = manager.root / (item["id"] + ".blob")
    assert blob.read_bytes() == payload
    source.write_bytes(b"a newer original must be preserved")
    with pytest.raises(FileExistsError):
        manager.restore(item["id"])
    assert source.read_bytes() == b"a newer original must be preserved"
    restored = sandbox / "restored.txt"
    result = manager.restore(item["id"], restored)
    assert result["status"] == "restored"
    assert restored.read_bytes() == payload
    assert not blob.exists()


def test_hash_mismatch_preserves_original_and_cleans_staging(manager, sandbox):
    source = sandbox / "original.txt"
    source.write_bytes(b"keep this")
    with pytest.raises(ValueError, match="expected SHA-256"):
        manager.quarantine(source, expected_sha256="0" * 64)
    assert source.read_bytes() == b"keep this"
    assert manager.list_items() == []
    assert list(manager.root.glob("*.blob")) == []
    assert list(manager.root.glob("*.partial")) == []


def test_quarantine_rejects_directories_protected_paths_size_and_bad_hash(manager, sandbox):
    source = sandbox / "sample.txt"
    source.write_text("too big", encoding="utf-8")
    with pytest.raises(ValueError, match="regular files"):
        manager.quarantine(sandbox)
    with pytest.raises(ValueError, match="Protected path"):
        manager.quarantine(Path(quarantine_module.__file__))
    with pytest.raises(ValueError, match="hexadecimal"):
        manager.quarantine(source, expected_sha256="invalid")
    manager.max_file_bytes = 1
    with pytest.raises(ValueError, match="limit"):
        manager.quarantine(source)
    assert source.exists()


def test_multiple_hardlinks_are_rejected(manager, sandbox):
    source = sandbox / "first.txt"
    source.write_bytes(b"protected by link count")
    linked = sandbox / "second.txt"
    try:
        os.link(source, linked)
    except OSError:
        pytest.skip("Filesystem does not support hardlinks.")
    with pytest.raises(ValueError, match="multiple hard links"):
        manager.quarantine(linked)
    assert source.exists() and linked.exists()


def test_symlink_source_rejected(manager, sandbox):
    source = sandbox / "first.txt"
    source.write_bytes(b"keep")
    linked = sandbox / "link.txt"
    try:
        linked.symlink_to(source)
    except OSError:
        pytest.skip("Creating symlinks requires Windows developer mode or privilege.")
    with pytest.raises(ValueError, match="reparse points"):
        manager.quarantine(linked)
    assert source.read_bytes() == b"keep"


def test_existing_parent_link_is_rejected_even_without_symlink_privilege(manager, sandbox):
    from sentinelcmd.response import _files

    source = sandbox / "source.txt"
    source.write_bytes(b"keep")
    actual_lstat = Path.lstat

    def mark_parent_as_reparse(path, *args, **kwargs):
        info = actual_lstat(path, *args, **kwargs)
        if path == sandbox:
            return Mock(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    with patch.object(Path, "lstat", mark_parent_as_reparse):
        with pytest.raises(ValueError, match="reparse points"):
            _files.reject_links(source)
    assert source.read_bytes() == b"keep"


def test_manifest_write_failure_never_removes_original(manager, sandbox):
    source = sandbox / "source.txt"
    source.write_bytes(b"safe")
    with patch.object(manager, "_write_manifest", side_effect=OSError("simulated disk full")):
        with pytest.raises(OSError, match="disk full"):
            manager.quarantine(source)
    assert source.read_bytes() == b"safe"
    assert manager.list_items() == []
    assert list(manager.root.glob("*.blob")) == []


def test_removal_failure_returns_copy_only_and_preserves_backup(manager, sandbox):
    source = sandbox / "source.txt"
    source.write_bytes(b"safe")
    with patch.object(quarantine_module, "remove_open_source", side_effect=OSError("locked")):
        item = manager.quarantine(source)
    assert item["status"] == "copy_only"
    assert item["source_removed"] is False
    assert source.read_bytes() == b"safe"
    assert (manager.root / (item["id"] + ".blob")).read_bytes() == b"safe"


def test_failed_final_commit_retains_recoverable_blob(manager, sandbox):
    source = sandbox / "source.txt"
    source.write_bytes(b"recoverable")
    actual_write = manager._write_manifest
    calls = 0

    def fail_second(item):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated final commit failure")
        actual_write(item)

    with patch.object(manager, "_write_manifest", side_effect=fail_second):
        item = manager.quarantine(source)
    assert item["status"] == "recovery_required"
    assert not source.exists()
    assert manager.list_items()[0]["status"] == "prepared"
    assert manager.restore(item["id"])["status"] == "restored"
    assert source.read_bytes() == b"recoverable"


def test_tampered_blob_never_restores(manager, sandbox):
    source = sandbox / "source.txt"
    source.write_bytes(b"initial")
    item = manager.quarantine(source)
    (manager.root / (item["id"] + ".blob")).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        manager.restore(item["id"])
    assert not source.exists()


def test_manifest_traversal_corruption_and_delete(manager, sandbox):
    with pytest.raises(ValueError, match="Invalid quarantine item ID"):
        manager.restore("../../outside")
    corrupt_id = "f" * 32
    (manager.root / (corrupt_id + ".json")).write_text("{ broken", encoding="utf-8")
    assert manager.list_items() == [
        {"id": corrupt_id, "status": "corrupt", "warning": "Corrupt quarantine manifest."}
    ]
    source = sandbox / "source.txt"
    source.write_bytes(b"delete only this quarantine fixture")
    item = manager.quarantine(source)
    assert manager.delete(item["id"])["status"] == "deleted"
    assert not (manager.root / (item["id"] + ".blob")).exists()
    with pytest.raises(ValueError, match="no longer"):
        manager.restore(item["id"])


def test_lock_prevents_two_concurrent_managers(manager, sandbox):
    other = QuarantineManager(sandbox / "data")
    with manager._locked():
        with pytest.raises(OSError):
            other.list_items()


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL access check")
def test_quarantine_blob_denies_execute_access_without_executing_it(manager, sandbox):
    import ctypes
    from ctypes import wintypes

    source = sandbox / "harmless.txt"
    source.write_bytes(b"plain harmless test data")
    item = manager.quarantine(source)
    blob = manager.root / (item["id"] + ".blob")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # Merely request FILE_EXECUTE access. This does NOT load or execute a file.
    handle = kernel.CreateFileW(str(blob), 0x20, 7, None, 3, 0x80, None)
    error = ctypes.get_last_error()
    invalid = ctypes.c_void_p(-1).value
    if handle != invalid:
        kernel.CloseHandle(handle)
    assert handle == invalid and error == 5  # ERROR_ACCESS_DENIED
    assert blob.read_bytes() == b"plain harmless test data"


@pytest.mark.skipif(os.name != "nt", reason="Windows source-handle sharing guarantees")
def test_quarantine_source_handle_rejects_concurrent_writes(manager, sandbox):
    from sentinelcmd.response._files import open_source

    source = sandbox / "harmless.txt"
    source.write_bytes(b"preserved")
    with open_source(source):
        with pytest.raises(PermissionError):
            with source.open("ab"):
                pass
    assert source.read_bytes() == b"preserved"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fe80::1",
        "fc00::1",
        "100.64.0.1",
        "203.0.113.4",
        "198.51.100.4",
        "192.0.2.4",
        "example.org",
        "8.8.8.8/32",
        "8.8.8.8; whoami",
        "fe80::1%12",
        "::ffff:8.8.8.8",
        "2002:0808:0808::1",
    ],
)
def test_firewall_rejects_non_public_or_ambiguous_addresses(address):
    firewall = FirewallManager()
    with patch.object(firewall, "_run") as runner:
        with pytest.raises(ValueError):
            firewall.block_ip(address)
        runner.assert_not_called()


def test_firewall_accepts_public_literals_without_network_access():
    assert validate_public_ip("8.8.8.8") == "8.8.8.8"
    assert validate_public_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"


def test_firewall_block_is_deterministic_and_reason_is_data():
    firewall = FirewallManager()
    calls = []

    def fake_run(script, parameters):
        calls.append((script, parameters))
        return {
            "status": "blocked",
            "id": parameters["SENTINEL_RULE_ID"],
            "ip": parameters["SENTINEL_REMOTE_IP"],
            "group": RULE_GROUP,
            "created": len(calls) == 1,
            "direction": "Outbound",
            "action": "Block",
        }

    reason = "'; Write-Host unexpected; #"
    with patch.object(firewall, "_run", side_effect=fake_run):
        first = firewall.block_ip("8.8.8.8", reason)
        second = firewall.block_ip("8.8.8.8", reason)
    assert first["created"] is True and second["created"] is False
    assert first["id"] == second["id"]
    assert reason not in calls[0][0]
    assert calls[0][1]["SENTINEL_RULE_REASON"] == reason


@pytest.mark.parametrize(
    "rule_id", ["other-rule", "SentinelCMD-*", "SentinelCMD-../../bad", "SentinelCMD-test;exit"]
)
def test_firewall_refuses_foreign_rule_ids(rule_id):
    firewall = FirewallManager()
    with patch.object(firewall, "_run") as runner:
        with pytest.raises(ValueError):
            firewall.remove_rule(rule_id)
        runner.assert_not_called()


def test_firewall_lists_only_owned_rules_and_validates_results():
    firewall = FirewallManager()
    owned = {"id": RULE_PREFIX + "a" * 32, "group": RULE_GROUP}
    foreign = {"id": RULE_PREFIX + "b" * 32, "group": "Foreign"}
    with patch.object(firewall, "_run", return_value=[owned, foreign]):
        assert firewall.list_rules() == [owned]
    with patch.object(firewall, "_run", return_value={"status": "blocked"}):
        with pytest.raises(OSError, match="verified"):
            firewall.block_ip("8.8.8.8")


@pytest.mark.skipif(os.name != "nt", reason="PowerShell runner is Windows only")
def test_firewall_subprocess_has_no_shell_and_uses_timeout():
    firewall = FirewallManager(timeout=5)
    completed = Mock(returncode=0, stdout="[]", stderr="")
    with patch("sentinelcmd.response.firewall.subprocess.run", return_value=completed) as runner:
        assert firewall.list_rules() == []
    args, kwargs = runner.call_args
    assert isinstance(args[0], list)
    assert "-NoProfile" in args[0] and "-EncodedCommand" in args[0]
    assert kwargs["shell"] is False and kwargs["timeout"] == 5


@pytest.mark.parametrize("pid", [0, 4, -1, True, os.getpid(), os.getppid()])
def test_manual_termination_rejects_protected_pids_without_touching_processes(pid):
    with patch("sentinelcmd.response.process.psutil.Process") as process:
        with pytest.raises(ValueError):
            terminate_process(pid, 123.0)
        process.assert_not_called()


def test_manual_termination_rejects_pid_reuse_and_critical_names():
    process = Mock()
    process.create_time.return_value = 124.0
    with patch("sentinelcmd.response.process.psutil.Process", return_value=process):
        with pytest.raises(ValueError, match="identity changed"):
            terminate_process(12345, 123.0)
    process.terminate.assert_not_called()
    process.create_time.return_value = 123.0
    process.name.return_value = "lsass.exe"
    with patch("sentinelcmd.response.process.psutil.Process", return_value=process):
        with pytest.raises(ValueError, match="critical"):
            terminate_process(12345, 123.0)
    process.terminate.assert_not_called()


def test_manual_termination_reports_disappearing_process_without_traceback():
    with patch("sentinelcmd.response.process.psutil.Process", side_effect=psutil.NoSuchProcess(12345)):
        with pytest.raises(ValueError, match="no longer available"):
            terminate_process(12345, 123.0)


def test_manual_termination_checks_fresh_identity_and_never_kills_children(sandbox):
    selected, current, own = Mock(), Mock(), Mock()
    selected.create_time.return_value = current.create_time.return_value = 123.0
    selected.name.return_value = "harmless-test.exe"
    selected.exe.return_value = str(sandbox / "harmless-test.exe")
    selected.username.return_value = own.username.return_value = "test-user"
    current.is_running.return_value = True
    current.wait.side_effect = psutil.TimeoutExpired(3)
    with patch("sentinelcmd.response.process.psutil.Process", side_effect=[selected, own, current]):
        result = terminate_process(12345, 123.0)
    assert result["status"] == "termination_requested"
    current.terminate.assert_called_once_with()
    current.kill.assert_not_called()
    selected.children.assert_not_called()
    current.children.assert_not_called()
