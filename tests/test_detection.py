"""Detection tests focus on false positives, identity boundaries and limits."""

import pytest

from sentinelcmd.detection import RuleEngine
from sentinelcmd.detection import engine as module


GOOD_HASH = "a" * 64
BAD_HASH = "b" * 64


def process(**updates):
    return {
        "kind": "process_started",
        "pid": 100,
        "ppid": 50,
        "process_created_at": 1700000000.0,
        "process_name": "app.exe",
        "executable": r"C:\Program Files\Vendor\app.exe",
        "command_line": ["app.exe"],
        **updates,
    }


@pytest.fixture
def clock(monkeypatch):
    current = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: current[0])
    return current


def test_normal_process_and_network_have_no_heuristic_verdict():
    engine = RuleEngine({})
    assert engine.evaluate(process()) is None
    assert engine.evaluate({"kind": "network_connection", "remote_ip": "8.8.8.8", "remote_port": 443}) is None


@pytest.mark.parametrize("path", [r"C:\Windows\System32\svchost.exe", r"C:\Windows\SysWOW64\svchost.exe", r"C:\WINDOWS\SYSTEM32\SVCHOST.EXE", r"C:\Windows\WinSxS\component\svchost.exe"])
def test_windows_known_directories_are_not_impersonation(path, monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert RuleEngine({}).evaluate(process(process_name="svchost.exe", executable=path)) is None


def test_windows_root_may_be_custom(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"D:\OperatingSystem")
    engine = RuleEngine({})
    assert engine.evaluate(process(process_name="lsass.exe", executable=r"D:\OperatingSystem\System32\lsass.exe")) is None
    result = engine.evaluate(process(process_name="lsass.exe", executable=r"C:\Windows\System32\lsass.exe"))
    assert result["rule_ids"] == ["system_name_path"]


def test_missing_path_does_not_prove_impersonation():
    assert RuleEngine({}).evaluate(process(process_name="svchost.exe", executable=None)) is None


def test_windows_name_outside_system_dir_is_only_medium():
    result = RuleEngine({}).evaluate(process(process_name="svchost.exe"))
    assert result["risk"] == "medium"
    assert result["evidence_count"] == 1
    assert "malware" not in " ".join(result["reasons"]).lower()


def test_nested_system32_does_not_match_expected_system_directory(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    result = RuleEngine({}).evaluate(process(process_name="svchost.exe", executable=r"C:\Windows\System32\Tools\svchost.exe"))
    assert "system_name_path" in result["rule_ids"]


def test_overlapping_location_rules_are_one_evidence_group():
    result = RuleEngine({}).evaluate(process(executable=r"C:\Users\Alice\AppData\Local\Temp\app.exe"))
    assert result["score"] == 20
    assert result["evidence_count"] == 1
    assert result["rule_ids"] == ["process_temp"]


def test_two_independent_signals_raise_risk():
    result = RuleEngine({}).evaluate(process(process_name="svchost.exe", executable=r"C:\Temp\svchost.exe"))
    assert result["score"] == 55
    assert result["risk"] == "high"
    assert result["evidence_count"] == 2


def test_powershell_argument_rules_do_not_double_count_commands():
    result = RuleEngine({}).evaluate(process(process_name="powershell.exe", command_line=["powershell.exe", "-EncodedCommand", "YWJj", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass"]))
    assert result["score"] == 30
    assert result["evidence_count"] == 1
    assert result["rule_ids"] == ["unusual_command"]


@pytest.mark.parametrize("command", ["powershell.exe -File normal.ps1", "powershell.exe -ExecutionPolicy Bypass -File setup.ps1", "powershell.exe -WindowStyle Hidden -File updater.ps1", "powershell.exe -ErrorAction Continue", "powershell.exe -encryption enabled"])
def test_single_common_powershell_arguments_not_suspicious(command):
    assert RuleEngine({}).evaluate(process(process_name="powershell.exe", command_line=command)) is None


def test_command_detection_is_specific_to_process():
    assert RuleEngine({}).evaluate(process(process_name="encoder.exe", command_line="encoder.exe -EncodedCommand abc")) is None


def test_download_folder_name_is_not_download_evidence():
    assert RuleEngine({}).evaluate(process(executable=r"C:\Users\Alice\Downloads\app.exe")) is None
    result = RuleEngine({}).evaluate(process(downloaded=True))
    assert result["rule_ids"] == ["downloaded_executable"]
    assert "Zone.Identifier" in result["reasons"][0]


@pytest.mark.parametrize("filename", ["invoice.pdf.exe", "photo.JPG.SCR", "report.txt.ps1"])
def test_double_extension(filename):
    result = RuleEngine({}).evaluate({"kind": "file_created", "file_path": "C:\\Users\\Alice\\" + filename})
    assert result["rule_ids"] == ["double_extension"]


@pytest.mark.parametrize("filename", ["report.pdf", "program.exe", "python3.12.exe", "archive.tar.gz", "file.exe.txt"])
def test_normal_extension(filename):
    assert RuleEngine({}).evaluate({"kind": "file_created", "file_path": "C:\\Users\\Alice\\" + filename}) is None


def test_exact_user_hash_can_be_critical_without_other_signals():
    result = RuleEngine({"blocked_hashes": [BAD_HASH.upper()]}).evaluate(process(sha256=BAD_HASH))
    assert result["risk"] == "critical"
    assert result["score"] == 100
    assert result["evidence_count"] == 1
    assert "fornecido pelo usuário" in result["reasons"][0]


def test_exact_hash_block_takes_precedence_over_directory_allowlist():
    result = RuleEngine({"allowed_paths": [r"C:\Program Files"], "blocked_hashes": [BAD_HASH]}).evaluate(process(sha256=BAD_HASH))
    assert result["rule_ids"] == ["blocked_hash"]


@pytest.mark.parametrize(("configured", "observed"), [("203.0.113.8", "203.0.113.8"), ("2001:db8::1", "2001:0db8:0000::1")])
def test_exact_ip_normalization(configured, observed):
    result = RuleEngine({"blocked_ips": [configured]}).evaluate({"kind": "network_connection", "remote_ip": observed})
    assert result["rule_ids"] == ["blocked_ip"]
    assert result["risk"] == "critical"


def test_ip_ioc_has_no_substring_matching():
    engine = RuleEngine({"blocked_ips": ["203.0.113.8"]})
    assert engine.evaluate({"kind": "network_connection", "remote_ip": "203.0.113.80"}) is None
    assert engine.evaluate({"kind": "network_connection", "remote_ip": "invalid"}) is None


@pytest.mark.parametrize("config", [
    {"blocked_ips": ["example.org"]}, {"blocked_ips": ["192.0.2.0/24"]},
    {"blocked_hashes": ["123"]}, {"allowed_hashes": ["z" * 64]},
    {"allowed_hashes": [GOOD_HASH], "blocked_hashes": [GOOD_HASH]},
    {"allowed_paths": ["relative/path"]}, {"allowed_paths": [r"C:relative"]},
    {"blocked_ips": "203.0.113.1"}, {"disabled_rules": ["not_a_rule"]},
    {"child_threshold": True}, {"child_threshold": 1},
    {"child_window_seconds": 0}, {"child_window_seconds": float("nan")},
    {"rules_enabled": "true"},
])
def test_configuration_rejects_invalid_indicators_and_limits(config):
    with pytest.raises(ValueError):
        RuleEngine(config)


def test_allowlist_exact_directory_boundary_and_case():
    engine = RuleEngine({"allowed_paths": [r"C:\Temp\Trusted"]})
    assert engine.evaluate(process(executable=r"c:\temp\TRUSTED\app.exe")) is None
    assert engine.evaluate(process(executable=r"C:\Temp\TrustedEvil\app.exe")) is not None
    assert engine.evaluate(process(executable=r"C:\Temp\Trusted\..\Evil\app.exe")) is not None


def test_allowlist_extended_windows_and_unc_paths():
    engine = RuleEngine({"allowed_paths": [r"C:\Temp\Trusted", r"\\server\share\Temp\Trusted"]})
    assert engine.evaluate(process(executable=r"\\?\C:\Temp\Trusted\app.exe")) is None
    assert engine.evaluate(process(executable=r"\\?\UNC\server\share\Temp\Trusted\app.exe")) is None


def test_posix_allowlist_preserves_case_and_boundary():
    engine = RuleEngine({"allowed_paths": ["/tmp/Trusted"]})
    assert engine.evaluate(process(executable="/tmp/Trusted/app")) is None
    assert engine.evaluate(process(executable="/tmp/trusted/app")) is not None
    assert engine.evaluate(process(executable="/tmp/TrustedEvil/app")) is not None


def test_hash_allowlist_suppresses_heuristics():
    assert RuleEngine({"allowed_hashes": [GOOD_HASH]}).evaluate(process(executable=r"C:\Temp\app.exe", sha256=GOOD_HASH)) is None


def test_lazy_hash_allowlist_discards_provisional_evidence():
    engine = RuleEngine({"allowed_hashes": [GOOD_HASH]})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    assert engine._evidence
    assert engine.evaluate(process(executable=r"C:\Temp\app.exe", sha256=GOOD_HASH)) is None
    assert not engine._evidence


def test_rules_can_be_disabled_and_reloaded():
    engine = RuleEngine({"disabled_rules": ["process_temp"]})
    assert engine.evaluate(process(executable=r"C:\Temp\app.exe")) is None
    assert not next(r for r in engine.list_rules() if r["id"] == "process_temp")["enabled"]
    engine.reload({})
    assert engine.evaluate(process(executable=r"C:\Temp\app.exe")) is not None
    engine.reload({"rules_enabled": False})
    assert engine.evaluate(process(executable=r"C:\Temp\app.exe")) is None
    assert not engine._evidence


def test_invalid_reload_keeps_previous_configuration():
    engine = RuleEngine({"blocked_ips": ["203.0.113.1"]})
    with pytest.raises(ValueError):
        engine.reload({"blocked_ips": ["not-an-ip"]})
    assert engine.evaluate({"kind": "network_connection", "remote_ip": "203.0.113.1"}) is not None


def test_rule_descriptors_are_copies():
    engine = RuleEngine({})
    descriptors = engine.list_rules()
    descriptors[0]["kinds"].clear()
    descriptors[0]["score"] = 100
    assert engine.evaluate(process(executable=r"C:\Temp\app.exe"))["score"] == 20


def test_same_identity_correlates_independent_signals_and_not_repetition():
    engine = RuleEngine({})
    first = engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    repeated = engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    assert first == repeated
    result = engine.evaluate(process(process_name="powershell.exe", command_line="powershell -enc YWJj"))
    assert result["score"] == 45
    assert result["evidence_count"] == 2


def test_pid_reuse_does_not_inherit_prior_evidence():
    engine = RuleEngine({})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    result = engine.evaluate(process(process_created_at=1700000001.0, process_name="powershell.exe", command_line="powershell -enc YWJj"))
    assert result["score"] == 25
    assert result["evidence_count"] == 1


def test_network_without_creation_time_cannot_inherit_pid_evidence():
    engine = RuleEngine({"blocked_ips": ["203.0.113.1"]})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    result = engine.evaluate({"kind": "network_connection", "pid": 100, "remote_ip": "203.0.113.1"})
    assert result["evidence_count"] == 1
    assert result["rule_ids"] == ["blocked_ip"]


def test_network_with_matching_creation_time_can_correlate():
    engine = RuleEngine({"blocked_ips": ["203.0.113.1"]})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    result = engine.evaluate({"kind": "network_connection", "pid": 100, "process_created_at": 1700000000.0, "remote_ip": "203.0.113.1"})
    assert result["evidence_count"] == 2


def test_file_pid_is_not_assumed_process_ownership():
    engine = RuleEngine({})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    result = engine.evaluate({"kind": "file_created", "pid": 100, "process_created_at": 1700000000.0, "file_path": r"C:\Docs\invoice.pdf.exe"})
    assert result["evidence_count"] == 1


def test_process_exit_removes_correlation():
    engine = RuleEngine({})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    engine.evaluate({"kind": "process_exited", "pid": 100})
    result = engine.evaluate(process(process_name="powershell.exe", command_line="powershell -enc YWJj"))
    assert result["evidence_count"] == 1


def test_late_exit_of_old_pid_identity_does_not_remove_new_identity():
    engine = RuleEngine({})
    engine.evaluate(process(executable=r"C:\Temp\app.exe", process_created_at=1700000001.0))
    engine.evaluate({"kind": "process_exited", "pid": 100, "process_created_at": 1700000000.0})
    result = engine.evaluate(process(process_name="powershell.exe", process_created_at=1700000001.0, command_line="powershell -enc YWJj"))
    assert result["evidence_count"] == 2


def test_correlation_expires_and_repeated_one_signal_does_not_refresh_others(clock):
    engine = RuleEngine({})
    engine.evaluate(process(executable=r"C:\Temp\app.exe"))
    clock[0] = 299
    engine.evaluate(process(process_name="powershell.exe", command_line="powershell -enc YWJj"))
    clock[0] = 301
    result = engine.evaluate(process(process_name="powershell.exe", command_line="powershell -enc YWJj"))
    assert result["evidence_count"] == 1
    clock[0] = 602
    engine.evaluate({"kind": "unknown"})
    assert not engine._evidence


def test_child_burst_uses_known_parent_and_short_window(clock):
    engine = RuleEngine({"child_threshold": 3, "child_window_seconds": 10})
    engine.evaluate(process(pid=50, ppid=1, process_created_at=1600000000.0))
    assert engine.evaluate(process(pid=100)) is None
    clock[0] = 1
    assert engine.evaluate(process(pid=101)) is None
    clock[0] = 2
    result = engine.evaluate(process(pid=102))
    assert result["rule_ids"] == ["child_burst"]
    assert "pai PID 50" in result["reasons"][0]
    assert "desconhecido" not in result["reasons"][0]
    clock[0] = 13
    assert engine.evaluate(process(pid=103)) is None


def test_duplicate_process_observation_does_not_create_child_burst():
    engine = RuleEngine({"child_threshold": 2})
    event = process(parent_created_at=1600000000.0)
    assert engine.evaluate(event) is None
    assert engine.evaluate(event) is None


def test_lazy_hash_reevaluation_preserves_child_burst_without_duplicate_count():
    engine = RuleEngine({"child_threshold": 2})
    engine.evaluate(process(pid=100, parent_created_at=1600000000.0))
    event = process(pid=101, parent_created_at=1600000000.0)
    first = engine.evaluate(event)
    second = engine.evaluate({**event, "sha256": GOOD_HASH})
    assert first == second
    assert all(len(entries) == 2 for _, entries in engine._children.values())


def test_baseline_does_not_count_preexisting_children_as_burst():
    engine = RuleEngine({"child_threshold": 2})
    for n in range(5):
        assert engine.evaluate(process(pid=100 + n, parent_created_at=1600000000.0, baseline=True)) is None
    assert not engine._children
    assert engine.evaluate(process(pid=200, parent_created_at=1600000000.0)) is None
    result = engine.evaluate(process(pid=201, parent_created_at=1600000000.0))
    assert "child_burst" in result["rule_ids"]


def test_baseline_still_applies_static_heuristics():
    result = RuleEngine({}).evaluate(process(executable=r"C:\Temp\app.exe", baseline=True))
    assert result["rule_ids"] == ["process_temp"]


def test_child_burst_does_not_merge_reused_parent_pid():
    engine = RuleEngine({"child_threshold": 2})
    engine.evaluate(process(pid=100, parent_created_at=1600000000.0))
    assert engine.evaluate(process(pid=101, parent_created_at=1600000001.0)) is None


def test_missing_parent_identity_does_not_guess_child_burst():
    engine = RuleEngine({"child_threshold": 2})
    assert engine.evaluate(process(pid=100)) is None
    assert engine.evaluate(process(pid=101)) is None


def test_all_tracking_maps_and_child_queues_are_bounded(monkeypatch):
    monkeypatch.setattr(RuleEngine, "MAX_IDENTITIES", 8)
    engine = RuleEngine({"child_threshold": 3})
    for n in range(50):
        engine.evaluate(process(pid=100 + n, ppid=1000 + n, parent_created_at=1500000000.0, executable=r"C:\Temp\app.exe"))
    assert len(engine._evidence) <= 8
    assert len(engine._known_processes) <= 8
    assert len(engine._children) <= 8
    for n in range(50):
        engine.evaluate(process(pid=200 + n, parent_created_at=1500000000.0))
    assert all(len(entries) <= 3 for _, entries in engine._children.values())
