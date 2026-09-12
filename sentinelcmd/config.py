"""Validated JSON configuration; no executable rules or remote configuration."""

from __future__ import annotations

import copy
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import tempfile

DEFAULTS = {
    "process_interval": 3.0,
    "network_interval": 5.0,
    "file_interval": 10.0,
    "monitor_paths": [],
    "max_files": 10000,
    "max_entries": 10000,
    "max_depth": 8,
    "file_scan_budget_ms": 100,
    "max_hash_mb": 64,
    "hashes_per_cycle": 4,
    "max_events": 50000,
    "retention_days": 30,
    "store_command_lines": False,
    "rules_enabled": True,
    "disabled_rules": [],
    "allowed_paths": [],
    "allowed_hashes": [],
    "blocked_hashes": [],
    "blocked_ips": [],
    "child_threshold": 12,
    "child_window_seconds": 60,
    "auto_block_ips": False,
    "log_connections": True,
}

RANGES = {
    "process_interval": (1, 3600), "network_interval": (2, 3600),
    "file_interval": (2, 3600), "max_files": (1, 100000), "max_depth": (0, 32),
    "file_scan_budget_ms": (5, 1000), "max_hash_mb": (1, 1024),
    "hashes_per_cycle": (0, 32), "max_events": (100, 1000000),
    "retention_days": (1, 3650), "child_threshold": (2, 1000),
    "max_entries": (1, 1000000),
    "child_window_seconds": (5, 3600),
}


def default_data_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "SentinelCMD"
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))) / "sentinelcmd"


def validate_config(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Configuracao precisa ser um objeto JSON.")
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise ValueError("Opcoes desconhecidas: " + ", ".join(sorted(unknown)))
    config = copy.deepcopy(DEFAULTS)
    config.update(raw)
    for key, default in DEFAULTS.items():
        value = config[key]
        if isinstance(default, bool):
            if type(value) is not bool:
                raise ValueError(f"{key}: use true ou false.")
        elif isinstance(default, (int, float)):
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError(f"{key}: numero invalido.")
            if isinstance(default, int) and type(value) is not int:
                raise ValueError(f"{key}: use um inteiro.")
            low, high = RANGES[key]
            if not low <= value <= high:
                raise ValueError(f"{key}: intervalo permitido {low} a {high}.")
        elif isinstance(default, list):
            if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
                raise ValueError(f"{key}: use uma lista de textos.")
            if len(value) > 10000 or any(len(x) > 32768 for x in value):
                raise ValueError(f"{key}: lista muito grande.")
    for key in ("allowed_hashes", "blocked_hashes"):
        if any(not re.fullmatch(r"[0-9a-fA-F]{64}", x) for x in config[key]):
            raise ValueError(f"{key}: cada hash deve ser SHA-256 hexadecimal completo.")
        config[key] = sorted({x.lower() for x in config[key]})
    config["blocked_ips"] = sorted({str(ipaddress.ip_address(x)) for x in config["blocked_ips"]})
    for key in ("monitor_paths", "allowed_paths"):
        paths = []
        for value in config[key]:
            path = Path(os.path.expandvars(value)).expanduser()
            if not path.is_absolute():
                raise ValueError(f"{key}: forneca caminhos absolutos.")
            # Reject UNC/device paths: this tool inspects local data only.
            if str(path).startswith(("\\\\", "//")):
                raise ValueError(f"{key}: caminhos de rede/dispositivo nao sao permitidos.")
            paths.append(str(path))
        config[key] = sorted(set(paths))
    # Bound aggregate configuration size as well as each individual value; a
    # large IOC/allowlist must not turn a settings update into a disk spike.
    encoded = json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("Configuracao excede 2 MB.")
    return config


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".sentinel-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class ConfigManager:
    def __init__(self, data_dir: Path, path: Path | None = None):
        self.path = path or data_dir / "config.json"

    def load(self) -> dict:
        if not self.path.exists():
            config = validate_config({})
            atomic_json(self.path, config)
            return config
        if self.path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Configuracao excede 2 MB.")
        with self.path.open(encoding="utf-8-sig") as stream:
            return validate_config(json.load(stream))

    def save(self, config: dict) -> dict:
        result = validate_config(config)
        atomic_json(self.path, result)
        return result
