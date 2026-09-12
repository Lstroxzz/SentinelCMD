"""Bounded heuristic scoring. A suspicious event is not a malware verdict.

Rules are declarative metadata mapped to a closed set of Python predicates;
configuration never evaluates code or imports plugins. Process correlation requires
both a PID and its creation timestamp; a PID alone is not an identity.
"""

from __future__ import annotations

import ipaddress
import json
import math
import ntpath
import os
import posixpath
import re
import time
from collections import OrderedDict, deque
from datetime import datetime
from pathlib import Path, PureWindowsPath


_HASH = re.compile(r"^[0-9a-fA-F]{64}$")
_ENCODED = re.compile(r"(?:^|\s)-(?:enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?:\s|:|$)", re.I)
_WINDOWS_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
    "smss.exe", "winlogon.exe", "dllhost.exe", "conhost.exe", "dwm.exe",
    "taskhostw.exe", "spoolsv.exe", "sihost.exe", "runtimebroker.exe",
}
_EXECUTABLE_EXTENSIONS = {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".hta"}
_DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png", ".zip", ".rar", ".csv"}


def _canonical_path(value: object) -> tuple[str, str] | None:
    """Normalize absolute paths lexically without opening potentially unsafe files.

    Windows paths ignore case and honor directory boundaries. POSIX paths remain
    case-sensitive so fixtures and future portable collectors retain semantics.
    Reparse points cannot be established from strings: collectors should supply
    the resolved executable path when available.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    if PureWindowsPath(value).is_absolute():
        return "windows", ntpath.normcase(ntpath.normpath(value))
    if value.startswith("/") and not value.startswith("//"):
        return "posix", posixpath.normpath(value)
    return None


def _within(path: tuple[str, str], directory: tuple[str, str]) -> bool:
    if path[0] != directory[0]:
        return False
    separator = "\\" if path[0] == "windows" else "/"
    return path[1] == directory[1] or path[1].startswith(directory[1].rstrip(separator) + separator)


def _timestamp(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (float, int)):
        return str(float(value)) if math.isfinite(value) and value > 0 else None
    if isinstance(value, str) and value.strip():
        try:
            numeric = float(value)
            if math.isfinite(numeric) and numeric > 0:
                return str(numeric)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                # Naive timestamps can represent a stable collector identity too.
                return parsed.isoformat()
            except ValueError:
                pass
    return None


def _identity(record: dict, *, parent: bool = False) -> tuple[int, str] | None:
    pid = record.get("ppid" if parent else "pid")
    created = _timestamp(record.get("parent_created_at" if parent else "process_created_at"))
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 0 or created is None:
        return None
    return pid, created


class RuleEngine:
    """Evaluate collector records and return risk metadata or ``None``.

    Scores use only the strongest signal in each independent evidence group.
    High risk requires at least two groups; critical requires three groups, or an
    exact user-provided indicator. Evidence expires after five minutes. Memory is
    capped regardless of uptime or the number of distinct observed processes.
    """

    MAX_IDENTITIES = 4096
    EVIDENCE_TTL_SECONDS = 300.0

    def __init__(self, config: dict):
        self._rules = json.loads(Path(__file__).with_name("rules.json").read_text(encoding="utf-8"))
        self._evidence: OrderedDict[tuple[int, str], tuple[float, dict[str, dict]]] = OrderedDict()
        self._children: OrderedDict[tuple[int, str], tuple[float, deque]] = OrderedDict()
        self._known_processes: OrderedDict[int, tuple[str, float]] = OrderedDict()
        self.reload(config)

    def reload(self, config: dict) -> None:
        """Validate a new configuration atomically, then discard stale evidence."""
        if not isinstance(config, dict):
            raise ValueError("A configuração de regras deve ser um objeto.")
        enabled = config.get("rules_enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("rules_enabled deve ser booleano.")
        lists: dict[str, list[str]] = {}
        for key in ("disabled_rules", "allowed_paths", "allowed_hashes", "blocked_hashes", "blocked_ips"):
            values = config.get(key, [])
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise ValueError(f"{key} deve ser uma lista de textos.")
            lists[key] = values
        known_rules = {r["id"] for r in self._rules}
        if set(lists["disabled_rules"]) - known_rules:
            raise ValueError("disabled_rules contém um identificador desconhecido.")
        hashes: dict[str, set[str]] = {}
        for key in ("allowed_hashes", "blocked_hashes"):
            if any(not _HASH.fullmatch(v) for v in lists[key]):
                raise ValueError(f"{key} aceita somente SHA-256 hexadecimal de 64 caracteres.")
            hashes[key] = {v.lower() for v in lists[key]}
        if hashes["allowed_hashes"] & hashes["blocked_hashes"]:
            raise ValueError("Um hash não pode estar nas listas de permissão e bloqueio simultaneamente.")
        try:
            blocked_ips = {ipaddress.ip_address(v).compressed for v in lists["blocked_ips"]}
        except ValueError as exc:
            raise ValueError("blocked_ips aceita somente endereços IPv4/IPv6 exatos; sem redes CIDR.") from exc
        allowed_paths = [_canonical_path(v) for v in lists["allowed_paths"]]
        if any(path is None for path in allowed_paths):
            raise ValueError("allowed_paths aceita somente caminhos absolutos.")
        threshold = config.get("child_threshold", 12)
        window = config.get("child_window_seconds", 60)
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 2 <= threshold <= 10000:
            raise ValueError("child_threshold deve estar entre 2 e 10000.")
        if isinstance(window, bool) or not isinstance(window, (int, float)) or not math.isfinite(window) or not 1 <= window <= 3600:
            raise ValueError("child_window_seconds deve estar entre 1 e 3600.")
        self._enabled = enabled
        self._disabled = set(lists["disabled_rules"])
        self._allowed_paths = allowed_paths
        self._allowed_hashes = hashes["allowed_hashes"]
        self._blocked_hashes = hashes["blocked_hashes"]
        self._blocked_ips = blocked_ips
        self._child_threshold = threshold
        self._child_window = float(window)
        root = _canonical_path(os.environ.get("SystemRoot", os.environ.get("WINDIR", r"C:\Windows")))
        self._windows_root = root if root and root[0] == "windows" else ("windows", r"c:\windows")
        self._evidence.clear()
        self._children.clear()
        self._known_processes.clear()

    def list_rules(self) -> list[dict]:
        return [{**r, "kinds": list(r["kinds"]), "enabled": self._enabled and r["id"] not in self._disabled} for r in self._rules]

    def _expire(self, now: float) -> None:
        # All maps are ordered by last observation; usual polling work is O(1).
        for mapping, ttl, time_index in (
            (self._evidence, self.EVIDENCE_TTL_SECONDS, 0),
            (self._children, self._child_window, 0),
            (self._known_processes, self.EVIDENCE_TTL_SECONDS, 1),
        ):
            while mapping:
                oldest = next(iter(mapping.values()))
                if now - oldest[time_index] <= ttl:
                    break
                mapping.popitem(last=False)

    def _trim(self, mapping: OrderedDict) -> None:
        while len(mapping) > self.MAX_IDENTITIES:
            mapping.popitem(last=False)

    def _forget(self, pid: int, identity: tuple[int, str] | None) -> None:
        for mapping in (self._evidence, self._children):
            for key in list(mapping):
                if key[0] == pid and (identity is None or key == identity):
                    del mapping[key]
        known = self._known_processes.get(pid)
        if known and (identity is None or known[0] == identity[1]):
            del self._known_processes[pid]

    def _child_burst(self, record: dict, now: float) -> bool:
        """Attribute a burst to the parent chain; never claim a child created it."""
        child = _identity(record)
        parent = _identity(record, parent=True)
        if parent is None:
            known = self._known_processes.get(record.get("ppid"))
            if known:
                parent = record["ppid"], known[0]
        if parent is None or child is None or parent == child:
            return False
        _, entries = self._children.get(parent, (now, deque(maxlen=self._child_threshold)))
        while entries and now - entries[0][0] > self._child_window:
            entries.popleft()
        if any(identity == child for _, identity in entries):
            # A second evaluation after lazy hashing must preserve the original
            # burst evidence without counting the same child twice.
            return len(entries) >= self._child_threshold
        entries.append((now, child))
        self._children[parent] = now, entries
        self._children.move_to_end(parent)
        self._trim(self._children)
        return len(entries) >= self._child_threshold

    def evaluate(self, record: dict) -> dict | None:
        if not isinstance(record, dict):
            raise ValueError("O evento deve ser um objeto.")
        now = time.monotonic()
        self._expire(now)
        kind = record.get("kind")
        identity = _identity(record)
        if kind == "process_exited":
            pid = record.get("pid")
            if isinstance(pid, int) and not isinstance(pid, bool):
                self._forget(pid, identity)
            return None
        if not self._enabled:
            return None
        if kind == "process_started" and identity:
            known = self._known_processes.get(identity[0])
            if known and known[0] != identity[1]:
                self._forget(identity[0], None)
            self._known_processes[identity[0]] = identity[1], now
            self._known_processes.move_to_end(identity[0])
            self._trim(self._known_processes)
        burst = (
            kind == "process_started"
            and record.get("baseline") is not True
            and "child_burst" not in self._disabled
            and self._child_burst(record, now)
        )
        path = _canonical_path(record.get("executable") if kind == "process_started" else record.get("file_path"))
        sha = record.get("sha256", "")
        sha = sha.lower() if isinstance(sha, str) and _HASH.fullmatch(sha) else ""
        allowlisted = sha in self._allowed_hashes or bool(path and any(_within(path, directory) for directory in self._allowed_paths))
        if allowlisted and identity:
            # The digest may arrive only on a second, lazy-hash evaluation.
            # Discard provisional heuristic evidence once that hash is allowed.
            self._evidence.pop(identity, None)
        matches: dict[str, dict] = {}
        for rule in self._rules:
            if kind not in rule["kinds"] or rule["id"] in self._disabled:
                continue
            if allowlisted and rule["group"] != "exact_ioc":
                continue
            reason = self._match(rule["detector"], record, path, sha, bool(burst))
            if reason:
                previous = matches.get(rule["group"])
                if previous is None or rule["score"] > previous["score"]:
                    matches[rule["group"]] = {"id": rule["id"], "score": rule["score"], "reason": reason, "at": now}
        if not matches:
            return None
        # File event PIDs may be guesses and are not evidence of process ownership.
        if identity and kind in {"process_started", "network_connection"}:
            _, prior = self._evidence.get(identity, (now, {}))
            combined = {group: value for group, value in prior.items() if now - value["at"] <= self.EVIDENCE_TTL_SECONDS}
            for group, match in matches.items():
                if group not in combined or match["score"] >= combined[group]["score"]:
                    combined[group] = match
            self._evidence[identity] = now, combined
            self._evidence.move_to_end(identity)
            self._trim(self._evidence)
            matches = combined
        score = min(100, sum(item["score"] for item in matches.values()))
        count = len(matches)
        exact = "exact_ioc" in matches
        if not exact:
            if count < 2:
                score = min(score, 49)
            elif count < 3:
                score = min(score, 79)
        risk = "critical" if score >= 80 else "high" if score >= 50 else "medium" if score >= 25 else "low"
        return {"score": score, "risk": risk, "reasons": [m["reason"] for m in matches.values()], "rule_ids": [m["id"] for m in matches.values()], "evidence_count": count}

    def _match(self, detector: str, record: dict, path: tuple[str, str] | None, sha: str, burst: bool) -> str | None:
        parts = path[1].replace("\\", "/").split("/") if path else []
        command = record.get("command_line", "")
        if isinstance(command, (list, tuple)):
            command = " ".join(str(argument) for argument in command)
        command = command.casefold() if isinstance(command, str) else ""
        process = record.get("process_name", "")
        process = str(process).casefold()
        powershell = process in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
        if detector == "temporary_path" and any(part in {"temp", "tmp"} for part in parts):
            return "Executável iniciado em pasta temporária; programas legítimos também usam esse local."
        if detector == "appdata_path" and "appdata" in parts:
            return "Executável iniciado no AppData; esse local também contém aplicativos legítimos."
        if detector == "system_name_path" and path and path[0] == "windows" and (process in _WINDOWS_NAMES or process == "explorer.exe"):
            directory = ntpath.dirname(path[1])
            root = self._windows_root[1]
            expected = {root} if process == "explorer.exe" else {ntpath.join(root, "system32"), ntpath.join(root, "syswow64")}
            servicing = _within(path, ("windows", ntpath.join(root, "winsxs")))
            if directory not in expected and not servicing:
                return f"Nome {process} associado ao Windows fora dos diretórios esperados; verificar assinatura e origem."
        if detector == "encoded_command" and powershell and _ENCODED.search(command):
            return "PowerShell recebeu comando codificado; o conteúdo precisa ser investigado."
        if detector == "unusual_command":
            hidden = re.search(r"(?:^|\s)-(?:w|windowstyle)\s+hidden(?:\s|$)", command)
            bypass = re.search(r"(?:^|\s)-(?:ep|executionpolicy)\s+bypass(?:\s|$)", command)
            if powershell and hidden and bypass:
                return "PowerShell combina janela oculta e política de execução bypass; verificar finalidade."
            if process in {"mshta.exe", "mshta"} and re.search(r"\bhttps?://", command):
                return "mshta recebeu uma URL remota; verificar origem e autorização."
            if process in {"rundll32.exe", "rundll32"} and "javascript:" in command:
                return "rundll32 recebeu conteúdo javascript; combinação incomum que exige revisão."
        if detector == "downloaded_executable" and record.get("downloaded") is True:
            # Contract: downloaded is emitted only after a collector observes a
            # recent Zone.Identifier stream, never inferred from a folder name.
            return "Executável marcado pelo coletor como download recente (Zone.Identifier); conferir origem."
        if detector == "child_burst" and burst:
            return f"O processo pai PID {record.get('ppid')} iniciou pelo menos {self._child_threshold} filhos em {self._child_window:g} segundos; este evento integra essa cadeia."
        if detector == "double_extension" and path:
            basename = parts[-1]
            stem, extension = posixpath.splitext(basename.casefold())
            if extension in _EXECUTABLE_EXTENSIONS and posixpath.splitext(stem)[1] in _DOCUMENT_EXTENSIONS:
                return "Nome de executável possui extensão dupla com aparência de documento; verificar tipo real."
        if detector == "blocked_hash" and sha and sha in self._blocked_hashes:
            return f"SHA-256 corresponde exatamente a indicador de bloqueio fornecido pelo usuário: {sha}."
        if detector == "blocked_ip":
            try:
                remote = ipaddress.ip_address(record.get("remote_ip", "")).compressed
            except (ValueError, TypeError):
                return None
            if remote in self._blocked_ips:
                return f"IP remoto corresponde exatamente a indicador de bloqueio fornecido pelo usuário: {remote}."
        return None
