"""Cooperative polling worker; no service installation, remote traffic or injection."""

from __future__ import annotations

from collections import OrderedDict
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import threading
import time

import psutil

from .collectors import FileCollector, NetworkCollector, ProcessCollector
from .detection import RuleEngine
from .hashing import HashCache
from .locking import MonitorLock
from .response import FirewallManager
from .storage import EventStore, utc_now


class Monitor:
    def __init__(self, config: dict, data_dir: Path, store: EventStore):
        self.config, self.data_dir, self.store = config, data_dir, store
        self.engine = RuleEngine(config)
        self.processes = ProcessCollector(config)
        self.network = NetworkCollector(config)
        self.files = FileCollector(config)
        self.hashes = HashCache(config["max_hash_mb"])
        self.firewall = FirewallManager()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._operation = threading.RLock()
        self._lock = MonitorLock(data_dir)
        self._process_records: dict[tuple, dict] = {}
        self._alert_signatures: OrderedDict[tuple, tuple] = OrderedDict()
        self._auto_attempts: dict[str, float] = {}
        self._health: dict[str, str] = {}
        self._last_sample: dict[str, str] = {}
        self._active_connections = 0
        self._self = psutil.Process()
        self._self.cpu_percent(None)
        self.started_at: str | None = None
        self.logger = logging.getLogger(f"sentinelcmd.{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        handler = RotatingFileHandler(data_dir / "sentinel.log", maxBytes=1024 * 1024,
                                      backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(handler)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        if self.running:
            return False
        self._lock.acquire()
        try:
            self._stop.clear()
            self.started_at = utc_now()
            self._health = {"startup": "Criando inventario inicial"}
            # New collectors reset baselines after a stop/start, not artificial deltas.
            self.processes = ProcessCollector(self.config)
            self.network = NetworkCollector(self.config)
            self.files = FileCollector(self.config)
            self.engine.reload(self.config)
            self._alert_signatures.clear()
            self._thread = threading.Thread(target=self._run, name="SentinelMonitor", daemon=False)
            self._thread.start()
        except Exception:
            self._lock.release()
            self._thread = None
            self.files.close()
            self._health = {}
            raise
        return True

    def stop(self) -> bool:
        was_running = self.running
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=30)
            if self._thread.is_alive():
                raise RuntimeError("Coletor ainda finalizando; aguarde antes de fechar o armazenamento.")
        self._lock.release()
        self.files.close()
        return was_running

    def _record_health(self, name: str, collector: object) -> None:
        error = getattr(collector, "last_error", None)
        if name == "files":
            status = self.files.status
            if status.get("truncated") or status.get("inaccessible_entries"):
                error = "Cobertura de arquivos parcial; consulte File Monitor."
        previous = self._health.get(name)
        if error:
            self._health[name] = str(error)
            if previous != error:
                self.store.append({"kind": "collector_error", "collector": name,
                                   "message": str(error)}, action="coverage_reduced")
        else:
            self._health.pop(name, None)
        self._last_sample[name] = utc_now()

    def _refresh_process_records(self, records: list[dict]) -> None:
        self._process_records = {(r.get("pid"), r.get("process_created_at")): r for r in records}

    def _enrich(self, record: dict) -> dict:
        record = dict(record)
        if record.get("kind") == "network_connection" and record.get("process_created_at"):
            process = self._process_records.get((record.get("pid"), record["process_created_at"]))
            if process:
                for field in ("ppid", "parent_created_at", "executable", "username", "command_line"):
                    record[field] = process.get(field)
        return record

    def _process(self, records: list[dict], *, baseline: bool = False,
                 engine: RuleEngine | None = None, allow_response: bool = True,
                 deduplicate: bool = True) -> list[dict]:
        engine = engine or self.engine
        alerts = []
        budget = self.config["hashes_per_cycle"]
        for raw in records:
            if self._stop.is_set() and self.running:
                break
            record = self._enrich(raw)
            if baseline:
                record["baseline"] = True
            detection = engine.evaluate(record)
            path = record.get("file_path") or record.get("executable")
            eligible = record.get("kind") in ("process_started", "file_created", "file_modified")
            if eligible and path and budget > 0 and (detection or self.config["blocked_hashes"]):
                budget -= 1
                digest = self.hashes.get(path)
                record["sha256"] = digest
                record["hash_status"] = "computed" if digest else "unavailable_or_budget_exceeded"
                if digest:
                    detection = engine.evaluate(record)
            elif eligible:
                record["hash_status"] = "not_computed"
            if baseline and record.get("kind") == "process_started":
                record["kind"] = "process_observed"
            action = "alerted" if detection else "observed"
            if detection and allow_response:
                action = self._respond(record, detection)
            persist = self.config["log_connections"] or record.get("kind") != "network_connection" or detection
            if persist:
                event = self.store.append(record, detection, action)
                if detection:
                    signature_key = (record.get("pid"), record.get("process_created_at"),
                                     record.get("file_path"), record.get("remote_ip"))
                    signature = tuple(detection["rule_ids"])
                    if not deduplicate or self._alert_signatures.get(signature_key) != signature:
                        alerts.append(event)
                        if deduplicate:
                            self._alert_signatures[signature_key] = signature
                            self._alert_signatures.move_to_end(signature_key)
                            while len(self._alert_signatures) > 2048:
                                self._alert_signatures.popitem(last=False)
        return alerts

    def _respond(self, record: dict, detection: dict) -> str:
        address = record.get("remote_ip")
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            return "alerted"
        if not (self.config["auto_block_ips"] and address in self.config["blocked_ips"]
                and detection["score"] >= 80):
            return "alerted"
        try:
            if not ipaddress.ip_address(address).is_global:
                return "alerted_auto_block_ineligible"
        except ValueError:
            return "alerted_auto_block_ineligible"
        now = time.monotonic()
        if now - self._auto_attempts.get(address, float("-inf")) < 300:
            return "alerted_auto_block_cooldown"
        self._auto_attempts[address] = now
        if len(self._auto_attempts) > 10000:
            self._auto_attempts = {address: now}
        try:
            result = self.firewall.block_ip(address, reason="Configured local IP indicator")
            if result.get("status") == "blocked":
                return "firewall_blocked" if result.get("created") else "firewall_already_blocked"
            return "auto_block_unconfirmed"
        except (OSError, ValueError, RuntimeError):
            self.logger.warning("Automatic firewall response failed; event remains an alert")
            return "auto_block_failed"

    def _run(self) -> None:
        try:
            with self._operation:
                self.store.append({"kind": "monitor_started"}, action="monitoring_started")
                self.processes.sample()
                current = self.processes.snapshot()
                self._refresh_process_records(current)
                self._process(current, baseline=True)
                self._record_health("processes", self.processes)
                self.network.sample()
                connections = self.network.snapshot()
                self._active_connections = len(connections)
                self._process(connections, baseline=True)
                self._record_health("network", self.network)
                self._health.pop("startup", None)
            due = {"processes": time.monotonic() + self.config["process_interval"],
                   "network": time.monotonic() + self.config["network_interval"], "files": 0.0}
            intervals = {"processes": self.config["process_interval"],
                         "network": self.config["network_interval"], "files": self.config["file_interval"]}
            while not self._stop.is_set():
                for name, collector in (("processes", self.processes), ("network", self.network),
                                        ("files", self.files)):
                    if self._stop.is_set():
                        break
                    if time.monotonic() < due[name]:
                        continue
                    try:
                        with self._operation:
                            records = collector.sample()
                            if name == "processes":
                                for record in records:
                                    key = (record.get("pid"), record.get("process_created_at"))
                                    if record["kind"] == "process_exited":
                                        self._process_records.pop(key, None)
                                    else:
                                        self._process_records[key] = record
                            self._process(records)
                            if name == "network":
                                # Do not enumerate twice per interval just to update the dashboard.
                                self._active_connections = len(getattr(collector, "_current", []))
                            self._record_health(name, collector)
                    except Exception as exc:
                        self._health[name] = type(exc).__name__
                        self.logger.error("Collector %s failed: %s", name, type(exc).__name__)
                    due[name] = time.monotonic() + intervals[name]
                self._stop.wait(min(0.5, max(0.01, min(due.values()) - time.monotonic())))
        except Exception as exc:
            self._health["worker"] = type(exc).__name__
            self.logger.error("Monitoring worker stopped: %s", type(exc).__name__)
        finally:
            self.files.close()
            try:
                self.store.append({"kind": "monitor_stopped"}, action="monitoring_stopped")
            except Exception:
                self.logger.error("Could not persist monitor stop")
            self._lock.release()

    def scan(self) -> dict:
        with self._operation:
            engine = RuleEngine(self.config)
            processes = self.processes.snapshot()
            self._refresh_process_records(processes)
            connections = self.network.snapshot()
            alerts = self._process(processes + connections, baseline=True,
                                   engine=engine, allow_response=False, deduplicate=False)
            self._record_health("processes", self.processes)
            self._record_health("network", self.network)
            self._active_connections = len(connections)
            return {"timestamp": utc_now(), "processes_scanned": len(processes),
                    "connections_scanned": len(connections), "alerts": alerts,
                    "coverage_errors": dict(self._health),
                    "scope": "Accessible running processes and local sockets; no disk-wide scan"}

    def status(self) -> dict:
        try:
            cpu, memory = self._self.cpu_percent(None), self._self.memory_info().rss / 1024 / 1024
        except psutil.Error:
            cpu = memory = None
        issues = {key: value for key, value in self._health.items() if key != "startup"}
        state = "STOPPED" if not self.running else "STARTING" if "startup" in self._health \
            else "DEGRADED" if issues else "MONITORING"
        return {"status": state,
                "started_at": self.started_at, "cpu_percent": cpu, "ram_mb": memory,
                "active_connections": self._active_connections, "health": dict(self._health),
                "last_sample": dict(self._last_sample), "files": dict(self.files.status),
                **self.store.counts()}

    def close(self) -> None:
        self.stop()
        for handler in list(self.logger.handlers):
            handler.close()
            self.logger.removeHandler(handler)
