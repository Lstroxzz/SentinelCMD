"""SQLite event journal with indexes, retention, bounded rows and atomic exports."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from .privacy import command_line_for_storage, csv_cell


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EventStore:
    def __init__(self, data_dir: Path, config: dict):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "events.sqlite3"
        self.config = config
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=10000")
        self._db.execute("PRAGMA cache_size=-2048")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, kind TEXT NOT NULL,
                score INTEGER NOT NULL, risk TEXT NOT NULL, pid INTEGER, data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS events_pid_time ON events(pid, timestamp);
            CREATE INDEX IF NOT EXISTS events_score ON events(score);
            PRAGMA user_version=1;
        """)
        self._writes = 0
        self._prune_at = 0.0
        self.prune()

    def append(self, record: dict, detection: dict | None = None, action: str = "observed") -> dict:
        event = {
            "id": uuid.uuid4().hex, "timestamp": utc_now(), "kind": "event",
            "pid": None, "ppid": None, "process_name": None, "executable": None,
            "file_path": None, "sha256": None, "command_line": None, "username": None,
            "process_created_at": None, "local_ip": None, "local_port": None,
            "remote_ip": None, "remote_port": None, "protocol": None,
            "score": 0, "risk": "info", "reasons": [], "rule_ids": [], "evidence_count": 0,
        }
        event.update(record)
        event["id"] = uuid.uuid4().hex
        if detection:
            event.update(detection)
        event["action"] = action
        event["command_line"] = command_line_for_storage(
            record.get("command_line"), self.config["store_command_lines"]
        )
        with self._lock:
            self._db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", (
                event["id"], event["timestamp"], event["kind"], event["score"], event["risk"],
                event["pid"], json.dumps(event, ensure_ascii=False, default=str),
            ))
            self._db.commit()
            self._writes += 1
            if self._writes >= 100 or time.monotonic() - self._prune_at >= 60:
                self.prune()
        return event

    def query(self, limit: int = 100, min_score: int = 0, pid: int | None = None,
              event_id: str | None = None) -> list[dict]:
        sql = "SELECT data FROM events WHERE score >= ?"
        params: list = [min_score]
        if pid is not None:
            sql += " AND pid = ?"
            params.append(pid)
        if event_id is not None:
            sql += " AND id = ?"
            params.append(event_id)
        sql += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(min(max(1, int(limit)), self.config["max_events"]))
        with self._lock:
            return [json.loads(row[0]) for row in self._db.execute(sql, params)]

    def counts(self) -> dict:
        today = datetime.now(timezone.utc).date().isoformat()
        with self._lock:
            rows = self._db.execute("SELECT data, score FROM events WHERE timestamp >= ?", (today,))
            suspicious = blocked = total = 0
            for data, score in rows:
                total += 1
                suspicious += score > 0
                blocked += json.loads(data).get("action") in ("firewall_blocked", "quarantined")
        return {"events_today_utc": total, "suspicious_today_utc": suspicious, "blocked_today_utc": blocked}

    def prune(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.config["retention_days"])).isoformat()
        with self._lock:
            self._db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            self._db.execute("""DELETE FROM events WHERE rowid IN
                (SELECT rowid FROM events ORDER BY timestamp DESC, rowid DESC LIMIT -1 OFFSET ?)""",
                (self.config["max_events"],))
            self._db.commit()
            self._db.execute("PRAGMA incremental_vacuum(128)")
            self._writes = 0
            self._prune_at = time.monotonic()

    def export(self, path: Path, fmt: str = "json", min_score: int = 0) -> dict:
        # Exclusive creation prevents accidentally overwriting evidence or other files.
        if fmt not in ("json", "csv"):
            raise ValueError("Formato deve ser json ou csv.")
        events = self.query(limit=self.config["max_events"], min_score=min_score)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8", newline="") as stream:
                if fmt == "json":
                    json.dump({"application": "SentinelCMD", "schema_version": 1,
                               "generated_at": utc_now(), "events": events}, stream,
                              ensure_ascii=False, indent=2)
                    stream.write("\n")
                else:
                    fields = ["id", "timestamp", "kind", "risk", "score", "pid", "ppid",
                              "process_created_at", "process_name", "executable", "file_path", "sha256",
                              "hash_status", "command_line", "username", "local_ip", "local_port",
                              "remote_ip", "remote_port", "protocol", "state", "evidence_count",
                              "reasons", "rule_ids", "action"]
                    writer = csv.DictWriter(stream, fieldnames=fields)
                    writer.writeheader()
                    for event in events:
                        writer.writerow({key: csv_cell(event.get(key)) for key in fields})
        except FileExistsError:
            raise
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return {"path": str(path.resolve()), "events": len(events), "format": fmt}

    def close(self) -> None:
        with self._lock:
            self.prune()
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._db.close()
