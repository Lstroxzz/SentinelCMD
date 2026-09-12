"""OS-managed, automatically released single-monitor lock (no stale PID files)."""

import os
from pathlib import Path


class MonitorLock:
    def __init__(self, data_dir: Path):
        self.path = data_dir / "monitor.lock"
        self.stream = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        stream = self.path.open("a+b")
        if self.path.stat().st_size == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            raise RuntimeError("Ja existe um monitor usando este diretorio de dados.") from exc
        self.stream = stream

    def release(self) -> None:
        if self.stream:
            self.stream.close()
            self.stream = None
