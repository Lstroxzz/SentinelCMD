"""Manual, integrity-checked file quarantine with recoverable manifests.

Only the unnamed data stream is stored: NTFS ADS (including Zone.Identifier),
ACLs, original timestamps, and executable permissions are not preserved. The
blob is not encrypted. A same-user attacker or administrator is outside this
module's isolation boundary. Never place its data directory on a shared path.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import uuid

from ._files import open_new_destination, open_source, private_permissions, regular_file, reject_links, remove_open_source


ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 256 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
STATES = {"prepared", "quarantined", "copy_only", "restored", "deleted", "recovery_required"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _hash_file(path: Path) -> str:
    regular_file(path)
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(CHUNK_BYTES):
            result.update(data)
    return result.hexdigest()


class QuarantineManager:
    """Quarantine only when explicitly requested; no heuristic calls this class.

    Manifests are atomically replaced one item at a time. ``prepared`` after a
    crash means that a verified backup exists but source removal is uncertain.
    ``copy_only`` means source removal failed. Neither means containment succeeded.
    The full file limit defaults to 256 MiB and can be lowered through
    ``manager.max_file_bytes``. Files are streamed with a 1 MiB buffer.
    """

    def __init__(self, data_dir: Path, protected_paths: list[Path] | None = None):
        self.data_dir = Path(os.path.abspath(data_dir))
        self.root = self.data_dir / "quarantine"
        self.max_file_bytes = MAX_FILE_BYTES
        self._thread_lock = threading.RLock()
        defaults = [self.data_dir, Path(__file__).resolve().parents[2], Path(sys.executable)]
        if os.name == "nt":
            defaults.extend(
                Path(os.environ.get(key, fallback))
                for key, fallback in (
                    ("SystemRoot", r"C:\Windows"),
                    ("WINDIR", r"C:\Windows"),
                    ("ProgramFiles", r"C:\Program Files"),
                    ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                    ("ProgramW6432", r"C:\Program Files"),
                )
            )
        self.protected_paths = [p.resolve(strict=False) for p in defaults + list(protected_paths or [])]
        # Create missing directories one component at a time, never traversing
        # an existing reparse point. Existing ancestor ACLs are not modified.
        for directory in reversed((self.root, *self.root.parents)):
            try:
                directory.lstat()
            except FileNotFoundError:
                directory.mkdir(mode=0o700)
            reject_links(directory)
            if not directory.is_dir():
                raise ValueError(f"Not a directory: {directory}")
        private_permissions(self.root, directory=True)

    def _validate_path(self, path: Path, *, missing_leaf: bool = False) -> Path:
        path = reject_links(Path(path), missing_leaf=missing_leaf)
        resolved = path.resolve(strict=not missing_leaf)
        for protected in self.protected_paths:
            if resolved == protected or protected in resolved.parents:
                raise ValueError(f"Protected path cannot be moved or restored: {protected}")
        return path

    @contextmanager
    def _locked(self):
        with self._thread_lock:
            reject_links(self.root)
            lock_path = self.root / ".lock"
            reject_links(lock_path, missing_leaf=True)
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            locked = False
            try:
                if os.name == "nt":
                    import msvcrt

                    if os.fstat(fd).st_size == 0:
                        os.write(fd, b"0")
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                yield
            finally:
                if locked:
                    if os.name == "nt":
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _paths(self, item_id: str) -> tuple[Path, Path]:
        if not isinstance(item_id, str) or not ID_PATTERN.fullmatch(item_id):
            raise ValueError("Invalid quarantine item ID.")
        return self.root / f"{item_id}.json", self.root / f"{item_id}.blob"

    def _read_manifest(self, item_id: str) -> dict:
        manifest, _ = self._paths(item_id)
        if regular_file(manifest).st_size > 64 * 1024:
            raise ValueError("Quarantine manifest is too large.")
        try:
            item = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("Corrupt quarantine manifest.") from error
        if (
            not isinstance(item, dict)
            or item.get("schema") != 1
            or item.get("id") != item_id
            or item.get("status") not in STATES
            or not isinstance(item.get("sha256"), str)
            or not HASH_PATTERN.fullmatch(item["sha256"])
            or type(item.get("size")) is not int
            or item["size"] < 0
            or not isinstance(item.get("original_path"), str)
            or not Path(item["original_path"]).is_absolute()
        ):
            raise ValueError("Invalid quarantine manifest fields.")
        return item

    def _write_manifest(self, item: dict) -> None:
        target, _ = self._paths(item["id"])
        temporary = self.root / f".{item['id']}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                private_permissions(temporary)
                json.dump(item, stream, ensure_ascii=False, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            if os.name != "nt":
                fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)

    def list_items(self) -> list[dict]:
        """Include audit states and surface corrupt records individually."""
        with self._locked():
            result = []
            for manifest in sorted(self.root.glob("*.json")):
                if not ID_PATTERN.fullmatch(manifest.stem):
                    continue
                try:
                    item = self._read_manifest(manifest.stem)
                    _, blob = self._paths(item["id"])
                    if item["status"] not in {"restored", "deleted"} and not blob.is_file():
                        item = dict(item, status="recovery_required", warning="Quarantine blob is missing.")
                    result.append(item)
                except (OSError, ValueError) as error:
                    result.append({"id": manifest.stem, "status": "corrupt", "warning": str(error)})
            return result

    def quarantine(self, path: Path, reason: str = "", expected_sha256: str | None = None) -> dict:
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or not HASH_PATTERN.fullmatch(expected_sha256.lower()):
                raise ValueError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
            expected_sha256 = expected_sha256.lower()
        with self._locked():
            source = self._validate_path(path)
            before = regular_file(source)
            if before.st_size > self.max_file_bytes:
                raise ValueError(f"File exceeds the {self.max_file_bytes}-byte quarantine limit.")
            item_id = uuid.uuid4().hex
            manifest, blob = self._paths(item_id)
            temporary = self.root / f".{item_id}.partial"
            prepared = False
            item = {
                "schema": 1,
                "id": item_id,
                "original_path": str(source),
                "reason": str(reason)[:2000],
                "created_at": _now(),
                "status": "prepared",
                "size": before.st_size,
                "source_removed": False,
            }
            try:
                with open_source(source) as incoming:
                    opened = os.fstat(incoming.fileno())
                    if _snapshot(before) != _snapshot(opened) or not stat.S_ISREG(opened.st_mode):
                        raise ValueError("Source identity changed before it was opened.")
                    self._validate_path(source)
                    digest = hashlib.sha256()
                    copied = 0
                    with temporary.open("xb") as outgoing:
                        private_permissions(temporary, blob=True)
                        while data := incoming.read(CHUNK_BYTES):
                            copied += len(data)
                            if copied > self.max_file_bytes:
                                raise ValueError("Source grew beyond the quarantine limit.")
                            outgoing.write(data)
                            digest.update(data)
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                    if copied != before.st_size or _snapshot(os.fstat(incoming.fileno())) != _snapshot(
                        opened
                    ):
                        raise ValueError("Source changed during copying; nothing was removed.")
                    item["sha256"] = digest.hexdigest()
                    if expected_sha256 is not None and item["sha256"] != expected_sha256:
                        raise ValueError("Source does not match the expected SHA-256; nothing was removed.")
                    if _hash_file(temporary) != item["sha256"]:
                        raise ValueError("Quarantine copy failed integrity verification.")
                    os.replace(temporary, blob)
                    self._write_manifest(item)
                    prepared = True
                    try:
                        self._validate_path(source)
                        remove_open_source(source, incoming)
                    except (OSError, ValueError) as error:
                        item.update(status="copy_only", warning=f"Source was not removed: {error}")
                        try:
                            self._write_manifest(item)
                        except OSError:
                            item["warning"] += " Manifest remains in prepared state."
                        return item
                item.update(status="quarantined", source_removed=True, quarantined_at=_now())
                try:
                    self._write_manifest(item)
                except OSError as error:
                    # The verified blob and prepared manifest remain recoverable.
                    item.update(
                        status="recovery_required",
                        warning=f"Source removed; finalize manifest failed: {error}",
                    )
                return item
            finally:
                temporary.unlink(missing_ok=True)
                if not prepared:
                    blob.unlink(missing_ok=True)
                    manifest.unlink(missing_ok=True)

    def restore(self, item_id: str, destination: Path | None = None) -> dict:
        """Restore verified bytes exclusively; keep backup if committing fails."""
        with self._locked():
            item = self._read_manifest(item_id)
            _, blob = self._paths(item_id)
            if item["status"] in {"restored", "deleted"}:
                raise ValueError("This item is no longer in quarantine.")
            target = self._validate_path(destination or Path(item["original_path"]), missing_leaf=True)
            if regular_file(blob).st_size != item["size"] or _hash_file(blob) != item["sha256"]:
                raise ValueError("Quarantine blob failed integrity verification; restore refused.")
            # Exclusive create rejects overwrite. Windows holds an unshared
            # handle through verification and removes that object on rollback.
            with open_new_destination(target) as outgoing:
                try:
                    digest = hashlib.sha256()
                    with blob.open("rb") as incoming:
                        while data := incoming.read(CHUNK_BYTES):
                            outgoing.write(data)
                            digest.update(data)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                    outgoing.seek(0)
                    verified = hashlib.sha256()
                    while data := outgoing.read(CHUNK_BYTES):
                        verified.update(data)
                    if digest.hexdigest() != item["sha256"] or verified.hexdigest() != item["sha256"]:
                        raise ValueError("Restored bytes failed integrity verification.")
                except BaseException:
                    remove_open_source(target, outgoing)
                    raise
            item.update(status="restored", restored_path=str(target), restored_at=_now())
            try:
                self._write_manifest(item)
            except OSError as error:
                # Do not remove a successfully restored file or the only backup.
                return dict(
                    item,
                    status="recovery_required",
                    warning=f"File restored; backup kept because manifest update failed: {error}",
                )
            try:
                blob.unlink()
            except OSError as error:
                item["warning"] = f"File restored, but backup cleanup failed: {error}"
            return item

    def delete(self, item_id: str) -> dict:
        """Permanently delete the stored blob; retain its audit manifest."""
        with self._locked():
            item = self._read_manifest(item_id)
            _, blob = self._paths(item_id)
            if blob.exists():
                regular_file(blob)
                blob.unlink()
            item.update(status="deleted", deleted_at=_now())
            try:
                self._write_manifest(item)
            except OSError as error:
                return dict(
                    item, status="recovery_required", warning=f"Blob deleted; manifest update failed: {error}"
                )
            return item
