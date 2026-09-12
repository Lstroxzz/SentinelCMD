"""Bounded, lazy hashing; size/mtime changes invalidate the small cache."""

from collections import OrderedDict
import hashlib
import os
from pathlib import Path
import stat
import time

from .collectors.common import is_local_path, no_reparse_components


class HashCache:
    def __init__(self, max_mb: int = 64, capacity: int = 256):
        self.max_bytes = max_mb * 1024 * 1024
        self.capacity = capacity
        self._cache: OrderedDict[tuple, str] = OrderedDict()

    def get(self, filename: str) -> str | None:
        if not filename or filename.startswith(("\\\\", "//")):
            return None
        path = Path(filename)
        try:
            if not is_local_path(path) or not no_reparse_components(path):
                return None
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_bytes:
                return None
            if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                return None
            # Size + modification time are stable across ordinary reads on
            # Windows; creation/change time can be reported differently after
            # an access and would make a reusable cache unusable. The stream is
            # still rechecked after hashing.
            key = (str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            digest = hashlib.sha256()
            started = time.monotonic()
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    return None
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > self.max_bytes or time.monotonic() - started > 0.25:
                        return None
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
                if (after.st_size, after.st_mtime_ns) != (info.st_size, info.st_mtime_ns):
                    return None
            result = digest.hexdigest()
            self._cache[key] = result
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)
            return result
        except (OSError, ValueError):
            return None
