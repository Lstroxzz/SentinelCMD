"""Hashing tests use small disposable files and never inspect host executables."""

from __future__ import annotations

import hashlib
import os

import pytest

from sentinelcmd.hashing import HashCache


def test_hashes_regular_file_and_reuses_cache(tmp_path):
    path = tmp_path / "sample.bin"
    payload = b"sentinel fixture"
    path.write_bytes(payload)
    cache = HashCache(max_mb=1)
    expected = hashlib.sha256(payload).hexdigest()
    assert cache.get(str(path)) == expected
    assert cache.get(str(path)) == expected


def test_metadata_change_invalidates_hash(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"first")
    cache = HashCache(max_mb=1)
    first = cache.get(str(path))
    path.write_bytes(b"second")
    os.utime(path, None)
    assert cache.get(str(path)) != first
    assert cache.get(str(path)) == hashlib.sha256(b"second").hexdigest()


def test_size_and_non_regular_files_are_not_hashed(tmp_path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"0123456789")
    assert HashCache(max_mb=0).get(str(path)) is None
    assert HashCache(max_mb=1).get(str(tmp_path)) is None
    assert HashCache(max_mb=1).get(str(tmp_path / "missing")) is None


def test_symlink_is_not_hashed(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this host")
    assert HashCache(max_mb=1).get(str(link)) is None
