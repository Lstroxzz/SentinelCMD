"""Small filesystem safety primitives used only by quarantine.

Windows source handles disallow concurrent writes/deletes. Directory path checks
reduce junction attacks, but this is not a security boundary against an admin or
another process running as the same user. Do not use a shared, untrusted data dir.
"""

from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path
from typing import BinaryIO


def reject_links(path: Path, *, missing_leaf: bool = False) -> Path:
    """Reject links/reparse points in *every* existing path component."""
    path = Path(os.path.abspath(path))
    if os.name == "nt":
        # Reject device/UNC paths and NTFS alternate streams. v1 is local only.
        if path.drive.startswith("\\\\") or any(":" in p for p in path.parts[1:]):
            raise ValueError("Use a local file path without alternate data streams.")
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if missing_leaf and component == path:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"Links and Windows reparse points are not allowed: {component}")
    return path


def regular_file(path: Path) -> os.stat_result:
    reject_links(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Only regular files may be quarantined.")
    if info.st_nlink != 1:
        raise ValueError("Files with multiple hard links are not supported.")
    return info


def private_permissions(path: Path, *, directory: bool = False, blob: bool = False) -> None:
    """Owner-only POSIX permissions or a protected Windows DACL.

    Windows also grants SYSTEM/Administrators recovery access. Blob DACLs deny
    FILE_EXECUTE to Everyone. This does not stop an authorized user from reading
    bytes, changing the ACL, or feeding a script to an interpreter.
    """
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    set_security = advapi.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    inheritance = "OICI" if directory else ""
    # Deny FILE_EXECUTE alone (0x20). SDDL FX also denies SYNCHRONIZE and
    # READ_CONTROL, which would unintentionally prevent ordinary file reads.
    deny = "(D;;0x20;;;WD)" if blob else ""
    sddl = "D:P" + deny + "".join(f"(A;{inheritance};FA;;;{sid})" for sid in ("OW", "SY", "BA"))
    descriptor = ctypes.c_void_p()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not set_security(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def open_source(path: Path) -> BinaryIO:
    """Open for reading and later deletion; fail if Windows cannot lock it."""
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        return os.fdopen(fd, "rb")
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    # GENERIC_READ | DELETE; FILE_SHARE_READ; OPEN_EXISTING;
    # FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN.
    handle = create_file(str(path), 0x80010000, 1, None, 3, 0x08200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(handle)
        raise
    return os.fdopen(fd, "rb")


def open_new_destination(path: Path) -> BinaryIO:
    """Create exclusively, holding the Windows object through restore/rollback."""
    if os.name != "nt":
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        return os.fdopen(fd, "w+b")
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    # GENERIC_READ | GENERIC_WRITE | DELETE; no sharing; CREATE_NEW.
    handle = create_file(str(path), 0xC0010000, 0, None, 1, 0x08200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(handle)
        raise
    return os.fdopen(fd, "w+b")


def remove_open_source(path: Path, stream: BinaryIO) -> None:
    """Delete the opened Windows object, not a newly substituted path."""
    if os.name != "nt":
        # Portable fallback has a residual check/unlink race; Windows is the
        # supported response platform and uses the handle operation below.
        before, opened = regular_file(path), os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("Source identity changed; no file was removed.")
        path.unlink()
        return
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    set_info = kernel.SetFileInformationByHandle
    set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_info.restype = wintypes.BOOL
    delete_file = wintypes.BYTE(1)
    # FileDispositionInfo = 4. Deletion completes when the source closes.
    if not set_info(
        msvcrt.get_osfhandle(stream.fileno()), 4, ctypes.byref(delete_file), ctypes.sizeof(delete_file)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
