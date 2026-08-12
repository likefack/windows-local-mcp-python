from __future__ import annotations

import ctypes
import os
import stat
from ctypes import create_unicode_buffer, wintypes
from pathlib import Path


def windows_system_executable(name: str) -> str:
    """Resolve a trusted Windows system executable without PATH or env lookup."""
    if os.name != "nt" or Path(name).name != name or not name.casefold().endswith(".exe"):
        raise OSError("a simple .exe name on native Windows is required")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = create_unicode_buffer(32768)
    length = kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    candidate = (Path(buffer.value) / name).resolve(strict=True)
    metadata = candidate.lstat()
    if not candidate.is_file() or metadata.st_file_attributes & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise OSError(f"untrusted Windows system executable: {candidate}")
    return str(candidate)


def physical_filesystem_path(path: Path) -> str:
    """Return the handle-resolved physical namespace path used for boundary comparison."""
    resolved = path.resolve(strict=True)
    if os.name != "nt":
        return str(resolved)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(resolved),
        0,
        0x00000001 | 0x00000002 | 0x00000004,  # share read/write/delete
        None,
        3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        None,
    )
    invalid = wintypes.HANDLE(-1).value
    if handle in (None, invalid):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = kernel32.GetFinalPathNameByHandleW(
            handle, None, 0, 0x00000001  # VOLUME_NAME_GUID | FILE_NAME_NORMALIZED
        )
        if size == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = create_unicode_buffer(size + 1)
        written = kernel32.GetFinalPathNameByHandleW(
            handle, buffer, len(buffer), 0x00000001
        )
        if written == 0 or written >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value
    finally:
        kernel32.CloseHandle(handle)
