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
