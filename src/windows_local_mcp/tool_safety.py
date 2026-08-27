from __future__ import annotations

import ctypes
import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import get_last_error, wintypes
from pathlib import Path
from typing import Any


class _ByHandleFileInformation(ctypes.Structure):
    """Windows file identity returned for an already opened file handle."""

    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture_stable_file_identity(path: str | Path) -> dict[str, Any]:
    """Return the platform file identity used in security-sensitive bindings.

    Windows uses the volume serial number and 64-bit file index obtained from an
    opened handle. The POSIX representation exists only for cross-platform tests;
    the supported Windows boundary never treats an inode-shaped value as proof.
    """

    resolved = Path(path).resolve(strict=True)
    if os.name != "nt":
        details = resolved.stat()
        if not details.st_ino:
            raise RuntimeError("filesystem does not expose a stable file identity")
        return {
            "platform": "posix",
            "device": int(details.st_dev),
            "inode": int(details.st_ino),
        }

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
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    invalid = wintypes.HANDLE(-1).value
    handle = kernel32.CreateFileW(
        str(resolved),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002 | 0x00000004,  # share read/write/delete for capture
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    if handle in (None, invalid):
        raise PermissionError(
            f"could not open file identity handle: {resolved} "
            f"(WinError {get_last_error()})"
        )
    try:
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise PermissionError(
                f"could not read stable file identity: {resolved} "
                f"(WinError {get_last_error()})"
            )
        file_index = (int(information.nFileIndexHigh) << 32) | int(
            information.nFileIndexLow
        )
        if file_index == 0:
            raise RuntimeError("Windows returned an empty stable file index")
        return {
            "platform": "windows",
            "volume_serial_number": int(information.dwVolumeSerialNumber),
            "file_index": file_index,
        }
    finally:
        kernel32.CloseHandle(handle)


def ensure_external_tool_executable(
    executable: str | Path,
    *,
    workspace_root: Path,
    data_dir: Path,
    sandbox_scratch_dir: Path | None = None,
) -> str:
    """Require an executable to be a regular file outside MCP-writable roots."""
    resolved = Path(executable).resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise PermissionError(f"automatic tool executable is not a regular file: {resolved}")

    protected = [("workspace", workspace_root.resolve(strict=True))]
    if data_dir.exists():
        protected.append(("data_dir", data_dir.resolve(strict=True)))
    if sandbox_scratch_dir is not None and sandbox_scratch_dir.exists():
        protected.append(("sandbox_scratch_dir", sandbox_scratch_dir.resolve(strict=True)))
    for label, root in protected:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise PermissionError(
            f"automatic tool executable must not be loaded from the {label}: {resolved}"
        )
    return str(resolved)


def capture_file_identity(
    file_path: str | Path,
    *,
    expected_sha256: str | None = None,
    provenance: str,
) -> dict[str, Any]:
    """Capture content and stable identity for a security-sensitive regular file."""

    path = Path(file_path).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise PermissionError(f"security-sensitive path is not a regular file: {path}")
    details = path.stat()
    digest = _sha256_file(path)
    if expected_sha256 is not None and digest != expected_sha256.casefold():
        raise PermissionError(f"configured SHA-256 does not match: {path}")
    return {
        "path": str(path),
        "sha256": digest,
        "size": int(details.st_size),
        "stable_file_identity": capture_stable_file_identity(path),
        "mtime_ns": int(details.st_mtime_ns),
        "provenance": provenance,
    }


def capture_executable_identity(
    executable: str | Path,
    *,
    expected_sha256: str | None = None,
    provenance: str,
) -> dict[str, Any]:
    """Capture the identity that must remain true until process creation."""

    return capture_file_identity(
        executable,
        expected_sha256=expected_sha256,
        provenance=provenance,
    )


def trusted_helper_identity(settings: Any, program_key: str) -> dict[str, Any]:
    """Resolve a Broker helper from a pinned identity and its required containment."""
    if program_key not in {"git", "adb"}:
        raise ValueError(f"no broker helper trust policy exists for {program_key}")
    configured_path = getattr(settings, f"{program_key}_executable_path")
    configured_sha256 = getattr(settings, f"{program_key}_executable_sha256")
    if configured_path is None or configured_sha256 is None:
        raise PermissionError(
            f"{program_key} is enabled but unavailable: configure both "
            f"{program_key}_executable_path and {program_key}_executable_sha256"
        )
    executable = ensure_external_tool_executable(
        configured_path,
        workspace_root=settings.workspace_root,
        data_dir=settings.data_dir,
        sandbox_scratch_dir=settings.sandbox_scratch_dir,
    )
    identity = capture_executable_identity(
        executable,
        expected_sha256=configured_sha256,
        provenance="explicit-local-config",
    )
    if program_key == "git":
        # Import lazily so the low-level identity helpers remain acyclic. Automatic Git is
        # available only when the same Windows sandbox/WFP/Job boundary used at execution has
        # current machine-bound live evidence; a valid git.exe hash alone is never sufficient.
        from .git_broker_sandbox import require_git_broker_containment

        require_git_broker_containment(settings, identity)
    return identity


def verify_file_identity(expected: dict[str, Any]) -> Path:
    path = Path(str(expected.get("path", ""))).resolve(strict=True)
    actual = capture_file_identity(
        path,
        expected_sha256=str(expected.get("sha256", "")),
        provenance=str(expected.get("provenance", "")),
    )
    if actual != expected:
        raise RuntimeError(f"file identity changed before use: {path}")
    return path


@contextmanager
def hold_file_identity(expected: dict[str, Any]) -> Iterator[Path]:
    """Hold a verified regular file against writes/replacement for the use interval.

    Windows is the supported security boundary. A FILE_SHARE_READ-only handle prevents a
    same-user actor from replacing or modifying the file between verification and use.
    Other platforms retain a read handle and perform the same identity checks for tests, but do
    not claim the Windows replacement-denial property.
    """
    path = Path(str(expected.get("path", ""))).resolve(strict=True)
    handle: Any | None = None
    source: Any | None = None
    if os.name == "nt":
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
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        invalid = wintypes.HANDLE(-1).value
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ only: deny writes, deletes, and replacement
            None,
            3,  # OPEN_EXISTING
            0x00000080,  # FILE_ATTRIBUTE_NORMAL
            None,
        )
        if handle in (None, invalid):
            raise PermissionError(
                f"could not lock file against replacement: {path} "
                f"(WinError {get_last_error()})"
            )
    else:
        source = path.open("rb")
    try:
        verified = verify_file_identity(expected)
        yield verified
        # On Windows the still-open FILE_SHARE_READ-only handle has denied all writes and
        # replacement for the whole interval. Other platforms recheck because their retained
        # read handle is not an equivalent security boundary.
        if os.name != "nt":
            verify_file_identity(expected)
    finally:
        if source is not None:
            source.close()
        if handle is not None:
            kernel32.CloseHandle(handle)


def verify_executable_identity(expected: dict[str, Any]) -> Path:
    """Verify a previously captured executable identity."""

    return verify_file_identity(expected)


@contextmanager
def hold_executable_identity(expected: dict[str, Any]) -> Iterator[Path]:
    """Hold a verified executable against writes/replacement during execution."""

    with hold_file_identity(expected) as path:
        yield path
