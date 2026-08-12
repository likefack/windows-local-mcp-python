from __future__ import annotations

import ctypes
import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import get_last_error, wintypes
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def capture_executable_identity(
    executable: str | Path,
    *,
    expected_sha256: str | None = None,
    provenance: str,
) -> dict[str, Any]:
    """Capture the identity that must remain true until process creation."""
    path = Path(executable).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise PermissionError(f"executable is not a regular file: {path}")
    details = path.stat()
    if not details.st_ino:
        raise RuntimeError("filesystem does not expose a stable executable identity")
    digest = _sha256_file(path)
    if expected_sha256 is not None and digest != expected_sha256.casefold():
        raise PermissionError(f"configured executable SHA-256 does not match: {path}")
    return {
        "path": str(path),
        "sha256": digest,
        "size": int(details.st_size),
        "device": int(details.st_dev),
        "inode": int(details.st_ino),
        "mtime_ns": int(details.st_mtime_ns),
        "provenance": provenance,
    }


def trusted_helper_identity(settings: Any, program_key: str) -> dict[str, Any]:
    """Resolve a broker helper only from an explicit path and SHA-256 trust anchor."""
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
    return capture_executable_identity(
        executable,
        expected_sha256=configured_sha256,
        provenance="explicit-local-config",
    )


def verify_executable_identity(expected: dict[str, Any]) -> Path:
    path = Path(str(expected.get("path", ""))).resolve(strict=True)
    actual = capture_executable_identity(
        path,
        expected_sha256=str(expected.get("sha256", "")),
        provenance=str(expected.get("provenance", "")),
    )
    if actual != expected:
        raise RuntimeError(f"executable identity changed before execution: {path}")
    return path


@contextmanager
def hold_executable_identity(expected: dict[str, Any]) -> Iterator[Path]:
    """Hold a verified executable against writes/replacement for the launch interval.

    Windows is the supported security boundary. A FILE_SHARE_READ-only handle prevents a
    same-user actor from replacing or modifying the executable between verification and use.
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
                f"could not lock executable against replacement: {path} "
                f"(WinError {get_last_error()})"
            )
    else:
        source = path.open("rb")
    try:
        verified = verify_executable_identity(expected)
        yield verified
        # On Windows the still-open FILE_SHARE_READ-only handle has denied all writes and
        # replacement for the whole interval. Other platforms recheck because their retained
        # read handle is not an equivalent security boundary.
        if os.name != "nt":
            verify_executable_identity(expected)
    finally:
        if source is not None:
            source.close()
        if handle is not None:
            kernel32.CloseHandle(handle)
