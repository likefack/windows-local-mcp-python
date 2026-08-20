from __future__ import annotations

import ctypes
import os
import stat
import threading
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import get_last_error, wintypes
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

from .config import Settings

_WINDOWS_DEVICES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_DIRECTORY_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000


@dataclass(frozen=True)
class PathIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


class _ByHandleFileInformation(ctypes.Structure):
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


class _WindowsHandleLease:
    def __init__(self, handles: list[Any]) -> None:
        self._handles = handles

    def close(self) -> None:
        handles, self._handles = self._handles, []
        if not handles or os.name != "nt":
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            for handle in reversed(handles):
                kernel32.CloseHandle(handle)
        except Exception:
            pass


_PathBase = type(Path())


class _HeldPath(_PathBase):
    __slots__ = ("_lease_finalizer", "_write_intent", "__weakref__")

    def __new__(cls, *parts: Any) -> "_HeldPath":
        instance = super().__new__(cls, *parts)
        instance._lease_finalizer = None
        instance._write_intent = False
        return instance

    @classmethod
    def attach(
        cls,
        path: Path,
        lease: _WindowsHandleLease,
        *,
        write_intent: bool = False,
    ) -> "_HeldPath":
        instance = cls(path)
        instance._write_intent = write_intent
        instance._lease_finalizer = weakref.finalize(instance, lease.close)
        return instance


class _MissingWritePath(_PathBase):
    """A lexical write target that was absent at validation time."""

    __slots__ = ("_snapshot_active", "__weakref__")

    def __new__(cls, *parts: Any) -> "_MissingWritePath":
        instance = super().__new__(cls, *parts)
        instance._snapshot_active = True
        return instance

    @classmethod
    def attach(cls, path: Path) -> "_MissingWritePath":
        return cls(path)

    def exists(self) -> bool:
        if self._snapshot_active:
            return False
        return super().exists()

    @property
    def parent(self) -> Path:
        return Path(super().parent)

    def resolve(self, strict: bool = False) -> Path:
        return Path(super().resolve(strict=strict))


def _release_held_path(path: Path) -> None:
    if not isinstance(path, _HeldPath):
        return
    finalizer = path._lease_finalizer
    if finalizer is not None and finalizer.alive:
        finalizer()


def release_write_intent_hold(path: Path) -> None:
    """Release only a write-target snapshot; read-validation leases stay pinned."""

    if isinstance(path, _HeldPath):
        if path._write_intent:
            _release_held_path(path)
        return
    if isinstance(path, _MissingWritePath):
        path._snapshot_active = False


def _windows_component_handles(
    path: Path,
    *,
    allow_directory: bool,
    allow_hardlinks: bool,
    write_intent: bool = False,
) -> Path:
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

    lexical = Path(os.path.abspath(os.path.normpath(path)))
    anchor = Path(lexical.anchor)
    parts = lexical.parts[1:] if lexical.anchor else lexical.parts
    current = anchor
    handles: list[Any] = []
    try:
        for index, part in enumerate(parts):
            current /= part
            final = index == len(parts) - 1
            share_mode = _FILE_SHARE_READ if final else (_FILE_SHARE_READ | _FILE_SHARE_WRITE)
            handle = kernel32.CreateFileW(
                str(current),
                _FILE_READ_ATTRIBUTES,
                share_mode,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            if handle in (None, invalid):
                raise PermissionError(
                    f"could not lock path component: {current} (WinError {get_last_error()})"
                )
            handles.append(handle)

            information = _ByHandleFileInformation()
            if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
                raise PermissionError(
                    f"could not inspect path component: {current} (WinError {get_last_error()})"
                )
            attributes = int(information.dwFileAttributes)
            is_directory = bool(attributes & _DIRECTORY_ATTRIBUTE)
            if attributes & _REPARSE_ATTRIBUTE:
                raise PermissionError(f"symlink, junction, or reparse point is denied: {current}")
            if not final and not is_directory:
                raise NotADirectoryError(f"path parent is not a directory: {current}")
            if final:
                if is_directory and not allow_directory:
                    raise IsADirectoryError(f"not a regular file: {current}")
                if (
                    not is_directory
                    and not allow_hardlinks
                    and int(information.nNumberOfLinks) > 1
                ):
                    raise PermissionError(f"files with multiple hard links are denied: {current}")

        if not parts:
            raise ValueError(f"path must identify a filesystem entry: {lexical}")
        lease = _WindowsHandleLease(handles)
        handles = []
        return _HeldPath.attach(lexical, lease, write_intent=write_intent)
    finally:
        for handle in reversed(handles):
            kernel32.CloseHandle(handle)


def hold_verified_path(
    path: str | Path,
    *,
    allow_directory: bool = False,
    allow_hardlinks: bool = False,
) -> Path:
    """Return a path whose Windows namespace/file identity remains locked while referenced.

    On Windows, every path component is opened with reparse-point semantics and retained
    without FILE_SHARE_DELETE. The final regular file also denies FILE_SHARE_WRITE. This
    prevents a same-user process from replacing a validated path, any parent directory, or
    the file itself before a caller later opens the returned path.
    """

    lexical = Path(os.path.abspath(os.path.normpath(os.fspath(path))))
    if os.name == "nt":
        return _windows_component_handles(
            lexical,
            allow_directory=allow_directory,
            allow_hardlinks=allow_hardlinks,
        )

    resolved = lexical.resolve(strict=True)
    current = Path(resolved.anchor)
    for part in resolved.parts[1:] if resolved.anchor else resolved.parts:
        current /= part
        if current.is_symlink():
            raise PermissionError(f"symlink, junction, or reparse point is denied: {current}")
    details = resolved.stat()
    if resolved.is_dir():
        if not allow_directory:
            raise IsADirectoryError(f"not a regular file: {resolved}")
    elif not resolved.is_file():
        raise PermissionError(f"path is not a regular file or directory: {resolved}")
    elif not allow_hardlinks and details.st_nlink > 1:
        raise PermissionError(f"files with multiple hard links are denied: {resolved}")
    return resolved


def _hold_write_target(path: Path) -> Path:
    if os.name == "nt":
        return _windows_component_handles(
            path,
            allow_directory=False,
            allow_hardlinks=False,
            write_intent=True,
        )
    return hold_verified_path(path, allow_directory=False, allow_hardlinks=False)


class Workspace:
    """Canonical path broker for every workspace filesystem boundary."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = settings.workspace_root.resolve(strict=True)
        self._blocked = {name.casefold() for name in settings.blocked_file_names}
        self._hidden = {name.casefold() for name in settings.hidden_directories}
        self._read_denied = {name.casefold() for name in settings.read_denied_directories}
        self._write_denied = {name.casefold() for name in settings.write_denied_directories}
        self._locks_guard = threading.Lock()
        self._target_locks: dict[str, threading.RLock] = {}
        self._reject_reparse_chain(self.root)

    @staticmethod
    def validate_windows_syntax(user_path: str) -> None:
        if not user_path or "\x00" in user_path:
            raise ValueError("path must be non-empty and contain no NUL")
        windows = PureWindowsPath(user_path)
        if windows.is_absolute() or windows.drive or user_path.startswith(("\\\\", "//")):
            raise PermissionError("absolute, drive-qualified, and UNC paths are not allowed")
        for raw_part in windows.parts:
            if raw_part in {".", "..", "\\", "/"}:
                continue
            if ":" in raw_part:
                raise PermissionError("NTFS alternate data streams are not allowed")
            if raw_part.endswith((" ", ".")):
                raise PermissionError("Windows paths ending in a space or dot are not allowed")
            device_base = raw_part.split(".", 1)[0].rstrip(" .").upper()
            if device_base in _WINDOWS_DEVICES:
                raise PermissionError(f"Windows reserved device name is not allowed: {raw_part}")

    def _is_inside(self, candidate: Path) -> bool:
        try:
            candidate.relative_to(self.root)
            return True
        except ValueError:
            return candidate == self.root

    def _check_inside(self, candidate: Path) -> None:
        if not self._is_inside(candidate):
            raise PermissionError(f"path escapes workspace_root: {candidate}")

    def _relative_parts(self, candidate: Path) -> tuple[str, ...]:
        if candidate == self.root:
            return ()
        return tuple(part.casefold() for part in candidate.relative_to(self.root).parts)

    def _check_access(self, candidate: Path, *, access: str) -> None:
        parts = self._relative_parts(candidate)
        denied = self._read_denied if access == "read" else self._write_denied
        if any(part in denied for part in parts):
            raise PermissionError(f"{access} access is denied by directory policy: {candidate}")
        base = candidate.name.casefold()
        if base in self._blocked or (base.startswith(".env.") and base != ".env.example"):
            raise PermissionError(f"access to a protected file name is denied: {candidate}")

    @staticmethod
    def _is_reparse(path: Path) -> bool:
        info = path.lstat()
        attributes = int(getattr(info, "st_file_attributes", 0))
        return path.is_symlink() or bool(attributes & _REPARSE_ATTRIBUTE)

    def _reject_reparse_chain(self, candidate: Path) -> None:
        self._check_inside(candidate)
        current = self.root
        if self._is_reparse(current):
            raise PermissionError("workspace_root must not be a reparse point")
        for part in candidate.relative_to(self.root).parts:
            current /= part
            if current.exists() and self._is_reparse(current):
                raise PermissionError(f"symlink, junction, or reparse point is denied: {current}")

    @staticmethod
    def _reject_hardlink(path: Path) -> None:
        if path.is_file() and path.stat().st_nlink > 1:
            raise PermissionError(f"files with multiple hard links are denied: {path}")

    def resolve_existing(
        self,
        user_path: str,
        *,
        allow_directory: bool = True,
        access: str = "read",
        hold_identity: bool = True,
    ) -> Path:
        self.validate_windows_syntax(user_path)
        candidate = self.root / user_path
        self._check_inside(candidate.resolve(strict=False))
        self._reject_reparse_chain(candidate)
        resolved = candidate.resolve(strict=True)
        self._check_inside(resolved)
        self._check_access(resolved, access=access)
        if not allow_directory and not resolved.is_file():
            raise IsADirectoryError(f"not a regular file: {resolved}")
        if resolved.is_file():
            self._reject_hardlink(resolved)
            if hold_identity:
                return hold_verified_path(
                    resolved,
                    allow_directory=False,
                    allow_hardlinks=False,
                )
        return resolved

    def resolve_directory(self, user_path: str, *, access: str = "read") -> Path:
        path = self.resolve_existing(user_path, allow_directory=True, access=access)
        if not path.is_dir():
            raise NotADirectoryError(f"not a directory: {path}")
        return path

    def resolve_for_write(self, user_path: str) -> Path:
        self.validate_windows_syntax(user_path)
        lexical = self.root / user_path
        unresolved = lexical.resolve(strict=False)
        self._check_inside(unresolved)
        parent = lexical.parent.resolve(strict=True)
        self._check_inside(parent)
        self._reject_reparse_chain(lexical.parent)
        target = parent / lexical.name
        self._check_inside(target)
        self._check_access(target, access="write")
        if target.exists():
            self._reject_reparse_chain(target)
            if not target.is_file():
                raise IsADirectoryError(f"write target is not a regular file: {target}")
            self._reject_hardlink(target)
            return _hold_write_target(target)
        return _MissingWritePath.attach(target)

    def resolve_planned_write(self, user_path: str) -> Path:
        """Validate a future regular-file target without creating missing parents."""
        self.validate_windows_syntax(user_path)
        lexical = self.root / user_path
        self._check_inside(lexical.resolve(strict=False))
        self._check_access(lexical, access="write")
        current = self.root
        parts = lexical.relative_to(self.root).parts
        for part in parts[:-1]:
            current /= part
            if current.exists():
                self._reject_reparse_chain(current)
                if not current.is_dir():
                    raise NotADirectoryError(f"planned write parent is not a directory: {current}")
                self._check_inside(current.resolve(strict=True))
        if lexical.exists():
            target = self.resolve_for_write(user_path)
            release_write_intent_hold(target)
            return Path(str(target))
        return lexical

    def ensure_directory_for_write(self, user_path: str) -> Path:
        """Create a workspace directory chain while rechecking every Windows path component."""
        self.validate_windows_syntax(user_path)
        lexical = self.root / user_path
        self._check_inside(lexical.resolve(strict=False))
        self._check_access(lexical, access="write")
        current = self.root
        for part in lexical.relative_to(self.root).parts:
            current /= part
            if current.exists():
                self._reject_reparse_chain(current)
                if not current.is_dir():
                    raise NotADirectoryError(f"write parent is not a directory: {current}")
            else:
                current.mkdir()
                self._reject_reparse_chain(current)
            self._check_inside(current.resolve(strict=True))
        return current.resolve(strict=True)

    def relative(self, path: Path) -> str:
        resolved = path.resolve(strict=False)
        self._check_inside(resolved)
        return str(resolved.relative_to(self.root)) or "."

    def is_hidden(self, path: Path) -> bool:
        try:
            parts = path.relative_to(self.root).parts
        except ValueError:
            return True
        return any(part.casefold() in self._hidden for part in parts)

    def identity(self, path: Path) -> PathIdentity | None:
        if not path.exists():
            return None
        info = path.stat()
        return PathIdentity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

    def revalidate_for_replace(
        self,
        target: Path,
        *,
        parent_identity: PathIdentity,
        target_identity: PathIdentity | None,
    ) -> None:
        fresh = self.resolve_for_write(self.relative(target))
        try:
            if fresh != target:
                raise RuntimeError("write target changed during operation")
            actual_target = Path(str(target))
            current_parent = self.identity(actual_target.parent)
            if current_parent is None or (
                current_parent.device,
                current_parent.inode,
            ) != (parent_identity.device, parent_identity.inode):
                raise RuntimeError("write target parent changed during operation")
            if self.identity(actual_target) != target_identity:
                raise RuntimeError("write target changed during operation")
        except Exception:
            release_write_intent_hold(fresh)
            raise
        release_write_intent_hold(fresh)
        release_write_intent_hold(target)

    @contextmanager
    def lock_target(self, target: Path) -> Iterator[None]:
        canonical = os.path.normcase(str(target.resolve(strict=False)))
        release_write_intent_hold(target)
        with self._locks_guard:
            lock = self._target_locks.setdefault(canonical, threading.RLock())
        with lock:
            yield
