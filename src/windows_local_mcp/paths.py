from __future__ import annotations

import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

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


@dataclass(frozen=True)
class PathIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


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
        return target

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
            return self.resolve_for_write(user_path)
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
        if fresh != target:
            raise RuntimeError("write target changed during operation")
        current_parent = self.identity(target.parent)
        if current_parent is None or (
            current_parent.device,
            current_parent.inode,
        ) != (parent_identity.device, parent_identity.inode):
            raise RuntimeError("write target parent changed during operation")
        if self.identity(target) != target_identity:
            raise RuntimeError("write target changed during operation")

    @contextmanager
    def lock_target(self, target: Path) -> Iterator[None]:
        canonical = os.path.normcase(str(target.resolve(strict=False)))
        with self._locks_guard:
            lock = self._target_locks.setdefault(canonical, threading.RLock())
        with lock:
            yield
