from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import threading
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, BinaryIO, Self

from .config import Settings

_LOCK_SLOT_COUNT = 32
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_NAMED_LOCK_DEPTH = threading.local()


@dataclass(frozen=True)
class DirectoryScan:
    total_bytes: int
    entry_count: int
    files: tuple[Path, ...] = ()


class WorkspaceExecutionLock:
    """Cross-process mutation lock with workspace-wide and target-specific scopes.

    With no target, all lock slots are acquired and the caller has exclusive workspace-write
    access. One or more known paths acquire only their deterministic canonical-path slots in
    sorted order. Hash collisions merely serialize unrelated writes; they never weaken
    exclusion or create a multi-lock deadlock.
    """

    def __init__(
        self,
        settings: Settings,
        timeout: float = 30.0,
        *,
        target: Path | None = None,
        targets: Iterable[Path] | None = None,
    ) -> None:
        if target is not None and targets is not None:
            raise ValueError("target and targets are mutually exclusive")
        self.lock_dir = settings.data_dir / "locks"
        self.timeout = timeout
        self.target = target
        self._held: list[tuple[BinaryIO, threading.RLock]] = []
        selected = tuple(targets) if targets is not None else ((target,) if target else None)
        if selected is not None and not selected:
            raise ValueError("targets must identify at least one path")
        self._slots = (
            sorted({self._target_slot(item) for item in selected})
            if selected is not None
            else list(range(_LOCK_SLOT_COUNT))
        )

    def __enter__(self) -> Self:
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        try:
            for slot in self._slots:
                self._acquire_slot(slot, deadline)
            return self
        except Exception:
            self._release_all()
            raise

    def __exit__(self, *_: object) -> None:
        self._release_all()

    @staticmethod
    def _target_slot(target: Path) -> int:
        canonical = os.path.normcase(str(target.resolve(strict=False))).encode("utf-8")
        digest = hashlib.sha256(canonical).digest()
        return int.from_bytes(digest[:8], "big") % _LOCK_SLOT_COUNT

    def _acquire_slot(self, slot: int, deadline: float) -> None:
        path = self.lock_dir / f"workspace-{slot:02d}.lock"
        local_lock = _local_lock_for(path)
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("workspace execution lock timed out")
            if not local_lock.acquire(blocking=False):
                time.sleep(0.05)
                continue
            file = path.open("a+b")
            if path.stat().st_size == 0:
                file.write(b"0")
                file.flush()
            try:
                _lock_one_byte(file)
            except OSError:
                file.close()
                local_lock.release()
                time.sleep(0.05)
                continue
            self._held.append((file, local_lock))
            return

    def _release_all(self) -> None:
        while self._held:
            file, local_lock = self._held.pop()
            try:
                _unlock_one_byte(file)
            finally:
                file.close()
                local_lock.release()


class NamedControlPlaneLock:
    """Cross-process lock for one trusted-store lifecycle, with same-thread nesting."""

    def __init__(self, settings: Settings, name: str, timeout: float = 30.0) -> None:
        if not name or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in name
        ):
            raise ValueError("invalid control-plane lock name")
        self.path = settings.data_dir / "locks" / f"control-{name}.lock"
        self.timeout = timeout
        self._file: BinaryIO | None = None
        self._local_lock: threading.RLock | None = None
        self._nested = False

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = os.path.normcase(str(self.path.resolve(strict=False)))
        depths = getattr(_NAMED_LOCK_DEPTH, "depths", {})
        _NAMED_LOCK_DEPTH.depths = depths
        if depths.get(key, 0):
            depths[key] += 1
            self._nested = True
            return self
        local_lock = _local_lock_for(self.path)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if not local_lock.acquire(blocking=False):
                time.sleep(0.05)
                continue
            file = self.path.open("a+b")
            if self.path.stat().st_size == 0:
                file.write(b"0")
                file.flush()
            try:
                _lock_one_byte(file)
            except OSError:
                file.close()
                local_lock.release()
                time.sleep(0.05)
                continue
            self._file = file
            self._local_lock = local_lock
            depths[key] = 1
            return self
        raise TimeoutError(f"control-plane lock timed out: {self.path.name}")

    def __exit__(self, *_: object) -> None:
        key = os.path.normcase(str(self.path.resolve(strict=False)))
        depths = getattr(_NAMED_LOCK_DEPTH, "depths", {})
        depth = depths.get(key, 0)
        if depth > 1:
            depths[key] = depth - 1
            return
        depths.pop(key, None)
        if self._file is not None:
            try:
                _unlock_one_byte(self._file)
            finally:
                self._file.close()
        if self._local_lock is not None:
            self._local_lock.release()


def _local_lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve(strict=False)))
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.RLock())


def _lock_one_byte(file: BinaryIO) -> None:
    file.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_one_byte(file: BinaryIO) -> None:
    file.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(file.fileno(), fcntl.LOCK_UN)


class BoundedStreamCapture:
    """Drain a child pipe without unbounded memory or disk growth."""

    def __init__(self, stream: BinaryIO, destination: Path, limit: int) -> None:
        self.stream = stream
        self.destination = destination
        self.limit = limit
        self.total_bytes = 0
        self.truncated = False
        self._head_limit = limit // 2
        self._tail_limit = max(1, limit - self._head_limit)
        self._head = bytearray()
        self._tail: deque[bytes] = deque()
        self._tail_bytes = 0
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join()
        self._write_result()

    def _drain(self) -> None:
        while True:
            chunk = self.stream.read(64 * 1024)
            if not chunk:
                break
            self.total_bytes += len(chunk)
            if len(self._head) < self._head_limit:
                take = min(self._head_limit - len(self._head), len(chunk))
                self._head.extend(chunk[:take])
                chunk = chunk[take:]
            if chunk:
                self._tail.append(chunk)
                self._tail_bytes += len(chunk)
                while self._tail and self._tail_bytes > self._tail_limit:
                    excess = self._tail_bytes - self._tail_limit
                    first = self._tail[0]
                    if len(first) <= excess:
                        self._tail.popleft()
                        self._tail_bytes -= len(first)
                    else:
                        self._tail[0] = first[excess:]
                        self._tail_bytes -= excess
            self.truncated = self.total_bytes > self.limit

    def _write_result(self) -> None:
        marker = (
            f"\n... <truncated {self.total_bytes - self.limit} bytes> ...\n".encode()
            if self.truncated
            else b""
        )
        tail = b"".join(self._tail)
        payload = bytes(self._head)
        if self.truncated:
            payload += marker + tail
        else:
            payload += tail
        self.destination.write_bytes(payload[: self.limit + len(marker)])

    def preview(self, character_limit: int) -> str:
        if not self.destination.exists():
            return ""
        data = self.destination.read_bytes()
        text = data.decode("utf-8", errors="replace")
        if len(text) <= character_limit:
            return text
        half = max(1, (character_limit - 32) // 2)
        return text[:half] + "\n... <preview truncated> ...\n" + text[-half:]


def directory_size(path: Path, *, stop_after: int | None = None) -> int:
    total = 0
    for root, directories, files in os.walk(path, followlinks=False):
        directories[:] = [
            name for name in directories if not (Path(root) / name).is_symlink()
        ]
        for name in files:
            candidate = Path(root) / name
            try:
                if candidate.is_symlink():
                    continue
                total += candidate.stat().st_size
            except FileNotFoundError:
                continue
            if stop_after is not None and total > stop_after:
                return total
    return total


def scan_directory_bounded(
    path: Path,
    *,
    stop_after_bytes: int,
    stop_after_entries: int,
    collect_files: bool = False,
    reject_alternate_streams: bool = False,
    reject_reparse_points: bool = False,
) -> DirectoryScan:
    """Scan a process-writable tree without building an unbounded inventory.

    Limits are reported by returning a value greater than the corresponding threshold.
    Unsafe filesystem features are rejected immediately so NTFS allocation cannot hide from
    the ordinary file-size quota and reparse points cannot redirect a later inventory walk.
    """
    total_bytes = 0
    entry_count = 0
    files: list[Path] = []
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            current_info = current.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        current_is_reparse = bool(
            getattr(current_info, "st_file_attributes", 0) & 0x400
        )
        if reject_reparse_points and (current.is_symlink() or current_is_reparse):
            raise RuntimeError(f"runtime tree contains a reparse point: {current}")
        if reject_alternate_streams and _has_named_data_stream(current):
            raise RuntimeError(
                f"runtime tree contains an NTFS alternate data stream: {current}"
            )
        try:
            entries = os.scandir(current)
        except FileNotFoundError:
            continue
        with entries:
            for entry in entries:
                candidate = Path(entry.path)
                entry_count += 1
                if entry_count > stop_after_entries:
                    return DirectoryScan(total_bytes, entry_count, tuple(files))
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                is_reparse = bool(getattr(info, "st_file_attributes", 0) & 0x400)
                if reject_reparse_points and (entry.is_symlink() or is_reparse):
                    raise RuntimeError(f"runtime tree contains a reparse point: {candidate}")
                if reject_alternate_streams and _has_named_data_stream(candidate):
                    raise RuntimeError(
                        f"runtime tree contains an NTFS alternate data stream: {candidate}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    pending.append(candidate)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise RuntimeError(
                        f"runtime tree contains a non-regular entry: {candidate}"
                    )
                total_bytes += info.st_size
                if collect_files:
                    files.append(candidate)
                if total_bytes > stop_after_bytes:
                    return DirectoryScan(total_bytes, entry_count, tuple(files))
    return DirectoryScan(total_bytes, entry_count, tuple(files))


def _has_named_data_stream(path: Path) -> bool:
    if os.name != "nt":
        return False

    import ctypes
    from ctypes import wintypes

    class Win32FindStreamData(ctypes.Structure):
        _fields_ = [
            ("stream_size", ctypes.c_longlong),
            ("stream_name", wintypes.WCHAR * 296),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL

    resolved = str(path.resolve(strict=True))
    if not resolved.startswith("\\\\?\\"):
        resolved = "\\\\?\\" + resolved
    data = Win32FindStreamData()
    handle = find_first(resolved, 0, ctypes.byref(data), 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in {2, 38, 50, 87}:
            return False
        raise OSError(error, f"FindFirstStreamW failed for {path}")
    try:
        while True:
            if data.stream_name != "::$DATA":
                return True
            if find_next(handle, ctypes.byref(data)):
                continue
            error = ctypes.get_last_error()
            if error == 38:
                return False
            raise OSError(error, f"FindNextStreamW failed for {path}")
    finally:
        find_close(handle)


def enforce_data_quota(settings: Settings, *, incoming_bytes: int = 0) -> None:
    used = directory_size(settings.data_dir, stop_after=settings.max_data_dir_bytes)
    if used + incoming_bytes > settings.max_data_dir_bytes:
        raise RuntimeError(
            f"data_dir quota exceeded: {used + incoming_bytes} > {settings.max_data_dir_bytes}"
        )


def _workspace_history_serialized(function: Any) -> Any:
    @wraps(function)
    def locked(settings: Settings, *args: Any, **kwargs: Any) -> Any:
        with NamedControlPlaneLock(settings, "workspace-cas"):
            return function(settings, *args, **kwargs)

    return locked


@_workspace_history_serialized
def prune_artifacts(settings: Settings, *, protected_ids: set[str] | None = None) -> int:
    """Apply age and size retention only to known artifact directories."""
    artifact_roots = [
        settings.data_dir / name
        for name in (
            "outputs",
            "diffs",
            "backups",
            "git-snapshots",
            "approval-staging",
            "binary-transfers",
        )
    ]
    protected_ids = protected_ids or set()
    removed = _prune_workspace_history(settings, protected_ids)
    cutoff = datetime.now(UTC) - timedelta(days=settings.retention_days)
    candidates: list[tuple[float, Path]] = []
    for root in artifact_roots:
        if not root.exists() or root.is_symlink():
            continue
        for candidate in root.iterdir():
            if candidate.is_symlink():
                continue
            if any(
                candidate.name.startswith(operation_id) for operation_id in protected_ids
            ):
                continue
            try:
                modified = datetime.fromtimestamp(candidate.stat().st_mtime, UTC)
            except FileNotFoundError:
                continue
            if modified < cutoff:
                _remove_artifact(candidate)
                removed += 1
            else:
                candidates.append((modified.timestamp(), candidate))

    used = directory_size(settings.data_dir, stop_after=settings.max_data_dir_bytes)
    for _, candidate in sorted(candidates):
        if used <= settings.max_data_dir_bytes:
            break
        size = (
            directory_size(candidate) if candidate.is_dir() else candidate.stat().st_size
        )
        _remove_artifact(candidate)
        used -= size
        removed += 1
    if settings.sandbox_scratch_dir is not None:
        scratch_candidates: list[tuple[float, Path]] = []
        for root in (
            settings.sandbox_scratch_dir / "approval-inputs",
            settings.sandbox_scratch_dir / "runs",
            settings.sandbox_scratch_dir / "live-verification",
            settings.sandbox_scratch_dir / "git-broker",
        ):
            try:
                if not root.exists() or root.is_symlink():
                    continue
                entries = list(root.iterdir())
            except OSError:
                continue
            for candidate in entries:
                try:
                    if candidate.is_symlink() or candidate.name in protected_ids:
                        continue
                    modified = datetime.fromtimestamp(candidate.stat().st_mtime, UTC)
                except FileNotFoundError:
                    continue
                except OSError:
                    continue
                if modified < cutoff:
                    if _try_remove_disposable_artifact(candidate):
                        removed += 1
                    else:
                        scratch_candidates.append((modified.timestamp(), candidate))
                else:
                    scratch_candidates.append((modified.timestamp(), candidate))
        try:
            scratch_used = directory_size(
                settings.sandbox_scratch_dir,
                stop_after=settings.max_sandbox_scratch_bytes,
            )
        except OSError:
            scratch_used = settings.max_sandbox_scratch_bytes + 1
        for _, candidate in sorted(scratch_candidates):
            if scratch_used <= settings.max_sandbox_scratch_bytes:
                break
            try:
                size = (
                    directory_size(candidate)
                    if candidate.is_dir()
                    else candidate.stat().st_size
                )
            except OSError:
                size = 0
            if _try_remove_disposable_artifact(candidate):
                scratch_used = max(0, scratch_used - size)
                removed += 1
    return removed


def _prune_workspace_history(settings: Settings, protected_ids: set[str]) -> int:
    """Prune operation manifests first, then garbage-collect unreferenced SHA blobs."""
    history = settings.data_dir / "workspace-history"
    operations = history / "operations"
    blobs = history / "blobs"
    if not operations.exists() or operations.is_symlink():
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=settings.retention_days)
    candidates: list[tuple[float, Path]] = []
    removed = 0
    for candidate in operations.iterdir():
        if candidate.is_symlink() or candidate.name in protected_ids:
            continue
        try:
            modified = datetime.fromtimestamp(candidate.stat().st_mtime, UTC)
        except FileNotFoundError:
            continue
        candidates.append((modified.timestamp(), candidate))
        if modified < cutoff:
            _remove_artifact(candidate)
            removed += 1
    remaining = [item for item in candidates if item[1].exists()]
    for _, candidate in sorted(remaining)[
        : max(0, len(remaining) - settings.retention_max_operations)
    ]:
        _remove_artifact(candidate)
        removed += 1
    removed += _garbage_collect_workspace_blobs(operations, blobs)
    return removed


def _garbage_collect_workspace_blobs(operations: Path, blobs: Path) -> int:
    if not blobs.exists() or blobs.is_symlink():
        return 0
    referenced: set[str] = set()
    for manifest in operations.glob("**/manifest.json"):
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            for item in payload.get("files", []):
                blob = item.get("blob")
                if isinstance(blob, str) and len(blob) == 64:
                    referenced.add(blob)
        except (OSError, ValueError, TypeError):
            return 0
    removed = 0
    for blob in blobs.glob("*.blob"):
        if blob.stem not in referenced:
            blob.unlink(missing_ok=True)
            removed += 1
    return removed


def _retry_windows_readonly_delete(
    function: Any,
    path: str,
    exc_info: tuple[type[BaseException], BaseException, Any],
) -> None:
    error = exc_info[1]
    if os.name == "nt" and isinstance(error, PermissionError):
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            function(path)
            return
        except OSError:
            pass
    raise error


def _remove_artifact(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, onerror=_retry_windows_readonly_delete)
        return
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        if os.name != "nt":
            raise
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        path.unlink(missing_ok=True)


def _try_remove_disposable_artifact(path: Path) -> bool:
    try:
        _remove_artifact(path)
    except OSError:
        return False
    return True
