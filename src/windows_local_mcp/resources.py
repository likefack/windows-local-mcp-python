from __future__ import annotations

import hashlib
import os
import shutil
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO, Self

from .config import Settings

_LOCK_SLOT_COUNT = 32
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.RLock] = {}


class WorkspaceExecutionLock:
    """Cross-process mutation lock with workspace-wide and target-specific scopes.

    With no target, all lock slots are acquired and the caller has exclusive workspace-write
    access. With a target, only the deterministic slot for that canonical path is acquired.
    Hash collisions merely serialize unrelated target writes; they never weaken exclusion.
    """

    def __init__(
        self,
        settings: Settings,
        timeout: float = 30.0,
        *,
        target: Path | None = None,
    ) -> None:
        self.lock_dir = settings.data_dir / "locks"
        self.timeout = timeout
        self.target = target
        self._held: list[tuple[BinaryIO, threading.RLock]] = []
        self._slots = (
            [self._target_slot(target)] if target is not None else list(range(_LOCK_SLOT_COUNT))
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
        directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
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


def enforce_data_quota(settings: Settings, *, incoming_bytes: int = 0) -> None:
    used = directory_size(settings.data_dir, stop_after=settings.max_data_dir_bytes)
    if used + incoming_bytes > settings.max_data_dir_bytes:
        raise RuntimeError(
            f"data_dir quota exceeded: {used + incoming_bytes} > {settings.max_data_dir_bytes}"
        )


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
            "workspace-history",
        )
    ]
    protected_ids = protected_ids or set()
    cutoff = datetime.now(UTC) - timedelta(days=settings.retention_days)
    candidates: list[tuple[float, Path]] = []
    removed = 0
    for root in artifact_roots:
        if not root.exists() or root.is_symlink():
            continue
        for candidate in root.iterdir():
            if candidate.is_symlink():
                continue
            if any(candidate.name.startswith(operation_id) for operation_id in protected_ids):
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
        size = directory_size(candidate) if candidate.is_dir() else candidate.stat().st_size
        _remove_artifact(candidate)
        used -= size
        removed += 1
    return removed


def _remove_artifact(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)
