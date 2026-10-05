"""Bounded, process-local plans; bytes and identities never travel through the model."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .paths import PathIdentity, Workspace, read_verified_bytes, release_verified_hold
from .util import sha256_bytes


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    data: bytes
    identity: PathIdentity


@dataclass
class WorkspacePlan:
    tool_name: str
    snapshots: dict[str, FileSnapshot] = field(default_factory=dict)
    absent: set[str] = field(default_factory=set)
    changes: dict[str, bytes] = field(default_factory=dict)
    deletions: set[str] = field(default_factory=set)
    directories: set[str] = field(default_factory=set)
    parents: dict[str, PathIdentity] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def scope(self) -> set[str]:
        return (
            set(self.snapshots)
            | self.absent
            | set(self.changes)
            | self.deletions
            | self.directories
        )

    @property
    def retained_bytes(self) -> int:
        return sum(len(item.data) for item in self.snapshots.values()) + sum(
            len(data) for data in self.changes.values()
        )


def snapshot_file(workspace: Workspace, path: str, max_bytes: int) -> FileSnapshot:
    """Validate both read and write policy, then read using the verified file handle."""
    max_bytes = min(max_bytes, workspace.settings.max_backup_bytes)
    readable = workspace.resolve_existing(path, allow_directory=False, access="read")
    try:
        canonical = workspace.relative(readable)
        workspace.resolve_existing(
            canonical, allow_directory=False, access="write", hold_identity=False
        )
        before = workspace.identity(readable)
        if before is None or before.size > max_bytes:
            raise ValueError("workspace plan file exceeds read/backup byte limit")
        data = read_verified_bytes(readable, max_bytes)
        if workspace.identity(readable) != before or len(data) != before.size:
            raise RuntimeError("workspace file changed during verified read")
        return FileSnapshot(canonical, data, before)
    finally:
        release_verified_hold(readable)


def validate_plan(workspace: Workspace, plan: WorkspacePlan) -> None:
    """Reject stale identities, hashes, newly occupied paths, and changed path policy."""
    for relative, expected in plan.snapshots.items():
        current = snapshot_file(workspace, relative, len(expected.data))
        if current.identity != expected.identity or sha256_bytes(current.data) != sha256_bytes(
            expected.data
        ):
            raise RuntimeError("workspace plan is stale; file identity or content changed")
    for relative in plan.absent:
        target = workspace.resolve_directory_target(relative, parents=True)
        if target.exists():
            raise RuntimeError("workspace plan is stale; destination is no longer absent")
    for relative, expected in plan.parents.items():
        parent = workspace.resolve_directory(relative, access="write")
        try:
            current = workspace.identity(parent)
            if current is None or workspace._native_identity(current) != workspace._native_identity(
                expected
            ):
                raise RuntimeError("workspace plan is stale; parent directory identity changed")
        finally:
            release_verified_hold(parent)


def bind_plan_parents(workspace: Workspace, plan: WorkspacePlan) -> None:
    """Bind existing ancestors without making unrelated child changes invalidate a plan."""
    for relative in plan.scope:
        parent = (workspace.root / relative).parent
        while True:
            if parent.exists():
                name = workspace.relative(parent)
                checked = workspace.resolve_directory(name, access="write")
                try:
                    identity = workspace.identity(checked)
                    if identity is None:
                        raise RuntimeError("workspace plan parent disappeared")
                    plan.parents[name] = identity
                finally:
                    release_verified_hold(checked)
            if parent == workspace.root:
                break
            parent = parent.parent


class WorkspacePlanStore:
    """Short-lived, one-shot references. Restart deliberately invalidates all plans."""

    ttl_seconds = 300
    max_plans = 4

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self._plans: dict[str, tuple[float, WorkspacePlan]] = {}
        self._lock = threading.Lock()

    def _prune(self) -> None:
        now = time.monotonic()
        self._plans = {key: item for key, item in self._plans.items() if item[0] > now}

    def put(self, plan: WorkspacePlan) -> str:
        with self._lock:
            self._prune()
            if len(self._plans) >= self.max_plans or (
                sum(item[1].retained_bytes for item in self._plans.values()) + plan.retained_bytes
                > self.max_bytes
            ):
                raise ValueError(
                    "workspace preview plan capacity exceeded; apply or wait for expiry"
                )
            token = secrets.token_urlsafe(24)
            self._plans[token] = (time.monotonic() + self.ttl_seconds, plan)
            return token

    def take(self, token: str) -> WorkspacePlan:
        with self._lock:
            self._prune()
            if not isinstance(token, str) or token not in self._plans:
                raise ValueError("unknown, expired, consumed, or restarted workspace plan")
            return self._plans.pop(token)[1]
