from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .config import Settings
from .config_binding import export_config_binding
from .runtime_trust import capture_runtime_dependency_state
from .util import canonical_json, sha256_bytes, sha256_text, utc_now_iso
from .windows_system import windows_system_executable

_ORIGINAL_SQLITE_CONNECT = sqlite3.connect
_AUDIT_GUARDS_LOCK = threading.RLock()
_ACTIVE_AUDIT_GUARDS: dict[str, _AuditMutationGuard] = {}
_SQLITE_CONNECT_PATCHED = False


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Approved Host control-plane capture exceeded operation deadline")


def _remaining_timeout(deadline: float | None, maximum: float) -> float:
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Approved Host control-plane capture exceeded operation deadline")
    return max(0.001, min(maximum, remaining))


def _tamper_marker(settings: Settings) -> Path:
    return settings.data_dir / "control-plane" / "tamper-detected.json"


def assert_control_plane_healthy(settings: Settings) -> None:
    if _tamper_marker(settings).exists():
        raise RuntimeError(
            "control-plane tampering was previously detected; operations are unavailable "
            "until the operator performs an explicit recovery"
        )


def _runtime_startup_candidate_paths() -> list[Path]:
    """Return present and absent path-configuration locations that can affect next startup."""
    directories: set[Path] = set()
    candidates: set[Path] = set()
    for value in (sys.executable, getattr(sys, "_base_executable", None)):
        if not value:
            continue
        executable = Path(str(value)).absolute()
        if executable.exists():
            executable = executable.resolve(strict=True)
        directories.add(executable.parent)
    for prefix_value in (sys.prefix, sys.base_prefix):
        prefix = Path(prefix_value).absolute()
        if prefix.exists():
            prefix = prefix.resolve(strict=True)
        directories.add(prefix)

    version_stem = f"python{sys.version_info.major}{sys.version_info.minor}"
    for directory in directories:
        candidates.add(directory / "pyvenv.cfg")
        candidates.add(directory / "python._pth")
        candidates.add(directory / f"{version_stem}._pth")
        candidates.add(directory / f"{version_stem}.zip")
        if directory.is_dir():
            for library in directory.glob("python*.dll"):
                if library.is_file():
                    candidates.add(library.with_suffix("._pth"))

    for value in sys.path:
        if value:
            candidates.add(Path(value).absolute())
    return sorted(candidates, key=lambda item: os.path.normcase(str(item)))


def _startup_path_acl_digest(
    path: Path, *, deadline: float | None = None
) -> str | None:
    if os.name != "nt":
        return None
    _check_deadline(deadline)
    try:
        completed = subprocess.run(
            [windows_system_executable("icacls.exe"), str(path), "/C"],
            capture_output=True,
            timeout=_remaining_timeout(deadline, 10),
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            "Approved Host control-plane capture exceeded operation deadline"
        ) from exc
    if completed.returncode != 0:
        raise RuntimeError(f"could not inspect Python startup path ACL: {path}")
    return sha256_bytes(completed.stdout + completed.stderr)


def _capture_runtime_startup_state(
    paths: list[Path] | None = None, *, deadline: float | None = None
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for candidate in paths or _runtime_startup_candidate_paths():
        _check_deadline(deadline)
        absolute = candidate.absolute()
        if not absolute.exists():
            records.append({"path": str(absolute), "kind": "missing"})
            continue
        if _is_reparse(absolute):
            raise RuntimeError(f"Python startup path is a reparse point: {absolute}")
        resolved = absolute.resolve(strict=True)
        details = resolved.stat()
        if resolved.is_file():
            if details.st_nlink > 1:
                raise RuntimeError(f"Python startup path is hard-linked: {resolved}")
            data = resolved.read_bytes()
            records.append(
                {
                    "path": str(resolved),
                    "kind": "file",
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "device": int(details.st_dev),
                    "inode": int(details.st_ino),
                    "acl_sha256": _startup_path_acl_digest(
                        resolved, deadline=deadline
                    ),
                }
            )
            continue
        if resolved.is_dir():
            records.append(
                {
                    "path": str(resolved),
                    "kind": "directory",
                    "device": int(details.st_dev),
                    "inode": int(details.st_ino),
                    "acl_sha256": _startup_path_acl_digest(
                        resolved, deadline=deadline
                    ),
                }
            )
            continue
        raise RuntimeError(f"Python startup path has unsupported type: {resolved}")
    records.sort(key=lambda item: os.path.normcase(str(item["path"])))
    return {
        "count": len(records),
        "digest": sha256_text(canonical_json(records)),
    }


def capture_critical_state(
    settings: Settings, operation_id: str, *, deadline: float | None = None
) -> dict[str, Any]:
    """Capture state that an Approved Host child is never allowed to mutate."""
    _check_deadline(deadline)
    database_identity = _database_identity(settings.data_dir / "audit.db")
    with _AUDIT_GUARDS_LOCK:
        active_guard = _ACTIVE_AUDIT_GUARDS.get(database_identity)
        if active_guard is not None and active_guard.operation_id != operation_id:
            raise RuntimeError("another Approved Host audit guard is already active")

    config_binding = export_config_binding(settings)
    roots = [
        settings.data_dir / "approval-staging",
        settings.data_dir / "binary-transfers",
        settings.data_dir / "worker-contexts" / f"{operation_id}.json",
        settings.data_dir / "control-plane",
        settings.data_dir / "workspace-history",
        Path(__file__).resolve(strict=True).parent.parent,
    ]
    if settings.sandbox_scratch_dir is not None:
        roots.append(settings.sandbox_scratch_dir / "approval-inputs")
        runs = settings.sandbox_scratch_dir / "runs"
        if runs.is_dir():
            roots.extend(
                child
                for child in runs.iterdir()
                if child.name != operation_id
            )
    config_path = config_binding.get("config_path")
    if config_path:
        roots.append(Path(str(config_path)).resolve(strict=True))
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for root in roots:
        _check_deadline(deadline)
        if not root.exists():
            continue
        candidates: list[Path] = []
        if root.is_file():
            candidates.append(root)
        else:
            for current, directories, files in os.walk(root, followlinks=False):
                _check_deadline(deadline)
                current_path = Path(current)
                for name in directories:
                    if _is_reparse(current_path / name):
                        raise RuntimeError(
                            "control-plane state contains a reparse directory"
                        )
                candidates.extend(current_path / name for name in files)
        for path in sorted(candidates, key=lambda item: str(item).casefold()):
            _check_deadline(deadline)
            if path == _tamper_marker(settings):
                continue
            if _is_reparse(path) or not path.is_file() or path.stat().st_nlink > 1:
                raise RuntimeError("control-plane state contains an unsafe file identity")
            data = path.read_bytes()
            total_bytes += len(data)
            if len(records) + 1 > settings.approval_manifest_max_files:
                raise RuntimeError("control-plane state exceeds the file admission limit")
            if total_bytes > settings.approval_manifest_max_bytes:
                raise RuntimeError("control-plane state exceeds the byte admission limit")
            try:
                record_path = str(path.relative_to(settings.data_dir)).replace("\\", "/")
            except ValueError:
                record_path = str(path.resolve(strict=True))
            records.append(
                {
                    "path": record_path,
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                }
            )
    runtime_state = (
        capture_runtime_dependency_state(
            max_files=settings.approval_manifest_max_files,
            max_bytes=settings.approval_manifest_max_bytes,
            deadline=deadline,
        )
        if os.name == "nt"
        else None
    )
    runtime_startup_state = (
        _capture_runtime_startup_state(deadline=deadline) if os.name == "nt" else None
    )
    _check_deadline(deadline)
    audit_snapshot, audit_bytes = _audit_state_snapshot(settings)
    _check_deadline(deadline)
    acl_digest, acl_bytes = _acl_state_digest(settings, roots, deadline=deadline)
    runtime_bytes = int(runtime_state["bytes"]) if runtime_state is not None else 0
    runtime_digest = str(runtime_state["digest"]) if runtime_state is not None else None
    runtime_startup_digest = (
        str(runtime_startup_state["digest"])
        if runtime_startup_state is not None
        else None
    )
    runtime_file_count = (
        int(runtime_state["file_count"]) if runtime_state is not None else 0
    )
    runtime_startup_path_count = (
        int(runtime_startup_state["count"])
        if runtime_startup_state is not None
        else 0
    )
    static_bytes = total_bytes + acl_bytes + runtime_bytes
    base_digest_payload = {
        "files": records,
        "acl_digest": acl_digest,
        "runtime_digest": runtime_digest,
        "runtime_startup_digest": runtime_startup_digest,
        "config_binding": config_binding,
    }
    state = _critical_state_summary(
        file_count=len(records),
        static_bytes=static_bytes,
        base_digest_payload=base_digest_payload,
        audit_snapshot=audit_snapshot,
        audit_bytes=audit_bytes,
        runtime_file_count=runtime_file_count,
        runtime_startup_path_count=runtime_startup_path_count,
    )

    if active_guard is not None:
        tracking_error = active_guard.tracking_error
        _deactivate_audit_guard(database_identity)
        if tracking_error is not None:
            raise RuntimeError(
                "trusted audit mutation tracking failed during Approved Host execution: "
                f"{tracking_error}"
            )
        return state

    _check_deadline(deadline)
    mirror = _build_audit_mirror(settings, deadline=deadline)
    _check_deadline(deadline)
    try:
        mirror_snapshot = _audit_snapshot_from_connection(mirror)
        if _snapshot_digest(mirror_snapshot) != _snapshot_digest(audit_snapshot):
            raise RuntimeError("audit mirror did not match the Approved Host preflight state")
        guard = _AuditMutationGuard(
            database_identity=database_identity,
            operation_id=operation_id,
            mirror=mirror,
            expected_state=state,
            file_count=len(records),
            static_bytes=static_bytes,
            base_digest_payload=base_digest_payload,
            max_snapshot_bytes=settings.max_data_dir_bytes,
            runtime_file_count=runtime_file_count,
            runtime_startup_path_count=runtime_startup_path_count,
        )
        _activate_audit_guard(guard)
    except Exception:
        mirror.close()
        raise
    return state


def _critical_state_summary(
    *,
    file_count: int,
    static_bytes: int,
    base_digest_payload: dict[str, Any],
    audit_snapshot: dict[str, Any],
    audit_bytes: int,
    runtime_file_count: int,
    runtime_startup_path_count: int,
) -> dict[str, Any]:
    audit_digest = _snapshot_digest(audit_snapshot)
    digest_payload = dict(base_digest_payload)
    digest_payload["audit_digest"] = audit_digest
    return {
        "file_count": file_count,
        "bytes": static_bytes + audit_bytes,
        "digest": sha256_text(canonical_json(digest_payload)),
        "audit_digest": audit_digest,
        "audit_bytes": audit_bytes,
        "audit_operation_count": len(audit_snapshot["operations"]),
        "audit_event_count": len(audit_snapshot["events"]),
        "acl_digest": base_digest_payload["acl_digest"],
        "runtime_digest": base_digest_payload["runtime_digest"],
        "runtime_file_count": runtime_file_count,
        "runtime_startup_digest": base_digest_payload["runtime_startup_digest"],
        "runtime_startup_path_count": runtime_startup_path_count,
        "config_binding": base_digest_payload["config_binding"],
    }


def _database_identity(database: object) -> str:
    value = os.fspath(database)
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    if value.startswith("file:"):
        value = unquote(value[5:].split("?", 1)[0])
    return os.path.normcase(os.path.abspath(value))


def _guarded_sqlite_connect(database: object, *args: Any, **kwargs: Any) -> sqlite3.Connection:
    connection = _ORIGINAL_SQLITE_CONNECT(database, *args, **kwargs)
    try:
        identity = _database_identity(database)
    except (TypeError, ValueError, OSError):
        return connection
    with _AUDIT_GUARDS_LOCK:
        guard = _ACTIVE_AUDIT_GUARDS.get(identity)
    if guard is not None:
        connection.set_trace_callback(guard.record_statement)
    return connection


def _activate_audit_guard(guard: _AuditMutationGuard) -> None:
    # Only this trusted worker process receives the trace callback. The Approved Host child
    # is a separate process, so its direct SQLite writes cannot advance the expected mirror.
    global _SQLITE_CONNECT_PATCHED
    with _AUDIT_GUARDS_LOCK:
        if guard.database_identity in _ACTIVE_AUDIT_GUARDS:
            guard.mirror.close()
            raise RuntimeError("Approved Host audit guard was armed twice")
        _ACTIVE_AUDIT_GUARDS[guard.database_identity] = guard
        if not _SQLITE_CONNECT_PATCHED:
            sqlite3.connect = _guarded_sqlite_connect
            _SQLITE_CONNECT_PATCHED = True


def _deactivate_audit_guard(database_identity: str) -> None:
    global _SQLITE_CONNECT_PATCHED
    with _AUDIT_GUARDS_LOCK:
        guard = _ACTIVE_AUDIT_GUARDS.pop(database_identity, None)
        if guard is not None:
            guard.mirror.close()
        if _SQLITE_CONNECT_PATCHED and not _ACTIVE_AUDIT_GUARDS:
            sqlite3.connect = _ORIGINAL_SQLITE_CONNECT
            _SQLITE_CONNECT_PATCHED = False


def _snapshot_rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    columns = [str(item[0]) for item in cursor.description or ()]
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def _canonicalize_process_creation_times(rows: list[dict[str, Any]]) -> None:
    # sqlite3's trace callback expands bound REAL parameters through SQL text and can
    # discard insignificant low-order digits. The Approved Host process identity uses
    # a 10 ms create-time tolerance, so retaining 15 significant digits here preserves
    # substantially more precision while preventing trusted mirror false positives.
    for row in rows:
        for field in ("worker_create_time", "child_create_time"):
            value = row.get(field)
            if value is not None:
                row[field] = float(format(float(value), ".15g"))


def _audit_snapshot_from_connection(connection: sqlite3.Connection) -> dict[str, Any]:
    integrity = connection.execute("PRAGMA quick_check").fetchone()
    if integrity != ("ok",):
        raise RuntimeError("audit database integrity check failed")
    schema = _snapshot_rows(
        connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    )
    operations = _snapshot_rows(connection.execute("SELECT * FROM operations ORDER BY id"))
    _canonicalize_process_creation_times(operations)
    events = _snapshot_rows(connection.execute("SELECT * FROM events ORDER BY id"))
    try:
        event_sequence = _snapshot_rows(
            connection.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name")
        )
    except sqlite3.OperationalError:
        event_sequence = []
    return {
        "schema": schema,
        "operations": operations,
        "events": events,
        "sqlite_sequence": event_sequence,
    }


def _snapshot_digest(snapshot: dict[str, Any]) -> str:
    return sha256_text(canonical_json(snapshot))


def _snapshot_bytes(snapshot: dict[str, Any], max_bytes: int) -> int:
    size = len(canonical_json(snapshot).encode("utf-8"))
    if size > max_bytes:
        raise RuntimeError("audit state exceeds the control-plane verification bound")
    return size


def _audit_state_snapshot(settings: Settings) -> tuple[dict[str, Any], int]:
    database = settings.data_dir / "audit.db"
    if not database.is_file():
        raise RuntimeError("audit database disappeared before Approved Host execution")
    connection = _ORIGINAL_SQLITE_CONNECT(f"file:{database}?mode=ro", uri=True, timeout=10)
    try:
        snapshot = _audit_snapshot_from_connection(connection)
        return snapshot, _snapshot_bytes(snapshot, settings.max_data_dir_bytes)
    finally:
        connection.close()


def _build_audit_mirror(
    settings: Settings, *, deadline: float | None = None
) -> sqlite3.Connection:
    _check_deadline(deadline)
    database = settings.data_dir / "audit.db"
    source = _ORIGINAL_SQLITE_CONNECT(
        f"file:{database}?mode=ro",
        uri=True,
        timeout=_remaining_timeout(deadline, 10),
    )
    mirror = _ORIGINAL_SQLITE_CONNECT(":memory:")
    try:
        source.backup(
            mirror,
            pages=64,
            progress=lambda _status, _remaining, _total: _check_deadline(deadline),
        )
        _check_deadline(deadline)
        mirror.execute("PRAGMA foreign_keys = ON")
        return mirror
    except Exception:
        mirror.close()
        raise
    finally:
        source.close()


class _AuditMutationGuard:
    """Advance the expected audit state only for SQL issued by the trusted worker process."""

    def __init__(
        self,
        *,
        database_identity: str,
        operation_id: str,
        mirror: sqlite3.Connection,
        expected_state: dict[str, Any],
        file_count: int,
        static_bytes: int,
        base_digest_payload: dict[str, Any],
        max_snapshot_bytes: int,
        runtime_file_count: int,
        runtime_startup_path_count: int,
    ) -> None:
        self.database_identity = database_identity
        self.operation_id = operation_id
        self.mirror = mirror
        self.expected_state = expected_state
        self.file_count = file_count
        self.static_bytes = static_bytes
        self.base_digest_payload = base_digest_payload
        self.max_snapshot_bytes = max_snapshot_bytes
        self.runtime_file_count = runtime_file_count
        self.runtime_startup_path_count = runtime_startup_path_count
        self.tracking_error: str | None = None
        self._lock = threading.RLock()

    def record_statement(self, statement: str) -> None:
        stripped = statement.lstrip()
        if not stripped:
            return
        keyword = stripped.split(None, 1)[0].casefold()
        folded = stripped.casefold()
        tracked_dml = keyword in {"insert", "update", "delete", "replace"} and (
            "operations" in folded or "events" in folded
        )
        transaction_control = keyword in {"begin", "commit", "rollback"}
        if not tracked_dml and not transaction_control:
            return
        with self._lock:
            if self.tracking_error is not None:
                return
            try:
                self.mirror.execute(statement)
                self._refresh_expected_state()
            except Exception as error:  # noqa: BLE001 - tracking uncertainty must fail closed
                self.tracking_error = f"{type(error).__name__}: {error}"

    def _refresh_expected_state(self) -> None:
        snapshot = _audit_snapshot_from_connection(self.mirror)
        audit_bytes = _snapshot_bytes(snapshot, self.max_snapshot_bytes)
        refreshed = _critical_state_summary(
            file_count=self.file_count,
            static_bytes=self.static_bytes,
            base_digest_payload=self.base_digest_payload,
            audit_snapshot=snapshot,
            audit_bytes=audit_bytes,
            runtime_file_count=self.runtime_file_count,
            runtime_startup_path_count=self.runtime_startup_path_count,
        )
        self.expected_state.clear()
        self.expected_state.update(refreshed)


def _acl_state_digest(
    settings: Settings, roots: list[Path], *, deadline: float | None = None
) -> tuple[str | None, int]:
    if os.name != "nt":
        return None, 0
    chunks: list[bytes] = []
    total = 0
    for root in roots:
        _check_deadline(deadline)
        if not root.exists():
            continue
        try:
            completed = subprocess.run(
                [windows_system_executable("icacls.exe"), str(root), "/T", "/C"],
                capture_output=True,
                timeout=_remaining_timeout(deadline, 30),
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                "Approved Host control-plane capture exceeded operation deadline"
            ) from exc
        if completed.returncode != 0:
            raise RuntimeError(f"could not inspect control-plane ACL: {root}")
        payload = completed.stdout + completed.stderr
        total += len(payload)
        if total > settings.approval_manifest_max_bytes:
            raise RuntimeError("control-plane ACL state exceeds the byte admission limit")
        chunks.append(str(root.resolve(strict=True)).encode("utf-8") + b"\0" + payload)
    return sha256_bytes(b"\0".join(chunks)), total


def _audit_state_digest(settings: Settings, operation_id: str) -> tuple[str, int]:
    del operation_id
    snapshot, size = _audit_state_snapshot(settings)
    return _snapshot_digest(snapshot), size


def mark_control_plane_tamper(
    settings: Settings,
    operation_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> str:
    _deactivate_audit_guard(_database_identity(settings.data_dir / "audit.db"))
    marker = _tamper_marker(settings)
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(
        {
            "version": 1,
            "detected_at": utc_now_iso(),
            "operation_id": operation_id,
            "before": before,
            "after": after,
            "recovery": "manual operator review required",
        }
    ).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=marker.parent) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, marker)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return str(marker)
