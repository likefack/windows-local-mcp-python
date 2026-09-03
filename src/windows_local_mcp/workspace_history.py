from __future__ import annotations

import difflib
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from functools import wraps
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .config import Settings
from .paths import Workspace, read_verified_bytes, read_verified_path_bytes
from .resources import NamedControlPlaneLock, directory_size, enforce_data_quota
from .util import canonical_json, sha256_bytes, utc_now_iso

_MANIFEST_VERSION = 3
_DIRECTORY_STATE = "directory"
_JOURNAL_TERMINAL = {"complete", "failed_recovered", "failed_preflight"}


@dataclass(frozen=True)
class WorkspaceState:
    manifest_path: str
    files_dir: str
    file_count: int
    total_bytes: int
    directory_count: int = 0


class WorkspaceMutationError(RuntimeError):
    def __init__(self, message: str, *, recovery_state: str, journal_path: str) -> None:
        super().__init__(message)
        self.recovery_state = recovery_state
        self.journal_path = journal_path


def _cas_serialized(function: Any) -> Any:
    @wraps(function)
    def locked(settings: Settings, *args: Any, **kwargs: Any) -> Any:
        with NamedControlPlaneLock(settings, "workspace-cas"):
            return function(settings, *args, **kwargs)

    return locked


@_cas_serialized
def capture_workspace_state(
    settings: Settings,
    operation_id: str,
    stage: str,
    *,
    paths: set[str] | None = None,
) -> WorkspaceState:
    """Capture a full manifest while storing file content once by SHA-256.

    A manifest remains a complete point-in-time view. The content-addressed blob store makes
    repeated checkpoints cheap without weakening untracked-file or deletion recovery.
    """
    if paths is not None:
        return _capture_scoped_workspace_state(settings, operation_id, stage, paths)
    base = _operation_root(settings, operation_id) / stage
    base.mkdir(parents=True, exist_ok=False)
    try:
        entries: list[dict[str, Any]] = []
        directory_entries: list[dict[str, str]] = []
        total = 0
        initial_data_bytes = directory_size(
            settings.data_dir, stop_after=settings.max_data_dir_bytes
        )
        workspace = Workspace(settings)
        denied = {name.casefold() for name in settings.write_denied_directories}
        blocked = {name.casefold() for name in settings.blocked_file_names}
        excluded: list[dict[str, str]] = []

        def fail_walk(error: OSError) -> None:
            raise RuntimeError(f"workspace checkpoint traversal failed: {error}") from error

        for root, dirs, files in os.walk(
            settings.workspace_root,
            topdown=True,
            followlinks=False,
            onerror=fail_walk,
        ):
            root_path = Path(root)
            retained_dirs: list[str] = []
            for name in sorted(dirs, key=str.casefold):
                candidate = root_path / name
                if name.casefold() in denied:
                    excluded.append(
                        {
                            "path": candidate.relative_to(settings.workspace_root).as_posix(),
                            "reason": "policy_write_denied_directory",
                        }
                    )
                elif workspace._is_reparse(candidate):
                    excluded.append(
                        {
                            "path": candidate.relative_to(settings.workspace_root).as_posix(),
                            "reason": "policy_reparse_directory",
                        }
                    )
                else:
                    retained_dirs.append(name)
            dirs[:] = retained_dirs
            for name in retained_dirs:
                relative_directory = (root_path / name).relative_to(
                    settings.workspace_root
                ).as_posix()
                directory_entries.append({"path": relative_directory})
                if len(entries) + len(directory_entries) > settings.approval_manifest_max_files:
                    raise ValueError("workspace history exceeds approval_manifest_max_files")
            for name in sorted(files, key=str.casefold):
                source = root_path / name
                relative = source.relative_to(settings.workspace_root)
                folded = name.casefold()
                if folded in blocked or (
                    folded.startswith(".env.") and folded != ".env.example"
                ):
                    excluded.append(
                        {"path": relative.as_posix(), "reason": "policy_blocked_file"}
                    )
                    continue
                try:
                    verified = workspace.resolve_existing(
                        str(relative), access="write", readable=True
                    )
                    stat = verified.stat()
                    if not verified.is_file():
                        excluded.append(
                            {"path": relative.as_posix(), "reason": "policy_non_regular_file"}
                        )
                        continue
                    if stat.st_nlink > 1:
                        excluded.append(
                            {"path": relative.as_posix(), "reason": "policy_hardlink"}
                        )
                        continue
                    data = read_verified_bytes(
                        verified, settings.approval_manifest_max_bytes
                    )
                except (FileNotFoundError, PermissionError, OSError, ValueError) as error:
                    raise RuntimeError(
                        f"workspace checkpoint could not capture {relative.as_posix()}: "
                        f"{type(error).__name__}: {error}"
                    ) from error
                total += len(data)
                if len(entries) + len(directory_entries) + 1 > settings.approval_manifest_max_files:
                    raise ValueError("workspace history exceeds approval_manifest_max_files")
                if total > settings.approval_manifest_max_bytes:
                    raise ValueError("workspace history exceeds approval_manifest_max_bytes")
                digest = sha256_bytes(data)
                _store_blob(settings, digest, data, initial_data_bytes)
                entries.append(
                    {
                        "path": relative.as_posix(),
                        "size": len(data),
                        "sha256": digest,
                        "blob": digest,
                    }
                )
        payload = {
            "version": _MANIFEST_VERSION,
            "operation_id": operation_id,
            "stage": stage,
            "files": entries,
            "directories": directory_entries,
            "excluded": excluded,
            "capture_complete": True,
            "scope": {"kind": "workspace"},
        }
        manifest_path = base / "manifest.json"
        _write_json_atomic(manifest_path, payload)
        enforce_data_quota(settings)
        return WorkspaceState(
            str(manifest_path),
            str(_blob_root(settings)),
            len(entries),
            total,
            len(directory_entries),
        )
    except Exception:
        shutil.rmtree(base, ignore_errors=True)
        raise


def _capture_scoped_workspace_state(
    settings: Settings,
    operation_id: str,
    stage: str,
    paths: set[str],
) -> WorkspaceState:
    if not paths:
        raise ValueError("scoped workspace checkpoint requires at least one path")
    normalized_paths = sorted(
        {PureWindowsPath(_validated_relative_path(path)).as_posix() for path in paths}
    )
    base = _operation_root(settings, operation_id) / stage
    base.mkdir(parents=True, exist_ok=False)
    try:
        entries: list[dict[str, Any]] = []
        directory_entries: list[dict[str, str]] = []
        represented_paths: set[str] = set()
        total = 0
        initial_data_bytes = directory_size(
            settings.data_dir, stop_after=settings.max_data_dir_bytes
        )
        workspace = Workspace(settings)
        for relative in normalized_paths:
            try:
                verified = workspace.resolve_existing(
                    relative, allow_directory=True, access="write", readable=True
                )
            except FileNotFoundError:
                workspace.resolve_planned_write(relative)
                continue
            actual_relative = _actual_workspace_relative(workspace, verified)
            if actual_relative in represented_paths:
                continue
            represented_paths.add(actual_relative)
            if verified.is_dir():
                directory_entries.append({"path": actual_relative})
                if len(entries) + len(directory_entries) > settings.approval_manifest_max_files:
                    raise ValueError("workspace history exceeds approval_manifest_max_files")
                continue
            parent_identity = workspace.identity(verified.parent)
            target_identity = workspace.identity(verified)
            if parent_identity is None or target_identity is None:
                raise RuntimeError(f"scoped checkpoint target disappeared: {relative}")
            details = verified.stat()
            if not verified.is_file() or details.st_nlink > 1:
                raise PermissionError(
                    f"scoped checkpoint target must be a unique regular file: {relative}"
                )
            data = read_verified_bytes(verified, settings.approval_manifest_max_bytes)
            workspace.revalidate_for_replace(
                verified,
                parent_identity=parent_identity,
                target_identity=target_identity,
            )
            if target_identity.size != len(data):
                raise RuntimeError(f"scoped checkpoint target changed while read: {relative}")
            total += len(data)
            if len(entries) + len(directory_entries) + 1 > settings.approval_manifest_max_files:
                raise ValueError("workspace history exceeds approval_manifest_max_files")
            if total > settings.approval_manifest_max_bytes:
                raise ValueError("workspace history exceeds approval_manifest_max_bytes")
            digest = sha256_bytes(data)
            _store_blob(settings, digest, data, initial_data_bytes)
            entries.append(
                {
                    "path": actual_relative,
                    "size": len(data),
                    "sha256": digest,
                    "blob": digest,
                }
            )
        payload = {
            "version": _MANIFEST_VERSION,
            "operation_id": operation_id,
            "stage": stage,
            "files": entries,
            "directories": directory_entries,
            "excluded": [],
            "capture_complete": True,
            "scope": {"kind": "paths", "paths": normalized_paths},
        }
        manifest_path = base / "manifest.json"
        _write_json_atomic(manifest_path, payload)
        enforce_data_quota(settings)
        return WorkspaceState(
            str(manifest_path),
            str(_blob_root(settings)),
            len(entries),
            total,
            len(directory_entries),
        )
    except Exception:
        shutil.rmtree(base, ignore_errors=True)
        raise


def _validated_relative_path(value: str) -> str:
    Workspace.validate_windows_syntax(value)
    pure = PureWindowsPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"workspace checkpoint path must be relative: {value}")
    normalized = pure.as_posix()
    if not normalized or normalized == ".":
        raise ValueError("workspace checkpoint path must identify a file")
    return normalized


def _actual_workspace_relative(workspace: Workspace, verified: Path) -> str:
    """Return the namespace spelling of an identity-held final component on Windows."""

    if os.name != "nt":
        return workspace.relative(verified)
    expected = workspace.identity(verified)
    with os.scandir(verified.parent) as entries:
        matches = [
            entry.name
            for entry in entries
            if entry.name.casefold() == verified.name.casefold()
        ]
    if len(matches) != 1:
        raise RuntimeError("workspace path casing is ambiguous during checkpoint capture")
    candidate = verified.parent / matches[0]
    if workspace.identity(candidate) != expected:
        raise RuntimeError("workspace path identity changed during casing capture")
    return workspace.relative(candidate)


def compare_workspace_states(
    settings: Settings, before_path: str, after_path: str, operation_id: str
) -> dict[str, Any]:
    before = _load_manifest(settings, before_path)
    after = _load_manifest(settings, after_path)
    scope = _require_matching_scope(before, after)
    before_map = _entry_map(before)
    after_map = _entry_map(after)
    changed_files = sorted(
        path
        for path in before_map.keys() | after_map.keys()
        if _entry_digest(before_map.get(path)) != _entry_digest(after_map.get(path))
    )
    before_directories = _directory_set(before)
    after_directories = _directory_set(after)
    changed_directories = sorted(before_directories ^ after_directories)
    changed = sorted(set(changed_files) | set(changed_directories))
    added_lines = removed_lines = 0
    chunks: list[str] = []
    limit = settings.max_diff_bytes
    diff_bytes = 0
    truncated = False
    for relative in changed_files:
        old = _entry_bytes(settings, Path(before_path), before_map.get(relative))
        new = _entry_bytes(settings, Path(after_path), after_map.get(relative))
        try:
            old_text, new_text = old.decode("utf-8"), new.decode("utf-8")
        except UnicodeDecodeError:
            marker = f"Binary files differ: {relative}\n"
            if diff_bytes + len(marker.encode("utf-8")) <= limit:
                chunks.append(marker)
                diff_bytes += len(marker.encode("utf-8"))
            continue
        for line in difflib.unified_diff(
            old_text.splitlines(True),
            new_text.splitlines(True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
        ):
            encoded_size = len(line.encode("utf-8"))
            if diff_bytes + encoded_size > limit:
                truncated = True
                break
            chunks.append(line)
            diff_bytes += encoded_size
            added_lines += line.startswith("+") and not line.startswith("+++")
            removed_lines += line.startswith("-") and not line.startswith("---")
        if truncated:
            break
    if truncated:
        marker = "\n... diff truncated by max_diff_bytes ...\n"
        marker_size = len(marker.encode("utf-8"))
        while chunks and diff_bytes + marker_size > limit:
            diff_bytes -= len(chunks.pop().encode("utf-8"))
        if marker_size <= limit:
            chunks.append(marker)
    diff_path = settings.data_dir / "diffs" / f"{operation_id}.diff"
    diff_path.write_text("".join(chunks), encoding="utf-8")
    return {
        "changed_files": changed_files,
        "changed_file_count": len(changed_files),
        "changed_directories": changed_directories,
        "changed_directory_count": len(changed_directories),
        "changed_paths": changed,
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "diff_path": str(diff_path),
        "checkpoint_scope": scope,
    }


def verify_checkpoint_integrity(settings: Settings, manifest_path: str) -> dict[str, str]:
    """Re-hash every content object that may be used for a restore."""
    manifest = _load_manifest(settings, manifest_path)
    verified: dict[str, str] = {}
    for relative, entry in _entry_map(manifest).items():
        data = _entry_bytes(settings, Path(manifest_path), entry)
        digest = sha256_bytes(data)
        expected = str(entry["sha256"])
        if digest != expected or len(data) != int(entry["size"]):
            raise RuntimeError(f"checkpoint integrity verification failed: {relative}")
        verified[relative] = digest
    return verified


def checkpoint_state(settings: Settings, manifest_path: str) -> dict[str, str]:
    """Return the verified file/directory state used by CAS and recovery."""

    manifest = _load_manifest(settings, manifest_path)
    files = verify_checkpoint_integrity(settings, manifest_path)
    return {
        **{path: f"file:{digest}" for path, digest in files.items()},
        **{path: _DIRECTORY_STATE for path in _directory_set(manifest)},
    }


def checkpoint_manifest_digest(settings: Settings, manifest_path: str) -> str:
    """Bind an approval to the exact persisted manifest bytes after schema validation."""
    manifest = _load_manifest(settings, manifest_path)
    resolved = Path(str(manifest["_manifest_path"]))
    return sha256_bytes(resolved.read_bytes())


def checkpoint_scope(settings: Settings, manifest_path: str) -> dict[str, Any]:
    """Return the validated rollback boundary recorded by a checkpoint."""
    return _manifest_scope(_load_manifest(settings, manifest_path))


def restore_workspace_state(
    settings: Settings,
    expected_path: str,
    target_path: str,
    *,
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Failure-atomic best-effort restore with durable interruption detection.

    There is no claim of an OS-wide filesystem transaction. All validation and content staging
    happen before the first workspace write. If applying fails, the captured starting state is
    restored automatically; an unrecovered state remains durably marked recovery_required.
    """
    transaction_id = operation_id or f"restore-{uuid.uuid4()}"
    transaction = _transaction_root(settings, transaction_id)
    transaction.mkdir(parents=True, exist_ok=False)
    journal_path = transaction / "journal.json"
    journal: dict[str, Any] = {
        "version": 1,
        "operation_id": transaction_id,
        "kind": "workspace_restore",
        "state": "preflight",
        "created_at": utc_now_iso(),
        "expected_manifest": str(Path(expected_path).resolve(strict=True)),
        "target_manifest": str(Path(target_path).resolve(strict=True)),
        "applied_paths": [],
    }
    _write_json_atomic(journal_path, journal)
    current: WorkspaceState | None = None
    try:
        expected_manifest = _load_manifest(settings, expected_path)
        target_manifest = _load_manifest(settings, target_path)
        scope = _require_matching_scope(expected_manifest, target_manifest)
        scope_paths = _scope_paths(scope)
        expected_map = checkpoint_state(settings, expected_path)
        target_map = checkpoint_state(settings, target_path)
        current = capture_workspace_state(
            settings,
            transaction_id,
            "transaction-before",
            paths=scope_paths,
        )
        current_map = checkpoint_state(settings, current.manifest_path)
        if expected_map != current_map:
            conflicts = sorted(
                path
                for path in expected_map.keys() | current_map.keys()
                if expected_map.get(path) != current_map.get(path)
            )
            journal.update(state="failed_preflight", conflicts=conflicts[:200])
            _write_json_atomic(journal_path, journal)
            raise RuntimeError(
                "workspace changed after approval preview; rollback conflicts: "
                + ", ".join(conflicts[:20])
            )
        current_manifest = _load_manifest(settings, current.manifest_path)
        changed = _changed_paths(current_manifest, target_manifest)
        _stage_manifest_files(settings, target_path, changed, transaction / "staged-target")
        _verify_staged_files(target_manifest, transaction / "staged-target", changed)
        journal.update(
            state="staged",
            before_manifest=current.manifest_path,
            changed_paths=changed,
        )
        _write_json_atomic(journal_path, journal)
    except Exception:
        if journal.get("state") not in _JOURNAL_TERMINAL:
            journal["state"] = "failed_preflight"
            _write_json_atomic(journal_path, journal)
        raise

    try:
        journal["state"] = "applying"
        _write_json_atomic(journal_path, journal)
        _apply_manifest(
            settings,
            target_path,
            staged_root=transaction / "staged-target",
            only_paths=set(journal["changed_paths"]),
            journal=journal,
            journal_path=journal_path,
            expected_hashes=expected_map,
        )
        final_map = _scan_current_state(settings, scope_paths)
        intended_map = _state_map(target_manifest)
        if final_map != intended_map:
            raise RuntimeError("post-restore workspace verification did not match target")
    except BaseException as apply_error:  # noqa: BLE001 - journal abrupt Python interruption too
        journal.update(
            state="recovering",
            apply_error=f"{type(apply_error).__name__}: {apply_error}"[:2000],
        )
        _write_json_atomic(journal_path, journal)
        try:
            if current is None:
                raise RuntimeError("transaction start state is unavailable")
            verify_checkpoint_integrity(settings, current.manifest_path)
            target_hashes = checkpoint_state(settings, target_path)
            current_hashes = checkpoint_state(settings, current.manifest_path)
            live_hashes = _scan_current_state(settings, scope_paths)
            changed_paths = {str(item) for item in journal.get("changed_paths") or []}
            conflicts = sorted(
                relative
                for relative in changed_paths
                if live_hashes.get(relative)
                not in {current_hashes.get(relative), target_hashes.get(relative)}
            )
            if conflicts:
                raise RuntimeError(
                    "automatic recovery refused concurrent changes: "
                    + ", ".join(conflicts[:20])
                )
            _apply_manifest(
                settings,
                current.manifest_path,
                only_paths=changed_paths,
            )
            recovered_hashes = _scan_current_state(settings, scope_paths)
            recovery_mismatches = sorted(
                relative
                for relative in changed_paths
                if recovered_hashes.get(relative) != current_hashes.get(relative)
            )
            if recovery_mismatches:
                raise RuntimeError(
                    "automatic recovery verification failed: "
                    + ", ".join(recovery_mismatches[:20])
                )
            _remove_created_directories(settings, journal.get("created_directories", []))
            journal["state"] = "failed_recovered"
            journal["recovered_at"] = utc_now_iso()
            _write_json_atomic(journal_path, journal)
            raise WorkspaceMutationError(
                f"restore failed and the starting workspace was recovered: {apply_error}",
                recovery_state="failed_recovered",
                journal_path=str(journal_path),
            ) from apply_error
        except WorkspaceMutationError:
            raise
        except BaseException as recovery_error:
            journal.update(
                state="recovery_required",
                recovery_error=f"{type(recovery_error).__name__}: {recovery_error}"[:2000],
            )
            _write_json_atomic(journal_path, journal)
            raise WorkspaceMutationError(
                f"restore failed and automatic recovery also failed: {recovery_error}",
                recovery_state="recovery_required",
                journal_path=str(journal_path),
            ) from recovery_error

    journal["state"] = "applied_verified"
    journal["applied_at"] = utc_now_iso()
    _write_json_atomic(journal_path, journal)
    target_manifest = _load_manifest(settings, target_path)
    current_manifest = _load_manifest(settings, expected_path)
    scope = _require_matching_scope(current_manifest, target_manifest)
    target_map = _entry_map(target_manifest)
    current_map = _entry_map(current_manifest)
    target_directories = _directory_set(target_manifest)
    current_directories = _directory_set(current_manifest)
    return {
        "restored_files": sorted(target_map),
        "removed_files": sorted(current_map.keys() - target_map.keys()),
        "restored_directories": sorted(target_directories),
        "removed_directories": sorted(current_directories - target_directories),
        "transaction_journal": str(journal_path),
        "failure_atomicity": "best_effort_with_automatic_recovery",
        "rollback_scope": scope,
    }


def finalize_workspace_transaction(settings: Settings, operation_id: str) -> None:
    journal_path = _transaction_root(settings, operation_id) / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    if journal.get("state") != "applied_verified":
        raise RuntimeError("workspace transaction is not ready for audit finalization")
    journal["state"] = "complete"
    journal["audit_reconciled"] = True
    journal["completed_at"] = utc_now_iso()
    _write_json_atomic(journal_path, journal)


def rollback_applied_workspace_transaction(
    settings: Settings, operation_id: str
) -> dict[str, Any]:
    """Undo an applied transaction without overwriting unattributed concurrent changes."""
    journal_path = _transaction_root(settings, operation_id) / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    if journal.get("state") != "applied_verified":
        raise RuntimeError("workspace transaction is not in an applied state")
    before_path = str(journal.get("before_manifest") or "")
    target_path = str(journal.get("target_manifest") or "")
    if not before_path or not target_path:
        raise RuntimeError("workspace transaction has incomplete recovery bindings")
    before = checkpoint_state(settings, before_path)
    target = checkpoint_state(settings, target_path)
    before_manifest = _load_manifest(settings, before_path)
    target_manifest = _load_manifest(settings, target_path)
    scope = _require_matching_scope(before_manifest, target_manifest)
    scope_paths = _scope_paths(scope)
    current = _scan_current_state(settings, scope_paths)
    changed = {str(item) for item in journal.get("changed_paths") or []}
    conflicts = sorted(
        relative
        for relative in changed
        if current.get(relative) not in {before.get(relative), target.get(relative)}
    )
    if conflicts:
        journal.update(
            state="recovery_required",
            recovery_error=(
                "automatic rollback refused concurrent changes: "
                + ", ".join(conflicts[:20])
            ),
            recovery_failed_at=utc_now_iso(),
        )
        _write_json_atomic(journal_path, journal)
        raise WorkspaceMutationError(
            "automatic rollback refused to overwrite concurrent changes: "
            + ", ".join(conflicts[:20]),
            recovery_state="recovery_required",
            journal_path=str(journal_path),
        )
    _apply_manifest(settings, before_path, only_paths=changed)
    recovered = _scan_current_state(settings, scope_paths)
    mismatches = sorted(
        relative for relative in changed if recovered.get(relative) != before.get(relative)
    )
    if mismatches:
        journal.update(
            state="recovery_required",
            recovery_error="automatic rollback verification failed: "
            + ", ".join(mismatches[:20]),
            recovery_failed_at=utc_now_iso(),
        )
        _write_json_atomic(journal_path, journal)
        raise WorkspaceMutationError(
            "automatic rollback verification failed: " + ", ".join(mismatches[:20]),
            recovery_state="recovery_required",
            journal_path=str(journal_path),
        )
    journal.update(state="failed_recovered", recovered_at=utc_now_iso())
    _write_json_atomic(journal_path, journal)
    return {
        "rollback_state": "failed_recovered",
        "recovered_paths": sorted(changed),
        "transaction_journal": str(journal_path),
        "rollback_scope": scope,
    }


def mark_workspace_transaction_audit_reconciled(
    settings: Settings, operation_id: str
) -> None:
    journal_path = _transaction_root(settings, operation_id) / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["audit_reconciled"] = True
    journal["audit_reconciled_at"] = utc_now_iso()
    _write_json_atomic(journal_path, journal)


@_cas_serialized
def prepare_selective_undo(
    settings: Settings,
    operation_id: str,
    before_path: str,
    after_path: str,
) -> dict[str, Any]:
    """Build and persist an approval-bound three-state selective undo plan."""
    verify_checkpoint_integrity(settings, before_path)
    verify_checkpoint_integrity(settings, after_path)
    before = _load_manifest(settings, before_path)
    after = _load_manifest(settings, after_path)
    scope = _require_matching_scope(before, after)
    current = capture_workspace_state(
        settings,
        operation_id,
        "undo-preview-current",
        paths=_scope_paths(scope),
    )
    verify_checkpoint_integrity(settings, current.manifest_path)
    current_manifest = _load_manifest(settings, current.manifest_path)
    desired, desired_directories, conflicts, automatic_merges = _selective_target(
        settings, Path(before_path), before, Path(after_path), after, current_manifest
    )
    target_path = _write_generated_manifest(
        settings,
        operation_id,
        "undo-preview-target",
        desired,
        scope=scope,
        directories=desired_directories,
    )
    preview = _restore_summary(current_manifest, _load_manifest(settings, target_path))
    preview.update(
        {
            "expected_current_checkpoint": current.manifest_path,
            "target_checkpoint": target_path,
            "conflicts": conflicts,
            "conflict_count": len(conflicts),
            "automatic_merge_files": automatic_merges,
            "automatic_merge": bool(automatic_merges),
            "fully_reversible": not conflicts,
            "undo_can_be_undone": True,
        }
    )
    return preview


def describe_workspace_restore(
    settings: Settings, expected_path: str, target_path: str
) -> dict[str, Any]:
    expected = _load_manifest(settings, expected_path)
    target = _load_manifest(settings, target_path)
    result = _restore_summary(expected, target)
    result.update(
        {
            "conflict_check": "current workspace must match the approval preview",
            "automatic_merge": False,
            "conflicts": [],
            "fully_reversible": True,
            "undo_can_be_undone": True,
        }
    )
    return result


def describe_current_workspace_restore(
    settings: Settings, target_path: str
) -> dict[str, Any]:
    """Describe a restore against the live workspace within the target checkpoint scope."""
    target = _load_manifest(settings, target_path)
    scope = _manifest_scope(target)
    current_state = _scan_current_state(settings, _scope_paths(scope))
    current = {
        "scope": scope,
        "files": [
            {"path": relative, "sha256": state.removeprefix("file:")}
            for relative, state in sorted(current_state.items())
            if state.startswith("file:")
        ],
        "directories": [
            {"path": relative}
            for relative, state in sorted(current_state.items())
            if state == _DIRECTORY_STATE
        ],
    }
    result = _restore_summary(current, target)
    result.update(
        {
            "available": True,
            "conflict_check": "current workspace must match the approval preview",
            "automatic_merge": False,
            "conflicts": [],
            "fully_reversible": True,
            "undo_can_be_undone": True,
        }
    )
    return result


@_cas_serialized
def build_workspace_target_from_bytes(
    settings: Settings,
    operation_id: str,
    expected_manifest_path: str,
    changes: dict[str, bytes],
    deletions: set[str] | None = None,
) -> str:
    """Create a content-addressed target manifest for broker-validated file updates."""
    expected = _load_manifest(settings, expected_manifest_path)
    scope = _manifest_scope(expected)
    scope_paths = _scope_paths(scope)
    entries = dict(_entry_map(expected))
    directories = set(_directory_set(expected))
    workspace = Workspace(settings)
    initial_size = directory_size(settings.data_dir)
    for relative in deletions or set():
        Workspace.validate_windows_syntax(relative)
        workspace.resolve_existing(relative, allow_directory=False, access="write")
        normalized = PureWindowsPath(relative).as_posix()
        if scope_paths is not None and normalized not in scope_paths:
            raise ValueError("workspace deletion falls outside checkpoint scope")
        entries.pop(normalized, None)
    for relative, data in changes.items():
        Workspace.validate_windows_syntax(relative)
        destination = workspace.resolve_planned_write(relative)
        if destination.exists():
            workspace.resolve_existing(relative, allow_directory=False, access="write")
        digest = sha256_bytes(data)
        _store_blob(settings, digest, data, initial_size)
        normalized = PureWindowsPath(relative).as_posix()
        if scope_paths is not None and normalized not in scope_paths:
            raise ValueError("workspace change falls outside checkpoint scope")
        entries[normalized] = {
            "path": normalized,
            "size": len(data),
            "sha256": digest,
            "blob": digest,
        }
        directories.discard(normalized)
    return _write_generated_manifest(
        settings,
        operation_id,
        "staged-workspace-write-target",
        entries,
        scope=scope,
        directories=directories,
    )


@_cas_serialized
def build_workspace_target(
    settings: Settings,
    operation_id: str,
    expected_manifest_path: str,
    *,
    changes: dict[str, bytes] | None = None,
    deletions: set[str] | None = None,
    directory_additions: set[str] | None = None,
    directory_deletions: set[str] | None = None,
) -> str:
    """Build a bounded file/directory target manifest for a fixed Broker mutation."""

    expected = _load_manifest(settings, expected_manifest_path)
    scope = _manifest_scope(expected)
    scope_paths = _scope_paths(scope)
    entries = dict(_entry_map(expected))
    directories = set(_directory_set(expected))
    initial_size = directory_size(settings.data_dir)

    def normalize(relative: str) -> str:
        normalized = PureWindowsPath(_validated_relative_path(relative)).as_posix()
        if scope_paths is not None and normalized not in scope_paths:
            raise ValueError("workspace target change falls outside checkpoint scope")
        return normalized

    for relative in deletions or set():
        normalized = normalize(relative)
        entries.pop(normalized, None)
    for relative in directory_deletions or set():
        normalized = normalize(relative)
        directories.discard(normalized)
    for relative, data in (changes or {}).items():
        if not isinstance(data, bytes):
            raise TypeError("workspace target file content must be bytes")
        normalized = normalize(relative)
        digest = sha256_bytes(data)
        _store_blob(settings, digest, data, initial_size)
        entries[normalized] = {
            "path": normalized,
            "size": len(data),
            "sha256": digest,
            "blob": digest,
        }
        directories.discard(normalized)
    for relative in directory_additions or set():
        normalized = normalize(relative)
        if normalized in entries:
            raise ValueError("workspace target path cannot be both file and directory")
        directories.add(normalized)

    return _write_generated_manifest(
        settings,
        operation_id,
        "staged-workspace-target",
        entries,
        scope=scope,
        directories=directories,
    )


def incomplete_workspace_transactions(settings: Settings) -> list[dict[str, Any]]:
    root = settings.data_dir / "workspace-history" / "transactions"
    result: list[dict[str, Any]] = []
    if not root.exists():
        return result
    for journal_path in root.glob("*/journal.json"):
        try:
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            result.append(
                {
                    "operation_id": journal_path.parent.name,
                    "state": "recovery_required",
                    "journal_path": str(journal_path),
                    "journal_error": f"{type(error).__name__}: {error}"[:1000],
                }
            )
            continue
        if (
            journal.get("state") not in _JOURNAL_TERMINAL
            or journal.get("audit_reconciled") is not True
        ):
            result.append({**journal, "journal_path": str(journal_path)})
    return result


def recover_incomplete_workspace_transaction(
    settings: Settings, journal: dict[str, Any]
) -> dict[str, Any]:
    """Recover an interrupted apply only when the live state is provably transaction-owned."""
    journal_path = Path(str(journal["journal_path"]))
    journal_path.resolve(strict=True).relative_to(
        (settings.data_dir / "workspace-history" / "transactions").resolve(strict=True)
    )
    state = str(journal.get("state") or "")
    if state == "preflight":
        if journal.get("applied_paths"):
            raise RuntimeError("preflight journal unexpectedly records applied paths")
        journal.update(state="failed_preflight", reconciled_at=utc_now_iso())
        _write_json_atomic(journal_path, journal)
        return journal
    if state == "staged":
        if journal.get("applied_paths"):
            raise RuntimeError("staged journal unexpectedly records applied paths")
        before_path = str(journal.get("before_manifest") or "")
        if not before_path:
            raise RuntimeError("staged journal has no before checkpoint")
        verify_checkpoint_integrity(settings, before_path)
        before_scope = _manifest_scope(_load_manifest(settings, before_path))
        _scan_current_state(settings, _scope_paths(before_scope))
        journal.update(state="failed_preflight", reconciled_at=utc_now_iso())
        _write_json_atomic(journal_path, journal)
        return journal
    if state in {"applied_verified", "complete"}:
        target_path = str(journal.get("target_manifest") or "")
        if not target_path:
            raise RuntimeError("applied journal has no target checkpoint")
        target = checkpoint_state(settings, target_path)
        target_scope = _manifest_scope(_load_manifest(settings, target_path))
        if _scan_current_state(settings, _scope_paths(target_scope)) != target:
            raise RuntimeError("applied workspace no longer matches its verified target")
        return journal
    if state not in {"applying", "recovering"}:
        return journal
    before_path = str(journal.get("before_manifest") or "")
    target_path = str(journal.get("target_manifest") or "")
    if journal.get("kind") == "single_file_write":
        if not before_path:
            raise RuntimeError("interrupted write transaction has no recovery manifest")
        before = verify_checkpoint_integrity(settings, before_path)
        before_scope = _manifest_scope(_load_manifest(settings, before_path))
        scope_paths = _scope_paths(before_scope)
        current = _scan_current_hashes(settings, scope_paths)
        changed = set(journal.get("changed_paths") or [])
        if len(changed) != 1:
            raise RuntimeError("interrupted write transaction has an invalid target set")
        relative = next(iter(changed))
        before_sha = journal.get("expected_before_sha256")
        after_sha = journal.get("intended_after_sha256")
        all_paths = before.keys() | current.keys()
        unexpected = [
            path
            for path in sorted(all_paths)
            if (
                current.get(path) not in {before_sha, after_sha}
                if path == relative
                else current.get(path) != before.get(path)
            )
        ]
        if unexpected:
            raise RuntimeError(
                "workspace contains changes that cannot be attributed to the interrupted write: "
                + ", ".join(unexpected[:20])
            )
        if current != before:
            _apply_manifest(settings, before_path, only_paths=changed)
            if _scan_current_hashes(settings, scope_paths) != before:
                raise RuntimeError("automatic interrupted-write recovery verification failed")
        journal.update(state="failed_recovered", recovered_at=utc_now_iso())
        _write_json_atomic(journal_path, journal)
        return journal
    if not before_path or not target_path:
        raise RuntimeError("interrupted workspace transaction has no recovery manifests")
    before = checkpoint_state(settings, before_path)
    target = checkpoint_state(settings, target_path)
    before_manifest = _load_manifest(settings, before_path)
    target_manifest = _load_manifest(settings, target_path)
    scope = _require_matching_scope(before_manifest, target_manifest)
    scope_paths = _scope_paths(scope)
    current = _scan_current_state(settings, scope_paths)
    changed = set(journal.get("changed_paths") or [])
    all_paths = before.keys() | target.keys() | current.keys()
    unexpected = [
        path
        for path in sorted(all_paths)
        if (
            current.get(path) not in {before.get(path), target.get(path)}
            if path in changed
            else current.get(path) != before.get(path)
        )
    ]
    if unexpected:
        raise RuntimeError(
            "workspace contains changes that cannot be attributed to the interrupted restore: "
            + ", ".join(unexpected[:20])
        )
    verify_checkpoint_integrity(settings, before_path)
    _apply_manifest(settings, before_path, only_paths=changed)
    if _scan_current_state(settings, scope_paths) != before:
        raise RuntimeError("automatic interrupted-transaction recovery verification failed")
    journal.update(state="failed_recovered", recovered_at=utc_now_iso())
    _write_json_atomic(journal_path, journal)
    return journal


def mark_workspace_transaction_recovery_required(
    journal: dict[str, Any], error: BaseException
) -> None:
    journal_path = Path(str(journal["journal_path"]))
    journal.update(
        state="recovery_required",
        recovery_error=f"{type(error).__name__}: {error}"[:2000],
        recovery_failed_at=utc_now_iso(),
    )
    _write_json_atomic(journal_path, journal)


def workspace_recovery_required(settings: Settings) -> bool:
    return bool(incomplete_workspace_transactions(settings))


def record_workspace_recovery_required(
    settings: Settings,
    operation_id: str,
    before_manifest: str,
    error: BaseException,
) -> str:
    """Persist a fail-closed marker for a non-transactional mutation recovery failure."""
    transaction = _transaction_root(settings, operation_id)
    transaction.mkdir(parents=True, exist_ok=False)
    journal_path = transaction / "journal.json"
    _write_json_atomic(
        journal_path,
        {
            "version": 1,
            "operation_id": operation_id,
            "kind": "single_file_write_recovery",
            "state": "recovery_required",
            "created_at": utc_now_iso(),
            "before_manifest": str(Path(before_manifest).resolve(strict=True)),
            "recovery_error": f"{type(error).__name__}: {error}"[:2000],
            "applied_paths": [],
        },
    )
    return str(journal_path)


def begin_single_file_write_transaction(
    settings: Settings,
    operation_id: str,
    before_manifest: str,
    relative_path: str,
    before_sha256: str | None,
    intended_after_sha256: str,
) -> str:
    """Durably record recovery data before the first single-file workspace mutation."""
    transaction = _transaction_root(settings, operation_id)
    transaction.mkdir(parents=True, exist_ok=False)
    journal_path = transaction / "journal.json"
    _write_json_atomic(
        journal_path,
        {
            "version": 1,
            "operation_id": operation_id,
            "kind": "single_file_write",
            "state": "applying",
            "created_at": utc_now_iso(),
            "before_manifest": str(Path(before_manifest).resolve(strict=True)),
            "expected_before_sha256": before_sha256,
            "intended_after_sha256": intended_after_sha256,
            "changed_paths": [relative_path],
            "applied_paths": [],
        },
    )
    return str(journal_path)


def begin_filesystem_primitive_transaction(
    settings: Settings,
    operation_id: str,
    *,
    before_manifest: str,
    target_manifest: str,
    changed_paths: set[str],
    operation_type: str,
) -> str:
    """Persist recovery bindings before one closed-world filesystem primitive commits."""

    if operation_type not in {"move_file", "copy_file", "delete_file", "make_directory"}:
        raise ValueError("unsupported filesystem primitive transaction type")
    if not changed_paths:
        raise ValueError("filesystem primitive transaction requires a bounded path set")
    before = _load_manifest(settings, before_manifest)
    target = _load_manifest(settings, target_manifest)
    scope = _require_matching_scope(before, target)
    allowed = _scope_paths(scope)
    normalized = sorted({_validated_relative_path(path) for path in changed_paths})
    if allowed is not None and not set(normalized).issubset(allowed):
        raise ValueError("filesystem primitive transaction exceeds checkpoint scope")
    transaction = _transaction_root(settings, operation_id)
    transaction.mkdir(parents=True, exist_ok=False)
    journal_path = transaction / "journal.json"
    _write_json_atomic(
        journal_path,
        {
            "version": 1,
            "operation_id": operation_id,
            "kind": "filesystem_primitive",
            "operation_type": operation_type,
            "state": "applying",
            "created_at": utc_now_iso(),
            "before_manifest": str(Path(before_manifest).resolve(strict=True)),
            "target_manifest": str(Path(target_manifest).resolve(strict=True)),
            "changed_paths": normalized,
            "applied_paths": [],
        },
    )
    return str(journal_path)


def update_filesystem_primitive_transaction(
    settings: Settings,
    operation_id: str,
    *,
    state: str,
    error: BaseException | None = None,
) -> str:
    if state not in {"applied_verified", "failed_recovered", "recovery_required"}:
        raise ValueError("invalid filesystem primitive transaction state")
    journal_path = _transaction_root(settings, operation_id) / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    if journal.get("kind") != "filesystem_primitive":
        raise RuntimeError("workspace transaction is not a filesystem primitive")
    journal["state"] = state
    journal[f"{state}_at"] = utc_now_iso()
    if error is not None:
        journal["recovery_error"] = f"{type(error).__name__}: {error}"[:2000]
    _write_json_atomic(journal_path, journal)
    return str(journal_path)


def rollback_filesystem_primitive_transaction(
    settings: Settings, operation_id: str
) -> dict[str, Any]:
    """Recover a primitive only when every changed path is still before/after-bound."""

    journal_path = _transaction_root(settings, operation_id) / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    if journal.get("kind") != "filesystem_primitive":
        raise RuntimeError("workspace transaction is not a filesystem primitive")
    state = str(journal.get("state") or "")
    if state == "applied_verified":
        return rollback_applied_workspace_transaction(settings, operation_id)
    if state not in {"applying", "recovering"}:
        raise RuntimeError("filesystem primitive transaction is not recoverable")
    recovered = recover_incomplete_workspace_transaction(
        settings, {**journal, "journal_path": str(journal_path)}
    )
    if recovered.get("state") != "failed_recovered":
        raise RuntimeError("filesystem primitive recovery did not reach a terminal state")
    return {
        "rollback_state": "failed_recovered",
        "recovered_paths": sorted(str(item) for item in journal.get("changed_paths") or []),
        "transaction_journal": str(journal_path),
        "rollback_scope": checkpoint_scope(
            settings, str(journal.get("before_manifest") or "")
        ),
    }


def update_single_file_write_transaction(
    settings: Settings,
    operation_id: str,
    *,
    state: str,
    target_manifest: str | None = None,
    error: BaseException | None = None,
) -> str:
    if state not in {"applied_verified", "failed_recovered", "recovery_required"}:
        raise ValueError("invalid single-file write transaction state")
    journal_path = _transaction_root(settings, operation_id) / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    if journal.get("kind") != "single_file_write":
        raise RuntimeError("workspace transaction is not a single-file write")
    journal["state"] = state
    journal[f"{state}_at"] = utc_now_iso()
    if target_manifest is not None:
        journal["target_manifest"] = str(Path(target_manifest).resolve(strict=True))
    if error is not None:
        journal["recovery_error"] = f"{type(error).__name__}: {error}"[:2000]
    _write_json_atomic(journal_path, journal)
    return str(journal_path)


def _selective_target(
    settings: Settings,
    before_path: Path,
    before: dict[str, Any],
    after_path: Path,
    after: dict[str, Any],
    current: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    set[str],
    list[dict[str, Any]],
    list[str],
]:
    before_map = _entry_map(before)
    after_map = _entry_map(after)
    current_map = dict(_entry_map(current))
    desired = dict(current_map)
    before_directories = _directory_set(before)
    after_directories = _directory_set(after)
    current_directories = _directory_set(current)
    desired_directories = set(current_directories)
    before_state = _state_map(before)
    after_state = _state_map(after)
    current_state = _state_map(current)
    conflicts: list[dict[str, Any]] = []
    automatic_merges: list[str] = []
    for relative in _changed_paths(before, after):
        old_entry = before_map.get(relative)
        operation_entry = after_map.get(relative)
        current_entry = current_map.get(relative)
        old_digest = before_state.get(relative)
        operation_digest = after_state.get(relative)
        current_digest = current_state.get(relative)
        if current_digest == old_digest:
            continue
        if current_digest == operation_digest:
            desired.pop(relative, None)
            desired_directories.discard(relative)
            if old_entry is None:
                if relative in before_directories:
                    desired_directories.add(relative)
            else:
                desired[relative] = old_entry
            continue
        if (
            relative in before_directories
            or relative in after_directories
            or relative in current_directories
            or old_entry is None
            or operation_entry is None
            or current_entry is None
        ):
            conflicts.append(
                _conflict(
                    relative,
                    "file lifecycle changed after the target operation",
                    old_entry,
                    operation_entry,
                    current_entry,
                )
            )
            continue
        try:
            old = _entry_bytes(settings, before_path, old_entry).decode("utf-8")
            operation = _entry_bytes(settings, after_path, operation_entry).decode("utf-8")
            current_bytes = _entry_bytes(
                settings, Path(str(current["_manifest_path"])), current_entry
            )
            current_text = current_bytes.decode("utf-8")
        except UnicodeDecodeError:
            conflicts.append(
                _conflict(
                    relative,
                    "binary content changed after the target operation",
                    old_entry,
                    operation_entry,
                    current_entry,
                )
            )
            continue
        merged = _reverse_text_change(old, operation, current_text)
        if merged is None:
            conflicts.append(
                _conflict(
                    relative,
                    "overlapping or ambiguous text changes",
                    old_entry,
                    operation_entry,
                    current_entry,
                    text_context={
                        "before": _bounded_text_context(old),
                        "operation_after": _bounded_text_context(operation),
                        "current": _bounded_text_context(current_text),
                    },
                )
            )
            continue
        merged_bytes = merged.encode("utf-8")
        digest = sha256_bytes(merged_bytes)
        _store_blob(settings, digest, merged_bytes, directory_size(settings.data_dir))
        desired[relative] = {
            "path": relative,
            "size": len(merged_bytes),
            "sha256": digest,
            "blob": digest,
        }
        automatic_merges.append(relative)
    return desired, desired_directories, conflicts, automatic_merges


def _reverse_text_change(before: str, after: str, current: str) -> str | None:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    current_lines = current.splitlines(keepends=True)
    groups = list(
        difflib.SequenceMatcher(None, before_lines, after_lines, autojunk=False).get_grouped_opcodes(3)
    )
    replacements: list[tuple[int, int, list[str]]] = []
    for group in groups:
        old_start = min(item[1] for item in group)
        old_end = max(item[2] for item in group)
        new_start = min(item[3] for item in group)
        new_end = max(item[4] for item in group)
        old_chunk = before_lines[old_start:old_end]
        new_chunk = after_lines[new_start:new_end]
        matches = [
            index
            for index in range(len(current_lines) - len(new_chunk) + 1)
            if current_lines[index : index + len(new_chunk)] == new_chunk
        ]
        if len(matches) != 1:
            return None
        start = matches[0]
        replacements.append((start, start + len(new_chunk), old_chunk))
    for start, end, replacement in sorted(replacements, reverse=True):
        current_lines[start:end] = replacement
    return "".join(current_lines)


def _restore_summary(expected: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    scope = _require_matching_scope(expected, target)
    expected_map = _entry_map(expected)
    target_map = _entry_map(target)
    changed = _changed_paths(expected, target)
    changed_files = sorted(
        path
        for path in changed
        if path in expected_map or path in target_map
    )
    created = sorted(target_map.keys() - expected_map.keys())
    deleted = sorted(expected_map.keys() - target_map.keys())
    restored = sorted(set(changed_files) - set(created) - set(deleted))
    expected_directories = _directory_set(expected)
    target_directories = _directory_set(target)
    created_directories = sorted(target_directories - expected_directories)
    deleted_directories = sorted(expected_directories - target_directories)
    return {
        "files_that_would_change": changed_files,
        "changed_file_count": len(changed_files),
        "created_files": created,
        "restored_files": restored,
        "deleted_files": deleted,
        "directories_that_would_change": sorted(
            set(created_directories) | set(deleted_directories)
        ),
        "changed_directory_count": len(
            set(created_directories) | set(deleted_directories)
        ),
        "created_directories": created_directories,
        "deleted_directories": deleted_directories,
        "creates_files": bool(created),
        "restores_files": bool(restored),
        "deletes_files": bool(deleted),
        "rollback_scope": scope,
    }


def _apply_manifest(
    settings: Settings,
    manifest_path: str,
    *,
    staged_root: Path | None = None,
    only_paths: set[str] | None = None,
    journal: dict[str, Any] | None = None,
    journal_path: Path | None = None,
    expected_hashes: dict[str, str] | None = None,
) -> None:
    manifest = _load_manifest(settings, manifest_path)
    target_map = _entry_map(manifest)
    target_directories = _directory_set(manifest)
    scope_paths = _scope_paths(_manifest_scope(manifest))
    current_state = _scan_current_state(settings, scope_paths)
    if expected_hashes is not None and current_state != expected_hashes:
        raise RuntimeError("workspace changed during restore staging")
    changed = (
        only_paths
        if only_paths is not None
        else set(current_state) | set(target_map) | target_directories
    )
    workspace = Workspace(settings)

    current_files = {
        path: state.removeprefix("file:")
        for path, state in current_state.items()
        if state.startswith("file:")
    }
    current_directories = {
        path for path, state in current_state.items() if state == _DIRECTORY_STATE
    }

    for relative in sorted((set(current_files) - set(target_map)) & changed, reverse=True):
        destination = workspace.resolve_for_write(relative)
        _verify_destination_digest(destination, current_files.get(relative), relative)
        parent_identity = workspace.identity(destination.parent)
        target_identity = workspace.identity(destination)
        expected = current_files.get(relative)
        if parent_identity is None or target_identity is None or expected is None:
            raise RuntimeError(f"restore delete target changed before commit: {relative}")
        workspace.commit_delete(
            destination,
            parent_identity=parent_identity,
            target_identity=target_identity,
            expected_sha256=expected,
        )
        _journal_applied(journal, journal_path, relative)

    # A directory-to-file lifecycle change is permitted only when the directory is empty.
    for relative in sorted(
        (current_directories & set(target_map) & changed),
        key=lambda item: item.count("/"),
        reverse=True,
    ):
        directory = workspace.resolve_directory(relative, access="write")
        parent_identity = workspace.identity(directory.parent)
        target_identity = workspace.identity(directory)
        if parent_identity is None or target_identity is None:
            raise RuntimeError(f"restore directory changed before commit: {relative}")
        workspace.commit_remove_directory(
            directory,
            parent_identity=parent_identity,
            target_identity=target_identity,
        )
        _journal_applied(journal, journal_path, relative)

    # Create directory targets before restoring files below them. Existing directories are
    # preserved; only paths represented by the target manifest are introduced.
    for relative in sorted(
        (target_directories - current_directories) & changed,
        key=lambda item: item.count("/"),
    ):
        workspace.ensure_directory_for_write(relative)
        _journal_applied(journal, journal_path, relative)

    for relative in sorted(set(target_map) & changed):
        parent_relative = str(PurePosixPath(relative).parent)
        parent_path = workspace.root / Path(parent_relative)
        missing_directories: list[str] = []
        current_parent = parent_path
        while current_parent != workspace.root and not current_parent.exists():
            missing_directories.append(
                current_parent.relative_to(workspace.root).as_posix()
            )
            current_parent = current_parent.parent
        if missing_directories and journal is not None and journal_path is not None:
            created = {str(item) for item in journal.get("created_directories", [])}
            created.update(missing_directories)
            journal["created_directories"] = sorted(created)
            _write_json_atomic(journal_path, journal)
        workspace.ensure_directory_for_write(parent_relative)
        destination = workspace.resolve_for_write(relative)
        entry = target_map[relative]
        source = (
            staged_root / Path(relative)
            if staged_root is not None and (staged_root / Path(relative)).exists()
            else _entry_source(settings, Path(manifest_path), entry)
        )
        data = source.read_bytes()
        if sha256_bytes(data) != entry["sha256"]:
            raise RuntimeError(f"restore content changed after preflight: {relative}")
        parent_identity = workspace.identity(destination.parent)
        target_identity = workspace.identity(destination)
        if parent_identity is None:
            raise RuntimeError(f"restore parent disappeared: {relative}")
        expected = current_files.get(relative)
        _verify_destination_digest(destination, expected, relative)
        workspace.commit_bytes(
            destination,
            data,
            parent_identity=parent_identity,
            target_identity=target_identity,
            expected_sha256=expected if target_identity is not None else None,
        )
        _journal_applied(journal, journal_path, relative)

    # Directory removal is deliberately non-recursive. Later files or subdirectories turn the
    # lifecycle change into a conflict instead of being destroyed by rollback or selective Undo.
    for relative in sorted(
        (current_directories - target_directories) & changed,
        key=lambda item: item.count("/"),
        reverse=True,
    ):
        candidate = workspace.resolve_directory(relative, access="write")
        parent_identity = workspace.identity(candidate.parent)
        target_identity = workspace.identity(candidate)
        if parent_identity is None or target_identity is None:
            raise RuntimeError(f"restore directory changed before commit: {relative}")
        workspace.commit_remove_directory(
            candidate,
            parent_identity=parent_identity,
            target_identity=target_identity,
        )
        _journal_applied(journal, journal_path, relative)


def _remove_created_directories(settings: Settings, directories: object) -> None:
    if not isinstance(directories, list):
        return
    workspace = Workspace(settings)
    for relative in sorted(
        (str(item) for item in directories),
        key=lambda item: item.count("/"),
        reverse=True,
    ):
        try:
            directory = workspace.resolve_directory(relative, access="write")
            parent_identity = workspace.identity(directory.parent)
            target_identity = workspace.identity(directory)
            if parent_identity is None or target_identity is None:
                raise RuntimeError("created directory identity is unavailable")
            workspace.commit_remove_directory(
                directory,
                parent_identity=parent_identity,
                target_identity=target_identity,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RuntimeError(
                f"automatic recovery could not remove created directory: {relative}"
            ) from error


def _scan_current_hashes(
    settings: Settings, paths: set[str] | None = None
) -> dict[str, str]:
    return {
        path: state.removeprefix("file:")
        for path, state in _scan_current_state(settings, paths).items()
        if state.startswith("file:")
    }


def _scan_current_state(
    settings: Settings, paths: set[str] | None = None
) -> dict[str, str]:
    workspace = Workspace(settings)
    if paths is not None:
        result: dict[str, str] = {}
        for relative in sorted(paths):
            normalized = _validated_relative_path(relative)
            try:
                verified = workspace.resolve_existing(
                    normalized, allow_directory=True, access="write", readable=True
                )
            except FileNotFoundError:
                workspace.resolve_planned_write(normalized)
                continue
            actual_relative = _actual_workspace_relative(workspace, verified)
            if verified.is_dir():
                result[actual_relative] = _DIRECTORY_STATE
                continue
            details = verified.stat()
            if not verified.is_file() or details.st_nlink > 1:
                raise PermissionError(
                    f"scoped workspace verification requires a unique regular file: {normalized}"
                )
            before_identity = workspace.identity(verified)
            parent_identity = workspace.identity(verified.parent)
            if before_identity is None or parent_identity is None:
                raise RuntimeError(
                    f"scoped workspace verification target disappeared: {normalized}"
                )
            data = read_verified_bytes(verified, settings.approval_manifest_max_bytes)
            workspace.revalidate_for_replace(
                verified,
                parent_identity=parent_identity,
                target_identity=before_identity,
            )
            result[actual_relative] = f"file:{sha256_bytes(data)}"
        return result
    denied = {name.casefold() for name in settings.write_denied_directories}
    blocked = {name.casefold() for name in settings.blocked_file_names}
    result: dict[str, str] = {}

    def fail_walk(error: OSError) -> None:
        raise RuntimeError(f"workspace verification traversal failed: {error}") from error

    for root, dirs, files in os.walk(
        settings.workspace_root,
        topdown=True,
        followlinks=False,
        onerror=fail_walk,
    ):
        root_path = Path(root)
        dirs[:] = [
            name
            for name in dirs
            if name.casefold() not in denied
            and not workspace._is_reparse(root_path / name)
        ]
        for name in dirs:
            relative_directory = (root_path / name).relative_to(
                settings.workspace_root
            ).as_posix()
            result[relative_directory] = _DIRECTORY_STATE
        for name in files:
            relative = (root_path / name).relative_to(settings.workspace_root)
            folded = name.casefold()
            if folded in blocked or (
                folded.startswith(".env.") and folded != ".env.example"
            ):
                continue
            try:
                path = workspace.resolve_existing(
                    str(relative), access="write", readable=True
                )
                if not path.is_file() or path.stat().st_nlink > 1:
                    continue
                result[relative.as_posix()] = (
                    "file:"
                    + sha256_bytes(
                        read_verified_bytes(path, settings.approval_manifest_max_bytes)
                    )
                )
            except (FileNotFoundError, OSError, PermissionError, ValueError) as error:
                raise RuntimeError(
                    f"workspace verification could not read {relative.as_posix()}: "
                    f"{type(error).__name__}: {error}"
                ) from error
    return result


def _verify_destination_digest(path: Path, expected: str | None, relative: str) -> None:
    if path.exists():
        size = path.stat().st_size
        if not path.is_file() or sha256_bytes(read_verified_path_bytes(path, size)) != expected:
            raise RuntimeError(f"workspace file changed during restore: {relative}")
    elif expected is not None:
        raise RuntimeError(f"workspace file disappeared during restore: {relative}")


def _stage_manifest_files(
    settings: Settings, manifest_path: str, changed: list[str], destination: Path
) -> None:
    manifest = _load_manifest(settings, manifest_path)
    entries = _entry_map(manifest)
    destination.mkdir(parents=True, exist_ok=False)
    incoming = sum(int(entries[path]["size"]) for path in changed if path in entries)
    enforce_data_quota(settings, incoming_bytes=incoming)
    for relative in changed:
        entry = entries.get(relative)
        if entry is None:
            continue
        target = destination / Path(relative)
        target.resolve(strict=False).relative_to(destination.resolve(strict=True))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_entry_source(settings, Path(manifest_path), entry), target)


def _verify_staged_files(
    manifest: dict[str, Any], staged_root: Path, changed: list[str]
) -> None:
    entries = _entry_map(manifest)
    for relative in changed:
        entry = entries.get(relative)
        if entry is None:
            continue
        data = (staged_root / Path(relative)).read_bytes()
        if sha256_bytes(data) != entry["sha256"] or len(data) != int(entry["size"]):
            raise RuntimeError(f"staged checkpoint integrity verification failed: {relative}")


def _load_manifest(settings: Settings, path: str) -> dict[str, Any]:
    resolved = Path(path).resolve(strict=True)
    resolved.relative_to((settings.data_dir / "workspace-history").resolve(strict=True))
    manifest = json.loads(resolved.read_text(encoding="utf-8"))
    if manifest.get("capture_complete") is not True:
        raise RuntimeError(
            "workspace checkpoint has no verified complete-capture marker; legacy or partial "
            "manifests cannot be used for restore/Undo"
        )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise TypeError("invalid workspace history manifest")
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise TypeError("invalid workspace history entry")
        relative = str(item.get("path", ""))
        pure = PurePosixPath(relative)
        digest = str(item.get("sha256", ""))
        Workspace.validate_windows_syntax(relative)
        if (
            not relative
            or "\\" in relative
            or pure.as_posix() != relative
            or pure.is_absolute()
            or ".." in pure.parts
            or relative in seen
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or int(item.get("size", -1)) < 0
        ):
            raise ValueError(f"invalid workspace history entry: {relative}")
        seen.add(relative)
    directories = manifest.get("directories", [])
    if not isinstance(directories, list):
        raise TypeError("invalid workspace history directory manifest")
    directory_seen: set[str] = set()
    normalized_directories: list[dict[str, str]] = []
    for item in directories:
        if not isinstance(item, dict) or set(item) != {"path"}:
            raise TypeError("invalid workspace history directory entry")
        relative = str(item.get("path", ""))
        pure = PurePosixPath(relative)
        Workspace.validate_windows_syntax(relative)
        if (
            not relative
            or "\\" in relative
            or pure.as_posix() != relative
            or pure.is_absolute()
            or ".." in pure.parts
            or relative in directory_seen
            or relative in seen
        ):
            raise ValueError(f"invalid workspace history directory entry: {relative}")
        directory_seen.add(relative)
        normalized_directories.append({"path": relative})
    manifest["directories"] = normalized_directories
    scope = _manifest_scope(manifest)
    scoped_paths = _scope_paths(scope)
    represented = seen | directory_seen
    if scoped_paths is not None and not represented.issubset(scoped_paths):
        raise ValueError("workspace history entry falls outside its declared checkpoint scope")
    manifest["scope"] = scope
    manifest["_manifest_path"] = str(resolved)
    return manifest


def _manifest_scope(manifest: dict[str, Any]) -> dict[str, Any]:
    raw = manifest.get("scope", {"kind": "workspace"})
    if not isinstance(raw, dict):
        raise TypeError("invalid workspace checkpoint scope")
    kind = raw.get("kind")
    if kind == "workspace":
        return {"kind": "workspace"}
    if kind != "paths" or not isinstance(raw.get("paths"), list) or not raw["paths"]:
        raise ValueError("invalid scoped workspace checkpoint")
    paths = sorted({_validated_relative_path(str(value)) for value in raw["paths"]})
    if len(paths) != len(raw["paths"]):
        raise ValueError("scoped workspace checkpoint contains duplicate paths")
    return {"kind": "paths", "paths": paths}


def _scope_paths(scope: dict[str, Any]) -> set[str] | None:
    if scope["kind"] == "workspace":
        return None
    return {str(path) for path in scope["paths"]}


def _require_matching_scope(*manifests: dict[str, Any]) -> dict[str, Any]:
    scopes = [_manifest_scope(manifest) for manifest in manifests]
    if any(scope != scopes[0] for scope in scopes[1:]):
        raise RuntimeError("workspace checkpoint scopes do not match")
    return scopes[0]


def _entry_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["path"]): item for item in manifest["files"]}


def _directory_set(manifest: dict[str, Any]) -> set[str]:
    return {str(item["path"]) for item in manifest.get("directories", [])}


def _hash_map(manifest: dict[str, Any]) -> dict[str, str]:
    return {path: str(entry["sha256"]) for path, entry in _entry_map(manifest).items()}


def _entry_digest(entry: dict[str, Any] | None) -> str | None:
    return None if entry is None else str(entry["sha256"])


def _state_map(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        **{
            path: f"file:{entry['sha256']}"
            for path, entry in _entry_map(manifest).items()
        },
        **{path: _DIRECTORY_STATE for path in _directory_set(manifest)},
    }


def _entry_source(settings: Settings, manifest_path: Path, entry: dict[str, Any]) -> Path:
    blob = entry.get("blob")
    if blob:
        source = _blob_root(settings) / f"{blob}.blob"
        source.resolve(strict=True).relative_to(_blob_root(settings).resolve(strict=True))
        return source
    source = manifest_path.parent / "files" / Path(str(entry["path"]))
    source.resolve(strict=True).relative_to((manifest_path.parent / "files").resolve(strict=True))
    return source


def _entry_bytes(
    settings: Settings, manifest_path: Path, entry: dict[str, Any] | None
) -> bytes:
    if entry is None:
        return b""
    return _entry_source(settings, manifest_path, entry).read_bytes()


def _changed_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    before_map = _state_map(before)
    after_map = _state_map(after)
    return sorted(
        path
        for path in before_map.keys() | after_map.keys()
        if before_map.get(path) != after_map.get(path)
    )


def _write_generated_manifest(
    settings: Settings,
    operation_id: str,
    stage: str,
    entries: dict[str, dict[str, Any]],
    *,
    scope: dict[str, Any] | None = None,
    directories: set[str] | None = None,
) -> str:
    base = _operation_root(settings, operation_id) / stage
    base.mkdir(parents=True, exist_ok=False)
    path = base / "manifest.json"
    _write_json_atomic(
        path,
        {
            "version": _MANIFEST_VERSION,
            "operation_id": operation_id,
            "stage": stage,
            "files": [entries[key] for key in sorted(entries)],
            "directories": [
                {"path": relative} for relative in sorted(directories or set())
            ],
            "excluded": [],
            "capture_complete": True,
            "scope": scope or {"kind": "workspace"},
        },
    )
    return str(path)


def _store_blob(settings: Settings, digest: str, data: bytes, initial_size: int) -> None:
    root = _blob_root(settings)
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f"{digest}.blob"
    if destination.exists():
        existing = destination.read_bytes()
        if sha256_bytes(existing) != digest:
            raise RuntimeError(f"content-addressed checkpoint blob is corrupt: {digest}")
        return
    if initial_size + len(data) > settings.max_data_dir_bytes:
        raise RuntimeError("workspace history would exceed max_data_dir_bytes")
    enforce_data_quota(settings, incoming_bytes=len(data))
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=root) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    payload = canonical_json(value).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=path.parent) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _journal_applied(
    journal: dict[str, Any] | None, journal_path: Path | None, relative: str
) -> None:
    if journal is None or journal_path is None:
        return
    journal.setdefault("applied_paths", []).append(relative)
    _write_json_atomic(journal_path, journal)


def _operation_root(settings: Settings, operation_id: str) -> Path:
    if not operation_id or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        for character in operation_id
    ):
        raise ValueError("invalid workspace history operation id")
    return settings.data_dir / "workspace-history" / "operations" / operation_id


def _transaction_root(settings: Settings, operation_id: str) -> Path:
    if not operation_id or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        for character in operation_id
    ):
        raise ValueError("invalid workspace transaction id")
    return settings.data_dir / "workspace-history" / "transactions" / operation_id


def _blob_root(settings: Settings) -> Path:
    return settings.data_dir / "workspace-history" / "blobs"


def _conflict(
    path: str,
    reason: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    current: dict[str, Any] | None,
    *,
    text_context: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {
        "path": path,
        "reason": reason,
        "before_sha256": _entry_digest(before),
        "operation_after_sha256": _entry_digest(after),
        "current_sha256": _entry_digest(current),
    }
    if text_context:
        result["bounded_text_context"] = text_context
    return result


def _bounded_text_context(value: str, limit: int = 800) -> str:
    if len(value) <= limit:
        return value
    half = max(1, (limit - 40) // 2)
    return value[:half] + "\n... conflict context truncated ...\n" + value[-half:]
