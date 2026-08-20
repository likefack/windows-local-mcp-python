from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from .paths import Workspace
from .util import sha256_bytes
from . import workspace_history as _history


def _apply_manifest_atomic(
    settings: Any,
    manifest_path: str,
    *,
    staged_root: Path | None = None,
    only_paths: set[str] | None = None,
    journal: dict[str, Any] | None = None,
    journal_path: Path | None = None,
    expected_hashes: dict[str, str] | None = None,
) -> None:
    manifest = _history._load_manifest(settings, manifest_path)
    target_map = _history._entry_map(manifest)
    scope_paths = _history._scope_paths(_history._manifest_scope(manifest))
    current = _history._scan_current_hashes(settings, scope_paths)
    if expected_hashes is not None and current != expected_hashes:
        raise RuntimeError("workspace changed during restore staging")
    changed = (
        only_paths
        if only_paths is not None
        else set(current.keys()) | set(target_map.keys())
    )
    workspace = Workspace(settings)

    for relative in sorted((set(current) - set(target_map)) & changed, reverse=True):
        destination = workspace.resolve_for_write(relative)
        _history._verify_destination_digest(destination, current.get(relative), relative)
        parent_identity = workspace.identity(destination.parent)
        target_identity = workspace.identity(destination)
        if parent_identity is None or target_identity is None:
            raise RuntimeError(f"restore delete target disappeared: {relative}")
        expected = current.get(relative)
        if expected is None:
            raise RuntimeError(f"restore delete has no expected digest: {relative}")
        workspace.commit_delete(
            destination,
            parent_identity=parent_identity,
            target_identity=target_identity,
            expected_sha256=expected,
        )
        _history._journal_applied(journal, journal_path, relative)

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
            _history._write_json_atomic(journal_path, journal)
        workspace.ensure_directory_for_write(parent_relative)
        destination = workspace.resolve_for_write(relative)
        entry = target_map[relative]
        source = (
            staged_root / Path(relative)
            if staged_root is not None and (staged_root / Path(relative)).exists()
            else _history._entry_source(settings, Path(manifest_path), entry)
        )
        data = source.read_bytes()
        if sha256_bytes(data) != entry["sha256"]:
            raise RuntimeError(f"restore content changed after preflight: {relative}")
        parent_identity = workspace.identity(destination.parent)
        target_identity = workspace.identity(destination)
        if parent_identity is None:
            raise RuntimeError(f"restore parent disappeared: {relative}")
        expected = current.get(relative)
        _history._verify_destination_digest(destination, expected, relative)
        workspace.commit_bytes(
            destination,
            data,
            parent_identity=parent_identity,
            target_identity=target_identity,
            expected_sha256=expected if target_identity is not None else None,
        )
        _history._journal_applied(journal, journal_path, relative)


def install() -> None:
    """Install the atomic workspace commit boundary before restore/Undo can execute."""
    if getattr(_history, "_ATOMIC_COMMIT_PATCH_INSTALLED", False):
        return
    _history._apply_manifest = _apply_manifest_atomic
    _history._ATOMIC_COMMIT_PATCH_INSTALLED = True


install()
