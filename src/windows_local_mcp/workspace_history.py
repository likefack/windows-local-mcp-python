from __future__ import annotations

import difflib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings
from .paths import Workspace
from .resources import directory_size, enforce_data_quota
from .util import canonical_json, sha256_bytes


@dataclass(frozen=True)
class WorkspaceState:
    manifest_path: str
    files_dir: str
    file_count: int
    total_bytes: int


def capture_workspace_state(settings: Settings, operation_id: str, stage: str) -> WorkspaceState:
    """Capture MCP-writable workspace files without traversing protected/reparse paths."""
    base = settings.data_dir / "workspace-history" / operation_id / stage
    files_dir = base / "files"
    files_dir.mkdir(parents=True, exist_ok=False)
    try:
        return _capture_workspace_state(settings, operation_id, stage, base, files_dir)
    except Exception:
        shutil.rmtree(base, ignore_errors=True)
        raise


def _capture_workspace_state(
    settings: Settings,
    operation_id: str,
    stage: str,
    base: Path,
    files_dir: Path,
) -> WorkspaceState:
    workspace = Workspace(settings)
    entries: list[dict[str, Any]] = []
    total = 0
    initial_data_bytes = directory_size(settings.data_dir, stop_after=settings.max_data_dir_bytes)
    denied = {name.casefold() for name in settings.write_denied_directories}
    for root, dirs, files in os.walk(settings.workspace_root, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            name
            for name in dirs
            if name.casefold() not in denied and not (root_path / name).is_symlink()
        ]
        for name in sorted(files, key=str.casefold):
            source = root_path / name
            relative = source.relative_to(settings.workspace_root)
            try:
                verified = workspace.resolve_existing(str(relative), access="write")
                stat = verified.stat()
                if not verified.is_file() or stat.st_nlink > 1:
                    continue
                data = verified.read_bytes()
            except (FileNotFoundError, PermissionError, OSError, ValueError):
                continue
            total += len(data)
            if len(entries) + 1 > settings.approval_manifest_max_files:
                raise ValueError("workspace history exceeds approval_manifest_max_files")
            if total > settings.approval_manifest_max_bytes:
                raise ValueError("workspace history exceeds approval_manifest_max_bytes")
            destination = files_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if initial_data_bytes + total + 1024 > settings.max_data_dir_bytes:
                raise RuntimeError("workspace history would exceed max_data_dir_bytes")
            destination.write_bytes(data)
            entries.append(
                {"path": relative.as_posix(), "size": len(data), "sha256": sha256_bytes(data)}
            )
    payload = {"operation_id": operation_id, "stage": stage, "files": entries}
    manifest = canonical_json(payload).encode("utf-8")
    enforce_data_quota(settings, incoming_bytes=len(manifest))
    manifest_path = base / "manifest.json"
    manifest_path.write_bytes(manifest)
    enforce_data_quota(settings)
    return WorkspaceState(str(manifest_path), str(files_dir), len(entries), total)


def compare_workspace_states(
    settings: Settings, before_path: str, after_path: str, operation_id: str
) -> dict[str, Any]:
    before = _load_manifest(settings, before_path)
    after = _load_manifest(settings, after_path)
    before_map = {item["path"]: item for item in before["files"]}
    after_map = {item["path"]: item for item in after["files"]}
    changed = sorted(
        path
        for path in before_map.keys() | after_map.keys()
        if before_map.get(path) != after_map.get(path)
    )
    added_lines = removed_lines = 0
    chunks: list[str] = []
    limit = settings.max_diff_bytes
    diff_bytes = 0
    truncated = False
    for relative in changed:
        old = _state_bytes(Path(before_path), relative) if relative in before_map else b""
        new = _state_bytes(Path(after_path), relative) if relative in after_map else b""
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
        "changed_files": changed,
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "diff_path": str(diff_path),
    }


def restore_workspace_state(
    settings: Settings, expected_path: str, target_path: str
) -> dict[str, Any]:
    """Restore only if the workspace still equals the last MCP-recorded state."""
    current = capture_workspace_state(settings, "rollback-check", os.urandom(8).hex())
    expected = _load_manifest(settings, expected_path)
    current_manifest = _load_manifest(settings, current.manifest_path)
    if _hash_map(expected) != _hash_map(current_manifest):
        expected_map, current_map = _hash_map(expected), _hash_map(current_manifest)
        conflicts = sorted(
            path
            for path in expected_map.keys() | current_map.keys()
            if expected_map.get(path) != current_map.get(path)
        )
        shutil.rmtree(Path(current.manifest_path).parents[1], ignore_errors=True)
        raise RuntimeError(
            "workspace changed after the last MCP operation; rollback conflicts: "
            + ", ".join(conflicts[:20])
        )
    shutil.rmtree(Path(current.manifest_path).parents[1], ignore_errors=True)
    target = _load_manifest(settings, target_path)
    target_map = _hash_map(target)
    expected_map = _hash_map(expected)
    workspace = Workspace(settings)
    for relative in sorted(expected_map.keys() - target_map.keys(), reverse=True):
        path = workspace.resolve_for_write(relative)
        parent_identity = workspace.identity(path.parent)
        target_identity = workspace.identity(path)
        if parent_identity is None:
            raise RuntimeError("rollback delete parent disappeared")
        workspace.revalidate_for_replace(
            path, parent_identity=parent_identity, target_identity=target_identity
        )
        path.unlink(missing_ok=True)
    for relative in sorted(target_map):
        parent_relative = str(Path(relative).parent)
        workspace.ensure_directory_for_write(parent_relative)
        destination = workspace.resolve_for_write(relative)
        source = Path(target_path).parent / "files" / Path(relative)
        parent_identity = workspace.identity(destination.parent)
        target_identity = workspace.identity(destination)
        if parent_identity is None:
            raise RuntimeError("rollback parent disappeared")
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=destination.parent) as output:
            output.write(source.read_bytes())
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        try:
            workspace.revalidate_for_replace(
                destination, parent_identity=parent_identity, target_identity=target_identity
            )
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    return {
        "restored_files": sorted(target_map),
        "removed_files": sorted(expected_map.keys() - target_map.keys()),
    }


def describe_workspace_restore(
    settings: Settings, expected_path: str, target_path: str
) -> dict[str, Any]:
    expected_map = _hash_map(_load_manifest(settings, expected_path))
    target_map = _hash_map(_load_manifest(settings, target_path))
    changed = sorted(
        path
        for path in expected_map.keys() | target_map.keys()
        if expected_map.get(path) != target_map.get(path)
    )
    return {
        "files_that_would_change": changed,
        "files_that_would_be_removed": sorted(expected_map.keys() - target_map.keys()),
        "files_that_would_be_restored_or_created": sorted(target_map),
        "conflict_check": "current workspace must still match latest MCP checkpoint",
    }


def _load_manifest(settings: Settings, path: str) -> dict[str, Any]:
    resolved = Path(path).resolve(strict=True)
    resolved.relative_to((settings.data_dir / "workspace-history").resolve(strict=True))
    return json.loads(resolved.read_text(encoding="utf-8"))


def _hash_map(manifest: dict[str, Any]) -> dict[str, str]:
    return {str(item["path"]): str(item["sha256"]) for item in manifest["files"]}


def _state_bytes(manifest_path: Path, relative: str) -> bytes:
    return (manifest_path.parent / "files" / Path(relative)).read_bytes()
