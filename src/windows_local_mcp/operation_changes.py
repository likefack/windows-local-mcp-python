"""Read complete operation changes from retained, verified checkpoints only.

The saved diff remains a bounded preview. This module reconstructs its complete contents
without saving file bodies in Audit or using the current workspace as historical evidence.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Any

from .config import Settings
from .paths import Workspace
from .util import sha256_bytes
from .workspace_history import (
    _change_bytes_are_text,
    _directory_change_line,
    _directory_set,
    _entry_map,
    _iter_file_change_lines,
    _read_change_manifest,
    _require_matching_scope,
    _state_map,
    _verified_change_entry_bytes,
)

if TYPE_CHECKING:
    from .audit import AuditStore


@dataclass(frozen=True)
class _Checkpoints:
    before: dict[str, Any]
    after: dict[str, Any]
    paths: list[str]
    scope: dict[str, Any]
    manifest_binding: str

    @cached_property
    def before_files(self) -> dict[str, dict[str, Any]]:
        return _entry_map(self.before)

    @cached_property
    def after_files(self) -> dict[str, dict[str, Any]]:
        return _entry_map(self.after)

    @cached_property
    def before_directories(self) -> set[str]:
        return _directory_set(self.before)

    @cached_property
    def after_directories(self) -> set[str]:
        return _directory_set(self.after)


class _CheckpointsUnavailable(RuntimeError):
    """A missing retained artifact is distinct from an invalid/tampered artifact."""


def _bounded_integer(value: int, name: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"invalid {name}")
    return value


def _operation_identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in value)
    ):
        raise ValueError("invalid operation id")
    return value


def _allowed_relative_path(settings: Settings, value: str) -> str:
    """Apply pathname policy lexically; historical paths need not exist today."""
    if not isinstance(value, str):
        raise TypeError("operation change path must be a string")
    Workspace.validate_windows_syntax(value)
    pure = PureWindowsPath(value)
    relative = pure.as_posix()
    if not relative or relative == "." or ".." in pure.parts:
        raise ValueError("operation change path must be workspace-relative")
    denied = {
        name.casefold()
        for name in (*settings.read_denied_directories, *settings.write_denied_directories)
    }
    blocked = {name.casefold() for name in settings.blocked_file_names}
    parts = tuple(part.casefold() for part in pure.parts)
    if any(part in denied for part in parts):
        raise PermissionError("checkpoint path is denied by directory policy")
    if parts[-1] in blocked or (parts[-1].startswith(".env.") and parts[-1] != ".env.example"):
        raise PermissionError("checkpoint path is denied by protected-file policy")
    return relative


def _load_checkpoint(
    settings: Settings, operation_id: str, value: object, expected_digest: object
) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise _CheckpointsUnavailable("checkpoint_not_recorded")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("checkpoint manifest must be in its operation namespace")
    root = Path(os.path.abspath(settings.data_dir / "workspace-history" / "operations" / operation_id))
    try:
        suffix = path.relative_to(root)
    except ValueError as error:
        raise ValueError("checkpoint manifest is outside its operation namespace") from error
    if len(suffix.parts) != 2 or suffix.name != "manifest.json":
        raise ValueError("invalid operation checkpoint manifest path")
    stage = _operation_identifier(suffix.parts[0])
    try:
        manifest = _read_change_manifest(settings, value)
    except FileNotFoundError as error:
        raise _CheckpointsUnavailable("checkpoint_missing_or_expired") from error
    except PermissionError as error:
        # Windows handle validation also wraps missing components in PermissionError. Check
        # absence without reading through an alternative path or interpreting exception text.
        try:
            path.lstat()
        except FileNotFoundError:
            raise _CheckpointsUnavailable("checkpoint_missing_or_expired") from error
        raise
    if manifest.get("operation_id") != operation_id or manifest.get("stage") != stage:
        raise ValueError("checkpoint identity does not match its operation namespace")
    if manifest.get("version") not in {1, 2, 3}:
        raise ValueError("unsupported checkpoint manifest version")
    if expected_digest is not None and expected_digest != manifest["_manifest_sha256"]:
        raise RuntimeError("checkpoint manifest integrity verification failed")
    files = _entry_map(manifest)
    directories = _directory_set(manifest)
    if len(files) + len(directories) > settings.approval_manifest_max_files:
        raise ValueError("checkpoint exceeds approval_manifest_max_files")
    total_bytes = 0
    for relative, entry in files.items():
        _allowed_relative_path(settings, relative)
        size = entry["size"]
        if type(size) is not int or size < 0:
            raise ValueError("invalid checkpoint entry size")
        total_bytes += size
        if total_bytes > settings.approval_manifest_max_bytes:
            raise ValueError("checkpoint exceeds approval_manifest_max_bytes")
        if entry.get("blob") is not None and entry["blob"] != entry["sha256"]:
            raise ValueError("checkpoint blob name does not match its content digest")
    for relative in directories:
        _allowed_relative_path(settings, relative)
    for relative in manifest["scope"].get("paths", []):
        _allowed_relative_path(settings, relative)
    # A persisted file cannot simultaneously be an ancestor directory of another entry.
    for relative in files.keys() | directories:
        if any(parent.as_posix() in files for parent in PurePosixPath(relative).parents):
            raise ValueError("checkpoint file/directory topology is inconsistent")
    return manifest


def _load_checkpoints(settings: Settings, operation: dict[str, Any]) -> _Checkpoints:
    operation_id = _operation_identifier(operation.get("id"))
    result = operation.get("result")
    result = result if isinstance(result, dict) else {}
    before_digest = result.get("before_manifest_sha256")
    after_digest = result.get("after_manifest_sha256")
    before = _load_checkpoint(settings, operation_id, operation.get("pre_workspace_path"), before_digest)
    after = _load_checkpoint(settings, operation_id, operation.get("post_workspace_path"), after_digest)
    scope = _require_matching_scope(before, after)
    before_state, after_state = _state_map(before), _state_map(after)
    changed = sorted(
        path for path in before_state.keys() | after_state.keys()
        if before_state.get(path) != after_state.get(path)
    )
    return _Checkpoints(
        before, after, changed, scope,
        "verified" if before_digest is not None and after_digest is not None else "unrecorded",
    )


def _state_description(
    files: dict[str, dict[str, Any]], directories: set[str], relative: str
) -> dict[str, Any]:
    entry = files.get(relative)
    if entry is not None:
        return {"kind": "file", "size_bytes": entry["size"], "sha256": entry["sha256"]}
    if relative in directories:
        return {"kind": "directory", "size_bytes": None, "sha256": None}
    return {"kind": "absent", "size_bytes": None, "sha256": None}


def _change_description(pair: _Checkpoints, relative: str) -> dict[str, Any]:
    before = _state_description(pair.before_files, pair.before_directories, relative)
    after = _state_description(pair.after_files, pair.after_directories, relative)
    change = (
        "added" if before["kind"] == "absent" else
        "deleted" if after["kind"] == "absent" else
        "type_changed" if before["kind"] != after["kind"] else "modified"
    )
    return {"path": relative, "change": change, "before": before, "after": after}


def _path_bytes(settings: Settings, pair: _Checkpoints, relative: str) -> tuple[bytes, bytes]:
    try:
        return (
            _verified_change_entry_bytes(
                settings, Path(pair.before["_manifest_path"]), pair.before_files.get(relative)
            ),
            _verified_change_entry_bytes(
                settings, Path(pair.after["_manifest_path"]), pair.after_files.get(relative)
            ),
        )
    except FileNotFoundError as error:
        raise _CheckpointsUnavailable("checkpoint_content_missing_or_expired") from error


def _path_diff_lines(
    pair: _Checkpoints, relative: str, before: bytes, after: bytes
) -> Iterator[str]:
    before_files, after_files = pair.before_files, pair.after_files
    if relative in before_files or relative in after_files:
        for line, _added, _removed in _iter_file_change_lines(
            relative, before, after,
            before_exists=relative in before_files,
            after_exists=relative in after_files,
        ):
            yield line
    before_dirs, after_dirs = pair.before_directories, pair.after_directories
    if (relative in before_dirs) != (relative in after_dirs):
        yield _directory_change_line(relative, relative in after_dirs)


def iter_operation_diff_lines(settings: Settings, operation: dict[str, Any]) -> Iterator[str]:
    """Yield full physical diff lines; callers own terminal escaping and error reporting."""
    pair = _load_checkpoints(settings, operation)
    for relative in pair.paths:
        before, after = _path_bytes(settings, pair, relative)
        yield from _path_diff_lines(pair, relative, before, after)


def _diff_page(lines: Iterator[str], offset: int, maximum: int) -> dict[str, Any]:
    """Hash the whole regenerated diff while keeping only the requested byte range."""
    total = 0
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    for line in lines:
        data = line.encode("utf-8")
        digest.update(data)
        start = max(offset - total, 0)
        end = min(offset + maximum - total, len(data))
        if start < end:
            chunks.append(data[start:end])
        total += len(data)
    if offset > total:
        raise ValueError("content_offset exceeds content size")
    chunk = b"".join(chunks)
    try:
        content = chunk.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        # Arbitrary byte offsets can split a multibyte character. Base64 preserves those bytes.
        content = base64.b64encode(chunk).decode("ascii")
        encoding = "base64"
    return {
        "encoding": encoding, "content": content, "bytes": len(chunk),
        "total_bytes": total, "sha256": digest.hexdigest(),
        "chunk_sha256": sha256_bytes(chunk),
        "next_offset": offset + len(chunk) if offset + len(chunk) < total else None,
        "eof": offset + len(chunk) >= total,
    }


def build_operation_changes(
    settings: Settings,
    audit: AuditStore,
    operation_id: str,
    *,
    offset: int = 0,
    limit: int = 50,
    path: str | None = None,
    view: str = "diff",
    content_offset: int = 0,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Page changed paths, exact before/after bytes, or the complete regenerated text diff."""
    _operation_identifier(operation_id)
    _bounded_integer(offset, "offset")
    _bounded_integer(limit, "limit", minimum=1, maximum=200)
    _bounded_integer(content_offset, "content_offset")
    _bounded_integer(max_bytes, "max_bytes", minimum=1, maximum=4 * 1024 * 1024)
    # Keep the normal default usable when the operator configures smaller transfer pages.
    max_bytes = min(max_bytes, settings.max_transfer_chunk_bytes)
    if view not in {"diff", "before", "after"}:
        raise ValueError("view must be diff, before, or after")
    relative = _allowed_relative_path(settings, path) if path is not None else None
    operation = audit.get_operation(operation_id, include_events=False)
    base: dict[str, Any] = {
        "operation_id": operation_id, "source": "persisted_checkpoints",
        "availability": "available", "complete": True,
        "status": operation.get("status"),
        "rollback_state": operation.get("rollback_state") or "not_applicable",
        "completeness_scope": "recorded_checkpoint_pair",
    }
    try:
        pair = _load_checkpoints(settings, operation)
        base.update({
            "checkpoint_scope": pair.scope,
            "manifest_binding": pair.manifest_binding,
            "before_manifest_sha256": pair.before["_manifest_sha256"],
            "after_manifest_sha256": pair.after["_manifest_sha256"],
            "changed_path_count": len(pair.paths),
            "changed_file_count": sum(
                relative in pair.before_files or relative in pair.after_files
                for relative in pair.paths
            ),
            "changed_directory_count": len(pair.before_directories ^ pair.after_directories),
            # Listing metadata is manifest-validated; blob checks apply to bytes actually returned.
            "content_integrity": "not_read",
        })
        if relative is None:
            if offset > len(pair.paths):
                raise ValueError("offset exceeds change count")
            selected = pair.paths[offset:offset + limit]
            next_offset = offset + len(selected)
            return {
                **base, "offset": offset, "limit": limit,
                "changes": [_change_description(pair, item) for item in selected],
                "next_offset": next_offset if next_offset < len(pair.paths) else None,
                "eof": next_offset >= len(pair.paths),
            }
        if relative not in pair.paths:
            raise ValueError("path is not a changed path in this operation")
        description = _change_description(pair, relative)
        base.update({
            **description, "view": view, "content_offset": content_offset,
            "max_bytes": max_bytes,
        })
        if view == "diff":
            before, after = _path_bytes(settings, pair, relative)
            base["content_integrity"] = "verified"
            base["is_binary"] = not _change_bytes_are_text(before, after)
            return {
                **base,
                "diff_kind": "binary_summary" if base["is_binary"] else "text_or_directory",
                "diff_content_complete": not base["is_binary"],
                "byte_exact_available": True,
                **_diff_page(_path_diff_lines(pair, relative, before, after), content_offset, max_bytes),
            }
        side = description[view]
        if side["kind"] != "file":
            return {
                **base, "availability": "not_applicable", "complete": True,
                "reason": "path_absent" if side["kind"] == "absent" else "directory_has_no_bytes",
                "content": None, "encoding": None, "bytes": 0,
                "total_bytes": 0, "next_offset": None, "eof": True,
            }
        # Raw retrieval needs only the selected side. Hash the exact bytes read; never use a
        # prior verified hash as permission to return newly read, unchecked content.
        manifest = pair.before if view == "before" else pair.after
        entries = pair.before_files if view == "before" else pair.after_files
        try:
            data = _verified_change_entry_bytes(
                settings, Path(manifest["_manifest_path"]), entries[relative]
            )
        except FileNotFoundError as error:
            raise _CheckpointsUnavailable("checkpoint_content_missing_or_expired") from error
        if content_offset > len(data):
            raise ValueError("content_offset exceeds content size")
        chunk = data[content_offset:content_offset + max_bytes]
        next_offset = content_offset + len(chunk)
        return {
            **base, "content_integrity": "verified", "encoding": "base64",
            "content": base64.b64encode(chunk).decode("ascii"),
            "bytes": len(chunk), "total_bytes": len(data), "sha256": side["sha256"],
            "chunk_sha256": sha256_bytes(chunk),
            "next_offset": next_offset if next_offset < len(data) else None,
            "eof": next_offset >= len(data),
        }
    except _CheckpointsUnavailable as error:
        return {
            **base, "availability": "unavailable", "complete": False, "reason": str(error),
            "changes": [], "next_offset": None, "eof": True,
        }
