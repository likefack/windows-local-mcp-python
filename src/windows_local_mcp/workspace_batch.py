"""Deterministic, mutation-free planning for bounded workspace file batches."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any

from .paths import Workspace, release_verified_hold
from .util import sha256_bytes
from .workspace_plan import WorkspacePlan, snapshot_file

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass
class _FileState:
    """The bytes and provenance visible at one point in the virtual operation order."""

    path: str
    data: bytes
    existing: bool
    modified: bool = False
    replacement_count: int = 0
    moved: bool = False


class _BatchPlanner:
    def __init__(
        self, workspace: Workspace, settings: Any, operations: list[dict[str, Any]]
    ) -> None:
        self.workspace = workspace
        self.settings = settings
        self.operations = operations
        self.max_files = self._positive_limit("max_high_level_files")
        self.max_text_bytes = self._positive_limit("max_text_file_bytes")
        self.max_write_bytes = self._positive_limit("max_write_bytes")
        self.max_total_bytes = self._positive_limit("max_high_level_total_bytes")
        # Binary files use the existing structured-file admission boundary. The request-wide
        # retained-byte limit usually narrows this further before a verified read starts.
        self.max_artifact_bytes = self._positive_limit("max_structured_file_bytes")

        self.plan = WorkspacePlan(tool_name="workspace_batch")
        self.files: dict[str, _FileState] = {}
        self.directories: dict[str, str] = {}
        self.removed: set[str] = set()
        self.spellings: dict[str, str] = {}
        self.copied_existing_sources: set[str] = set()
        self.total_bytes = 0
        self.operation_counts = {
            name: 0 for name in ("mkdir", "create", "replace", "copy", "move", "delete")
        }

    def _positive_limit(self, name: str) -> int:
        value = getattr(self.settings, name, None)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def _key(path: str) -> str:
        return path.replace("\\", "/").casefold()

    def _claim_path(self, value: Any, field: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a non-empty string")
        # Explicit traversal components are rejected even when their normalized result would
        # remain inside the workspace; this keeps aliases out of one batch request.
        parts = PureWindowsPath(value).parts
        if any(part in {".", ".."} for part in parts):
            raise PermissionError(f"{field} must not contain traversal components")
        self.workspace.validate_windows_syntax(value)
        spelling = PureWindowsPath(value).as_posix()
        key = self._key(spelling)
        prior = self.spellings.get(key)
        if prior is not None and prior != spelling:
            raise ValueError("workspace batch contains a case-colliding path alias")
        self.spellings[key] = spelling
        return value

    @staticmethod
    def _validate_fields(
        operation: dict[str, Any], *, required: set[str], optional: set[str] = frozenset()
    ) -> None:
        missing = required - set(operation)
        if missing:
            raise ValueError(
                "workspace batch operation is missing fields: " + ", ".join(sorted(missing))
            )
        unknown = set(operation) - required - optional
        if unknown:
            raise ValueError("unsupported workspace batch fields: " + ", ".join(sorted(unknown)))

    @staticmethod
    def _expected_hash(operation: dict[str, Any]) -> str | None:
        expected = operation.get("expected_sha256")
        if expected is None:
            return None
        if not isinstance(expected, str) or _SHA256_RE.fullmatch(expected) is None:
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        return expected

    def _charge(self, size: int) -> None:
        self.total_bytes += size
        if self.total_bytes > self.max_total_bytes:
            raise ValueError("workspace batch exceeds max_high_level_total_bytes")

    def _remaining_bytes(self) -> int:
        return self.max_total_bytes - self.total_bytes

    def _require_parent(self, relative: str) -> None:
        parent = (self.workspace.root / relative).parent
        if parent == self.workspace.root:
            return
        parent_relative = self.workspace.relative_lexical(parent)
        parent_key = self._key(parent_relative)
        if parent_key in self.directories:
            return
        if parent_key in self.files or parent_key in self.removed:
            raise NotADirectoryError(
                f"workspace batch parent is not a directory: {parent_relative}"
            )
        checked = self.workspace.resolve_directory(parent_relative, access="write")
        release_verified_hold(checked)

    def _new_file_target(self, raw_path: Any, field: str) -> tuple[str, str]:
        path = self._claim_path(raw_path, field)
        target = self.workspace.resolve_planned_write(path)
        relative = self.workspace.relative_lexical(target)
        key = self._key(relative)
        if target.exists():
            raise FileExistsError(f"workspace batch destination already exists: {relative}")
        if key in self.files or key in self.directories or key in self.removed:
            raise ValueError(f"workspace batch destination is already used: {relative}")
        self._require_parent(relative)
        self.plan.absent.add(relative)
        return relative, key

    def _load_file(self, raw_path: Any, field: str, max_bytes: int) -> tuple[str, _FileState]:
        path = self._claim_path(raw_path, field)
        requested_key = self._key(PureWindowsPath(path).as_posix())
        if requested_key in self.removed:
            raise FileNotFoundError(f"workspace batch source was already removed: {path}")
        state = self.files.get(requested_key)
        if state is not None:
            if len(state.data) > max_bytes:
                raise ValueError("workspace plan file exceeds byte limit")
            return requested_key, state

        remaining = self._remaining_bytes()
        if remaining <= 0:
            raise ValueError("workspace batch exceeds max_high_level_total_bytes")
        # snapshot_file compares the identity size before it reads the file, so an input which
        # cannot fit in the retained-byte budget is rejected without allocating those bytes.
        snapshot = snapshot_file(self.workspace, path, min(max_bytes, remaining))
        canonical_key = self._key(snapshot.path)
        if canonical_key in self.removed:
            raise FileNotFoundError(f"workspace batch source was already removed: {snapshot.path}")
        prior = self.files.get(canonical_key)
        if prior is not None:
            if len(prior.data) > max_bytes:
                raise ValueError("workspace plan file exceeds byte limit")
            return canonical_key, prior
        self.plan.snapshots[snapshot.path] = snapshot
        self._charge(len(snapshot.data))
        state = _FileState(snapshot.path, snapshot.data, existing=True)
        self.files[canonical_key] = state
        return canonical_key, state

    def _verify_expected(self, state: _FileState, expected: str | None) -> None:
        if expected is not None and sha256_bytes(state.data) != expected:
            raise RuntimeError("expected_sha256 mismatch; source is stale or concurrently modified")

    @staticmethod
    def _encode_text(value: Any, field: str) -> bytes:
        if not isinstance(value, str):
            raise TypeError(f"{field} must be a string")
        if "\x00" in value:
            raise ValueError(f"{field} must not contain NUL")
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError(f"{field} must be valid Unicode text") from error

    def _mkdir(self, operation: dict[str, Any]) -> None:
        self._validate_fields(operation, required={"op", "path"})
        path = self._claim_path(operation["path"], "path")
        target = self.workspace.resolve_directory_target(path, parents=True)
        relative = self.workspace.relative_lexical(target)
        key = self._key(relative)
        if target.exists():
            raise FileExistsError(f"workspace batch directory already exists: {relative}")
        if key in self.files or key in self.directories or key in self.removed:
            raise ValueError(f"workspace batch destination is already used: {relative}")
        self._require_parent(relative)
        self.directories[key] = relative
        self.plan.directories.add(relative)
        self.plan.absent.add(relative)

    def _create(self, operation: dict[str, Any]) -> None:
        self._validate_fields(operation, required={"op", "path", "content"})
        content = operation["content"]
        if not isinstance(content, str):
            raise TypeError("content must be a string")
        if len(content) > self.max_write_bytes:
            raise ValueError("created file exceeds max_write_bytes")
        data = self._encode_text(content, "content")
        if len(data) > self.max_write_bytes:
            raise ValueError("created file exceeds max_write_bytes")
        relative, key = self._new_file_target(operation["path"], "path")
        self._charge(len(data))
        state = _FileState(relative, data, existing=False, modified=True)
        self.files[key] = state
        self.plan.changes[relative] = data

    def _replace(self, operation: dict[str, Any]) -> None:
        self._validate_fields(
            operation,
            required={"op", "path", "old_text", "new_text"},
            optional={"expected_sha256"},
        )
        old_text = operation["old_text"]
        new_text = operation["new_text"]
        if not isinstance(old_text, str) or not isinstance(new_text, str):
            raise TypeError("old_text and new_text must be strings")
        if not old_text:
            raise ValueError("old_text must not be empty")
        if len(old_text) > self.max_text_bytes:
            raise ValueError("old_text exceeds max_text_file_bytes")
        if len(new_text) > self.max_write_bytes:
            raise ValueError("new_text exceeds max_write_bytes")
        if "\x00" in old_text or "\x00" in new_text:
            raise ValueError("replacement text must not contain NUL")
        old_bytes = self._encode_text(old_text, "old_text")
        new_bytes = self._encode_text(new_text, "new_text")
        if len(old_bytes) > self.max_text_bytes:
            raise ValueError("old_text exceeds max_text_file_bytes")
        if len(new_bytes) > self.max_write_bytes:
            raise ValueError("new_text exceeds max_write_bytes")
        expected = self._expected_hash(operation)
        key, state = self._load_file(operation["path"], "path", self.max_text_bytes)
        self._verify_expected(state, expected)
        if state.moved or state.replacement_count or (state.existing and state.modified):
            raise ValueError("workspace batch target has already been modified")
        if state.existing and key in self.copied_existing_sources:
            raise ValueError("an existing copy source cannot later become a write target")
        try:
            text = state.data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("replacement target is not UTF-8 text") from error
        if "\x00" in text:
            raise ValueError("replacement target is binary text containing NUL")
        if text.count(old_text) != 1:
            raise RuntimeError("old_text must occur exactly once")
        predicted_size = len(state.data) - len(old_bytes) + len(new_bytes)
        if predicted_size > self.max_write_bytes:
            raise ValueError("replaced file exceeds max_write_bytes")
        if predicted_size > self._remaining_bytes():
            raise ValueError("workspace batch exceeds max_high_level_total_bytes")
        after = self._encode_text(text.replace(old_text, new_text, 1), "replacement output")
        if len(after) != predicted_size:
            raise RuntimeError("replacement output size changed unexpectedly")
        self._charge(len(after))
        state.data = after
        state.modified = True
        state.replacement_count += 1
        self.plan.changes[state.path] = after

    def _copy_or_move(self, operation: dict[str, Any], *, move: bool) -> None:
        name = "move" if move else "copy"
        self._validate_fields(
            operation,
            required={"op", "source", "destination"},
            optional={"expected_sha256"},
        )
        expected = self._expected_hash(operation)
        read_limit = min(self.max_artifact_bytes, self.max_write_bytes)
        source_key, state = self._load_file(operation["source"], "source", read_limit)
        self._verify_expected(state, expected)
        if len(state.data) > self.max_write_bytes:
            raise ValueError(f"{name} output exceeds max_write_bytes")
        if state.moved or (state.existing and state.modified):
            raise ValueError(f"workspace batch {name} source was already modified")
        if not move and not state.existing:
            raise ValueError("copy source must be an unchanged existing file")
        if move and state.existing and source_key in self.copied_existing_sources:
            raise ValueError("an existing copy source cannot later become a move source")

        destination, destination_key = self._new_file_target(
            operation["destination"], "destination"
        )
        self._charge(len(state.data))
        destination_state = _FileState(
            destination,
            state.data,
            existing=False,
            modified=True,
            replacement_count=state.replacement_count,
            moved=True,
        )
        self.files[destination_key] = destination_state
        self.plan.changes[destination] = state.data
        if move:
            self.files.pop(source_key, None)
            self.removed.add(source_key)
            if state.existing:
                self.plan.deletions.add(state.path)
            else:
                self.plan.changes.pop(state.path, None)
        else:
            self.copied_existing_sources.add(source_key)

    def _delete(self, operation: dict[str, Any]) -> None:
        self._validate_fields(operation, required={"op", "path"}, optional={"expected_sha256"})
        expected = self._expected_hash(operation)
        key, state = self._load_file(operation["path"], "path", self.max_artifact_bytes)
        self._verify_expected(state, expected)
        if not state.existing or state.modified or state.moved:
            raise ValueError("delete target must be one unchanged existing file")
        if key in self.copied_existing_sources:
            raise ValueError("an existing copy source cannot later become a delete target")
        self.files.pop(key, None)
        self.removed.add(key)
        self.plan.deletions.add(state.path)

    def build(self) -> WorkspacePlan:
        for operation in self.operations:
            if not isinstance(operation, dict):
                raise TypeError("each workspace batch operation must be an object")
            name = operation.get("op")
            if not isinstance(name, str) or name not in self.operation_counts:
                raise ValueError("unsupported workspace batch operation")
            self.operation_counts[name] += 1
            if name == "mkdir":
                self._mkdir(operation)
            elif name == "create":
                self._create(operation)
            elif name == "replace":
                self._replace(operation)
            elif name == "copy":
                self._copy_or_move(operation, move=False)
            elif name == "move":
                self._copy_or_move(operation, move=True)
            else:
                self._delete(operation)

        if len(self.plan.scope) > self.max_files:
            raise ValueError("workspace batch scope exceeds max_high_level_files")
        self.plan.summary = {
            "metadata_policy": "content_only",
            "operation_count": len(self.operations),
            "operation_counts": dict(self.operation_counts),
            "change_count": len(self.plan.changes),
            "deletion_count": len(self.plan.deletions),
            "directory_count": len(self.plan.directories),
            "snapshot_count": len(self.plan.snapshots),
            "change_paths": sorted(self.plan.changes),
            "deletion_paths": sorted(self.plan.deletions),
            "directory_paths": sorted(self.plan.directories),
        }
        return self.plan


def plan_workspace_batch(
    workspace: Workspace, settings: Any, operations: list[dict[str, Any]]
) -> WorkspacePlan:
    """Build a complete batch plan without changing the workspace."""

    if not isinstance(operations, list) or not operations:
        raise ValueError("operations must contain at least one workspace operation")
    max_files = getattr(settings, "max_high_level_files", None)
    if not isinstance(max_files, int) or isinstance(max_files, bool) or max_files <= 0:
        raise ValueError("max_high_level_files must be a positive integer")
    if len(operations) > max_files:
        raise ValueError("workspace batch operation count exceeds max_high_level_files")
    return _BatchPlanner(workspace, settings, operations).build()
