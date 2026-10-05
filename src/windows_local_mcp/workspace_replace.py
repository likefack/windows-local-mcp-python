"""Bounded planning for literal replacements across workspace text files.

Planning is deliberately mutation-free.  Every selected file is retained as a verified
snapshot, including files with no match, so the caller can later validate the complete
scope before committing any of the proposed changes.
"""

from __future__ import annotations

import fnmatch
import re
from collections import deque
from pathlib import Path
from typing import Any

from .high_level_read import (
    _bounded_entries,
    _classify_entry,
    _directory_entry_limit,
    _file_byte_limit,
    _request_file_limit,
    _request_limit,
    _request_total_byte_limit,
    _setting,
    _validate_depth,
    _validate_file_glob,
)
from .paths import Workspace, release_verified_hold
from .workspace_plan import FileSnapshot, WorkspacePlan, snapshot_file

_MATCH_MODES = {"all", "unique_per_file"}


def _literal_match_spans(
    text: str,
    old_text: str,
    *,
    case_sensitive: bool,
    remaining_matches: int,
    unique_per_file: bool,
) -> list[tuple[int, int]]:
    """Return bounded, non-overlapping match spans without constructing output.

    Case-insensitive matching uses Python's Unicode ``re.IGNORECASE`` semantics on the
    original text.  Match spans therefore always refer to the original string.  We
    intentionally do not casefold the text and reuse casefolded offsets, because Unicode
    case folding can change string length (for example, ``"ß".casefold() == "ss"``).
    """

    if case_sensitive:
        def iter_spans() -> Any:
            start = 0
            while True:
                found = text.find(old_text, start)
                if found < 0:
                    return
                end = found + len(old_text)
                yield found, end
                start = end

        matches = iter_spans()
    else:
        pattern = re.compile(re.escape(old_text), re.IGNORECASE)
        matches = ((match.start(), match.end()) for match in pattern.finditer(text))

    spans: list[tuple[int, int]] = []
    for span in matches:
        if unique_per_file and spans:
            raise RuntimeError("workspace replace is ambiguous: file contains multiple matches")
        if len(spans) >= remaining_matches:
            raise ValueError("workspace replace match limit exceeded")
        spans.append(span)
    return spans


def _apply_literal_spans(
    text: str,
    spans: list[tuple[int, int]],
    new_text: str,
) -> str:
    """Apply already bounded match spans left-to-right."""

    if not spans:
        return text
    pieces: list[str] = []
    previous = 0
    for start, end in spans:
        pieces.append(text[previous:start])
        pieces.append(new_text)
        previous = end
    pieces.append(text[previous:])
    return "".join(pieces)


def _matches_glob(name: str, pattern: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return fnmatch.fnmatchcase(name, pattern)
    return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())


def _validate_expected_matches(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("expected_total_matches must be an integer")
    if value < 0:
        raise ValueError("expected_total_matches must be non-negative")
    return value


def _validate_text_inputs(old_text: str, new_text: str, case_sensitive: bool) -> None:
    if not isinstance(old_text, str) or not isinstance(new_text, str):
        raise TypeError("old_text and new_text must be strings")
    if not old_text:
        raise ValueError("old_text must not be empty")
    if "\x00" in old_text:
        raise ValueError("old_text must not contain NUL")
    if "\x00" in new_text:
        raise ValueError("new_text must not contain NUL")
    if not isinstance(case_sensitive, bool):
        raise TypeError("case_sensitive must be boolean")


def plan_workspace_replace(
    workspace: Workspace,
    settings: Any,
    path: str,
    old_text: str,
    new_text: str,
    *,
    file_glob: str = "*",
    case_sensitive: bool = True,
    expected_total_matches: int | None,
    match_mode: str = "all",
    max_depth: int | None = None,
    max_entries: int | None = None,
    max_files: int | None = None,
    max_total_bytes: int | None = None,
    max_matches: int | None = None,
    max_changed_files: int | None = None,
) -> WorkspacePlan:
    """Build a bounded, deterministic plan for literal workspace replacements.

    ``path`` may identify one regular file or a directory root.  For a directory, depth
    zero selects no descendants, depth one selects direct children, and larger values add
    that many directory levels.  ``None`` uses the configured depth ceiling rather than an
    unbounded traversal.  Glob matching is against each file name, not its full path.

    Matching is left-to-right and non-overlapping.  ``unique_per_file`` permits zero or one
    match in each selected file and rejects a selected file containing multiple matches.
    The request-wide match count must equal ``expected_total_matches`` exactly when that
    precondition is supplied.  ``None`` is reserved for preview planning that discovers the
    count; callers that apply directly must require an integer before invoking the planner.
    """

    _validate_text_inputs(old_text, new_text, case_sensitive)
    expected = _validate_expected_matches(expected_total_matches)
    pattern = _validate_file_glob(file_glob)
    if pattern is None:  # The public API requires a concrete glob.
        raise ValueError("file_glob must be a non-empty string without NUL")
    if not isinstance(match_mode, str) or match_mode not in _MATCH_MODES:
        raise ValueError("match_mode must be 'all' or 'unique_per_file'")

    configured_depth = _setting(settings, "max_workspace_tree_depth", 8)
    depth_limit = _validate_depth(settings, max_depth, default=configured_depth)
    entry_limit = _directory_entry_limit(settings, max_entries)
    file_limit = _request_file_limit(settings, max_files)
    total_limit = _request_total_byte_limit(settings, max_total_bytes, max_files=file_limit)
    match_limit = _request_limit(
        max_matches,
        name="max_matches",
        default=_setting(settings, "max_workspace_search_results", 500),
        maximum=_setting(settings, "max_workspace_search_results", 500),
        allow_zero=True,
    )
    changed_limit = _request_limit(
        max_changed_files,
        name="max_changed_files",
        default=file_limit,
        maximum=min(file_limit, _setting(settings, "max_high_level_files", 64)),
        allow_zero=True,
    )
    per_file_read_limit = _file_byte_limit(settings)
    per_file_write_limit = _setting(settings, "max_write_bytes", 2 * 1024 * 1024)
    try:
        old_bytes = old_text.encode("utf-8")
        new_bytes = new_text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("old_text and new_text must be valid UTF-8 text") from error
    if len(old_bytes) > per_file_read_limit:
        raise ValueError("old_text exceeds max_text_file_bytes")
    if len(new_bytes) > per_file_write_limit:
        raise ValueError("new_text exceeds max_write_bytes")

    if not isinstance(path, str):
        raise TypeError("path must be a string")
    root = workspace.resolve_existing(path, allow_directory=True, access="read")
    root_relative = workspace.relative(root)
    pending: deque[tuple[Path, int]] = deque()
    direct_file: str | None = None
    if root.is_dir():
        pending.append((root, 0))
    else:
        direct_file = root_relative
        release_verified_hold(root)

    snapshots: dict[str, FileSnapshot] = {}
    changes: dict[str, bytes] = {}
    matched_paths: list[str] = []
    scanned_entries = 0
    scanned_files = 0
    read_bytes = 0
    retained_bytes = 0
    total_matches = 0

    def consider_file(relative: str, name: str) -> None:
        nonlocal scanned_files, read_bytes, retained_bytes, total_matches
        scanned_files += 1
        if scanned_files > file_limit:
            raise ValueError("workspace replace file limit exceeded")
        if not _matches_glob(name, pattern, case_sensitive=case_sensitive):
            return

        snapshot = snapshot_file(
            workspace,
            relative,
            min(
                per_file_read_limit,
                total_limit - read_bytes,
                total_limit - retained_bytes,
            ),
        )
        canonical = snapshot.path
        if read_bytes + len(snapshot.data) > total_limit:
            raise ValueError("workspace replace total read byte limit exceeded")
        read_bytes += len(snapshot.data)
        if b"\x00" in snapshot.data:
            raise ValueError(f"workspace replace target contains NUL bytes: {canonical}")
        try:
            text = snapshot.data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"workspace replace target is not valid UTF-8 text: {canonical}"
            ) from error

        spans = _literal_match_spans(
            text,
            old_text,
            case_sensitive=case_sensitive,
            remaining_matches=match_limit - total_matches,
            unique_per_file=match_mode == "unique_per_file",
        )
        count = len(spans)
        total_matches += count
        snapshots[canonical] = snapshot
        retained_bytes += len(snapshot.data)
        if retained_bytes > total_limit:
            raise ValueError("workspace replace snapshot and change bytes exceed total byte limit")
        if count:
            matched_paths.append(canonical)

        would_change = any(text[start:end] != new_text for start, end in spans)
        if would_change:
            predicted_bytes = len(snapshot.data) + sum(
                len(new_bytes) - len(text[start:end].encode("utf-8"))
                for start, end in spans
            )
            if predicted_bytes > per_file_write_limit:
                raise ValueError(
                    f"workspace replace output exceeds max_write_bytes: {canonical}"
                )
            if len(changes) >= changed_limit:
                raise ValueError("workspace replace changed file limit exceeded")
            if retained_bytes + predicted_bytes > total_limit:
                raise ValueError(
                    "workspace replace snapshot and change bytes exceed total byte limit"
                )
            after_text = _apply_literal_spans(text, spans, new_text)
            after = after_text.encode("utf-8")
            if len(after) != predicted_bytes:
                raise RuntimeError("workspace replace output byte prediction mismatch")
            changes[canonical] = after
            retained_bytes += len(after)

    try:
        if direct_file is not None:
            consider_file(direct_file, Path(direct_file).name)
        while pending:
            directory, current_depth = pending.popleft()
            try:
                if current_depth >= depth_limit:
                    continue
                children = _bounded_entries(directory, entry_limit - scanned_entries)
                children.sort(key=lambda item: (item.name.casefold(), item.name))
                for child in children:
                    scanned_entries += 1
                    kind = _classify_entry(child)
                    candidate = Path(child.path)
                    if workspace.is_hidden(candidate):
                        continue
                    relative = workspace.relative(candidate)
                    child_depth = current_depth + 1
                    if kind == "directory":
                        checked = workspace.resolve_directory(relative, access="read")
                        if child_depth < depth_limit:
                            pending.append((checked, child_depth))
                        else:
                            release_verified_hold(checked)
                        continue
                    consider_file(relative, child.name)
            finally:
                release_verified_hold(directory)
    finally:
        while pending:
            queued, _ = pending.popleft()
            release_verified_hold(queued)

    if expected is not None and total_matches != expected:
        raise RuntimeError(
            "expected_total_matches mismatch: "
            f"expected {expected}, found {total_matches}"
        )

    # Stable ordering makes previews independent of filesystem enumeration order.
    order_key = lambda value: (value.casefold(), value)
    snapshots = {key: snapshots[key] for key in sorted(snapshots, key=order_key)}
    changes = {key: changes[key] for key in sorted(changes, key=order_key)}
    target_paths = list(snapshots)
    matched_paths.sort(key=order_key)
    changed_paths = list(changes)
    return WorkspacePlan(
        tool_name="workspace_replace",
        snapshots=snapshots,
        changes=changes,
        summary={
            "path": root_relative,
            "target_paths": target_paths,
            "matched_paths": matched_paths,
            "changed_paths": changed_paths,
            "scanned_entry_count": scanned_entries,
            "scanned_file_count": scanned_files,
            "target_file_count": len(target_paths),
            "matched_file_count": len(matched_paths),
            "changed_file_count": len(changed_paths),
            "match_count": total_matches,
            "read_bytes": read_bytes,
            "retained_bytes": retained_bytes,
        },
    )
