"""Bounded, read-only workspace operations used by the high-level MCP surface.

The functions in this module deliberately stay close to the existing workspace boundary.
They do not implement a second path validator or a second file-reading primitive: every
candidate is resolved through :class:`~windows_local_mcp.paths.Workspace`, and file bytes
are consumed through ``read_verified_bytes`` so Windows reads use the validation handle.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from collections import deque
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .paths import Workspace, read_verified_bytes, release_verified_hold

# These are request-level defaults, not new security policy.  The effective per-file
# boundary always remains ``settings.max_text_file_bytes`` and traversal remains bounded
# by ``settings.max_directory_entries``.
_DEFAULT_READ_FILES = 32
_DEFAULT_SEARCH_RESULTS = 100
_MAX_TREE_DEPTH = 64
_MAX_REQUEST_RESPONSE_BYTES = 32 * 1024 * 1024


def _setting(settings: Any, name: str, default: int) -> int:
    value = getattr(settings, name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"settings.{name} must be a positive integer")
    return value


def _request_limit(
    value: int | None,
    *,
    name: str,
    default: int,
    maximum: int | None = None,
    allow_zero: bool = False,
) -> int:
    limit = default if value is None else value
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError(f"{name} must be an integer")
    minimum = 0 if allow_zero else 1
    if limit < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and limit > maximum:
        raise ValueError(f"{name} exceeds the configured bound")
    return limit


def _directory_entry_limit(settings: Any, requested: int | None) -> int:
    configured = _setting(settings, "max_directory_entries", 3000)
    return _request_limit(
        requested,
        name="max_entries",
        default=configured,
        maximum=configured,
    )


def _file_byte_limit(settings: Any) -> int:
    return _setting(settings, "max_text_file_bytes", 2 * 1024 * 1024)


def _request_file_limit(settings: Any, requested: int | None) -> int:
    configured = _setting(settings, "max_directory_entries", 3000)
    default = min(_DEFAULT_READ_FILES, configured)
    return _request_limit(
        requested,
        name="max_files",
        default=default,
        maximum=configured,
    )


def _request_total_byte_limit(
    settings: Any,
    requested: int | None,
    *,
    max_files: int,
) -> int:
    per_file = _file_byte_limit(settings)
    # The request default is finite even when a caller supplies a permissive directory
    # quota.  A caller may lower it, or raise it up to the safe per-file aggregate.
    aggregate = per_file * max_files
    default = min(aggregate, _MAX_REQUEST_RESPONSE_BYTES)
    return _request_limit(
        requested,
        name="max_total_bytes",
        default=default,
        maximum=aggregate,
        allow_zero=True,
    )


def _validate_depth(value: int | None, *, default: int) -> int:
    return _request_limit(
        value,
        name="max_depth",
        default=default,
        maximum=_MAX_TREE_DEPTH,
        allow_zero=True,
    )


def _validate_file_glob(file_glob: str | None) -> str | None:
    if file_glob is None:
        return None
    if not isinstance(file_glob, str) or not file_glob or "\x00" in file_glob:
        raise ValueError("file_glob must be a non-empty string without NUL")
    if "/" in file_glob or "\\" in file_glob:
        raise ValueError("file_glob must match a file name, not a path")
    return file_glob


def _classify_entry(entry: os.DirEntry[str]) -> str:
    """Classify an entry without following a reparse target.

    Recursive high-level operations cannot safely return a reparse entry and continue,
    because a later path reopen could follow a target that was not in the workspace.  The
    operation therefore refuses the entry after inspecting it with no-follow semantics.
    """

    try:
        details = entry.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        raise RuntimeError(f"workspace entry disappeared during traversal: {entry.path}") from error
    attributes = int(getattr(details, "st_file_attributes", 0))
    if entry.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise PermissionError(f"workspace reparse point is denied: {entry.path}")
    if stat.S_ISDIR(details.st_mode):
        return "directory"
    if stat.S_ISREG(details.st_mode):
        return "file"
    raise PermissionError(f"workspace entry is not a regular file or directory: {entry.path}")


def _bounded_entries(directory: Path, remaining: int) -> list[os.DirEntry[str]]:
    """Read at most ``remaining + 1`` names so an entry-limit breach is fail closed."""

    if remaining < 0:
        raise ValueError("workspace entry limit exceeded")
    with os.scandir(directory) as scanner:
        entries: list[os.DirEntry[str]] = []
        for _ in range(remaining + 1):
            entry = next(scanner, None)
            if entry is None:
                break
            entries.append(entry)
    if len(entries) > remaining:
        raise ValueError("workspace entry limit exceeded")
    return sorted(entries, key=lambda item: item.name.casefold())


def _file_result(
    workspace: Workspace,
    settings: Any,
    relative_path: str,
    *,
    max_bytes: int,
    start_line: int | None = None,
    end_line: int | None = None,
) -> tuple[dict[str, Any], int]:
    """Read one regular file through its verified handle and return metadata plus bytes."""

    file_path = workspace.resolve_existing(
        relative_path,
        allow_directory=False,
        access="read",
    )
    try:
        before = workspace.identity(file_path)
        if before is None:
            raise RuntimeError(f"workspace file disappeared before reading: {relative_path}")
        if before.size > max_bytes:
            raise ValueError(f"file exceeds byte limit: {before.size} > {max_bytes}")
        raw = read_verified_bytes(file_path, max_bytes)
        after = workspace.identity(file_path)
        if after is None or after != before or len(raw) != before.size:
            raise RuntimeError(f"workspace file changed during read: {relative_path}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                "file is not valid UTF-8 text; use the byte-exact artifact route for binary files"
            ) from error

        lines = text.splitlines()
        start = 1 if start_line is None else max(1, start_line)
        end = len(lines) if end_line is None else min(len(lines), max(start, end_line))
        result = {
            "path": workspace.relative(file_path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_bytes": len(raw),
            "newline": (
                "mixed"
                if "\r\n" in text and "\n" in text.replace("\r\n", "")
                else "crlf"
                if "\r\n" in text
                else "lf"
            ),
            "start_line": start,
            "end_line": end,
            "total_lines": len(lines),
            "content": "\n".join(lines[start - 1 : end]),
        }
        return result, len(raw)
    finally:
        # On Windows this closes the component/file handles retained by resolve_existing.
        release_verified_hold(file_path)


def _root_directory(workspace: Workspace, path: str) -> tuple[Path, str]:
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    directory = workspace.resolve_directory(path, access="read")
    return directory, workspace.relative(directory)


def workspace_tree(
    workspace: Workspace,
    settings: Any,
    path: str = ".",
    *,
    max_depth: int | None = 3,
    max_entries: int | None = None,
) -> dict[str, Any]:
    """Return a bounded directory tree without following reparse points."""

    depth_limit = _validate_depth(max_depth, default=3)
    entry_limit = _directory_entry_limit(settings, max_entries)
    root, root_relative = _root_directory(workspace, path)
    pending: deque[tuple[Path, int]] = deque([(root, 0)])
    entries: list[dict[str, Any]] = []
    visited_entries = 0
    try:
        while pending:
            directory, current_depth = pending.popleft()
            try:
                if current_depth >= depth_limit:
                    continue
                remaining = entry_limit - visited_entries
                children = _bounded_entries(directory, remaining)
                for child in children:
                    visited_entries += 1
                    kind = _classify_entry(child)
                    candidate = Path(child.path)
                    relative = workspace.relative(candidate)
                    if workspace.is_hidden(candidate):
                        continue
                    child_depth = current_depth + 1
                    if kind == "directory":
                        checked = workspace.resolve_directory(relative, access="read")
                        try:
                            identity = workspace.identity(checked)
                            if identity is None:
                                raise RuntimeError(f"workspace directory disappeared: {relative}")
                            entries.append(
                                {
                                    "path": relative,
                                    "name": child.name,
                                    "type": "directory",
                                    "depth": child_depth,
                                }
                            )
                        finally:
                            # Keep a separate verified handle in the queue only when it will
                            # actually be traversed at the requested depth.
                            if child_depth < depth_limit:
                                pending.append((checked, child_depth))
                            else:
                                release_verified_hold(checked)
                    else:
                        checked = workspace.resolve_existing(
                            relative,
                            allow_directory=False,
                            access="read",
                        )
                        try:
                            identity = workspace.identity(checked)
                            if identity is None:
                                raise RuntimeError(f"workspace file disappeared: {relative}")
                            entries.append(
                                {
                                    "path": relative,
                                    "name": child.name,
                                    "type": "file",
                                    "depth": child_depth,
                                    "size": identity.size,
                                }
                            )
                        finally:
                            release_verified_hold(checked)
            finally:
                release_verified_hold(directory)
    finally:
        while pending:
            pending_directory, _ = pending.popleft()
            release_verified_hold(pending_directory)

    return {
        "path": root_relative,
        "entries": entries,
        "entry_count": len(entries),
        "scanned_entry_count": visited_entries,
        "max_depth": depth_limit,
    }


def workspace_search(
    workspace: Workspace,
    settings: Any,
    path: str,
    query: str,
    *,
    file_glob: str | None = None,
    case_sensitive: bool = False,
    max_depth: int | None = None,
    max_entries: int | None = None,
    max_files: int | None = None,
    max_results: int | None = None,
    max_total_bytes: int | None = None,
) -> dict[str, Any]:
    """Search bounded UTF-8 text files with literal substring matching.

    ``query`` is intentionally not a regular expression.  Matching and traversal happen
    inside LocalMCP, while every opened file still goes through the existing workspace and
    same-handle read boundary.
    """

    if not isinstance(query, str) or not query or "\x00" in query:
        raise ValueError("query must be a non-empty string without NUL")
    if not isinstance(case_sensitive, bool):
        raise TypeError("case_sensitive must be boolean")
    pattern = _validate_file_glob(file_glob)
    depth_limit = _validate_depth(max_depth, default=_MAX_TREE_DEPTH)
    entry_limit = _directory_entry_limit(settings, max_entries)
    file_limit = _request_file_limit(settings, max_files)
    result_limit = _request_limit(
        max_results,
        name="max_results",
        default=min(_DEFAULT_SEARCH_RESULTS, entry_limit),
        maximum=entry_limit,
    )
    total_limit = _request_total_byte_limit(settings, max_total_bytes, max_files=file_limit)
    root, root_relative = _root_directory(workspace, path)
    pending: deque[tuple[Path, int]] = deque([(root, 0)])
    matches: list[dict[str, Any]] = []
    scanned_files = 0
    scanned_bytes = 0
    needle = query if case_sensitive else query.casefold()
    visited_entries = 0
    try:
        while pending:
            directory, current_depth = pending.popleft()
            try:
                if current_depth >= depth_limit:
                    continue
                children = _bounded_entries(directory, entry_limit - visited_entries)
                for child in children:
                    visited_entries += 1
                    kind = _classify_entry(child)
                    candidate = Path(child.path)
                    relative = workspace.relative(candidate)
                    if workspace.is_hidden(candidate):
                        continue
                    child_depth = current_depth + 1
                    if kind == "directory":
                        checked = workspace.resolve_directory(relative, access="read")
                        if child_depth < depth_limit:
                            pending.append((checked, child_depth))
                        else:
                            release_verified_hold(checked)
                        continue

                    scanned_files += 1
                    if scanned_files > file_limit:
                        raise ValueError("workspace search file limit exceeded")
                    if pattern is not None:
                        left = child.name if case_sensitive else child.name.casefold()
                        right = pattern if case_sensitive else pattern.casefold()
                        if not fnmatch.fnmatchcase(left, right):
                            continue
                    # Resolve once to obtain the stable size before committing request quota.
                    checked = workspace.resolve_existing(
                        relative,
                        allow_directory=False,
                        access="read",
                    )
                    try:
                        identity = workspace.identity(checked)
                        if identity is None:
                            raise RuntimeError(f"workspace file disappeared: {relative}")
                        if identity.size > _file_byte_limit(settings):
                            raise ValueError(
                                f"file exceeds byte limit: {identity.size} > "
                                f"{_file_byte_limit(settings)}"
                            )
                        if scanned_bytes + identity.size > total_limit:
                            raise ValueError("workspace search total byte limit exceeded")
                    finally:
                        release_verified_hold(checked)
                    result, raw_bytes = _file_result(
                        workspace,
                        settings,
                        relative,
                        max_bytes=min(_file_byte_limit(settings), total_limit - scanned_bytes),
                    )
                    scanned_bytes += raw_bytes
                    text = result["content"] if result["start_line"] == 1 and result["end_line"] == result["total_lines"] else None
                    if text is None:
                        # _file_result is called without line bounds above, so this is only a
                        # defensive branch if that implementation changes later.
                        text = result["content"]
                    for line_number, line in enumerate(text.splitlines(), start=1):
                        haystack = line if case_sensitive else line.casefold()
                        if needle not in haystack:
                            continue
                        if len(matches) >= result_limit:
                            raise ValueError("workspace search result limit exceeded")
                        matches.append(
                            {
                                "path": result["path"],
                                "line": line_number,
                                "text": line,
                            }
                        )
            finally:
                release_verified_hold(directory)
    finally:
        while pending:
            pending_directory, _ = pending.popleft()
            release_verified_hold(pending_directory)

    return {
        "path": root_relative,
        "query": query,
        "matches": matches,
        "result_count": len(matches),
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "scanned_entry_count": visited_entries,
        "max_depth": depth_limit,
    }


def _iter_requested_paths(paths: Iterable[str], max_files: int) -> list[str]:
    if isinstance(paths, (str, bytes)):
        raise TypeError("paths must be a sequence of workspace-relative paths")
    output: list[str] = []
    iterator = iter(paths)
    for index in range(max_files + 1):
        try:
            item = next(iterator)
        except StopIteration:
            break
        if index >= max_files:
            raise ValueError("read_files file count limit exceeded")
        if not isinstance(item, str):
            raise TypeError("each read_files path must be a string")
        output.append(item)
    if not output:
        raise ValueError("paths must contain at least one file")
    return output


def read_files(
    workspace: Workspace,
    settings: Any,
    paths: Sequence[str] | Iterable[str],
    *,
    max_files: int | None = None,
    max_total_bytes: int | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> dict[str, Any]:
    """Read several bounded UTF-8 workspace files in one logical read operation."""

    if start_line is not None and (
        isinstance(start_line, bool) or not isinstance(start_line, int) or start_line < 1
    ):
        raise ValueError("start_line must be a positive integer")
    if end_line is not None and (
        isinstance(end_line, bool) or not isinstance(end_line, int) or end_line < 1
    ):
        raise ValueError("end_line must be a positive integer")
    file_limit = _request_file_limit(settings, max_files)
    total_limit = _request_total_byte_limit(settings, max_total_bytes, max_files=file_limit)
    requested = _iter_requested_paths(paths, file_limit)
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for path in requested:
        # Resolve once before reading to canonicalize case and reject duplicate targets.  The
        # actual bytes are read by _file_result, which repeats validation for the read handle.
        checked = workspace.resolve_existing(path, allow_directory=False, access="read")
        try:
            canonical = workspace.relative(checked)
            key = os.path.normcase(canonical)
        finally:
            release_verified_hold(checked)
        if key in seen:
            raise ValueError(f"duplicate workspace path: {canonical}")
        seen.add(key)
        result, raw_bytes = _file_result(
            workspace,
            settings,
            canonical,
            max_bytes=min(_file_byte_limit(settings), total_limit - total_bytes),
            start_line=start_line,
            end_line=end_line,
        )
        total_bytes += raw_bytes
        if total_bytes > total_limit:
            raise ValueError("read_files total byte limit exceeded")
        files.append(result)
    return {
        "files": files,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "max_total_bytes": total_limit,
    }
