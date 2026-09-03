from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .util import sha256_bytes

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class TextEditPlan:
    """One fully validated, ambiguity-free text-file replacement plan."""

    path: str
    expected_sha256: str
    before: bytes
    after: bytes
    replacement_count: int


def plan_exact_text_edits(
    edits: list[dict[str, Any]],
    *,
    read_file: Any,
    max_files: int,
    max_read_bytes: int,
    max_write_bytes: int,
    max_total_bytes: int,
) -> list[TextEditPlan]:
    """Validate every CAS precondition and build all outputs before any mutation starts."""

    if not isinstance(edits, list) or not edits:
        raise ValueError("edits must contain at least one text edit")
    if len(edits) > max_files:
        raise ValueError("edit file count exceeds max_high_level_files")

    seen: set[str] = set()
    plans: list[TextEditPlan] = []
    total_bytes = 0
    for edit in edits:
        if not isinstance(edit, dict):
            raise TypeError("each edit must be an object")
        unknown = set(edit) - {"path", "expected_sha256", "replacements"}
        if unknown:
            raise ValueError("unsupported text edit fields: " + ", ".join(sorted(unknown)))
        path = edit.get("path")
        expected = edit.get("expected_sha256")
        replacements = edit.get("replacements")
        if not isinstance(path, str) or not path:
            raise ValueError("each edit requires a non-empty path")
        if path.casefold() in seen:
            raise ValueError("each workspace_apply path must be unique")
        seen.add(path.casefold())
        if not isinstance(expected, str) or _SHA256_RE.fullmatch(expected) is None:
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        if not isinstance(replacements, list) or not replacements:
            raise ValueError("each edit requires at least one exact replacement")

        before = read_file(path)
        if not isinstance(before, bytes):
            raise TypeError("read_file callback must return bytes")
        if len(before) > max_read_bytes:
            raise ValueError("existing file exceeds max_text_file_bytes")
        if sha256_bytes(before) != expected:
            raise RuntimeError("expected_sha256 mismatch; target is stale or concurrently modified")
        try:
            text = before.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("existing file is not UTF-8 text") from error

        for replacement in replacements:
            if not isinstance(replacement, dict):
                raise TypeError("each replacement must be an object")
            if set(replacement) != {"old_text", "new_text"}:
                raise ValueError("replacement requires only old_text and new_text")
            old_text = replacement.get("old_text")
            new_text = replacement.get("new_text")
            if not isinstance(old_text, str) or not isinstance(new_text, str):
                raise TypeError("old_text and new_text must be strings")
            if not old_text:
                raise ValueError("old_text must not be empty")
            occurrences = text.count(old_text)
            if occurrences != 1:
                raise RuntimeError(
                    "exact replacement is ambiguous or stale; old_text must occur exactly once"
                )
            text = text.replace(old_text, new_text, 1)

        after = text.encode("utf-8")
        if len(after) > max_write_bytes:
            raise ValueError("edited file exceeds max_write_bytes")
        total_bytes += len(before) + len(after)
        if total_bytes > max_total_bytes:
            raise ValueError("text edit request exceeds max_high_level_total_bytes")
        plans.append(
            TextEditPlan(
                path=path,
                expected_sha256=expected,
                before=before,
                after=after,
                replacement_count=len(replacements),
            )
        )
    return plans
