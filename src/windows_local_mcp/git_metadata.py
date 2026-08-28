from __future__ import annotations

from collections.abc import Sequence

# Automatic Git must not emit arbitrary commit-object text such as messages or decorations.
# Hashes and the numeric commit timestamp preserve useful history topology without materializing
# free-form object bytes that may contain historical protected information.
GIT_STRUCTURAL_COMMIT_FORMAT = "--format=%H%x09%P%x09%T%x09%ct"
_FREEFORM_PRETTY_FLAGS = frozenset({"--oneline", "--decorate", "--no-decorate"})


def force_structural_commit_output(values: Sequence[str]) -> list[str]:
    """Force Git log/show output to structural fields before any pathspec separator."""

    cleaned = [value for value in values if value not in _FREEFORM_PRETTY_FLAGS]
    if "--" in cleaned:
        split = cleaned.index("--")
        return [
            *cleaned[:split],
            GIT_STRUCTURAL_COMMIT_FORMAT,
            *cleaned[split:],
        ]
    return [*cleaned, GIT_STRUCTURAL_COMMIT_FORMAT]
