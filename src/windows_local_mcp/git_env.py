from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping

_GIT_AMBIENT_EXACT = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_INDEX_FILE",
        "GIT_SHALLOW_FILE",
        "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "GIT_LITERAL_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
        "GIT_CONFIG",
    }
)
_GIT_AMBIENT_PREFIXES = ("GIT_CONFIG_",)


def is_git_ambient_override(name: str) -> bool:
    """Return whether an environment variable can redirect or reinterpret Git access."""
    normalized = name.upper()
    return normalized in _GIT_AMBIENT_EXACT or any(
        normalized.startswith(prefix) for prefix in _GIT_AMBIENT_PREFIXES
    )


def sanitized_git_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a copy of an environment with Git repository/config overrides removed."""
    source = os.environ if environment is None else environment
    return {key: value for key, value in source.items() if not is_git_ambient_override(key)}


def strip_git_ambient_environment(
    environment: MutableMapping[str, str] | None = None,
) -> None:
    """Remove Git repository/config overrides from a live process environment in place."""
    target = os.environ if environment is None else environment
    for key in list(target):
        if is_git_ambient_override(key):
            target.pop(key, None)
