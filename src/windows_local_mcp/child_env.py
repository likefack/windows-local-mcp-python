from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping, MutableMapping
from pathlib import Path

from .git_env import is_git_ambient_override, sanitized_git_environment

# Minimal Windows/toolchain environment that ordinary subprocesses commonly need.
# Arbitrary project-specific values are not inherited unless explicitly allowlisted in config.
_BASE_ALLOWED_NAMES = frozenset(
    {
        "ALLUSERSPROFILE",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "APPDATA",
        "COMSPEC",
        "FLUTTER_ROOT",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PUB_CACHE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TZ",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "WINDIR",
    }
)

# These variables can inject code, redirect language/tool runtimes, or alter MCP internals.
# They remain forbidden even if a user tries to add them to child_environment_allowlist.
_FORBIDDEN_EXPLICIT_NAMES = frozenset(
    {
        "CLASSPATH",
        "DART_VM_OPTIONS",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "FLUTTER_TOOL_ARGS",
        "GRADLE_OPTS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5LIB",
        "PSMODULEPATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYLIB",
        "_JAVA_OPTIONS",
        "WINDOWS_LOCAL_MCP_JOB_NONCE",
    }
)

# The server/worker needs these only to locate the same MCP configuration and transport.
# They are deliberately not copied to the final host command.
_INTERNAL_NAMES = frozenset(
    {"LOCAL_MCP_CONFIG", "LOCAL_MCP_ROOT", "LOCAL_MCP_TRANSPORT"}
)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_()]*$")


def normalize_extra_environment_names(names: Iterable[str]) -> list[str]:
    """Validate explicit child-environment additions and return deduplicated uppercase names."""
    result: list[str] = []
    seen: set[str] = set()
    for value in names:
        name = value.strip()
        if not name or not _ENV_NAME.fullmatch(name):
            raise ValueError(f"invalid child environment variable name: {value!r}")
        normalized = name.upper()
        if normalized.startswith("LOCAL_MCP_"):
            raise ValueError(f"MCP internal environment variable cannot be allowlisted: {name}")
        if normalized in _FORBIDDEN_EXPLICIT_NAMES or is_git_ambient_override(normalized):
            raise ValueError(f"unsafe child environment variable cannot be allowlisted: {name}")
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def build_allowlisted_environment(
    source: Mapping[str, str] | None = None,
    *,
    extra_names: Iterable[str] = (),
) -> dict[str, str]:
    """Build a child environment from an explicit allowlist instead of copying the parent."""
    source = os.environ if source is None else source
    allowed = set(_BASE_ALLOWED_NAMES)
    allowed.update(normalize_extra_environment_names(extra_names))
    result: dict[str, str] = {}
    for key, value in source.items():
        if key.upper() in allowed:
            result[key] = value
    return result


def build_worker_environment(
    source: Mapping[str, str] | None = None,
    *,
    extra_names: Iterable[str] = (),
    nonce: str,
) -> dict[str, str]:
    """Build the environment for the internal worker process."""
    source = os.environ if source is None else source
    result = build_allowlisted_environment(source, extra_names=extra_names)
    for key, value in source.items():
        if key.upper() in _INTERNAL_NAMES:
            result[key] = value
    result["WINDOWS_LOCAL_MCP_JOB_NONCE"] = nonce
    return result


def build_command_environment(
    source: Mapping[str, str] | None = None,
    *,
    extra_names: Iterable[str] = (),
    nonce: str,
    git_command: bool = False,
) -> dict[str, str]:
    """Build the final host-command environment without leaking MCP-internal or ambient values."""
    result = build_allowlisted_environment(source, extra_names=extra_names)
    if git_command:
        result = sanitized_git_environment(result)
    result["WINDOWS_LOCAL_MCP_JOB_NONCE"] = nonce
    return result


def sanitize_executable_search_path(
    environment: MutableMapping[str, str],
    *,
    forbidden_roots: Iterable[Path],
    prepend: Iterable[Path] = (),
) -> None:
    """Remove relative and untrusted PATH entries before launching a trusted boundary."""
    # Configured boundary roots and explicitly prepended directories are trusted inputs. If
    # either cannot be resolved, launching without that boundary would be unsafe, so fail.
    roots = [root.resolve(strict=True) for root in forbidden_roots]
    candidates = [str(path.resolve(strict=True)) for path in prepend]
    candidates.extend(environment.get("PATH", "").split(os.pathsep))
    retained: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        value = value.strip().strip('"')
        if not value:
            continue
        candidate = Path(value)
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_dir():
                continue
        except (OSError, RuntimeError):
            # Ambient PATH commonly contains unavailable App Execution Alias or stale
            # directories. They are not required dependencies and must not make a trusted
            # launch use an unsanitized fallback PATH.
            continue
        if any(_is_relative_to(resolved, root) for root in roots):
            continue
        folded = os.path.normcase(str(resolved))
        if folded not in seen:
            seen.add(folded)
            retained.append(str(resolved))
    environment["PATH"] = os.pathsep.join(retained)


def _is_relative_to(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def sanitize_process_environment(
    environment: MutableMapping[str, str] | None = None,
    *,
    extra_names: Iterable[str] = (),
) -> None:
    """Reduce the MCP process environment so internal subprocesses inherit the same safe base."""
    target = os.environ if environment is None else environment
    original = dict(target)
    filtered = build_allowlisted_environment(original, extra_names=extra_names)
    for key, value in original.items():
        if key.upper() in _INTERNAL_NAMES or key.upper() == "WINDOWS_LOCAL_MCP_JOB_NONCE":
            filtered[key] = value
    target.clear()
    target.update(filtered)
