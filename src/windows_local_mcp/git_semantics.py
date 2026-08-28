from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Any

from .config import Settings
from .paths import hold_verified_path, read_verified_bytes, release_verified_hold

_GIT_CONFIG_LIMIT = 1024 * 1024
_GIT_FOR_WINDOWS_RUNTIME_ROOTS = frozenset({"mingw64", "mingw32", "clangarm64"})


class GitSemanticConfigUnavailable(RuntimeError):
    """The trusted Git semantic subset could not be reconstructed safely."""


def normalize_core_autocrlf(value: str | None, *, default: str = "false") -> str:
    """Normalize Git's core.autocrlf scalar to the only accepted semantic values."""

    candidate = default if value is None else value
    folded = candidate.strip().casefold()
    if folded == "input":
        return "input"
    if folded in {"true", "yes", "on", "1"}:
        return "true"
    if folded in {"false", "no", "off", "0"}:
        return "false"
    raise GitSemanticConfigUnavailable(
        "Automatic Git encountered an invalid core.autocrlf value"
    )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _trusted_config_path(settings: Settings, path: Path) -> Path:
    resolved = path.resolve(strict=False)
    protected = (
        settings.workspace_root.resolve(strict=True),
        settings.data_dir.resolve(strict=True),
        settings.sandbox_scratch_dir.resolve(strict=True)
        if settings.sandbox_scratch_dir is not None
        else None,
    )
    for root in protected:
        if root is not None and _is_relative_to(resolved, root):
            raise GitSemanticConfigUnavailable(
                "Automatic Git trusted Git config path overlaps an untrusted or control-plane root"
            )
    return resolved


def _parse_trusted_config(settings: Settings, path: Path) -> configparser.RawConfigParser | None:
    candidate = _trusted_config_path(settings, path)
    try:
        candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise GitSemanticConfigUnavailable(
            f"Automatic Git cannot inspect trusted Git config: {candidate}"
        ) from error

    held: Path | None = None
    try:
        held = hold_verified_path(
            candidate,
            allow_directory=False,
            allow_hardlinks=False,
            readable=True,
        )
        details = held.stat()
        if details.st_size > _GIT_CONFIG_LIMIT:
            raise GitSemanticConfigUnavailable(
                "Automatic Git trusted Git config exceeds the 1 MiB parsing limit"
            )
        raw = read_verified_bytes(held, _GIT_CONFIG_LIMIT)
    except GitSemanticConfigUnavailable:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise GitSemanticConfigUnavailable(
            f"Automatic Git trusted Git config is not safely readable: {candidate}"
        ) from error
    finally:
        if held is not None:
            release_verified_hold(held)

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise GitSemanticConfigUnavailable(
            "Automatic Git trusted Git config is not UTF-8"
        ) from error

    parser = configparser.RawConfigParser(
        interpolation=None,
        strict=False,
        allow_no_value=True,
    )
    try:
        parser.read_string(text)
    except configparser.Error as error:
        raise GitSemanticConfigUnavailable(
            "Automatic Git trusted Git config is not safely parseable"
        ) from error

    for section in parser.sections():
        folded = section.strip().casefold()
        if folded == "include" or folded.startswith("includeif "):
            raise GitSemanticConfigUnavailable(
                "Automatic Git does not reconstruct Git config include semantics automatically"
            )
    return parser


def _core_autocrlf_from_file(settings: Settings, path: Path) -> str | None:
    parser = _parse_trusted_config(settings, path)
    if parser is None:
        return None
    value = parser.get("core", "autocrlf", fallback=None)
    if value is None:
        return None
    return normalize_core_autocrlf(value)


def _git_for_windows_install_root(git_identity: dict[str, Any]) -> Path:
    try:
        executable = Path(str(git_identity["path"])).resolve(strict=True)
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        raise GitSemanticConfigUnavailable(
            "Automatic Git cannot resolve the pinned Git runtime for semantic config"
        ) from error
    if (
        executable.name.casefold() != "git.exe"
        or executable.parent.name.casefold() != "bin"
        or executable.parent.parent.name.casefold()
        not in _GIT_FOR_WINDOWS_RUNTIME_ROOTS
    ):
        raise GitSemanticConfigUnavailable(
            "Automatic Git cannot derive the trusted Git for Windows config root from the "
            "pinned runtime layout"
        )
    return executable.parent.parent.parent.resolve(strict=True)


def _operator_home() -> Path:
    home_value = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home_value:
        return Path(os.path.expandvars(os.path.expanduser(home_value))).resolve(strict=False)
    return Path.home().resolve(strict=False)


def resolve_trusted_core_autocrlf(
    settings: Settings,
    git_identity: dict[str, Any],
) -> str:
    """Reconstruct only the inert core.autocrlf scalar from trusted Git config scopes.

    The Git child continues to receive no raw system/global config. This function reads the
    operator/toolchain config in the trusted Broker process, rejects include semantics, and
    returns only a normalized scalar that can be copied into the sanitized repository config.
    Repository-local direct overrides are applied later while the verified source .git/config
    is sanitized.
    """

    install_root = _git_for_windows_install_root(git_identity)
    system_candidates = [install_root / "etc" / "gitconfig"]
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        system_candidates.append(Path(program_data) / "Git" / "config")

    system_values = [
        value
        for value in (
            _core_autocrlf_from_file(settings, candidate)
            for candidate in system_candidates
        )
        if value is not None
    ]
    if len(set(system_values)) > 1:
        raise GitSemanticConfigUnavailable(
            "Automatic Git found conflicting core.autocrlf values in Windows system Git config"
        )
    resolved = system_values[-1] if system_values else "false"

    home = _operator_home()
    xdg_value = os.environ.get("XDG_CONFIG_HOME")
    xdg_root = (
        Path(os.path.expandvars(os.path.expanduser(xdg_value))).resolve(strict=False)
        if xdg_value
        else home / ".config"
    )
    for candidate in (xdg_root / "git" / "config", home / ".gitconfig"):
        value = _core_autocrlf_from_file(settings, candidate)
        if value is not None:
            resolved = value
    return normalize_core_autocrlf(resolved)
