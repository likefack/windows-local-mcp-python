from __future__ import annotations

import configparser
import fnmatch
import hashlib
import os
import shutil
import stat
import struct
import subprocess
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .paths import hold_verified_path, read_verified_bytes, release_verified_hold
from .resources import BoundedStreamCapture, scan_directory_bounded
from .sandbox_backend import (
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    guard_and_launch_codex_sandbox,
    hold_codex_sandbox_backend,
    isolation_context_digest,
    require_codex_sandbox_live_verification,
    resolve_codex_sandbox_backend,
)
from .tool_safety import hold_executable_identity
from .util import canonical_json, sha256_bytes, sha256_text
from .wfp_guard_identity import hold_wfp_guard_implementation
from .windows_job import WindowsJobLimits

GIT_BROKER_POLICY_VERSION = 3
_GIT_PROCESS_LIMIT = 16
_GIT_MEMORY_LIMIT = 1024 * 1024 * 1024
_GIT_CONFIG_LIMIT = 1024 * 1024
_GIT_IGNORE_LIMIT = 1024 * 1024
_GIT_INDEX_LIMIT = 128 * 1024 * 1024
_GIT_INDEX_EXTENDED = 0x4000


class GitBrokerUnavailable(RuntimeError):
    """Automatic Git cannot run without its verified containment boundary."""


@dataclass(frozen=True)
class GitBrokerContainment:
    backend: CodexSandboxBackend
    live_evidence: dict[str, Any]
    policy_digest: str


@dataclass(frozen=True)
class GitBrokerStage:
    root: Path
    repository: Path
    runtime: Path
    source_root: Path
    snapshot_digest: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True)
class GitBrokerResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    backend_version: str
    containment_policy_digest: str
    snapshot_digest: str
    wfp_guard_verification: dict[str, object]


@dataclass
class _ProjectionPrunePolicy:
    root_ignore_globs: tuple[str, ...] = ()
    tracked_paths: frozenset[str] = frozenset()
    pinned_files: dict[str, Path] = field(default_factory=dict)
    pinned_bytes: dict[str, bytes] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return bool(self.root_ignore_globs)

    def close(self) -> None:
        for held in self.pinned_files.values():
            release_verified_hold(held)
        self.pinned_files.clear()
        self.pinned_bytes.clear()


def require_git_broker_containment(
    settings: Settings, git_identity: dict[str, Any]
) -> GitBrokerContainment:
    """Require the already live-verified Windows sandbox before Git is called available."""

    if os.name != "nt":
        raise GitBrokerUnavailable("Automatic Git Broker requires native Windows")
    try:
        backend = resolve_codex_sandbox_backend(settings)
        evidence = require_codex_sandbox_live_verification(settings, backend)
        context = {
            "version": GIT_BROKER_POLICY_VERSION,
            "git_executable": git_identity,
            "git_process_cwd": "trusted-executable-directory-before-fixed--C",
            "sandbox_backend": backend.as_dict(),
            "sandbox_isolation_context_digest": isolation_context_digest(settings, backend),
            "workspace_root": str(settings.workspace_root.resolve(strict=True)),
            "source_workspace_access": "deny",
            "execution_input": "sanitized-disposable-repository-snapshot",
            "network": "deny",
            "host_fallback": False,
        }
        return GitBrokerContainment(
            backend=backend,
            live_evidence=evidence,
            policy_digest=sha256_text(canonical_json(context)),
        )
    except GitBrokerUnavailable:
        raise
    except ApprovedSandboxUnavailable as error:
        raise GitBrokerUnavailable(
            f"Automatic Git Broker containment is unavailable: {error}"
        ) from error
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        raise GitBrokerUnavailable(
            "Automatic Git Broker containment could not be verified"
        ) from error


def _repo_limits(settings: Settings) -> tuple[int, int]:
    # Keep at least half of the configured scratch budget available for the operation-specific
    # runtime tree and transient bounded stdout/stderr files. Do not invent a repository-size
    # floor that can exceed the operator-configured scratch quota.
    byte_limit = max(
        1024,
        min(settings.max_sandbox_scratch_bytes // 2, 1024 * 1024 * 1024),
    )
    entry_limit = max(4096, min(settings.approval_manifest_max_files * 8, 200_000))
    return byte_limit, entry_limit


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    return path.is_symlink() or bool(int(getattr(details, "st_file_attributes", 0)) & 0x400)


def _validate_source_repository(settings: Settings) -> Path:
    """Validate only the metadata root needed to begin projection construction."""

    source = settings.workspace_root.resolve(strict=True)
    metadata = source / ".git"
    held: Path | None = None
    try:
        held = hold_verified_path(
            metadata,
            allow_directory=True,
            allow_hardlinks=True,
        )
        if not stat.S_ISDIR(held.stat().st_mode):
            raise GitBrokerUnavailable(
                "automatic Git requires an in-workspace regular .git directory; gitfiles "
                "require an approved route"
            )
    except GitBrokerUnavailable:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise GitBrokerUnavailable(
            "automatic Git repository metadata root is not safely inspectable"
        ) from error
    finally:
        if held is not None:
            release_verified_hold(held)
    return source


def _protected_worktree_path(relative: Path, settings: Settings) -> bool:
    parts = [part.casefold() for part in relative.parts]
    denied_directories = {name.casefold() for name in settings.read_denied_directories}
    if any(part in denied_directories for part in parts[:-1]):
        return True
    name = relative.name.casefold()
    if name in {value.casefold() for value in settings.blocked_file_names}:
        return True
    return name.startswith(".env.") and name != ".env.example"


def _copy_held_file(
    held: Path,
    destination: Path,
    *,
    byte_limit: int,
) -> tuple[int, str]:
    details = held.stat()
    if details.st_nlink > 1:
        raise GitBrokerUnavailable(f"hard-linked Git input is denied: {held}")
    data = read_verified_bytes(held, byte_limit)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    try:
        shutil.copystat(held, destination, follow_symlinks=False)
    except OSError:
        pass
    return len(data), sha256_bytes(data)


def _copy_verified_file(
    source: Path,
    destination: Path,
    *,
    byte_limit: int,
) -> tuple[int, str]:
    held = hold_verified_path(
        source,
        allow_directory=False,
        allow_hardlinks=False,
        readable=True,
    )
    try:
        return _copy_held_file(held, destination, byte_limit=byte_limit)
    finally:
        release_verified_hold(held)


def _hold_projection_file(path: Path, *, byte_limit: int) -> tuple[Path, bytes]:
    held = hold_verified_path(
        path,
        allow_directory=False,
        allow_hardlinks=False,
        readable=True,
    )
    try:
        details = held.stat()
        if details.st_nlink > 1:
            raise GitBrokerUnavailable(f"hard-linked Git input is denied: {path}")
        if details.st_size > byte_limit:
            raise GitBrokerUnavailable(f"automatic Git planning input exceeds limit: {path}")
        return held, read_verified_bytes(held, byte_limit)
    except Exception:
        release_verified_hold(held)
        raise


def _parse_index_tracked_paths(data: bytes) -> frozenset[str] | None:
    """Return tracked paths for normal v2/v3 indexes, or None when pruning cannot be proven."""

    if len(data) < 32 or data[:4] != b"DIRC":
        return None
    if hashlib.sha1(data[:-20]).digest() != data[-20:]:
        return None
    version, entry_count = struct.unpack(">II", data[4:12])
    if version not in {2, 3}:
        return None
    payload_end = len(data) - 20
    if payload_end < 12:
        return None
    offset = 12
    tracked: set[str] = set()
    for _index in range(entry_count):
        entry_start = offset
        if offset + 62 > payload_end:
            return None
        flags = struct.unpack(">H", data[offset + 60 : offset + 62])[0]
        offset += 62
        if version >= 3 and flags & _GIT_INDEX_EXTENDED:
            if offset + 2 > payload_end:
                return None
            offset += 2
        terminator = data.find(b"\0", offset, payload_end)
        if terminator < 0:
            return None
        raw_path = data[offset:terminator]
        if not raw_path or b"\0" in raw_path:
            return None
        try:
            path = raw_path.decode("utf-8", errors="surrogateescape")
        except UnicodeError:
            return None
        tracked.add(path.replace("\\", "/"))
        consumed = terminator + 1 - entry_start
        offset = entry_start + ((consumed + 7) // 8) * 8
        if offset > payload_end:
            return None

    while offset < payload_end:
        if offset + 8 > payload_end:
            return None
        signature = data[offset : offset + 4]
        extension_size = struct.unpack(">I", data[offset + 4 : offset + 8])[0]
        offset += 8
        if extension_size > payload_end - offset:
            return None
        if signature == b"link":
            # A split index inherits entries from sharedindex.*, so this file alone cannot prove
            # that an ignored directory has no tracked descendants.
            return None
        offset += extension_size

    return frozenset(tracked)


def _safe_root_ignore_globs(data: bytes) -> tuple[str, ...]:
    """Extract a conservative subset that proves a root directory is wholly ignored."""

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ()
    lines = text.splitlines()
    if any(line.startswith("!") for line in lines):
        # A later negation can change the result of an earlier positive pattern.
        return ()
    patterns: list[str] = []
    for line in lines:
        if (
            not line
            or line.startswith("#")
            or line != line.strip()
            or not line.startswith("/")
            or not line.endswith("/")
        ):
            continue
        body = line[1:-1]
        if (
            not body
            or "/" in body
            or "\\" in body
            or "**" in body
            or "[" in body
            or "]" in body
        ):
            continue
        patterns.append(body)
    return tuple(patterns)


def _commands_observe_ignored_untracked(
    commands: Sequence[Sequence[str]],
) -> bool:
    if not commands:
        return True
    for command in commands:
        try:
            index = list(command).index("ls-files")
        except ValueError:
            continue
        tail = set(command[index + 1 :])
        if "--others" in tail and "--exclude-standard" not in tail:
            return True
    return False


def _build_projection_prune_policy(
    source: Path,
    commands: Sequence[Sequence[str]],
    *,
    byte_limit: int,
) -> _ProjectionPrunePolicy:
    policy = _ProjectionPrunePolicy()
    if _commands_observe_ignored_untracked(commands):
        return policy

    index_path = source / ".git" / "index"
    tracked_paths: frozenset[str]
    try:
        index_path.lstat()
    except FileNotFoundError:
        tracked_paths = frozenset()
    except OSError as error:
        raise GitBrokerUnavailable(
            "automatic Git index presence is not safely inspectable"
        ) from error
    else:
        try:
            held_index, index_data = _hold_projection_file(
                index_path,
                byte_limit=min(byte_limit, _GIT_INDEX_LIMIT),
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise GitBrokerUnavailable(
                "automatic Git index is not safely inspectable"
            ) from error
        tracked = _parse_index_tracked_paths(index_data)
        if tracked is None:
            release_verified_hold(held_index)
            return policy
        policy.pinned_files[".git/index"] = held_index
        policy.pinned_bytes[".git/index"] = index_data
        tracked_paths = tracked

    ignore_path = source / ".gitignore"
    try:
        ignore_path.lstat()
    except FileNotFoundError:
        policy.close()
        return _ProjectionPrunePolicy()
    except OSError as error:
        policy.close()
        raise GitBrokerUnavailable(
            "automatic Git root ignore file presence is not safely inspectable"
        ) from error
    try:
        held_ignore, ignore_data = _hold_projection_file(
            ignore_path,
            byte_limit=min(byte_limit, _GIT_IGNORE_LIMIT),
        )
    except (OSError, RuntimeError, ValueError) as error:
        policy.close()
        raise GitBrokerUnavailable(
            "automatic Git root ignore file is not safely inspectable"
        ) from error
    patterns = _safe_root_ignore_globs(ignore_data)
    if not patterns:
        release_verified_hold(held_ignore)
        policy.close()
        return _ProjectionPrunePolicy()

    policy.root_ignore_globs = patterns
    policy.tracked_paths = tracked_paths
    policy.pinned_files[".gitignore"] = held_ignore
    policy.pinned_bytes[".gitignore"] = ignore_data
    return policy


def _tracked_below_root_directory(name: str, tracked_paths: frozenset[str]) -> bool:
    folded_name = name.casefold()
    prefix = f"{folded_name}/"
    return any(
        tracked.casefold() == folded_name or tracked.casefold().startswith(prefix)
        for tracked in tracked_paths
    )


def _can_prune_root_directory(
    relative: Path,
    *,
    prune_policy: _ProjectionPrunePolicy,
) -> bool:
    if not prune_policy.enabled or len(relative.parts) != 1:
        return False
    name = relative.name
    if _tracked_below_root_directory(name, prune_policy.tracked_paths):
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in prune_policy.root_ignore_globs)


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    folded = value.strip().casefold()
    if folded in {"true", "yes", "on", "1"}:
        return True
    if folded in {"false", "no", "off", "0"}:
        return False
    raise GitBrokerUnavailable("automatic Git repository has an invalid boolean core setting")


def _safe_repository_config(source_config: Path, *, byte_limit: int) -> bytes:
    """Parse source config in trusted memory and emit only inert core settings."""

    held = hold_verified_path(
        source_config,
        allow_directory=False,
        allow_hardlinks=False,
        readable=True,
    )
    try:
        details = held.stat()
        if details.st_nlink > 1:
            raise GitBrokerUnavailable("automatic Git repository config is hard-linked")
        config_limit = min(byte_limit, _GIT_CONFIG_LIMIT)
        if details.st_size > config_limit:
            raise GitBrokerUnavailable(
                "automatic Git repository config exceeds the 1 MiB parsing limit"
            )
        raw = read_verified_bytes(held, config_limit)
    finally:
        release_verified_hold(held)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GitBrokerUnavailable("automatic Git repository config is not UTF-8") from error
    parser = configparser.RawConfigParser(
        interpolation=None,
        strict=False,
        allow_no_value=True,
    )
    try:
        parser.read_string(text)
    except configparser.Error as error:
        raise GitBrokerUnavailable(
            "automatic Git repository config is not safely parseable"
        ) from error
    repository_format = parser.get("core", "repositoryformatversion", fallback="0").strip()
    if repository_format != "0":
        raise GitBrokerUnavailable(
            "automatic Git supports repositoryformatversion=0 only; extended repositories "
            "require approval"
        )
    if parser.has_section("extensions") and list(parser.items("extensions")):
        raise GitBrokerUnavailable(
            "automatic Git does not accept repository extensions without explicit approval"
        )
    filemode = _parse_bool(parser.get("core", "filemode", fallback=None), default=False)
    ignorecase = _parse_bool(
        parser.get("core", "ignorecase", fallback=None), default=os.name == "nt"
    )
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        f"\tfilemode = {'true' if filemode else 'false'}\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        f"\tignorecase = {'true' if ignorecase else 'false'}\n"
    ).encode()


def _record_snapshot_file(digest: Any, relative: Path, data: bytes) -> None:
    digest.update(relative.as_posix().encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(len(data)).encode("ascii"))
    digest.update(b"\0")
    digest.update(sha256_bytes(data).encode("ascii"))
    digest.update(b"\n")


def _record_snapshot_digest(
    digest: Any,
    relative: Path,
    *,
    size: int,
    file_digest: str,
) -> None:
    digest.update(relative.as_posix().encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(size).encode("ascii"))
    digest.update(b"\0")
    digest.update(file_digest.encode("ascii"))
    digest.update(b"\n")


def _extended_metadata_action(relative: Path, details: os.stat_result) -> str | None:
    folded = relative.as_posix().casefold()
    unsafe = {
        ".git/commondir",
        ".git/config.worktree",
        ".git/objects/info/alternates",
        ".git/objects/info/http-alternates",
    }
    if folded not in unsafe:
        return None
    if not stat.S_ISREG(details.st_mode) or details.st_size != 0:
        raise GitBrokerUnavailable(
            "automatic Git does not accept external/extended repository metadata: "
            f"{relative}"
        )
    return "copy" if folded == ".git/commondir" else "skip"


def _copy_repository_tree(
    source: Path,
    destination: Path,
    settings: Settings,
    *,
    byte_limit: int,
    entry_limit: int,
    prune_policy: _ProjectionPrunePolicy | None = None,
) -> tuple[int, int, str]:
    prune_policy = prune_policy or _ProjectionPrunePolicy()
    file_count = 0
    entry_count = 0
    total_bytes = 0
    digest = hashlib.sha256()
    pending: list[tuple[Path, Path]] = [(source, Path())]
    while pending:
        current, relative_root = pending.pop()
        held_directory = hold_verified_path(
            current,
            allow_directory=True,
            allow_hardlinks=True,
        )
        try:
            with os.scandir(held_directory) as scanner:
                entries = sorted(scanner, key=lambda entry: entry.name.casefold())
        finally:
            release_verified_hold(held_directory)
        for entry in entries:
            entry_count += 1
            if entry_count > entry_limit:
                raise GitBrokerUnavailable("automatic Git snapshot exceeds its entry-count limit")
            relative = relative_root / entry.name
            candidate = Path(entry.path)
            try:
                details = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise GitBrokerUnavailable(
                    f"automatic Git cannot inspect repository input: {relative}"
                ) from error
            if entry.is_symlink() or bool(
                int(getattr(details, "st_file_attributes", 0)) & 0x400
            ):
                raise GitBrokerUnavailable(f"reparse input is denied: {relative}")

            if relative.parts and relative.parts[0].casefold() == ".git":
                if len(relative.parts) == 1:
                    if not entry.is_dir(follow_symlinks=False):
                        raise GitBrokerUnavailable(
                            "automatic Git requires .git to remain a regular directory"
                        )
                    (destination / relative).mkdir(parents=True, exist_ok=True)
                    pending.append((candidate, relative))
                    continue
                metadata_parts = [part.casefold() for part in relative.parts[1:]]
                action = _extended_metadata_action(relative, details)
                if action == "skip":
                    continue
                if metadata_parts and metadata_parts[0] in {"hooks", "modules"}:
                    continue
                if relative.as_posix().casefold() == ".git/info/attributes":
                    continue
            elif relative.name.casefold() == ".git":
                raise GitBrokerUnavailable(
                    f"automatic Git does not accept nested .git metadata: {relative}"
                )
            elif _protected_worktree_path(
                relative, settings
            ) or relative.name.casefold() == ".gitattributes":
                continue

            if entry.is_dir(follow_symlinks=False):
                if _can_prune_root_directory(relative, prune_policy=prune_policy):
                    continue
                (destination / relative).mkdir(parents=True, exist_ok=True)
                pending.append((candidate, relative))
                continue
            if not entry.is_file(follow_symlinks=False):
                raise GitBrokerUnavailable(f"non-regular Git input is denied: {relative}")
            if details.st_nlink > 1:
                raise GitBrokerUnavailable(f"hard-linked Git input is denied: {relative}")

            file_count += 1
            remaining = byte_limit - total_bytes
            if remaining < 0:
                raise GitBrokerUnavailable("automatic Git snapshot exceeds its byte limit")

            target = destination / relative
            folded = relative.as_posix().casefold()
            if folded == ".git/config":
                data = _safe_repository_config(candidate, byte_limit=remaining)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                size = len(data)
                _record_snapshot_file(digest, relative, data)
            elif folded in prune_policy.pinned_files:
                held = prune_policy.pinned_files[folded]
                data = prune_policy.pinned_bytes[folded]
                if len(data) > remaining:
                    raise GitBrokerUnavailable("automatic Git snapshot exceeds its byte limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                try:
                    shutil.copystat(held, target, follow_symlinks=False)
                except OSError:
                    pass
                size = len(data)
                _record_snapshot_file(digest, relative, data)
            else:
                size, file_digest = _copy_verified_file(
                    candidate,
                    target,
                    byte_limit=remaining,
                )
                _record_snapshot_digest(
                    digest,
                    relative,
                    size=size,
                    file_digest=file_digest,
                )
            total_bytes += size
            if total_bytes > byte_limit:
                raise GitBrokerUnavailable("automatic Git snapshot exceeds its byte limit")
    if not (destination / ".git" / "config").is_file():
        raise GitBrokerUnavailable("automatic Git repository has no .git/config")
    return file_count, total_bytes, digest.hexdigest()


def stage_git_repository(
    settings: Settings,
    token: str,
    *,
    commands: Sequence[Sequence[str]] = (),
) -> GitBrokerStage:
    """Create a bounded, sanitized repository projection outside the live workspace."""

    if settings.sandbox_scratch_dir is None:
        raise GitBrokerUnavailable("sandbox_scratch_dir is required for Automatic Git Broker")
    source = _validate_source_repository(settings)
    byte_limit, entry_limit = _repo_limits(settings)
    prune_policy = _build_projection_prune_policy(
        source,
        commands,
        byte_limit=byte_limit,
    )
    safe_token = "".join(ch for ch in token if ch.isalnum() or ch in "-_")[:120]
    if not safe_token:
        prune_policy.close()
        raise ValueError("invalid Automatic Git snapshot token")
    root = settings.sandbox_scratch_dir / "git-broker" / safe_token
    if root.exists():
        prune_policy.close()
        raise GitBrokerUnavailable("Automatic Git snapshot directory already exists")
    repository = root / "repository"
    runtime = root / "runtime"
    repository.mkdir(parents=True, exist_ok=False)
    runtime.mkdir(parents=True, exist_ok=False)
    try:
        file_count, total_bytes, snapshot_digest = _copy_repository_tree(
            source,
            repository,
            settings,
            byte_limit=byte_limit,
            entry_limit=entry_limit,
            prune_policy=prune_policy,
        )
        verification = scan_directory_bounded(
            repository,
            stop_after_bytes=byte_limit,
            stop_after_entries=entry_limit,
            reject_alternate_streams=True,
            reject_reparse_points=True,
        )
        if verification.total_bytes > byte_limit or verification.entry_count > entry_limit:
            raise GitBrokerUnavailable("staged Automatic Git repository exceeds resource limits")
        return GitBrokerStage(
            root=root,
            repository=repository,
            runtime=runtime,
            source_root=source,
            snapshot_digest=snapshot_digest,
            file_count=file_count,
            total_bytes=total_bytes,
        )
    except GitBrokerUnavailable:
        shutil.rmtree(root, ignore_errors=True)
        raise
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        shutil.rmtree(root, ignore_errors=True)
        raise GitBrokerUnavailable(
            f"automatic Git repository projection could not be verified: {error}"
        ) from error
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    finally:
        prune_policy.close()


def _rewrite_path(value: str, source: Path, destination: Path) -> str:
    candidate = Path(value)
    if not candidate.is_absolute():
        return value
    try:
        relative = candidate.resolve(strict=False).relative_to(source)
    except (OSError, ValueError):
        return value
    return str(destination / relative)


def _rewrite_command(command: Sequence[str], stage: GitBrokerStage) -> list[str]:
    if not command:
        raise ValueError("Git Broker command cannot be empty")
    return [
        command[0],
        *(
            _rewrite_path(value, stage.source_root, stage.repository)
            for value in command[1:]
        ),
    ]


def _rewrite_cwd(cwd: str, stage: GitBrokerStage) -> Path:
    source_cwd = Path(cwd).resolve(strict=True)
    try:
        relative = source_cwd.relative_to(stage.source_root)
    except ValueError as error:
        raise GitBrokerUnavailable("automatic Git cwd escaped workspace_root") from error
    staged = stage.repository / relative
    if not staged.is_dir():
        raise GitBrokerUnavailable("automatic Git cwd is absent from the sanitized snapshot")
    return staged


def _prepare_git_launch(
    command: Sequence[str], stage: GitBrokerStage, git_identity: dict[str, Any], cwd: str
) -> tuple[list[str], Path]:
    """Keep the Windows process cwd trusted and move Git itself with a fixed -C operand."""

    rewritten = _rewrite_command(command, stage)
    staged_cwd = _rewrite_cwd(cwd, stage)
    bound_executable = Path(str(git_identity["path"])).resolve(strict=True)
    if Path(rewritten[0]).resolve(strict=True) != bound_executable:
        raise GitBrokerUnavailable("Automatic Git command does not match the bound executable")
    trusted_launch_cwd = bound_executable.parent.resolve(strict=True)
    return [rewritten[0], "-C", str(staged_cwd), *rewritten[1:]], trusted_launch_cwd


def _map_output_paths(data: bytes, stage: GitBrokerStage) -> bytes:
    replacements = (
        (str(stage.repository).encode(), str(stage.source_root).encode()),
        (stage.repository.as_posix().encode(), stage.source_root.as_posix().encode()),
    )
    result = data
    for staged, source in replacements:
        result = result.replace(staged, source)
    return result


def _git_environment(
    settings: Settings,
    containment: GitBrokerContainment,
    stage: GitBrokerStage,
    git_identity: dict[str, Any],
) -> dict[str, str]:
    nonce = uuid.uuid4().hex
    environment = build_command_environment(
        os.environ,
        extra_names=settings.child_environment_allowlist,
        nonce=nonce,
        git_command=True,
    )
    home = stage.runtime / "home"
    temp = stage.runtime / "temp"
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(home / "AppData" / "Local"),
            "TEMP": str(temp),
            "TMP": str(temp),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_CONFIG_SYSTEM": "NUL",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_ALLOW_PROTOCOL": "",
            "GCM_INTERACTIVE": "Never",
        }
    )
    assert settings.sandbox_scratch_dir is not None
    sanitize_executable_search_path(
        environment,
        forbidden_roots=(
            settings.workspace_root,
            settings.data_dir,
            settings.sandbox_scratch_dir,
        ),
        prepend=(
            Path(str(git_identity["path"])).resolve(strict=True).parent,
            Path(containment.backend.executable).resolve(strict=True).parent,
        ),
    )
    return environment


def _require_current_git_live_marker(
    settings: Settings,
    git_identity: dict[str, Any],
    *,
    live_verification_probe: bool,
) -> None:
    if live_verification_probe:
        return
    # Local import avoids a module cycle: the explicit verifier uses this runner to create the
    # first marker, while every ordinary execution must already have a current marker.
    from .git_broker_live_verify import require_git_broker_live_verification

    require_git_broker_live_verification(settings, git_identity)


def _run_one(
    *,
    settings: Settings,
    containment: GitBrokerContainment,
    stage: GitBrokerStage,
    git_identity: dict[str, Any],
    command: Sequence[str],
    cwd: str,
    deadline: float,
    output_limit: int,
    output_paths: tuple[Path, Path] | None,
    live_verification_probe: bool,
    on_launch: Callable[
        [subprocess.Popen[Any], dict[str, object], CodexSandboxBackend], None
    ]
    | None,
) -> GitBrokerResult:
    launch_command, launch_cwd = _prepare_git_launch(command, stage, git_identity, cwd)
    environment = _git_environment(settings, containment, stage, git_identity)
    if output_paths is None:
        token = uuid.uuid4().hex
        stdout_path = stage.runtime / f"{token}.stdout"
        stderr_path = stage.runtime / f"{token}.stderr"
        persistent = False
    else:
        stdout_path, stderr_path = output_paths
        persistent = True
    process: subprocess.Popen[Any] | None = None
    job: Any | None = None
    stdout_capture: BoundedStreamCapture | None = None
    stderr_capture: BoundedStreamCapture | None = None
    guard_payload: dict[str, object] = {}
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Automatic Git operation deadline exceeded before launch")
        _require_current_git_live_marker(
            settings,
            git_identity,
            live_verification_probe=live_verification_probe,
        )
        process, job, _argv, guard_payload = guard_and_launch_codex_sandbox(
            containment.backend,
            settings=settings,
            command=launch_command,
            cwd=launch_cwd,
            writable_roots=(stage.root,),
            environment=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            limits=WindowsJobLimits(
                max_processes=min(_GIT_PROCESS_LIMIT, containment.backend.max_processes),
                max_memory_bytes=min(
                    _GIT_MEMORY_LIMIT, containment.backend.max_memory_bytes
                ),
            ),
            expected_live_evidence=containment.live_evidence,
        )
        if on_launch is not None:
            on_launch(process, guard_payload, containment.backend)
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("Automatic Git sandbox did not create output pipes")
        stdout_capture = BoundedStreamCapture(process.stdout, stdout_path, output_limit)
        stderr_capture = BoundedStreamCapture(process.stderr, stderr_path, output_limit)
        stdout_capture.start()
        stderr_capture.start()
        while True:
            if job.violation is not None:
                raise GitBrokerUnavailable(
                    f"Automatic Git sandbox resource limit exceeded: {job.violation}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Automatic Git operation exceeded its runtime limit")
            try:
                returncode = process.wait(timeout=min(0.5, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if not job.wait_empty(timeout=min(10.0, max(0.0, deadline - time.monotonic()))):
            raise GitBrokerUnavailable("Automatic Git sandbox descendants did not drain")
        if job.violation is not None:
            raise GitBrokerUnavailable(
                f"Automatic Git sandbox resource limit exceeded: {job.violation}"
            )
        stdout_capture.join()
        stderr_capture.join()
        stdout = _map_output_paths(stdout_path.read_bytes(), stage)
        stderr = _map_output_paths(stderr_path.read_bytes(), stage)
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        return GitBrokerResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_capture.truncated,
            stderr_truncated=stderr_capture.truncated,
            backend_version=containment.backend.version,
            containment_policy_digest=containment.policy_digest,
            snapshot_digest=stage.snapshot_digest,
            wfp_guard_verification=guard_payload,
        )
    finally:
        if job is not None:
            try:
                job.terminate()
                job.wait_empty(timeout=10)
            finally:
                job.close()
        if stdout_capture is not None:
            stdout_capture.join()
        if stderr_capture is not None:
            stderr_capture.join()
        if not persistent:
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)


def run_git_broker_batch(
    *,
    settings: Settings,
    git_identity: dict[str, Any],
    commands: Sequence[Sequence[str]],
    cwd: str,
    timeout: float,
    output_limit: int,
    token: str | None = None,
    output_paths: tuple[Path, Path] | None = None,
    live_verification_probe: bool = False,
    on_launch: Callable[
        [subprocess.Popen[Any], dict[str, object], CodexSandboxBackend], None
    ]
    | None = None,
) -> list[GitBrokerResult]:
    if not commands:
        return []
    containment = require_git_broker_containment(settings, git_identity)
    stage = stage_git_repository(
        settings,
        token or uuid.uuid4().hex,
        commands=commands,
    )
    deadline = time.monotonic() + max(0.0, timeout)
    try:
        with (
            hold_executable_identity(git_identity),
            hold_codex_sandbox_backend(containment.backend),
            hold_wfp_guard_implementation(),
        ):
            results: list[GitBrokerResult] = []
            for index, command in enumerate(commands):
                persistent_paths = output_paths if len(commands) == 1 and index == 0 else None
                results.append(
                    _run_one(
                        settings=settings,
                        containment=containment,
                        stage=stage,
                        git_identity=git_identity,
                        command=command,
                        cwd=cwd,
                        deadline=deadline,
                        output_limit=output_limit,
                        output_paths=persistent_paths,
                        live_verification_probe=live_verification_probe,
                        on_launch=on_launch if index == 0 else None,
                    )
                )
            return results
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)


def run_git_broker_command(
    *,
    settings: Settings,
    git_identity: dict[str, Any],
    command: Sequence[str],
    cwd: str,
    timeout: float,
    output_limit: int,
    token: str | None = None,
    output_paths: tuple[Path, Path] | None = None,
    live_verification_probe: bool = False,
    on_launch: Callable[
        [subprocess.Popen[Any], dict[str, object], CodexSandboxBackend], None
    ]
    | None = None,
) -> GitBrokerResult:
    results = run_git_broker_batch(
        settings=settings,
        git_identity=git_identity,
        commands=(command,),
        cwd=cwd,
        timeout=timeout,
        output_limit=output_limit,
        token=token,
        output_paths=output_paths,
        live_verification_probe=live_verification_probe,
        on_launch=on_launch,
    )
    return results[0]
