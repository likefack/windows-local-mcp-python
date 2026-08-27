from __future__ import annotations

import re
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, PrivateAttr

from .config import Settings
from .paths import Workspace
from .tool_safety import capture_executable_identity, trusted_helper_identity
from .util import canonical_json, sha256_text


class NormalizedCommand(BaseModel):
    executable: str
    args: list[str]
    cwd: str
    display_command: list[str]
    program_key: str
    network_expected: bool = False
    executable_identity: dict[str, object] | None = None
    _cwd_hold: Path | None = PrivateAttr(default=None)


class CommandPolicy:
    """Deny-by-default grammars for commands that may run without approval."""

    GIT_SUBCOMMANDS: ClassVar[set[str]] = {
        "status",
        "diff",
        "log",
        "show",
        "rev-parse",
        "ls-files",
    }
    GIT_COMMON_FLAGS: ClassVar[set[str]] = {
        "--no-color",
        "--color=never",
        "--stat",
        "--name-only",
        "--name-status",
        "--oneline",
        "--decorate",
        "--no-decorate",
        "--no-patch",
    }
    SAFE_REVISION = re.compile(r"[A-Za-z0-9._/@~^{}+-]+")
    SAFE_LOG_COUNT = re.compile(r"-(?:[1-9]|[1-9][0-9]|1[0-9]{2}|200)")
    ADB_PROPERTIES: ClassVar[set[str]] = {
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.kernel.qemu",
    }

    def __init__(self, settings: Settings, workspace: Workspace) -> None:
        self.settings = settings
        self.workspace = workspace

    @staticmethod
    def _reject_nul(values: Sequence[str]) -> None:
        for value in values:
            if "\x00" in value:
                raise ValueError("NUL is not allowed in command arguments")

    @staticmethod
    def _resolve_executable(candidates: Sequence[str]) -> str:
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return str(Path(resolved).resolve())
        raise FileNotFoundError(f"executable was not found on PATH: {', '.join(candidates)}")

    def _resolve_safe_executable(self, program_key: str) -> dict[str, object]:
        return trusted_helper_identity(self.settings, program_key)

    def _require_workspace_git_root(self) -> None:
        """Prevent automatic Git from discovering and reading a repository above workspace_root."""
        if not (self.workspace.root / ".git").exists():
            raise PermissionError(
                "automatic Git requires workspace_root itself to be a Git worktree root"
            )

    @staticmethod
    def _program_key(program: str) -> str:
        key = Path(program).name.casefold()
        for suffix in (".exe", ".bat", ".cmd"):
            key = key.removesuffix(suffix)
        return key

    def normalize_safe(self, *, program: str, args: list[str], cwd: str) -> NormalizedCommand:
        if not args:
            raise ValueError("a subcommand or arguments are required")
        self._reject_nul([program, *args])
        self._check_argument_limits(args)
        cwd_path = self.workspace.resolve_directory(cwd, access="read")
        key = self._program_key(program)

        if key == "git":
            self._require_enabled("git", self.settings.git_enabled)
            self._require_workspace_git_root()
            normalized_args = self._normalize_git(args)
            identity = self._resolve_safe_executable("git")
            return self._result(identity, normalized_args, cwd_path, "git")

        if key in {"flutter", "dart"}:
            raise PermissionError(
                f"{key} processing may load project-controlled code or plugins; "
                "use request_sandbox_command"
            )

        if key == "adb":
            self._require_enabled("adb", self.settings.adb_enabled)
            normalized_args = self._normalize_adb(args)
            identity = self._resolve_safe_executable("adb")
            return self._result(identity, normalized_args, cwd_path, "adb")

        raise PermissionError(
            f"{program} is not eligible for automatic execution; use request_sandbox_command"
        )

    def normalize_host(
        self,
        *,
        command: list[str],
        cwd: str,
        network_expected: bool,
    ) -> NormalizedCommand:
        if not command:
            raise ValueError("command must contain an executable")
        self._reject_nul(command)
        self._check_argument_limits(command)
        cwd_path = self.workspace.resolve_directory(cwd, access="read")
        executable = shutil.which(command[0])
        if executable is None:
            candidate = Path(command[0]).expanduser()
            if candidate.exists() and candidate.is_file():
                executable = str(candidate.resolve())
            else:
                raise FileNotFoundError(f"executable was not found: {command[0]}")
        key = self._program_key(executable)
        self._require_host_capability(key)
        identity = capture_executable_identity(
            executable, provenance="approval-request"
        )
        normalized = NormalizedCommand(
            executable=str(identity["path"]),
            args=list(command[1:]),
            cwd=str(cwd_path),
            display_command=list(command),
            program_key=key,
            network_expected=network_expected,
            executable_identity=identity,
        )
        normalized._cwd_hold = cwd_path
        return normalized

    def _require_host_capability(self, key: str) -> None:
        if key == "git":
            self._require_enabled("git", self.settings.git_enabled)
        elif key == "flutter":
            self._require_enabled("flutter", self.settings.flutter_enabled)
        elif key == "dart":
            self._require_enabled("dart", self.settings.dart_enabled)
        elif key == "adb":
            self._require_enabled("adb", self.settings.adb_enabled)
        elif key in {"powershell", "pwsh"}:
            self._require_enabled("PowerShell", self.settings.powershell_enabled)

    @staticmethod
    def _require_enabled(name: str, enabled: bool) -> None:
        if not enabled:
            raise PermissionError(f"{name} capability is disabled")

    def _check_argument_limits(self, values: list[str]) -> None:
        if len(values) > self.settings.max_command_arguments:
            raise ValueError("command exceeds max_command_arguments")
        if any(
            len(value) > self.settings.max_command_argument_characters for value in values
        ):
            raise ValueError("command argument exceeds max_command_argument_characters")

    def _normalize_git(self, args: list[str]) -> list[str]:
        subcommand = args[0].casefold()
        if subcommand not in self.GIT_SUBCOMMANDS:
            raise PermissionError(f"git {args[0]} requires human approval")
        tail = list(args[1:])

        if subcommand == "status":
            allowed = {
                "--short",
                "-s",
                "--branch",
                "-b",
                "--porcelain",
                "--porcelain=v1",
                "--untracked-files=all",
                "--untracked-files=normal",
                "--untracked-files=no",
            }
            normalized = self._flags_and_pathspec(tail, allowed)
        elif subcommand == "diff":
            has_paths = "--" in tail and bool(tail[tail.index("--") + 1 :])
            explicit_content = any(value in {"--patch", "-p", "--binary"} for value in tail)
            metadata_only = any(
                value in {"--stat", "--name-only", "--name-status", "--quiet"}
                for value in tail
            )
            content_output = has_paths and (explicit_content or not metadata_only)
            allowed = self.GIT_COMMON_FLAGS | {
                "--cached",
                "--staged",
                "--quiet",
                "--exit-code",
                "--no-renames",
            }
            if has_paths:
                allowed |= {"--patch", "-p", "--binary"}
            normalized = self._git_revisions_flags_paths(
                tail,
                allowed,
                files_only=content_output,
                require_commitish=True,
            )
            if not has_paths and not any(
                value in {"--stat", "--name-only", "--name-status", "--quiet"}
                for value in normalized
            ):
                normalized.insert(0, "--stat")
            normalized = ["--no-ext-diff", "--no-textconv", *normalized]
        elif subcommand == "log":
            allowed = self.GIT_COMMON_FLAGS | {"--all", "--branches", "--tags"}
            normalized = self._git_revisions_flags_paths(tail, allowed, allow_count=True)
            normalized = ["--no-ext-diff", "--no-textconv", *normalized]
        elif subcommand == "show":
            has_paths = "--" in tail and bool(tail[tail.index("--") + 1 :])
            explicit_content = any(value in {"--patch", "-p"} for value in tail)
            metadata_only = any(
                value in {"--stat", "--name-only", "--name-status", "--no-patch"}
                for value in tail
            )
            content_output = has_paths and (explicit_content or not metadata_only)
            allowed = self.GIT_COMMON_FLAGS | ({"--patch", "-p"} if has_paths else set())
            normalized = self._git_revisions_flags_paths(
                tail,
                allowed,
                files_only=content_output,
                require_commitish=True,
                default_revision="HEAD",
            )
            if not has_paths and not any(
                value in {"--stat", "--name-only", "--name-status", "--no-patch"}
                for value in normalized
            ):
                normalized.insert(0, "--no-patch")
            normalized = ["--no-ext-diff", "--no-textconv", *normalized]
        elif subcommand == "rev-parse":
            permitted = {
                ("HEAD",),
                ("--short", "HEAD"),
                ("--abbrev-ref", "HEAD"),
                ("--show-toplevel",),
                ("--is-inside-work-tree",),
            }
            if tuple(tail) not in permitted:
                raise PermissionError("git rev-parse arguments are not in the safe grammar")
            normalized = tail
        else:  # ls-files
            allowed = {
                "--cached",
                "--modified",
                "--deleted",
                "--others",
                "--exclude-standard",
                "--stage",
            }
            normalized = self._flags_and_pathspec(tail, allowed)

        return [
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "diff.autoRefreshIndex=false",
            "-c",
            "diff.external=",
            "-c",
            "credential.helper=",
            subcommand,
            *normalized,
        ]

    def _flags_and_pathspec(self, values: list[str], allowed: set[str]) -> list[str]:
        if "--" in values:
            split = values.index("--")
            flags, paths = values[:split], values[split + 1 :]
        else:
            flags, paths = values, []
        if any(flag not in allowed for flag in flags):
            raise PermissionError("Git option is not in the safe grammar")
        if paths:
            return [*flags, "--", *self._normalize_read_paths(paths)]
        return flags

    def _git_revisions_flags_paths(
        self,
        values: list[str],
        allowed: set[str],
        *,
        allow_count: bool = False,
        files_only: bool = False,
        require_commitish: bool = False,
        default_revision: str | None = None,
    ) -> list[str]:
        if "--" in values:
            split = values.index("--")
            head, paths = values[:split], values[split + 1 :]
        else:
            head, paths = values, []
        normalized_head: list[str] = []
        revision_count = 0
        for value in head:
            if value in allowed or (allow_count and self.SAFE_LOG_COUNT.fullmatch(value)):
                normalized_head.append(value)
            elif self.SAFE_REVISION.fullmatch(value) and not value.startswith("-"):
                if require_commitish and ".." in value:
                    raise PermissionError(
                        "automatic Git accepts individual commit-ish revisions only"
                    )
                revision_count += 1
                normalized_head.append(
                    f"{value}^{{commit}}" if require_commitish else value
                )
            else:
                raise PermissionError("Git revision or option is not in the safe grammar")
        if require_commitish and revision_count == 0 and default_revision is not None:
            normalized_head.append(f"{default_revision}^{{commit}}")
        if paths:
            return [
                *normalized_head,
                "--",
                *self._normalize_read_paths(paths, files_only=files_only),
            ]
        return normalized_head

    def _normalize_adb(self, args: list[str]) -> list[str]:
        if args in (["devices"], ["devices", "-l"]):
            raise PermissionError(
                "automatic ADB device enumeration is disabled because it can disclose or "
                "broaden access to non-allowlisted devices; use a targeted '-s SERIAL' read"
            )
        if len(args) < 3 or args[0] != "-s":
            raise PermissionError("targeted ADB operations require '-s SERIAL'")
        serial = args[1]
        self._validate_adb_serial(serial)
        operation = args[2:]
        allowed = (
            operation == ["get-state"]
            or operation == ["shell", "wm", "size"]
            or operation == ["shell", "wm", "density"]
            or operation == ["shell", "dumpsys", "battery"]
            or operation == ["shell", "dumpsys", "display"]
            or operation == ["shell", "dumpsys", "window"]
            or operation == ["shell", "dumpsys", "activity", "activities"]
            or operation == ["exec-out", "screencap", "-p"]
            or (
                len(operation) == 3
                and operation[:2] == ["shell", "getprop"]
                and operation[2] in self.ADB_PROPERTIES
            )
        )
        if not allowed:
            raise PermissionError("ADB operation is not in the fixed read-only grammar")
        return ["-s", serial, *operation]

    def _validate_adb_serial(self, serial: str) -> None:
        allowed = self.settings.adb_allowed_serials
        if not allowed:
            raise PermissionError(
                "automatic ADB requires at least one explicitly allowlisted target"
            )
        if serial not in allowed:
            raise PermissionError(f"ADB serial is not allowlisted: {serial}")
        if self.settings.adb_emulator_only and not serial.casefold().startswith("emulator-"):
            raise PermissionError("physical or nonstandard ADB targets are disabled")

    def _normalize_read_paths(
        self, paths: list[str], *, files_only: bool = False
    ) -> list[str]:
        return [
            str(
                self.workspace.resolve_existing(
                    path, access="read", allow_directory=not files_only
                )
            )
            for path in paths
        ]

    @staticmethod
    def _result(
        executable_identity: dict[str, object],
        args: list[str],
        cwd: Path,
        program_key: str,
    ) -> NormalizedCommand:
        normalized = NormalizedCommand(
            executable=str(executable_identity["path"]),
            args=args,
            cwd=str(cwd),
            display_command=[str(executable_identity["path"]), *args],
            program_key=program_key,
            network_expected=False,
            executable_identity=executable_identity,
        )
        normalized._cwd_hold = cwd
        return normalized


def approval_hash(
    *,
    normalized: NormalizedCommand,
    reason: str,
    risk_summary: str,
    manifest_digest: str,
    execution_tier: str = "approved_host",
    backend_digest: str | None = None,
) -> str:
    payload = {
        "executable": normalized.executable,
        "args": normalized.args,
        "cwd": normalized.cwd,
        "network_expected": normalized.network_expected,
        "reason": reason,
        "risk_summary": risk_summary,
        "manifest_digest": manifest_digest,
        "execution_tier": execution_tier,
        "backend_digest": backend_digest,
        "executable_identity": normalized.executable_identity,
    }
    return sha256_text(canonical_json(payload))


def approved_request_hash(request: dict[str, object]) -> str:
    """Bind every persisted capability of a versioned Approved request."""
    if request.get("approval_binding_version") != 3:
        raise ValueError("approved request uses an unsupported approval binding version")
    return sha256_text(canonical_json(request))