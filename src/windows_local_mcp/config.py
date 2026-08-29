from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import json
import os
import stat
import subprocess
import tomllib
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from .child_env import normalize_extra_environment_names, sanitize_process_environment
from .git_env import strip_git_ambient_environment
from .tool_safety import capture_file_identity, hold_file_identity
from .windows_system import physical_filesystem_path, windows_system_executable
from .windows_transaction import probe_transactional_workspace_commit


class Settings(BaseModel):
    """Validated, fail-closed configuration for one MCP instance/workspace."""

    model_config = ConfigDict(extra="forbid")

    workspace_root: Path
    data_dir: Path
    sandbox_scratch_dir: Path | None = None

    filesystem_enabled: bool = True
    git_enabled: bool = True
    flutter_enabled: bool = False
    dart_enabled: bool = False
    adb_enabled: bool = False
    powershell_enabled: bool = False

    adb_emulator_only: bool = True
    adb_allowed_serials: list[str] = Field(default_factory=list)
    # Broker helpers are never selected from PATH. Enabling a capability and making it
    # available are separate states; both an absolute path and an operator-pinned hash are
    # required before automatic execution is possible.
    git_executable_path: Path | None = None
    git_executable_sha256: str | None = None
    adb_executable_path: Path | None = None
    adb_executable_sha256: str | None = None

    max_text_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    max_write_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    max_diff_bytes: int = Field(default=4 * 1024 * 1024, ge=1024)
    max_backup_bytes: int = Field(default=16 * 1024 * 1024, ge=1024)
    max_output_bytes_per_stream: int = Field(default=16 * 1024 * 1024, ge=4096)
    max_data_dir_bytes: int = Field(default=512 * 1024 * 1024, ge=1024 * 1024)
    retention_days: int = Field(default=14, ge=1, le=3650)
    retention_max_operations: int = Field(default=2000, ge=10, le=1_000_000)
    max_directory_entries: int = Field(default=3000, ge=1, le=100000)
    max_image_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    # Structured binary files are deliberately bounded separately from source-text writes.
    max_structured_file_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    max_transfer_chunk_bytes: int = Field(default=512 * 1024, ge=4096, le=4 * 1024 * 1024)
    max_zip_entries: int = Field(default=10000, ge=1, le=100000)
    max_zip_expanded_bytes: int = Field(default=256 * 1024 * 1024, ge=1024)
    max_structured_elements: int = Field(default=250000, ge=100, le=2000000)
    max_image_pixels: int = Field(default=40_000_000, ge=1_000_000, le=500_000_000)
    max_image_decoded_bytes: int = Field(
        default=256 * 1024 * 1024, ge=4 * 1024 * 1024, le=2 * 1024 * 1024 * 1024
    )
    output_preview_characters: int = Field(default=12000, ge=1000, le=200000)
    max_command_arguments: int = Field(default=64, ge=1, le=1000)
    max_command_argument_characters: int = Field(default=1024, ge=32, le=65536)
    max_reason_characters: int = Field(default=4000, ge=32, le=65536)
    max_audit_record_bytes: int = Field(default=128 * 1024, ge=4096, le=1024 * 1024)

    approval_request_ttl_seconds: int = Field(default=1800, ge=30, le=86400)
    approval_execution_ttl_seconds: int = Field(default=60, ge=5, le=600)
    approval_manifest_max_files: int = Field(default=10000, ge=1, le=100000)
    approval_manifest_max_bytes: int = Field(
        default=256 * 1024 * 1024, ge=1024, le=4 * 1024 * 1024 * 1024
    )
    default_foreground_timeout_seconds: int = Field(default=30, ge=0, le=600)
    default_max_runtime_seconds: int = Field(default=1800, ge=10, le=86400)
    max_concurrent_jobs: int = Field(default=4, ge=1, le=64)
    max_pending_approvals: int = Field(default=100, ge=1, le=10000)
    max_open_transfers: int = Field(default=32, ge=1, le=1000)
    max_sandbox_scratch_bytes: int = Field(default=512 * 1024 * 1024, ge=1024 * 1024)
    max_sandbox_processes: int = Field(default=64, ge=4, le=1024)
    max_sandbox_memory_bytes: int = Field(
        default=4 * 1024 * 1024 * 1024,
        ge=128 * 1024 * 1024,
        le=64 * 1024 * 1024 * 1024,
    )

    # Parent environment is not inherited wholesale. Add only project-specific variables that a
    # child genuinely needs; known injection/redirection variables are rejected even if listed.
    child_environment_allowlist: list[str] = Field(default_factory=list)

    blocked_file_names: list[str] = Field(
        default_factory=lambda: [
            ".env",
            ".env.local",
            ".env.production",
            "id_rsa",
            "id_ed25519",
            "credentials.json",
            "service-account.json",
        ]
    )
    hidden_directories: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".dart_tool",
            "build",
            "node_modules",
            ".venv",
            "__pycache__",
        ]
    )
    read_denied_directories: list[str] = Field(default_factory=lambda: [".git"])
    write_denied_directories: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".dart_tool",
            "build",
            "node_modules",
            ".venv",
            "__pycache__",
        ]
    )
    safe_powershell_scripts: list[str] = Field(default_factory=list)
    default_approver: str = "local-user"

    http_enabled: bool = False
    http_host: str = "127.0.0.1"
    http_port: int = Field(default=8000, ge=1, le=65535)
    http_multi_principal_enabled: bool = False
    protect_data_dir_acl: bool = True
    sandbox_dependency_readable_paths: list[Path] = Field(default_factory=list)
    approved_sandbox_enabled: bool = True
    approved_sandbox_backend: Literal["codex_cli"] = "codex_cli"
    approved_sandbox_codex_path: Path | None = None
    approved_sandbox_windows_mode: Literal["elevated"] = "elevated"
    approved_sandbox_permission_profile: Literal[":workspace"] = ":workspace"
    approved_sandbox_require_live_verification: bool = True
    approved_host_enabled: bool = True

    _config_selection_source: str = PrivateAttr(default="direct_settings")
    _config_selector_path: str | None = PrivateAttr(default=None)
    _config_path: str | None = PrivateAttr(default=None)
    _config_file_identity: dict[str, object] | None = PrivateAttr(default=None)
    _workspace_selection_source: str = PrivateAttr(default="settings")
    _ambient_root_present: bool = PrivateAttr(default=False)

    @model_validator(mode="before")
    @classmethod
    def validate_lexical_overlap(cls, payload: object) -> object:
        if not isinstance(payload, dict):
            return payload
        root_value = payload.get("workspace_root")
        data_value = payload.get("data_dir")
        scratch_value = payload.get("sandbox_scratch_dir")
        if root_value and data_value:
            root = Path(os.path.expandvars(os.path.expanduser(str(root_value)))).absolute()
            data = Path(os.path.expandvars(os.path.expanduser(str(data_value)))).absolute()
            if _is_relative_to(data, root) or _is_relative_to(root, data):
                raise ValueError("data_dir and workspace_root lexically overlap")
            if scratch_value:
                scratch = Path(
                    os.path.expandvars(os.path.expanduser(str(scratch_value)))
                ).absolute()
                for left, right in ((scratch, root), (scratch, data)):
                    if _is_relative_to(left, right) or _is_relative_to(right, left):
                        raise ValueError("sandbox_scratch_dir must not overlap trusted roots")
        return payload

    @field_validator("workspace_root", "data_dir", mode="before")
    @classmethod
    def expand_path(cls, value: object) -> Path:
        if value is None or str(value).strip() == "":
            raise ValueError("path must not be empty")
        return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()

    @field_validator(
        "approved_sandbox_codex_path",
        "git_executable_path",
        "adb_executable_path",
        mode="before",
    )
    @classmethod
    def expand_optional_executable(cls, value: object) -> Path | None:
        if value is None or not str(value).strip():
            return None
        return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve(strict=True)

    @field_validator("git_executable_sha256", "adb_executable_sha256", mode="before")
    @classmethod
    def normalize_executable_sha256(cls, value: object) -> str | None:
        if value is None or not str(value).strip():
            return None
        digest = str(value).strip().casefold()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("executable SHA-256 must contain exactly 64 hexadecimal characters")
        return digest

    @field_validator("sandbox_scratch_dir", mode="before")
    @classmethod
    def expand_optional_directory(cls, value: object) -> Path | None:
        if value is None or not str(value).strip():
            return None
        return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()

    @field_validator("sandbox_dependency_readable_paths", mode="before")
    @classmethod
    def expand_readable_paths(cls, value: object) -> list[Path]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError("sandbox_dependency_readable_paths must be a list")
        return [
            Path(os.path.expandvars(os.path.expanduser(str(item)))).resolve()
            for item in value
        ]

    @field_validator("adb_allowed_serials")
    @classmethod
    def validate_serials(cls, values: list[str]) -> list[str]:
        clean: list[str] = []
        for value in values:
            serial = value.strip()
            if not serial or any(character.isspace() for character in serial):
                raise ValueError("ADB serials must be non-empty and contain no whitespace")
            clean.append(serial)
        return clean

    @field_validator("child_environment_allowlist")
    @classmethod
    def validate_child_environment_allowlist(cls, values: list[str]) -> list[str]:
        return normalize_extra_environment_names(values)

    @model_validator(mode="after")
    def validate_security_boundaries(self) -> Settings:
        root = self.workspace_root
        data = self.data_dir
        if self.sandbox_scratch_dir is None:
            self.sandbox_scratch_dir = data.parent / f"{data.name}-sandbox-scratch"
        scratch = self.sandbox_scratch_dir.resolve()
        if _is_relative_to(data, root) or _is_relative_to(root, data):
            raise ValueError("data_dir and workspace_root must not overlap")
        for left, right in ((scratch, root), (scratch, data)):
            if _is_relative_to(left, right) or _is_relative_to(right, left):
                raise ValueError("sandbox_scratch_dir must not overlap trusted roots")
        if self.http_enabled and self.http_multi_principal_enabled:
            raise ValueError(
                "multi-principal HTTP is unsupported without authenticated principal ownership"
            )
        if self.http_enabled and not _is_loopback_host(self.http_host):
            raise ValueError("unauthenticated HTTP is restricted to a loopback host")
        if self.http_enabled:
            raise ValueError(
                "streamable HTTP is disabled until authenticated principal ownership is configured"
            )
        if self.http_multi_principal_enabled:
            raise ValueError(
                "multi-principal HTTP is unsupported without authenticated principal ownership"
            )
        if self.safe_powershell_scripts and not self.powershell_enabled:
            raise ValueError("safe_powershell_scripts requires powershell_enabled=true")
        if self.approved_sandbox_enabled and not self.approved_sandbox_require_live_verification:
            raise ValueError(
                "approved_sandbox_require_live_verification cannot be disabled while "
                "Approved Sandbox is enabled"
            )
        for path in self.sandbox_dependency_readable_paths:
            if path == Path(path.anchor):
                raise ValueError("sandbox_dependency_readable_paths cannot include a drive root")
            if any(
                _is_relative_to(path, protected) or _is_relative_to(protected, path)
                for protected in (root, data, scratch)
            ):
                raise ValueError(
                    "sandbox_dependency_readable_paths cannot overlap workspace_root, data_dir, "
                    "sandbox_scratch_dir, or an ancestor of those roots"
                )
        codex_path = self.approved_sandbox_codex_path
        if codex_path is not None:
            if not codex_path.is_file() or _is_reparse(codex_path):
                raise ValueError("approved_sandbox_codex_path must be a regular non-reparse file")
            if any(
                _is_relative_to(codex_path, protected)
                for protected in (root, data, scratch)
            ):
                raise ValueError(
                    "approved_sandbox_codex_path must be outside untrusted and control-plane roots"
                )
        for key in ("git", "adb"):
            executable_path = getattr(self, f"{key}_executable_path")
            executable_sha256 = getattr(self, f"{key}_executable_sha256")
            if (executable_path is None) != (executable_sha256 is None):
                raise ValueError(
                    f"{key}_executable_path and {key}_executable_sha256 must be configured together"
                )
            if executable_path is None:
                continue
            if not executable_path.is_file() or _is_reparse(executable_path):
                raise ValueError(f"{key}_executable_path must be a regular non-reparse file")
            if any(
                _is_relative_to(executable_path, protected)
                for protected in (root, data, scratch)
            ):
                raise ValueError(
                    f"{key}_executable_path must be outside workspace, data, and scratch roots"
                )
        return self

    def ensure_directories(self) -> None:
        if not self.workspace_root.exists() or not self.workspace_root.is_dir():
            raise FileNotFoundError(f"workspace_root does not exist: {self.workspace_root}")
        if _is_reparse(self.workspace_root):
            raise ValueError("workspace_root must not be a symbolic link or reparse point")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if _is_reparse(self.data_dir):
            raise ValueError("data_dir must not be a symbolic link or reparse point")
        assert self.sandbox_scratch_dir is not None
        self.sandbox_scratch_dir.mkdir(parents=True, exist_ok=True)
        if _is_reparse(self.sandbox_scratch_dir):
            raise ValueError("sandbox_scratch_dir must not be a reparse point")
        workspace_identity = self.workspace_root.stat()
        data_identity = self.data_dir.stat()
        scratch_identity = self.sandbox_scratch_dir.stat()
        if not all(
            identity.st_ino
            for identity in (workspace_identity, data_identity, scratch_identity)
        ):
            raise RuntimeError("filesystem does not expose stable file identities")
        identities = {
            "workspace_root": (workspace_identity.st_dev, workspace_identity.st_ino),
            "data_dir": (data_identity.st_dev, data_identity.st_ino),
            "sandbox_scratch_dir": (scratch_identity.st_dev, scratch_identity.st_ino),
        }
        if len(set(identities.values())) != len(identities):
            raise ValueError("workspace, data, and scratch must be distinct filesystem objects")
        physical_paths = {
            "workspace_root": physical_filesystem_path(self.workspace_root),
            "data_dir": physical_filesystem_path(self.data_dir),
            "sandbox_scratch_dir": physical_filesystem_path(self.sandbox_scratch_dir),
        }
        for left_index, (left_name, left_path) in enumerate(physical_paths.items()):
            for right_name, right_path in list(physical_paths.items())[left_index + 1 :]:
                if _physical_paths_overlap(left_path, right_path):
                    raise ValueError(
                        f"{left_name} and {right_name} physically overlap after alias resolution"
                    )
        for name in (
            "logs",
            "outputs",
            "diffs",
            "backups",
            "git-snapshots",
            "approval-staging",
            "binary-transfers",
            "worker-contexts",
            "control-plane",
            "workspace-history",
        ):
            directory = self.data_dir / name
            directory.mkdir(parents=True, exist_ok=True)
            if _is_reparse(directory):
                raise ValueError(f"data_dir child must not be a reparse point: {directory}")
        for name in ("operations", "blobs", "transactions"):
            directory = self.data_dir / "workspace-history" / name
            directory.mkdir(parents=True, exist_ok=True)
            if _is_reparse(directory):
                raise ValueError(f"workspace-history child must not be a reparse point: {directory}")
        namespace_created = _ensure_control_plane_namespace(self)
        if self.protect_data_dir_acl and os.name == "nt":
            _protect_windows_acl(
                self.data_dir,
                allow_initial_provision=namespace_created,
            )
        _probe_filesystem_semantics(self.data_dir)
        _probe_filesystem_semantics(self.sandbox_scratch_dir)
        if self.filesystem_enabled:
            _probe_filesystem_semantics(self.workspace_root)
            probe_transactional_workspace_commit(self.workspace_root)

    def selection_info(self) -> dict[str, object]:
        return {
            "config_source": self._config_selection_source,
            "config_path": self._config_path,
            "workspace_source": self._workspace_selection_source,
            "ambient_root_present": self._ambient_root_present,
            "ambient_root_overrode_config": False,
        }


def _is_relative_to(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _physical_paths_overlap(left: str, right: str) -> bool:
    normalized_left = os.path.normcase(left.rstrip("\\/"))
    normalized_right = os.path.normcase(right.rstrip("\\/"))
    try:
        common = os.path.commonpath((normalized_left, normalized_right))
    except ValueError:
        return False
    return common in {normalized_left, normalized_right}


def _is_loopback_host(host: str) -> bool:
    return host.strip().casefold() in {"127.0.0.1", "::1", "localhost"}


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    attributes = int(getattr(info, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _probe_filesystem_semantics(directory: Path) -> None:
    """Fail closed when stable identity, exclusion locking, or replacement is unavailable."""
    token = uuid.uuid4().hex
    first = directory / f".wlmcp-fs-probe-{token}.a"
    second = directory / f".wlmcp-fs-probe-{token}.b"
    try:
        first.write_bytes(b"before")
        initial = first.stat()
        if not initial.st_ino or initial.st_nlink != 1 or _is_reparse(first):
            raise RuntimeError("filesystem probe could not establish a unique file identity")
        if os.name == "nt":
            import msvcrt

            with first.open("r+b") as owner, first.open("r+b") as contender:
                owner.seek(0)
                msvcrt.locking(owner.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    contender.seek(0)
                    try:
                        msvcrt.locking(contender.fileno(), msvcrt.LK_NBLCK, 1)
                    except OSError:
                        pass
                    else:
                        msvcrt.locking(contender.fileno(), msvcrt.LK_UNLCK, 1)
                        raise RuntimeError("filesystem does not enforce exclusion locks")
                finally:
                    owner.seek(0)
                    msvcrt.locking(owner.fileno(), msvcrt.LK_UNLCK, 1)
        second.write_bytes(b"after")
        replacement_identity = second.stat()
        os.replace(second, first)
        final = first.stat()
        if first.read_bytes() != b"after" or (final.st_dev, final.st_ino) != (
            replacement_identity.st_dev,
            replacement_identity.st_ino,
        ):
            raise RuntimeError("filesystem does not provide verifiable atomic replacement")
    except OSError as error:
        raise RuntimeError(f"required filesystem semantics are unavailable: {directory}") from error
    finally:
        first.unlink(missing_ok=True)
        second.unlink(missing_ok=True)


def _ensure_control_plane_namespace(settings: Settings) -> bool:
    details = settings.workspace_root.stat()
    data = settings.data_dir.stat()
    assert settings.sandbox_scratch_dir is not None
    scratch = settings.sandbox_scratch_dir.stat()
    expected = {
        "version": 3,
        "workspace_path": str(settings.workspace_root.resolve(strict=True)),
        "workspace_device": int(details.st_dev),
        "workspace_inode": int(details.st_ino),
        "workspace_physical_path": physical_filesystem_path(settings.workspace_root),
        "data_dir_path": str(settings.data_dir.resolve(strict=True)),
        "data_dir_device": int(data.st_dev),
        "data_dir_inode": int(data.st_ino),
        "data_dir_physical_path": physical_filesystem_path(settings.data_dir),
        "config_path": settings._config_path,
        "sandbox_scratch_path": str(settings.sandbox_scratch_dir.resolve(strict=True)),
        "sandbox_scratch_device": int(scratch.st_dev),
        "sandbox_scratch_inode": int(scratch.st_ino),
        "sandbox_scratch_physical_path": physical_filesystem_path(
            settings.sandbox_scratch_dir
        ),
    }
    marker = settings.data_dir / "control-plane" / "namespace.json"
    payload = json.dumps(expected, sort_keys=True, separators=(",", ":"))
    try:
        with marker.open("x", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        return True
    except FileExistsError:
        try:
            current = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise PermissionError("control-plane namespace marker is corrupt") from error
        legacy_v2 = {
            key: value
            for key, value in expected.items()
            if not key.endswith("_physical_path") and key != "version"
        }
        legacy_v2["version"] = 2
        legacy_v1 = {
            key: value
            for key, value in legacy_v2.items()
            if key not in {"version", "data_dir_path", "data_dir_device", "data_dir_inode"}
        }
        can_upgrade = current == legacy_v2 or (
            current.get("version") == 1
            and {key: value for key, value in current.items() if key != "version"}
            == legacy_v1
        )
        if can_upgrade:
            temporary = marker.with_suffix(".upgrade.tmp")
            temporary.write_text(payload, encoding="utf-8")
            os.replace(temporary, marker)
            return False
        if current != expected:
            raise PermissionError(
                "data_dir belongs to a different workspace or configuration profile"
            )
        return False


def _required_windows_acl_digest(path: Path, sid: str) -> str:
    """Return a stable digest only when the root DACL exactly matches our policy."""
    if os.name != "nt":
        raise RuntimeError("Windows ACL inspection requires native Windows")

    class _ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [
            ("Header", _ACE_HEADER),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_named_security_info = advapi32.GetNamedSecurityInfoW
    get_named_security_info.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_ACL)),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_named_security_info.restype = wintypes.DWORD
    get_descriptor_control = advapi32.GetSecurityDescriptorControl
    get_descriptor_control.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_descriptor_control.restype = wintypes.BOOL
    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        ctypes.POINTER(_ACL),
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_ace.restype = wintypes.BOOL
    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    dacl = ctypes.POINTER(_ACL)()
    descriptor = ctypes.c_void_p()
    error = get_named_security_info(
        str(path),
        1,  # SE_FILE_OBJECT
        0x00000004,  # DACL_SECURITY_INFORMATION
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if error != 0 or not descriptor.value or not dacl:
        raise RuntimeError(f"GetNamedSecurityInfoW failed for data_dir: {error}")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not get_descriptor_control(
            descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise RuntimeError(
                f"GetSecurityDescriptorControl failed: WinError {ctypes.get_last_error()}"
            )
        protected = bool(int(control.value) & 0x1000)  # SE_DACL_PROTECTED
        records: list[tuple[int, int, int, str]] = []
        for index in range(int(dacl.contents.AceCount)):
            ace_pointer = ctypes.c_void_p()
            if not get_ace(dacl, index, ctypes.byref(ace_pointer)):
                raise RuntimeError(f"GetAce failed: WinError {ctypes.get_last_error()}")
            header = ctypes.cast(ace_pointer, ctypes.POINTER(_ACE_HEADER)).contents
            if int(header.AceType) != 0:  # ACCESS_ALLOWED_ACE_TYPE
                raise PermissionError("data_dir root contains an unsupported ACL entry")
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
            sid_pointer = ctypes.c_void_p(
                int(ace_pointer.value) + _ACCESS_ALLOWED_ACE.SidStart.offset
            )
            sid_text = wintypes.LPWSTR()
            if not sid_to_string(sid_pointer, ctypes.byref(sid_text)):
                raise RuntimeError(
                    f"ConvertSidToStringSidW failed: WinError {ctypes.get_last_error()}"
                )
            try:
                records.append(
                    (
                        int(ace.Header.AceType),
                        int(ace.Header.AceFlags),
                        int(ace.Mask),
                        str(sid_text.value),
                    )
                )
            finally:
                local_free(sid_text)
    finally:
        local_free(descriptor)

    full_control = 0x001F01FF
    inherit_only = 0x01 | 0x02 | 0x08  # OBJECT/CONTAINER_INHERIT + INHERIT_ONLY
    expected = sorted(
        [
            (0, 0, full_control, "S-1-5-18"),
            (0, 0, full_control, sid),
            (0, inherit_only, full_control, "S-1-5-18"),
            (0, inherit_only, full_control, sid),
        ]
    )
    if not protected or sorted(records) != expected:
        raise PermissionError("data_dir root ACL does not match the required policy")
    payload = json.dumps(
        {"protected": protected, "aces": sorted(records)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _write_acl_policy_marker(marker: Path, *, sid: str, acl_digest: str) -> None:
    payload = json.dumps(
        {
            "version": 2,
            "sid": sid,
            "acl_policy": "current-user-system-full-control-v1",
            "root_acl_sha256": acl_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    temporary = marker.with_name(f"{marker.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)


def _protect_windows_acl(path: Path, *, allow_initial_provision: bool) -> None:
    identity = subprocess.run(
        [windows_system_executable("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        shell=False,
    )
    if identity.returncode != 0:
        raise PermissionError("failed to determine the current Windows security principal")
    row = next(csv.reader(io.StringIO(identity.stdout)), None)
    if not row or len(row) < 2 or not row[1].startswith("S-"):
        raise PermissionError("failed to parse the current Windows security principal SID")
    sid = row[1]
    marker = path / ".acl-policy.json"
    expected_marker: dict[str, object] | None = None
    if marker.is_file():
        try:
            loaded = json.loads(marker.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                expected_marker = loaded
        except (OSError, ValueError):
            raise PermissionError("data_dir ACL policy marker is corrupt") from None
    if expected_marker is not None:
        try:
            current_digest = _required_windows_acl_digest(path, sid)
        except (OSError, RuntimeError, PermissionError):
            current_digest = None
        marker_version = expected_marker.get("version")
        marker_matches = (
            current_digest is not None
            and marker_version == 2
            and expected_marker.get("sid") == sid
            and expected_marker.get("acl_policy") == "current-user-system-full-control-v1"
            and expected_marker.get("root_acl_sha256") == current_digest
        )
        legacy_can_upgrade = (
            marker_version == 1
            and expected_marker.get("sid") == sid
            and isinstance(expected_marker.get("root_acl_sha256"), str)
            and current_digest is not None
        )
        if not marker_matches and not legacy_can_upgrade:
            raise PermissionError(
                "data_dir ACL changed after provisioning; automatic repair is disabled. "
                "Do not delete .acl-policy.json. Preserve data_dir and its marker, inspect "
                "the ACL difference, then use a new config/data_dir or explicitly "
                "reprovision the reviewed ACL before retrying"
            )
        if legacy_can_upgrade:
            _write_acl_policy_marker(marker, sid=sid, acl_digest=current_digest)
        return
    if not allow_initial_provision:
        raise PermissionError(
            "data_dir ACL policy marker is missing after provisioning; automatic repair "
            "and marker deletion recovery are disabled. Preserve data_dir and inspect the "
            "ACL state before explicit reprovisioning"
        )
    reset = subprocess.run(
        [windows_system_executable("icacls.exe"), str(path), "/reset", "/T", "/C"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
    )
    if reset.returncode != 0:
        raise PermissionError(f"failed to reset data_dir ACL: {reset.stderr.strip()}")
    isolation = subprocess.run(
        [
            windows_system_executable("icacls.exe"),
            str(path),
            "/inheritance:r",
            "/T",
            "/C",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    if isolation.returncode != 0:
        raise PermissionError(
            f"failed to isolate data_dir ACL inheritance: {isolation.stderr.strip()}"
        )
    result = subprocess.run(
        [
            windows_system_executable("icacls.exe"),
            str(path),
            "/grant:r",
            f"*{sid}:F",
            "SYSTEM:F",
            "/T",
            "/C",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise PermissionError(f"failed to protect data_dir ACL: {result.stderr.strip()}")
    inheritance = subprocess.run(
        [
            windows_system_executable("icacls.exe"),
            str(path),
            "/grant",
            f"*{sid}:(OI)(CI)(IO)F",
            "SYSTEM:(OI)(CI)(IO)F",
            "/T",
            "/C",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    if inheritance.returncode != 0:
        raise PermissionError(
            f"failed to provision inherited data_dir ACL: {inheritance.stderr.strip()}"
        )
    try:
        verified_digest = _required_windows_acl_digest(path, sid)
    except (OSError, RuntimeError, PermissionError) as error:
        raise PermissionError("failed to verify protected data_dir ACL") from error
    namespace_marker = path / "control-plane" / "namespace.json"
    try:
        namespace_marker.read_bytes()
        probe = path / f".acl-write-probe-{os.getpid()}"
        probe.write_bytes(b"acl-probe")
        if probe.read_bytes() != b"acl-probe":
            raise OSError("ACL write probe did not round-trip")
        probe.unlink()
    except OSError as error:
        raise PermissionError(
            "protected data_dir ACL denied the current WLMCP principal"
        ) from error
    _write_acl_policy_marker(marker, sid=sid, acl_digest=verified_digest)


def _load_file_backed_config(
    config_path_value: str,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    """Parse the exact config object whose content and stable identity are security-bound."""
    selector = Path(config_path_value).expanduser().absolute()
    config_path = selector.resolve(strict=True)
    identity = capture_file_identity(config_path, provenance="active-config")
    with hold_file_identity(identity) as held_path:
        try:
            selected = selector.resolve(strict=True)
        except OSError as error:
            raise RuntimeError("active config selector changed during load") from error
        if selected != held_path:
            raise RuntimeError("active config selector changed during load")
        with held_path.open("rb") as file:
            payload = tomllib.load(file)
        try:
            selected_after_parse = selector.resolve(strict=True)
        except OSError as error:
            raise RuntimeError("active config selector changed during load") from error
        if selected_after_parse != held_path:
            raise RuntimeError("active config selector changed during load")
    return selector, config_path, identity, payload


def _normalize_file_config_payload(payload: dict[str, object]) -> None:
    """Apply the same compatibility checks to active and staged config payloads."""
    if "safe_network_readable_paths" in payload:
        if "sandbox_dependency_readable_paths" in payload:
            raise ValueError(
                "use only sandbox_dependency_readable_paths; the legacy key is ambiguous"
            )
        payload["sandbox_dependency_readable_paths"] = payload.pop(
            "safe_network_readable_paths"
        )
    obsolete = {
        "safe_network_isolation_mode",
        "safe_network_profile_prefix",
    }.intersection(payload)
    if obsolete:
        raise ValueError(
            "obsolete Safe Tier/AppContainer settings must be removed: "
            + ", ".join(sorted(obsolete))
        )


def _populate_file_config_defaults(
    payload: dict[str, object], *, config_path: Path
) -> None:
    if "workspace_root" not in payload or not str(payload["workspace_root"]).strip():
        raise ValueError("explicit config must define workspace_root")
    data_dir = str(payload.get("data_dir", "")).strip()
    if not data_dir:
        configured_root = Path(str(payload["workspace_root"])).expanduser().resolve(strict=True)
        payload["data_dir"] = str(_default_data_dir(configured_root, config_path))
    if not str(payload.get("sandbox_scratch_dir", "")).strip():
        configured_data = Path(str(payload["data_dir"])).expanduser().resolve()
        payload["sandbox_scratch_dir"] = str(
            configured_data.parent / f"{configured_data.name}-sandbox-scratch"
        )


def validate_configuration_candidate(
    candidate_path: str | Path, *, final_config_path: str | Path
) -> Settings:
    """Validate staged config content without provisioning directories or marker state."""
    _, _, _, payload = _load_file_backed_config(str(candidate_path))
    _normalize_file_config_payload(payload)
    final_path = Path(final_config_path).expanduser().absolute().resolve()
    _populate_file_config_defaults(payload, config_path=final_path)
    for name in ("workspace_root", "data_dir", "sandbox_scratch_dir"):
        lexical_root = Path(
            os.path.expandvars(os.path.expanduser(str(payload[name])))
        ).absolute()
        if lexical_root.exists() and _is_reparse(lexical_root):
            raise ValueError(f"{name} must not be a symbolic link or reparse point")
        resolved_root = lexical_root.resolve()
        if resolved_root == Path(resolved_root.anchor):
            raise ValueError(f"{name} cannot be a drive root")
    settings = Settings.model_validate(payload)
    if _is_relative_to(final_path, settings.workspace_root):
        raise ValueError("the active config path must be outside workspace_root")

    roots = {
        "workspace_root": settings.workspace_root.resolve(),
        "data_dir": settings.data_dir.resolve(),
        "sandbox_scratch_dir": settings.sandbox_scratch_dir.resolve(),
    }
    for name, path in roots.items():
        if name == "workspace_root":
            if not path.exists() or not path.is_dir():
                raise ValueError("workspace_root must be an existing directory")
        elif path.exists() and not path.is_dir():
            raise ValueError(f"{name} must be a directory when it already exists")
        if path.exists() and _is_reparse(path):
            raise ValueError(f"{name} must not be a symbolic link or reparse point")
    return settings


def _default_data_dir(workspace_root: Path, config_path: Path | None) -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base = Path(local_app_data) / "WindowsLocalMCP"
    else:
        base = Path.home() / ".windows-local-mcp"
    workspace = workspace_root.resolve(strict=True)
    details = workspace.stat()
    namespace_payload = "|".join(
        (
            str(workspace).casefold(),
            str(int(details.st_dev)),
            str(int(details.st_ino)),
            str(config_path).casefold() if config_path is not None else "environment-only",
        )
    )
    namespace = hashlib.sha256(namespace_payload.encode("utf-8")).hexdigest()[:24]
    return base / namespace


def load_settings() -> Settings:
    # Every production entrypoint calls load_settings(). Scrub Git repository/config overrides
    # before any Git probe, snapshot, approval-state capture, or child process can inherit them.
    strip_git_ambient_environment(os.environ)

    config_path_value = os.environ.get("LOCAL_MCP_CONFIG", "").strip()
    payload: dict[str, object] = {}

    config_selector_path: Path | None = None
    config_path: Path | None = None
    config_file_identity: dict[str, object] | None = None
    if config_path_value:
        (
            config_selector_path,
            config_path,
            config_file_identity,
            payload,
        ) = _load_file_backed_config(config_path_value)
        _normalize_file_config_payload(payload)

    env_root = os.environ.get("LOCAL_MCP_ROOT", "").strip()
    if config_path is not None and env_root:
        if "workspace_root" not in payload or not str(payload["workspace_root"]).strip():
            raise ValueError("explicit config must define workspace_root; LOCAL_MCP_ROOT cannot fill it")
        configured = Path(str(payload["workspace_root"])).expanduser().resolve(strict=True)
        ambient = Path(env_root).expanduser().resolve(strict=True)
        if configured != ambient:
            raise ValueError(
                "LOCAL_MCP_ROOT conflicts with the explicitly selected config workspace_root"
            )
    elif env_root:
        payload["workspace_root"] = env_root

    if "workspace_root" not in payload or not str(payload["workspace_root"]).strip():
        raise ValueError(
            "workspace_root must be explicitly set in LOCAL_MCP_CONFIG or LOCAL_MCP_ROOT"
        )

    if config_path is not None:
        _populate_file_config_defaults(payload, config_path=config_path)
    else:
        data_dir = str(payload.get("data_dir", "")).strip()
        if not data_dir:
            configured_root = Path(str(payload["workspace_root"])).expanduser().resolve(
                strict=True
            )
            payload["data_dir"] = str(_default_data_dir(configured_root, config_path))
        if not str(payload.get("sandbox_scratch_dir", "")).strip():
            configured_data = Path(str(payload["data_dir"])).expanduser().resolve()
            payload["sandbox_scratch_dir"] = str(
                configured_data.parent / f"{configured_data.name}-sandbox-scratch"
            )

    settings = Settings.model_validate(payload)
    if config_path is not None and _is_relative_to(config_path, settings.workspace_root):
        raise ValueError("the active config path must be outside workspace_root")
    settings._config_selection_source = (
        "LOCAL_MCP_CONFIG" if config_path is not None else "environment_only"
    )
    settings._config_selector_path = (
        str(config_selector_path) if config_selector_path is not None else None
    )
    settings._config_path = str(config_path) if config_path is not None else None
    settings._config_file_identity = config_file_identity
    settings._workspace_selection_source = (
        "explicit_config" if config_path is not None else "LOCAL_MCP_ROOT"
    )
    settings._ambient_root_present = bool(env_root)
    # After the config is resolved, discard unrelated ambient values from the MCP process itself.
    # Internal Git probes and approval-state subprocesses then inherit the same minimal baseline.
    sanitize_process_environment(
        os.environ,
        extra_names=settings.child_environment_allowlist,
    )
    settings.ensure_directories()
    return settings
