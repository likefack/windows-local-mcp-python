from __future__ import annotations

import csv
import io
import os
import stat
import subprocess
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

from .child_env import normalize_extra_environment_names, sanitize_process_environment
from .git_env import strip_git_ambient_environment
from .windows_system import windows_system_executable


class Settings(BaseModel):
    """Validated, fail-closed configuration for one MCP instance/workspace."""

    workspace_root: Path
    data_dir: Path

    filesystem_enabled: bool = True
    git_enabled: bool = True
    flutter_enabled: bool = False
    dart_enabled: bool = False
    adb_enabled: bool = False
    powershell_enabled: bool = False

    adb_emulator_only: bool = True
    adb_allowed_serials: list[str] = Field(default_factory=list)

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
    safe_network_isolation_mode: Literal["appcontainer", "compatibility"] = "appcontainer"
    safe_network_profile_prefix: str = "WindowsLocalMCP.SafeTier"
    safe_network_readable_paths: list[Path] = Field(default_factory=list)
    approved_sandbox_enabled: bool = True
    approved_sandbox_backend: Literal["codex_cli"] = "codex_cli"
    approved_sandbox_codex_path: Path | None = None
    approved_sandbox_windows_mode: Literal["elevated"] = "elevated"
    approved_sandbox_permission_profile: Literal[":workspace"] = ":workspace"

    _config_selection_source: str = PrivateAttr(default="direct_settings")
    _config_path: str | None = PrivateAttr(default=None)
    _workspace_selection_source: str = PrivateAttr(default="settings")
    _ambient_root_present: bool = PrivateAttr(default=False)

    @model_validator(mode="before")
    @classmethod
    def validate_lexical_overlap(cls, payload: object) -> object:
        if not isinstance(payload, dict):
            return payload
        root_value = payload.get("workspace_root")
        data_value = payload.get("data_dir")
        if root_value and data_value:
            root = Path(os.path.expandvars(os.path.expanduser(str(root_value)))).absolute()
            data = Path(os.path.expandvars(os.path.expanduser(str(data_value)))).absolute()
            if _is_relative_to(data, root) or _is_relative_to(root, data):
                raise ValueError("data_dir and workspace_root lexically overlap")
        return payload

    @field_validator("workspace_root", "data_dir", mode="before")
    @classmethod
    def expand_path(cls, value: object) -> Path:
        if value is None or str(value).strip() == "":
            raise ValueError("path must not be empty")
        return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()

    @field_validator("approved_sandbox_codex_path", mode="before")
    @classmethod
    def expand_optional_executable(cls, value: object) -> Path | None:
        if value is None or not str(value).strip():
            return None
        return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve(strict=True)

    @field_validator("safe_network_readable_paths", mode="before")
    @classmethod
    def expand_readable_paths(cls, value: object) -> list[Path]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError("safe_network_readable_paths must be a list")
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

    @field_validator("safe_network_profile_prefix")
    @classmethod
    def validate_appcontainer_prefix(cls, value: str) -> str:
        prefix = value.strip()
        allowed = set("-_. ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        if not prefix or len(prefix) > 24 or any(character not in allowed for character in prefix):
            raise ValueError("safe_network_profile_prefix is invalid")
        return prefix

    @field_validator("child_environment_allowlist")
    @classmethod
    def validate_child_environment_allowlist(cls, values: list[str]) -> list[str]:
        return normalize_extra_environment_names(values)

    @model_validator(mode="after")
    def validate_security_boundaries(self) -> Settings:
        root = self.workspace_root
        data = self.data_dir
        if _is_relative_to(data, root) or _is_relative_to(root, data):
            raise ValueError("data_dir and workspace_root must not overlap")
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
        for path in self.safe_network_readable_paths:
            if path == Path(path.anchor):
                raise ValueError("safe_network_readable_paths cannot include a drive root")
            if any(
                _is_relative_to(path, protected) or _is_relative_to(protected, path)
                for protected in (root, data)
            ):
                raise ValueError(
                    "safe_network_readable_paths cannot overlap workspace_root, data_dir, "
                    "or an ancestor of either"
                )
        codex_path = self.approved_sandbox_codex_path
        if codex_path is not None:
            if not codex_path.is_file() or _is_reparse(codex_path):
                raise ValueError("approved_sandbox_codex_path must be a regular non-reparse file")
            if _is_relative_to(codex_path, root) or _is_relative_to(codex_path, data):
                raise ValueError(
                    "approved_sandbox_codex_path must be outside workspace_root and data_dir"
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
        for name in (
            "logs",
            "outputs",
            "diffs",
            "backups",
            "git-snapshots",
            "approval-staging",
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
        if self.protect_data_dir_acl and os.name == "nt":
            _protect_windows_acl(self.data_dir)

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


def _is_loopback_host(host: str) -> bool:
    return host.strip().casefold() in {"127.0.0.1", "::1", "localhost"}


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    attributes = int(getattr(info, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _protect_windows_acl(path: Path) -> None:
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
    result = subprocess.run(
        [
            windows_system_executable("icacls.exe"),
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(OI)(CI)F",
            "SYSTEM:(OI)(CI)F",
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


def _default_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "WindowsLocalMCP"
    return Path.home() / ".windows-local-mcp"


def load_settings() -> Settings:
    # Every production entrypoint calls load_settings(). Scrub Git repository/config overrides
    # before any Git probe, snapshot, approval-state capture, or child process can inherit them.
    strip_git_ambient_environment(os.environ)

    config_path_value = os.environ.get("LOCAL_MCP_CONFIG", "").strip()
    payload: dict[str, object] = {}

    config_path: Path | None = None
    if config_path_value:
        config_path = Path(config_path_value).expanduser().resolve(strict=True)
        with config_path.open("rb") as file:
            payload = tomllib.load(file)

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

    data_dir = str(payload.get("data_dir", "")).strip()
    if not data_dir:
        payload["data_dir"] = str(_default_data_dir())

    settings = Settings.model_validate(payload)
    if config_path is not None and _is_relative_to(config_path, settings.workspace_root):
        raise ValueError("the active config path must be outside workspace_root")
    settings._config_selection_source = (
        "LOCAL_MCP_CONFIG" if config_path is not None else "environment_only"
    )
    settings._config_path = str(config_path) if config_path is not None else None
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
