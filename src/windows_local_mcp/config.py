from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class Settings(BaseModel):
    workspace_root: Path
    data_dir: Path
    max_text_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    max_image_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    max_directory_entries: int = Field(default=3000, ge=1, le=100000)
    approval_ttl_seconds: int = Field(default=1800, ge=60, le=86400)
    default_foreground_timeout_seconds: int = Field(default=30, ge=0, le=600)
    default_max_runtime_seconds: int = Field(default=1800, ge=10, le=86400)
    output_preview_characters: int = Field(default=12000, ge=1000, le=200000)
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
    excluded_directories: list[str] = Field(
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

    @field_validator("workspace_root", "data_dir", mode="before")
    @classmethod
    def expand_path(cls, value: object) -> Path:
        if value is None or str(value).strip() == "":
            raise ValueError("path must not be empty")
        return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()

    def ensure_directories(self) -> None:
        if not self.workspace_root.exists() or not self.workspace_root.is_dir():
            raise FileNotFoundError(f"workspace_rootが存在しません: {self.workspace_root}")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for name in ("logs", "outputs", "diffs", "backups", "git-snapshots"):
            (self.data_dir / name).mkdir(parents=True, exist_ok=True)


def _default_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "WindowsLocalMCP"
    return Path.home() / ".windows-local-mcp"


def load_settings() -> Settings:
    config_path_value = os.environ.get("LOCAL_MCP_CONFIG", "").strip()
    payload: dict[str, object] = {}

    if config_path_value:
        config_path = Path(config_path_value).expanduser().resolve()
        with config_path.open("rb") as file:
            payload = tomllib.load(file)

    env_root = os.environ.get("LOCAL_MCP_ROOT", "").strip()
    if env_root:
        payload["workspace_root"] = env_root

    if "workspace_root" not in payload:
        payload["workspace_root"] = os.getcwd()

    data_dir = str(payload.get("data_dir", "")).strip()
    if not data_dir:
        payload["data_dir"] = str(_default_data_dir())

    settings = Settings.model_validate(payload)
    settings.ensure_directories()
    return settings
