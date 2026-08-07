from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy


def make_settings(tmp_path: Path) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    settings = Settings(workspace_root=root, data_dir=data)
    settings.ensure_directories()
    return settings


def test_rejects_unknown_program(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="python", args=["-c", "print(1)"], cwd=".")


def test_rejects_git_push_before_executable_lookup(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="git", args=["push"], cwd=".")
