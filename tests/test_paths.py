from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace


def make_workspace(tmp_path: Path) -> Workspace:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    settings = Settings(workspace_root=root, data_dir=data)
    settings.ensure_directories()
    return Workspace(settings)


def test_allows_file_inside_workspace(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    target = workspace.root / "hello.txt"
    target.write_text("hello", encoding="utf-8")
    assert workspace.resolve_existing("hello.txt") == target.resolve()


def test_rejects_parent_escape(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(PermissionError):
        workspace.resolve_existing("../outside.txt")


def test_rejects_env_file(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    target = workspace.root / ".env"
    target.write_text("TOKEN=x", encoding="utf-8")
    with pytest.raises(PermissionError):
        workspace.resolve_existing(".env")
