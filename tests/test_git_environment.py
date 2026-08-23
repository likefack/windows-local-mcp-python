import os
import shutil
import subprocess
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings, load_settings
from windows_local_mcp.git_env import sanitized_git_environment
from windows_local_mcp.git_snapshot import capture_git_snapshot
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy
from windows_local_mcp.util import sha256_file


@pytest.mark.parametrize(
    "name",
    [
        "GIT_DIR",
        "git_work_tree",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_INDEX_FILE",
        "GIT_SHALLOW_FILE",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_GLOBAL",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_LITERAL_PATHSPECS",
    ],
)
def test_sanitized_git_environment_removes_ambient_overrides(name: str) -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_AUTHOR_NAME": "expected-author",
        name: "hostile-value",
    }
    sanitized = sanitized_git_environment(environment)
    assert name not in sanitized
    assert sanitized["GIT_AUTHOR_NAME"] == "expected-author"
    assert sanitized["PATH"] == environment["PATH"]


def test_load_settings_strips_unapproved_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = true",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "outside.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "outside"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.worktree")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(tmp_path / "outside"))
    monkeypatch.setenv("GIT_AUTHOR_NAME", "unlisted-author")

    settings = load_settings()

    assert settings.workspace_root == workspace.resolve()
    assert "GIT_DIR" not in os.environ
    assert "GIT_WORK_TREE" not in os.environ
    assert "GIT_CONFIG_COUNT" not in os.environ
    assert "GIT_CONFIG_KEY_0" not in os.environ
    assert "GIT_CONFIG_VALUE_0" not in os.environ
    assert "GIT_AUTHOR_NAME" not in os.environ
    assert os.environ["LOCAL_MCP_CONFIG"] == str(config)


def test_git_snapshot_is_disabled_even_with_trusted_git_executable(tmp_path: Path) -> None:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(
        [git, "init", str(workspace)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=True,
        git_executable_path=Path(git),
        git_executable_sha256=sha256_file(Path(git))[0],
    )
    settings.ensure_directories()

    snapshot = capture_git_snapshot(
        settings=settings,
        operation_id="git-disabled",
        stage="test",
    )

    assert snapshot is None


def test_automatic_git_rejects_workspace_gitfile_pointing_outside(tmp_path: Path) -> None:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")

    outside = tmp_path / "outside"
    outside.mkdir()
    subprocess.run(
        [git, "init", str(outside)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").write_text(
        f"gitdir: {outside / '.git'}\n",
        encoding="utf-8",
    )
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=True,
        git_executable_path=Path(git),
        git_executable_sha256=sha256_file(Path(git))[0],
    )
    settings.ensure_directories()

    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(
        PermissionError, match="automatic Git broker execution is disabled"
    ):
        policy.normalize_safe(program="git", args=["status", "--short"], cwd=".")

    snapshot = capture_git_snapshot(
        settings=settings,
        operation_id="external-gitdir",
        stage="test",
    )
    assert snapshot is None
