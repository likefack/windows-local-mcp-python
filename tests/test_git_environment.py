import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp.config import Settings, load_settings
from windows_local_mcp.git_broker_sandbox import (
    GitBrokerUnavailable,
    stage_git_repository,
)
from windows_local_mcp.git_env import sanitized_git_environment
from windows_local_mcp.git_snapshot import capture_git_snapshot
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


def _git_settings(tmp_path: Path) -> tuple[Settings, Path]:
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
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        git_enabled=True,
        git_executable_path=Path(git),
        git_executable_sha256=sha256_file(Path(git))[0],
    )
    settings.ensure_directories()
    return settings, Path(git)


def test_git_snapshot_runs_through_sandboxed_broker_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _git = _git_settings(tmp_path)
    from windows_local_mcp import git_snapshot

    identity = {
        "path": str(settings.git_executable_path),
        "sha256": settings.git_executable_sha256,
    }
    monkeypatch.setattr(
        git_snapshot,
        "trusted_helper_identity",
        lambda _settings, _program_key: identity,
    )

    def fake_batch(**kwargs: object) -> list[SimpleNamespace]:
        commands = list(kwargs["commands"])  # type: ignore[index]
        return [
            SimpleNamespace(returncode=0, stdout=f"result-{index}".encode(), stderr=b"")
            for index, _command in enumerate(commands)
        ]

    monkeypatch.setattr(git_snapshot, "run_git_broker_batch", fake_batch)
    snapshot = capture_git_snapshot(
        settings=settings,
        operation_id="git-restored",
        stage="test",
    )

    assert snapshot is not None
    content = Path(snapshot).read_text(encoding="utf-8")
    assert "===== status exit=0 =====" in content
    assert "result-2" in content


def test_git_snapshot_excludes_secrets_and_project_behavior_metadata(tmp_path: Path) -> None:
    settings, _git = _git_settings(tmp_path)
    workspace = settings.workspace_root
    (workspace / "ordinary.txt").write_text("ordinary", encoding="utf-8")
    (workspace / ".env").write_text("TOP_SECRET=value", encoding="utf-8")
    (workspace / ".gitattributes").write_text(
        "*.txt diff=attacker\n", encoding="utf-8"
    )
    hooks = workspace / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "post-checkout").write_text("attacker", encoding="utf-8")
    config = workspace / ".git" / "config"
    with config.open("a", encoding="utf-8") as output:
        output.write("\n[diff \"attacker\"]\n\tcommand = cmd.exe /c echo leaked\n")

    stage = stage_git_repository(settings, "sanitize")
    try:
        assert (stage.repository / "ordinary.txt").read_text(encoding="utf-8") == "ordinary"
        assert not (stage.repository / ".env").exists()
        projected_attributes = (stage.repository / ".gitattributes").read_bytes()
        assert len(projected_attributes) == len((workspace / ".gitattributes").read_bytes())
        assert set(projected_attributes) <= {ord("#"), ord("\n"), ord("\r")}
        assert not (stage.repository / ".git" / "hooks").exists()
        staged_config = (stage.repository / ".git" / "config").read_text(encoding="utf-8")
        assert "attacker" not in staged_config
        assert "repositoryformatversion = 0" in staged_config
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)


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
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        git_enabled=True,
        git_executable_path=Path(git),
        git_executable_sha256=sha256_file(Path(git))[0],
    )
    settings.ensure_directories()

    with pytest.raises(GitBrokerUnavailable, match="regular .git directory"):
        stage_git_repository(settings, "external-gitdir")


def test_automatic_git_rejects_object_alternates(tmp_path: Path) -> None:
    settings, _git = _git_settings(tmp_path)
    info = settings.workspace_root / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text(str(tmp_path / "outside-objects"), encoding="utf-8")

    with pytest.raises(GitBrokerUnavailable, match="external/extended repository metadata"):
        stage_git_repository(settings, "alternates")


def test_automatic_git_rejects_nested_git_metadata(tmp_path: Path) -> None:
    settings, _git = _git_settings(tmp_path)
    nested = settings.workspace_root / "vendor" / ".git"
    nested.mkdir(parents=True)
    (nested / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")

    with pytest.raises(GitBrokerUnavailable, match="nested .git metadata"):
        stage_git_repository(settings, "nested-git")


def test_automatic_git_rejects_oversized_repository_config(tmp_path: Path) -> None:
    settings, _git = _git_settings(tmp_path)
    config = settings.workspace_root / ".git" / "config"
    config.write_bytes(b"[core]\nrepositoryformatversion = 0\n#" + b"x" * (1024 * 1024))

    with pytest.raises(GitBrokerUnavailable, match="1 MiB parsing limit"):
        stage_git_repository(settings, "oversized-config")
