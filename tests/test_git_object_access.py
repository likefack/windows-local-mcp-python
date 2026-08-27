from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy


def _policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, executable: Path
) -> tuple[Settings, CommandPolicy]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=True,
    )
    settings.ensure_directories()
    details = executable.stat()
    identity = {
        "path": str(executable.resolve()),
        "sha256": sha256(executable.read_bytes()).hexdigest(),
        "size": details.st_size,
        "device": details.st_dev,
        "inode": details.st_ino,
        "mtime_ns": details.st_mtime_ns,
        "provenance": "test-config",
    }
    monkeypatch.setattr(
        "windows_local_mcp.policy.trusted_helper_identity",
        lambda _settings, _program_key: identity,
    )
    return settings, CommandPolicy(settings, Workspace(settings))


def test_git_show_raw_blob_is_forced_through_commit_peel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    executable = Path(git)
    settings, policy = _policy(tmp_path, monkeypatch, executable=executable)
    shutil.rmtree(settings.workspace_root / ".git")
    subprocess.run(
        [git, "init", str(settings.workspace_root)],
        capture_output=True,
        check=True,
        shell=False,
    )
    blob = subprocess.run(
        [git, "hash-object", "-w", "--stdin"],
        cwd=settings.workspace_root,
        input=b"TOP_SECRET\n",
        capture_output=True,
        check=True,
        shell=False,
    ).stdout.decode("ascii").strip()

    normalized = policy.normalize_safe(program="git", args=["show", blob], cwd=".")

    assert f"{blob}^{{commit}}" in normalized.args
    result = subprocess.run(
        [git, *normalized.args],
        cwd=settings.workspace_root,
        capture_output=True,
        check=False,
        shell=False,
    )
    assert result.returncode != 0
    assert b"TOP_SECRET" not in result.stdout
    assert b"TOP_SECRET" not in result.stderr


def test_git_show_default_revision_is_commit_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"MZ fake")
    _settings, policy = _policy(tmp_path, monkeypatch, executable=executable)

    normalized = policy.normalize_safe(program="git", args=["show", "--stat"], cwd=".")

    assert "HEAD^{commit}" in normalized.args


def test_git_show_revision_range_is_not_automatic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"MZ fake")
    _settings, policy = _policy(tmp_path, monkeypatch, executable=executable)

    with pytest.raises(PermissionError, match="individual commit-ish revisions"):
        policy.normalize_safe(program="git", args=["show", "HEAD~2..HEAD"], cwd=".")
