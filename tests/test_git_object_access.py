import shutil
import subprocess
from hashlib import sha256
from pathlib import Path

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


def _real_git_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, Settings, CommandPolicy]:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    settings, policy = _policy(tmp_path, monkeypatch, executable=Path(git))
    shutil.rmtree(settings.workspace_root / ".git")
    subprocess.run(
        [git, "init", str(settings.workspace_root)],
        capture_output=True,
        check=True,
        shell=False,
    )
    return git, settings, policy


def _write_blob(git: str, workspace: Path, payload: bytes) -> str:
    return subprocess.run(
        [git, "hash-object", "-w", "--stdin"],
        cwd=workspace,
        input=payload,
        capture_output=True,
        check=True,
        shell=False,
    ).stdout.decode("ascii").strip()


def test_git_show_raw_blob_is_forced_through_commit_peel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings, policy = _real_git_policy(tmp_path, monkeypatch)
    blob = _write_blob(git, settings.workspace_root, b"TOP_SECRET\n")

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


def test_git_diff_raw_blobs_are_forced_through_commit_peel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings, policy = _real_git_policy(tmp_path, monkeypatch)
    secret = _write_blob(git, settings.workspace_root, b"TOP_SECRET  \n")
    public = _write_blob(git, settings.workspace_root, b"PUBLIC\n")

    normalized = policy.normalize_safe(
        program="git", args=["diff", "--stat", secret, public], cwd="."
    )

    assert f"{secret}^{{commit}}" in normalized.args
    assert f"{public}^{{commit}}" in normalized.args
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


def test_git_diff_check_requires_regular_file_pathspec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"MZ fake")
    settings, policy = _policy(tmp_path, monkeypatch, executable=executable)
    source = settings.workspace_root / "public.txt"
    source.write_text("public\n", encoding="utf-8")

    with pytest.raises(PermissionError, match="safe grammar"):
        policy.normalize_safe(program="git", args=["diff", "--check"], cwd=".")
    normalized = policy.normalize_safe(
        program="git", args=["diff", "--check", "--", "public.txt"], cwd="."
    )
    assert "--check" in normalized.args
    assert str(source.resolve()) in normalized.args


def test_git_show_default_revision_is_commit_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"MZ fake")
    _settings, policy = _policy(tmp_path, monkeypatch, executable=executable)

    normalized = policy.normalize_safe(program="git", args=["show", "--stat"], cwd=".")

    assert "HEAD^{commit}" in normalized.args


def test_git_revision_ranges_bind_both_commit_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"MZ fake")
    _settings, policy = _policy(tmp_path, monkeypatch, executable=executable)

    show = policy.normalize_safe(program="git", args=["show", "HEAD~2..HEAD"], cwd=".")
    diff = policy.normalize_safe(program="git", args=["diff", "HEAD~2...HEAD"], cwd=".")

    assert "HEAD~2^{commit}..HEAD^{commit}" in show.args
    assert "HEAD~2^{commit}...HEAD^{commit}" in diff.args
