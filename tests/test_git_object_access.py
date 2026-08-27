import os
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


def test_content_bearing_git_output_cannot_dereference_secret_blob_via_safe_tree_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings, policy = _real_git_policy(tmp_path, monkeypatch)
    secret = _write_blob(git, settings.workspace_root, b"TOP_SECRET_FROM_OBJECT_GRAPH\n")
    tree = subprocess.run(
        [git, "mktree"],
        cwd=settings.workspace_root,
        input=f"100644 blob {secret}\tsafe.txt\n".encode(),
        capture_output=True,
        check=True,
        shell=False,
    ).stdout.decode("ascii").strip()
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Automatic Git Regression",
            "GIT_AUTHOR_EMAIL": "regression@example.invalid",
            "GIT_COMMITTER_NAME": "Automatic Git Regression",
            "GIT_COMMITTER_EMAIL": "regression@example.invalid",
        }
    )
    commit = subprocess.run(
        [git, "commit-tree", tree],
        cwd=settings.workspace_root,
        input=b"crafted object graph\n",
        capture_output=True,
        check=True,
        shell=False,
        env=environment,
    ).stdout.decode("ascii").strip()
    (settings.workspace_root / "safe.txt").write_text("public working-tree file\n", encoding="utf-8")

    unsafe = subprocess.run(
        [git, "show", "--format=", "--patch", commit, "--", "safe.txt"],
        cwd=settings.workspace_root,
        capture_output=True,
        check=True,
        shell=False,
    )
    assert b"TOP_SECRET_FROM_OBJECT_GRAPH" in unsafe.stdout

    with pytest.raises(PermissionError, match="request_sandbox_command"):
        policy.normalize_safe(
            program="git",
            args=["show", "--patch", commit, "--", "safe.txt"],
            cwd=".",
        )
    metadata = policy.normalize_safe(
        program="git",
        args=["show", "--stat", commit, "--", "safe.txt"],
        cwd=".",
    )
    assert f"{commit}^{{commit}}" in metadata.args


def test_git_diff_check_is_not_automatic_content_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"MZ fake")
    settings, policy = _policy(tmp_path, monkeypatch, executable=executable)
    source = settings.workspace_root / "public.txt"
    source.write_text("public\n", encoding="utf-8")

    for args in (
        ["diff", "--check"],
        ["diff", "--check", "--", "public.txt"],
    ):
        with pytest.raises(PermissionError, match="request_sandbox_command"):
            policy.normalize_safe(program="git", args=args, cwd=".")


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
