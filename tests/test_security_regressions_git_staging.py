from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from windows_local_mcp.approval import (
    materialize_execution_copy,
    prepare_approval_bundle,
    verify_approval_bundle,
)
from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy, NormalizedCommand


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        **overrides,
    )
    settings.ensure_directories()
    return settings


def _fake_python(tmp_path: Path, cwd: Path) -> NormalizedCommand:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"approved executable")
    return NormalizedCommand(
        executable=str(executable),
        args=["main.py"],
        cwd=str(cwd),
        display_command=[str(executable), "main.py"],
        program_key="python",
    )


def test_approval_staging_rejects_empty_directory_entry_bomb(tmp_path: Path) -> None:
    settings = _settings(tmp_path, approval_manifest_max_files=1)
    workspace = settings.workspace_root
    (workspace / "main.py").write_text("print('ok')\n", encoding="utf-8")
    for index in range(129):
        (workspace / f"empty-{index:03d}").mkdir()

    with pytest.raises(ValueError, match="filesystem entry count exceeds limit"):
        prepare_approval_bundle(
            settings=settings,
            workspace=Workspace(settings),
            operation_id="entry-bomb",
            normalized=_fake_python(tmp_path, workspace),
        )

    assert not (settings.data_dir / "approval-staging" / "entry-bomb").exists()
    assert settings.sandbox_scratch_dir is not None
    assert not (
        settings.sandbox_scratch_dir / "approval-inputs" / "entry-bomb"
    ).exists()


def test_materialization_rechecks_entry_bound_after_staging_tamper(tmp_path: Path) -> None:
    settings = _settings(tmp_path, approval_manifest_max_files=1)
    workspace = settings.workspace_root
    (workspace / "main.py").write_text("print('ok')\n", encoding="utf-8")
    execution, manifest, _digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="entry-tamper",
        normalized=_fake_python(tmp_path, workspace),
    )
    staged_cwd = Path(str(manifest["staged_cwd"]))
    staged_cwd.chmod(0o755)
    for index in range(129):
        (staged_cwd / f"empty-{index:03d}").mkdir()

    with pytest.raises(ValueError, match="filesystem entry count exceeds limit"):
        materialize_execution_copy(
            settings=settings,
            operation_id="entry-tamper",
            normalized=execution,
        )

    assert settings.sandbox_scratch_dir is not None
    assert not (settings.sandbox_scratch_dir / "runs" / "entry-tamper").exists()


def test_git_read_grammar_disables_optional_locks_and_index_refresh(tmp_path: Path) -> None:
    settings = _settings(tmp_path, git_enabled=True)
    policy = CommandPolicy(settings, Workspace(settings))

    normalized = policy._normalize_git(["diff", "--stat"])

    assert "--no-optional-locks" in normalized
    assert "diff.autoRefreshIndex=false" in normalized


def test_approved_git_state_capture_does_not_execute_or_follow_git_metadata(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, git_enabled=True)
    workspace = settings.workspace_root
    fake_git = tmp_path / "git.exe"
    fake_git.write_bytes(b"not an executable")
    metadata = workspace / ".git"
    (metadata / "objects" / "info").mkdir(parents=True)
    outside = tmp_path / "outside-objects"
    outside.mkdir()
    (outside / "secret").write_text("outside", encoding="utf-8")
    (metadata / "objects" / "info" / "alternates").write_text(
        str(outside), encoding="utf-8"
    )
    (metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    normalized = CommandPolicy(settings, Workspace(settings)).normalize_host(
        command=[str(fake_git), "status", "--short"],
        cwd=".",
        network_expected=False,
    )
    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="approved-git-noexec",
        normalized=normalized,
    )
    verified = verify_approval_bundle(
        settings=settings,
        operation_id="approved-git-noexec",
        expected_digest=digest,
    )

    assert manifest["mode"] == "git-state-source-workspace"
    assert verified.program_key == "git"
    assert "metadata_digest" in manifest["git_state"]


def test_approved_git_state_change_invalidates_approval(tmp_path: Path) -> None:
    settings = _settings(tmp_path, git_enabled=True)
    workspace = settings.workspace_root
    fake_git = tmp_path / "git.exe"
    fake_git.write_bytes(b"not an executable")
    metadata = workspace / ".git"
    metadata.mkdir()
    head = metadata / "HEAD"
    head.write_text("ref: refs/heads/main\n", encoding="utf-8")
    normalized = CommandPolicy(settings, Workspace(settings)).normalize_host(
        command=[str(fake_git), "status", "--short"],
        cwd=".",
        network_expected=False,
    )
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="approved-git-change",
        normalized=normalized,
    )
    head.write_text("ref: refs/heads/other\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Git metadata changed after approval"):
        verify_approval_bundle(
            settings=settings,
            operation_id="approved-git-change",
            expected_digest=digest,
        )


def test_approved_git_state_capture_preserves_real_index(tmp_path: Path) -> None:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")

    settings = _settings(tmp_path, git_enabled=True)
    workspace = settings.workspace_root
    tracked = workspace / "tracked.txt"
    subprocess.run(
        [git, "init", str(workspace)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    tracked.write_text("approved\n", encoding="utf-8")
    subprocess.run(
        [git, "-C", str(workspace), "add", "tracked.txt"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    subprocess.run(
        [
            git,
            "-C",
            str(workspace),
            "-c",
            "user.name=WLMCP Test",
            "-c",
            "user.email=wlmcp@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )

    policy = CommandPolicy(settings, Workspace(settings))
    normalized = policy.normalize_host(
        command=[git, "status", "--short"],
        cwd=".",
        network_expected=False,
    )
    index = workspace / ".git" / "index"
    old_time = time.time() - 120
    os.utime(index, (old_time, old_time))
    before_bytes = index.read_bytes()
    before_mtime = index.stat().st_mtime_ns

    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="approved-git",
        normalized=normalized,
    )
    verified = verify_approval_bundle(
        settings=settings,
        operation_id="approved-git",
        expected_digest=digest,
    )

    assert manifest["mode"] == "git-state-source-workspace"
    assert verified.program_key == "git"
    assert index.read_bytes() == before_bytes
    assert index.stat().st_mtime_ns == before_mtime
