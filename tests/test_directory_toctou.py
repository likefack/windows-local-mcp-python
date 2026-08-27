import gc
import os
import sys
from pathlib import Path

import pytest

import windows_local_mcp.git_snapshot as git_snapshot_module
import windows_local_mcp.safe_process as safe_process_module
from windows_local_mcp.config import Settings
from windows_local_mcp.git_snapshot import capture_git_snapshot
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy
from windows_local_mcp.process_utils import build_process_argv
from windows_local_mcp.safe_process import SafeProcessResult, run_safe_process

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows file-share semantics are the directory TOCTOU security boundary",
)


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    settings = Settings(
        workspace_root=root,
        data_dir=data,
        protect_data_dir_acl=False,
        **overrides,
    )
    settings.ensure_directories()
    return settings


def test_resolve_directory_pins_namespace_until_hold_is_released(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    workspace = Workspace(settings)
    target = workspace.root / "safe"
    target.mkdir()
    replacement = workspace.root / "replacement"
    replacement.mkdir()
    moved = workspace.root / "moved"

    verified = workspace.resolve_directory("safe")
    with pytest.raises(OSError):
        os.rename(target, moved)

    del verified
    gc.collect()
    os.rename(target, moved)
    os.rename(replacement, target)
    assert target.is_dir()


def test_normalized_broker_command_keeps_cwd_hold_alive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(tmp_path)
    (settings.workspace_root / ".git").mkdir()
    target = settings.workspace_root / "safe"
    target.mkdir()
    moved = settings.workspace_root / "moved"
    policy = CommandPolicy(settings, Workspace(settings))
    monkeypatch.setattr(
        policy,
        "_resolve_safe_executable",
        lambda _program_key: {"path": sys.executable},
    )

    normalized = policy.normalize_safe(
        program="git",
        args=["status", "--short"],
        cwd="safe",
    )
    assert normalized.cwd == str(target.resolve())
    normalized.model_dump()
    with pytest.raises(OSError):
        os.rename(target, moved)

    del normalized
    gc.collect()
    os.rename(target, moved)
    assert moved.is_dir()


def test_process_argv_pins_cwd_until_argv_is_released(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    target = settings.workspace_root / "safe"
    target.mkdir()
    moved = settings.workspace_root / "moved"

    argv = build_process_argv("tool.exe", [], cwd=target)
    with pytest.raises(OSError):
        os.rename(target, moved)

    del argv
    gc.collect()
    os.rename(target, moved)
    assert moved.is_dir()


def test_safe_process_pins_cwd_before_subprocess_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(tmp_path)
    target = settings.workspace_root / "safe"
    target.mkdir()
    moved = settings.workspace_root / "moved"

    def reject_launch(*_args: object, **_kwargs: object) -> None:
        with pytest.raises(OSError):
            os.rename(target, moved)
        raise RuntimeError("launch sentinel")

    monkeypatch.setattr(safe_process_module.subprocess, "Popen", reject_launch)
    identity = {"path": str(Path(sys.executable).resolve(strict=True))}
    with pytest.raises(RuntimeError, match="launch sentinel"):
        run_safe_process(
            settings=settings,
            program_key="git",
            command=[str(Path(sys.executable).resolve(strict=True))],
            cwd=str(target),
            timeout=1,
            output_limit=1024,
            executable_identity=identity,
            executable_already_held=True,
        )

    os.rename(target, moved)
    assert moved.is_dir()


def test_git_snapshot_pins_workspace_root_across_sandbox_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(tmp_path, git_enabled=True)
    root = settings.workspace_root
    (root / ".git").mkdir()
    moved = tmp_path / "moved-workspace"
    identity = {"path": str(Path(sys.executable).resolve(strict=True))}
    monkeypatch.setattr(
        git_snapshot_module,
        "trusted_helper_identity",
        lambda _settings, _program_key: identity,
    )

    def fake_batch(
        *, commands: list[list[str]], **_kwargs: object
    ) -> list[SafeProcessResult]:
        with pytest.raises(OSError):
            os.rename(root, moved)
        return [
            SafeProcessResult(
                returncode=0,
                stdout=b"",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
            )
            for _command in commands
        ]

    monkeypatch.setattr(git_snapshot_module, "run_git_broker_batch", fake_batch)

    snapshot = capture_git_snapshot(
        settings=settings,
        operation_id="directory-race",
        stage="before",
    )
    assert snapshot is not None
    assert root.is_dir()
