from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import windows_local_mcp.git_broker_sandbox as git_broker
from windows_local_mcp.config import Settings
from windows_local_mcp.git_broker_sandbox import GitBrokerUnavailable, stage_git_repository


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        max_sandbox_scratch_bytes=64 * 1024 * 1024,
    )
    settings.ensure_directories()
    return settings


def _init_repository(tmp_path: Path) -> tuple[str, Settings]:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    settings = _settings(tmp_path)
    subprocess.run(
        [git, "init", str(settings.workspace_root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    tracked = settings.workspace_root / "tracked.txt"
    tracked.write_text("tracked\n", encoding="utf-8")
    subprocess.run(
        [git, "-C", str(settings.workspace_root), "add", "tracked.txt"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    subprocess.run(
        [
            git,
            "-C",
            str(settings.workspace_root),
            "-c",
            "user.name=Automatic Git Ref Regression",
            "-c",
            "user.email=regression@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    return git, settings


def _status_command(git: str) -> tuple[str, ...]:
    return (git, "status", "--porcelain=v1", "--untracked-files=no")


def _head_ref(git: str, settings: Settings) -> str:
    result = subprocess.run(
        [git, "-C", str(settings.workspace_root), "symbolic-ref", "HEAD"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
    )
    return result.stdout.strip()


def test_verifier_and_git_snapshot_batches_are_head_only() -> None:
    git = "git.exe"
    base = (
        git,
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
    )
    verifier = (
        (*base, "rev-parse", "--is-inside-work-tree"),
        (*base, "status", "--porcelain=v1", "--untracked-files=no"),
        (*base, "--list-cmds=builtins"),
    )
    snapshot = (
        (*base, "symbolic-ref", "--short", "HEAD"),
        (*base, "rev-parse", "HEAD"),
        (*base, "status", "--porcelain=v1", "--branch", "--untracked-files=all"),
        (*base, "diff", "--stat", "--name-status"),
        (*base, "diff", "--cached", "--stat", "--name-status"),
        (*base, "log", "-10", "--format=%H%x09%P%x09%T%x09%ct"),
        (*base, "diff", "--name-status", "HEAD"),
    )

    assert git_broker._commands_require_full_refs(verifier) is False
    assert git_broker._commands_require_full_refs(snapshot) is False


@pytest.mark.parametrize(
    "command",
    [
        ("git.exe", "log", "--all"),
        ("git.exe", "log", "--branches"),
        ("git.exe", "show", "topic"),
        ("git.exe", "log", "HEAD@{1}"),
    ],
)
def test_ref_observing_commands_require_full_refs(command: tuple[str, ...]) -> None:
    assert git_broker._command_requires_full_refs(command) is True


def test_head_only_projection_does_not_open_or_materialize_unrelated_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings = _init_repository(tmp_path)
    unrelated = settings.workspace_root / ".git" / "refs" / "codex"
    deep = (
        unrelated
        / "turn-diffs"
        / "checkpoints"
        / ("a" * 40)
        / ("b" * 40)
        / "1787777885799"
    )
    deep.parent.mkdir(parents=True)
    head = subprocess.run(
        [git, "-C", str(settings.workspace_root), "rev-parse", "HEAD"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
    ).stdout.strip()
    deep.write_text(head + "\n", encoding="ascii")

    original_hold = git_broker.hold_verified_path

    def guarded_hold(path: str | Path, **kwargs: object) -> Path:
        if Path(path) == unrelated:
            raise AssertionError("unrelated ref namespace must not be opened")
        return original_hold(path, **kwargs)

    monkeypatch.setattr(git_broker, "hold_verified_path", guarded_hold)
    stage = stage_git_repository(
        settings,
        "head-only-unrelated-refs",
        commands=(_status_command(git),),
    )
    try:
        assert not (stage.repository / ".git" / "refs" / "codex").exists()
        current_ref = _head_ref(git, settings)
        assert (stage.repository / ".git" / Path(current_ref)).is_file()
        status = subprocess.run(
            [git, "-C", str(stage.repository), "status", "--porcelain=v1"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            shell=False,
        )
        assert status.returncode == 0, status.stderr.decode(errors="replace")
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)


def test_full_ref_command_keeps_unrelated_ref_namespace_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings = _init_repository(tmp_path)
    unrelated = settings.workspace_root / ".git" / "refs" / "topic"
    unrelated.mkdir(parents=True)
    (unrelated / "branch").write_text("0" * 40 + "\n", encoding="ascii")
    original_hold = git_broker.hold_verified_path

    def guarded_hold(path: str | Path, **kwargs: object) -> Path:
        if Path(path) == unrelated:
            raise PermissionError("simulated unreadable required ref namespace")
        return original_hold(path, **kwargs)

    monkeypatch.setattr(git_broker, "hold_verified_path", guarded_hold)
    with pytest.raises(GitBrokerUnavailable, match="projection could not be verified"):
        stage_git_repository(
            settings,
            "full-refs-required",
            commands=((git, "log", "--all"),),
        )


def test_head_only_projection_retains_loose_current_ref(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    current_ref = _head_ref(git, settings)
    source_ref = settings.workspace_root / ".git" / Path(current_ref)
    assert source_ref.is_file()

    stage = stage_git_repository(
        settings,
        "loose-head",
        commands=(_status_command(git),),
    )
    try:
        staged_ref = stage.repository / ".git" / Path(current_ref)
        assert staged_ref.read_bytes() == source_ref.read_bytes()
        source_head = subprocess.run(
            [git, "-C", str(settings.workspace_root), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        staged_head = subprocess.run(
            [git, "-C", str(stage.repository), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        assert staged_head == source_head
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)


def test_head_only_projection_supports_packed_current_branch(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    current_ref = _head_ref(git, settings)
    subprocess.run(
        [git, "-C", str(settings.workspace_root), "pack-refs", "--all", "--prune"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    assert not (settings.workspace_root / ".git" / Path(current_ref)).exists()
    assert (settings.workspace_root / ".git" / "packed-refs").is_file()

    stage = stage_git_repository(
        settings,
        "packed-head",
        commands=(_status_command(git),),
    )
    try:
        assert (stage.repository / ".git" / "packed-refs").is_file()
        assert not (stage.repository / ".git" / Path(current_ref)).exists()
        source_head = subprocess.run(
            [git, "-C", str(settings.workspace_root), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        staged_head = subprocess.run(
            [git, "-C", str(stage.repository), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        assert staged_head == source_head
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)
