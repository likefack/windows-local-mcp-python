from __future__ import annotations

import os
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
    return git, settings


def _commit_file(git: str, settings: Settings, relative: str, content: str) -> None:
    target = settings.workspace_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    subprocess.run(
        [git, "-C", str(settings.workspace_root), "add", "--", relative],
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
            "user.name=Automatic Git Regression",
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


def _status_command(git: str) -> tuple[str, ...]:
    return (git, "status", "--porcelain=v1")


def test_ignored_untracked_root_directory_is_not_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings = _init_repository(tmp_path)
    (settings.workspace_root / ".gitignore").write_text(
        "/.pytest-tmp-*/\n",
        encoding="utf-8",
    )
    subprocess.run(
        [git, "-C", str(settings.workspace_root), "add", ".gitignore"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    artifact = settings.workspace_root / ".pytest-tmp-default"
    artifact.mkdir()
    (artifact / "unreadable-test-output.bin").write_bytes(b"test-only")

    original_hold = git_broker.hold_verified_path

    def guarded_hold(path: str | Path, **kwargs: object) -> Path:
        if Path(path) == artifact:
            raise PermissionError("simulated unreadable ignored tree")
        return original_hold(path, **kwargs)

    monkeypatch.setattr(git_broker, "hold_verified_path", guarded_hold)
    stage = stage_git_repository(
        settings,
        "ignored-unreadable",
        commands=(_status_command(git),),
    )
    try:
        assert not (stage.repository / artifact.name).exists()
        assert (stage.repository / ".gitignore").is_file()
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)


def test_tracked_path_prevents_ignored_directory_pruning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings = _init_repository(tmp_path)
    (settings.workspace_root / ".gitignore").write_text(
        "/generated-*/\n",
        encoding="utf-8",
    )
    tracked = settings.workspace_root / "generated-state" / "tracked.txt"
    tracked.parent.mkdir()
    tracked.write_text("tracked\n", encoding="utf-8")
    subprocess.run(
        [
            git,
            "-C",
            str(settings.workspace_root),
            "add",
            "-f",
            ".gitignore",
            "generated-state/tracked.txt",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    artifact = tracked.parent
    original_hold = git_broker.hold_verified_path

    def guarded_hold(path: str | Path, **kwargs: object) -> Path:
        if Path(path) == artifact:
            raise PermissionError("simulated unreadable tracked tree")
        return original_hold(path, **kwargs)

    monkeypatch.setattr(git_broker, "hold_verified_path", guarded_hold)
    with pytest.raises(GitBrokerUnavailable, match="projection could not be verified"):
        stage_git_repository(
            settings,
            "tracked-unreadable",
            commands=(_status_command(git),),
        )


def test_ls_files_others_without_exclude_standard_disables_ignored_pruning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings = _init_repository(tmp_path)
    (settings.workspace_root / ".gitignore").write_text(
        "/generated-*/\n",
        encoding="utf-8",
    )
    artifact = settings.workspace_root / "generated-cache"
    artifact.mkdir()
    (artifact / "cache.bin").write_bytes(b"cache")
    original_hold = git_broker.hold_verified_path

    def guarded_hold(path: str | Path, **kwargs: object) -> Path:
        if Path(path) == artifact:
            raise PermissionError("simulated unreadable observable tree")
        return original_hold(path, **kwargs)

    monkeypatch.setattr(git_broker, "hold_verified_path", guarded_hold)
    with pytest.raises(GitBrokerUnavailable, match="projection could not be verified"):
        stage_git_repository(
            settings,
            "ls-files-others",
            commands=((git, "ls-files", "--others"),),
        )


def test_security_relevant_git_metadata_remains_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git, settings = _init_repository(tmp_path)
    objects = settings.workspace_root / ".git" / "objects"
    original_hold = git_broker.hold_verified_path

    def guarded_hold(path: str | Path, **kwargs: object) -> Path:
        if Path(path) == objects:
            raise PermissionError("simulated unreadable object database")
        return original_hold(path, **kwargs)

    monkeypatch.setattr(git_broker, "hold_verified_path", guarded_hold)
    with pytest.raises(GitBrokerUnavailable, match="projection could not be verified"):
        stage_git_repository(
            settings,
            "objects-unreadable",
            commands=(_status_command(git),),
        )


def test_reparse_input_remains_rejected(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    target = settings.workspace_root / "target"
    target.mkdir()
    link = settings.workspace_root / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlink creation is unavailable: {error}")

    with pytest.raises(GitBrokerUnavailable, match="reparse input is denied"):
        stage_git_repository(
            settings,
            "reparse",
            commands=(_status_command(git),),
        )


def test_hardlinked_relevant_input_remains_rejected(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    source = settings.workspace_root / "tracked.txt"
    source.write_text("tracked\n", encoding="utf-8")
    outside = tmp_path / "second-link.txt"
    try:
        os.link(source, outside)
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error}")

    with pytest.raises(GitBrokerUnavailable, match="hard-linked Git input"):
        stage_git_repository(
            settings,
            "hardlink",
            commands=(_status_command(git),),
        )


def test_nested_git_metadata_remains_rejected(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    nested = settings.workspace_root / "nested" / ".git"
    nested.mkdir(parents=True)
    (nested / "config").write_text("[core]\n", encoding="utf-8")

    with pytest.raises(GitBrokerUnavailable, match=r"nested \.git metadata"):
        stage_git_repository(
            settings,
            "nested-git",
            commands=(_status_command(git),),
        )


def test_object_alternates_remain_rejected(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    alternates = settings.workspace_root / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str(tmp_path / "outside-objects"), encoding="utf-8")

    with pytest.raises(
        GitBrokerUnavailable,
        match="external/extended repository metadata",
    ):
        stage_git_repository(
            settings,
            "alternates",
            commands=(_status_command(git),),
        )


@pytest.mark.skipif(os.name != "nt", reason="real NTFS ADS regression")
def test_named_ads_is_dropped_at_projection_boundary(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    _commit_file(git, settings, "tracked.txt", "tracked\n")
    source = settings.workspace_root / "tracked.txt"
    source_ads = Path(f"{source}:Zone.Identifier")
    source_ads.write_text("[ZoneTransfer]\nZoneId=3\n", encoding="utf-8")
    assert source_ads.exists()

    stage = stage_git_repository(
        settings,
        "ads",
        commands=(_status_command(git),),
    )
    try:
        staged = stage.repository / "tracked.txt"
        assert staged.read_text(encoding="utf-8") == "tracked\n"
        assert not Path(f"{staged}:Zone.Identifier").exists()
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle sharing is the TOCTOU boundary")
def test_pruning_inputs_are_pinned_against_mutation(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    ignore = settings.workspace_root / ".gitignore"
    ignore.write_text("/generated-*/\n", encoding="utf-8")
    subprocess.run(
        [git, "-C", str(settings.workspace_root), "add", ".gitignore"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    policy = git_broker._build_projection_prune_policy(
        settings.workspace_root,
        (_status_command(git),),
        byte_limit=32 * 1024 * 1024,
    )
    try:
        assert policy.enabled
        with pytest.raises(OSError):
            ignore.write_text("/different-*/\n", encoding="utf-8")
        with pytest.raises(OSError):
            (settings.workspace_root / ".git" / "index").write_bytes(b"replacement")
    finally:
        policy.close()


def test_real_git_structural_operations_survive_projection(tmp_path: Path) -> None:
    git, settings = _init_repository(tmp_path)
    _commit_file(git, settings, "tracked.txt", "before\n")
    (settings.workspace_root / "tracked.txt").write_text("after\n", encoding="utf-8")
    (settings.workspace_root / ".gitignore").write_text(
        "/generated-*/\n",
        encoding="utf-8",
    )
    ignored = settings.workspace_root / "generated-cache"
    ignored.mkdir()
    (ignored / "cache.bin").write_bytes(b"cache")

    commands = (
        (git, "status", "--porcelain=v1"),
        (git, "diff", "--stat"),
        (git, "log", "--format=%H%x09%P%x09%T%x09%ct", "-1"),
        (git, "show", "--no-patch", "--format=%H%x09%P%x09%T%x09%ct", "HEAD"),
        (git, "rev-parse", "--is-inside-work-tree"),
        (git, "ls-files", "--stage"),
    )
    stage = stage_git_repository(settings, "real-git", commands=commands)
    try:
        for command in commands:
            result = subprocess.run(
                [command[0], "-C", str(stage.repository), *command[1:]],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                shell=False,
            )
            assert result.returncode == 0, result.stderr.decode(errors="replace")
        status = subprocess.run(
            [git, "-C", str(stage.repository), "status", "--porcelain=v1"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        assert b"tracked.txt" in status
        assert b"generated-cache" not in status
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)
