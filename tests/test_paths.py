import gc
import os
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.process_utils import build_process_argv
from windows_local_mcp.resources import WorkspaceExecutionLock


def make_workspace(tmp_path: Path) -> Workspace:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    settings = Settings(
        workspace_root=root, data_dir=data, protect_data_dir_acl=False
    )
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


@pytest.mark.parametrize("path", ["file.txt:secret", "NUL", "con.txt", "name. "])
def test_rejects_windows_special_paths(tmp_path: Path, path: str) -> None:
    workspace = make_workspace(tmp_path)
    with pytest.raises(PermissionError):
        workspace.resolve_for_write(path)


def test_hides_generated_directory_but_allows_read(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    generated = workspace.root / "node_modules"
    generated.mkdir()
    file_path = generated / "package.json"
    file_path.write_text("{}", encoding="utf-8")
    assert workspace.is_hidden(generated)
    assert workspace.resolve_existing("node_modules/package.json") == file_path.resolve()
    with pytest.raises(PermissionError, match="write access"):
        workspace.resolve_for_write("node_modules/package.json")


def test_git_is_read_and_write_denied(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    git_dir = workspace.root / ".git"
    git_dir.mkdir()
    head = git_dir / "HEAD"
    head.write_text("ref: refs/heads/main", encoding="utf-8")
    with pytest.raises(PermissionError):
        workspace.resolve_existing(".git/HEAD")
    with pytest.raises(PermissionError):
        workspace.resolve_for_write(".git/HEAD")


def test_rejects_symlink_or_junction_escape(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link = workspace.root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or elevation")
    with pytest.raises(PermissionError):
        workspace.resolve_existing("linked/secret.txt")


def test_rejects_hardlinked_file(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    linked = workspace.root / "linked.txt"
    try:
        linked.hardlink_to(outside)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(PermissionError, match="hard links"):
        workspace.resolve_existing("linked.txt", allow_directory=False)


def test_missing_write_target_is_a_stable_snapshot_until_revalidation(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    planned = workspace.resolve_for_write("new.txt")
    parent_identity = workspace.identity(planned.parent)
    target_identity = workspace.identity(planned)
    assert parent_identity is not None
    assert target_identity is None

    raced = workspace.root / "new.txt"
    raced.write_text("raced", encoding="utf-8")
    assert not planned.exists()

    with pytest.raises(RuntimeError, match="write target changed"):
        workspace.revalidate_for_replace(
            planned,
            parent_identity=parent_identity,
            target_identity=target_identity,
        )


_SAFE_GIT_ARGS = [
    "--no-pager",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "diff.external=",
    "-c",
    "credential.helper=",
    "diff",
    "--no-ext-diff",
    "--no-textconv",
    "--patch",
]


def test_broker_git_argv_rejects_hardlinked_pathspec(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("secret", encoding="utf-8")
    linked = tmp_path / "linked.txt"
    try:
        linked.hardlink_to(source)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    with pytest.raises(PermissionError, match="hard links"):
        build_process_argv(
            "git.exe",
            [*_SAFE_GIT_ARGS, "--", str(linked.resolve())],
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows file-share semantics are the security boundary")
def test_verified_path_blocks_replacement_until_reader_releases_it(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    target = workspace.root / "safe.txt"
    target.write_text("safe", encoding="utf-8")
    replacement = workspace.root / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")

    verified = workspace.resolve_existing("safe.txt", allow_directory=False)
    with pytest.raises(OSError):
        os.replace(replacement, target)
    assert verified.read_text(encoding="utf-8") == "safe"

    del verified
    gc.collect()
    os.replace(replacement, target)
    assert target.read_text(encoding="utf-8") == "replacement"


@pytest.mark.skipif(os.name != "nt", reason="Windows file-share semantics are the security boundary")
def test_write_target_is_pinned_until_replace_revalidation(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    target = workspace.root / "safe.txt"
    target.write_text("safe", encoding="utf-8")
    replacement = workspace.root / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")

    outer = workspace.resolve_for_write("safe.txt")
    with WorkspaceExecutionLock(
        workspace.settings, target=outer
    ), workspace.lock_target(outer):
        current = workspace.resolve_for_write("safe.txt")
        parent_identity = workspace.identity(current.parent)
        target_identity = workspace.identity(current)
        assert parent_identity is not None
        assert target_identity is not None

        with pytest.raises(OSError):
            os.replace(replacement, target)
        assert current.read_text(encoding="utf-8") == "safe"

        workspace.revalidate_for_replace(
            current,
            parent_identity=parent_identity,
            target_identity=target_identity,
        )
        os.replace(replacement, target)

    assert target.read_text(encoding="utf-8") == "replacement"


@pytest.mark.skipif(os.name != "nt", reason="Windows file-share semantics are the security boundary")
def test_broker_git_argv_pins_pathspec_until_child_argv_is_released(tmp_path: Path) -> None:
    target = tmp_path / "safe.txt"
    target.write_text("safe", encoding="utf-8")
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")

    argv = build_process_argv(
        "git.exe",
        [*_SAFE_GIT_ARGS, "--", str(target.resolve())],
    )
    with pytest.raises(OSError):
        os.replace(replacement, target)

    del argv
    gc.collect()
    os.replace(replacement, target)
    assert target.read_text(encoding="utf-8") == "replacement"
