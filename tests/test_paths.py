from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace


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
