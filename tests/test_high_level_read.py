from __future__ import annotations

import os
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.high_level_read import read_files, workspace_search, workspace_tree
from windows_local_mcp.paths import Workspace


def _workspace(tmp_path: Path, **overrides: object) -> tuple[Workspace, Path]:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
        **overrides,
    )
    settings.ensure_directories()
    return Workspace(settings), root


def test_workspace_search_reads_nested_utf8_files_in_one_operation(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "src").mkdir()
    (root / "src" / "main.py").write_text("first\nneedle here\n", encoding="utf-8")
    (root / "src" / "notes.txt").write_text("needle in notes\n", encoding="utf-8")
    (root / "ignored.py").write_text("needle at root\n", encoding="utf-8")

    result = workspace_search(
        workspace,
        workspace.settings,
        ".",
        "needle",
        file_glob="*.py",
        max_depth=3,
        max_entries=10,
        max_files=10,
        max_results=10,
        max_total_bytes=4096,
    )

    assert result["result_count"] == 2
    assert [item["path"] for item in result["matches"]] == ["ignored.py", "src/main.py"]
    assert result["matches"][1]["line"] == 2


def test_workspace_tree_is_bounded_by_depth_and_entries(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "one").mkdir()
    (root / "one" / "two").mkdir()
    (root / "one" / "two" / "three.txt").write_text("x", encoding="utf-8")

    shallow = workspace_tree(workspace, workspace.settings, ".", max_depth=1, max_entries=10)
    assert [item["path"] for item in shallow["entries"]] == ["one"]

    (root / "extra.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="entry limit"):
        workspace_tree(workspace, workspace.settings, ".", max_depth=2, max_entries=1)


def test_read_files_preserves_read_file_metadata_and_request_bounds(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path, max_text_file_bytes=1024)
    (root / "a.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    (root / "b.txt").write_text("gamma\n", encoding="utf-8")

    result = read_files(
        workspace,
        workspace.settings,
        ["a.txt", "b.txt"],
        max_files=2,
        max_total_bytes=32,
    )

    assert result["file_count"] == 2
    assert result["total_bytes"] == len((root / "a.txt").read_bytes()) + len(
        (root / "b.txt").read_bytes()
    )
    assert result["files"][0]["path"] == "a.txt"
    assert result["files"][0]["content"] == "alpha\nbeta"
    assert len(result["files"][0]["sha256"]) == 64
    with pytest.raises(ValueError, match="total byte"):
        read_files(workspace, workspace.settings, ["a.txt", "b.txt"], max_total_bytes=10)


def test_high_level_reads_reject_workspace_escape_and_non_utf8(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("needle", encoding="utf-8")
    with pytest.raises(PermissionError, match="workspace_root"):
        read_files(workspace, workspace.settings, ["../outside.txt"])

    (root / "binary.bin").write_bytes(b"\xff\xfe")
    with pytest.raises(ValueError, match="UTF-8"):
        read_files(workspace, workspace.settings, ["binary.bin"])


def test_reparse_entries_are_refused_without_following_them(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("needle", encoding="utf-8")
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")

    with pytest.raises(PermissionError, match="reparse"):
        workspace_tree(workspace, workspace.settings, ".", max_depth=2, max_entries=10)
    with pytest.raises(PermissionError, match="reparse"):
        workspace_search(workspace, workspace.settings, ".", "needle", max_depth=2)


@pytest.mark.skipif(os.name == "nt", reason="mutation while a verified Windows read handle is held is denied")
def test_read_files_detects_change_during_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, root = _workspace(tmp_path)
    target = root / "change.txt"
    target.write_text("before", encoding="utf-8")

    from windows_local_mcp import high_level_read

    original = high_level_read.read_verified_bytes

    def mutate_after_validation(path: Path, max_bytes: int) -> bytes:
        data = original(path, max_bytes)
        target.write_text("after!", encoding="utf-8")
        return data

    monkeypatch.setattr(high_level_read, "read_verified_bytes", mutate_after_validation)
    with pytest.raises(RuntimeError, match="changed during read"):
        read_files(workspace, workspace.settings, ["change.txt"])


@pytest.mark.skipif(os.name != "nt", reason="same-HANDLE read is the Windows security boundary")
def test_read_files_consumes_the_verified_handle_without_path_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, root = _workspace(tmp_path)
    target = root / "safe.txt"
    target.write_text("safe", encoding="utf-8")
    real_open = Path.open

    def guarded_open(self: Path, *args: object, **kwargs: object):
        if Path(self).resolve(strict=False) == target.resolve(strict=False):
            raise AssertionError("verified workspace file was reopened by pathname")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    result = read_files(workspace, workspace.settings, ["safe.txt"])
    assert result["files"][0]["content"] == "safe"
