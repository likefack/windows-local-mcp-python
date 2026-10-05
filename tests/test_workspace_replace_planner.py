from __future__ import annotations

import os
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.workspace_replace import plan_workspace_replace


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


def test_literal_file_plan_retains_verified_snapshot_and_only_changed_output(
    tmp_path: Path,
) -> None:
    workspace, root = _workspace(tmp_path)
    target = root / "one.txt"
    target.write_bytes(b"old old\n")

    plan = plan_workspace_replace(
        workspace,
        workspace.settings,
        "one.txt",
        "old",
        "new",
        expected_total_matches=2,
    )

    assert plan.tool_name == "workspace_replace"
    assert plan.snapshots["one.txt"].data == b"old old\n"
    assert plan.changes == {"one.txt": b"new new\n"}
    assert plan.summary["match_count"] == 2
    assert plan.summary["target_paths"] == ["one.txt"]
    assert target.read_bytes() == b"old old\n"


def test_directory_glob_and_literal_matching_share_case_sensitivity(
    tmp_path: Path,
) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "nested").mkdir()
    (root / "A.TXT").write_bytes(b"ALPHA\n")
    (root / "nested" / "b.txt").write_bytes("alpha İ\n".encode())
    (root / "nested" / "skip.md").write_bytes(b"alpha\n")

    plan = plan_workspace_replace(
        workspace,
        workspace.settings,
        ".",
        "i",
        "X",
        file_glob="*.txt",
        case_sensitive=False,
        expected_total_matches=1,
        max_depth=2,
        max_entries=10,
        max_files=10,
    )

    assert list(plan.snapshots) == ["A.TXT", "nested/b.txt"]
    assert plan.changes == {"nested/b.txt": b"alpha X\n"}
    assert plan.summary["scanned_file_count"] == 3


def test_selected_files_without_matches_are_still_snapshotted(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_text("old", encoding="utf-8")
    (root / "b.txt").write_text("none", encoding="utf-8")

    plan = plan_workspace_replace(
        workspace,
        workspace.settings,
        ".",
        "old",
        "new",
        expected_total_matches=1,
        max_depth=1,
    )

    assert list(plan.snapshots) == ["a.txt", "b.txt"]
    assert list(plan.changes) == ["a.txt"]
    assert plan.summary["matched_paths"] == ["a.txt"]


def test_unique_per_file_rejects_multiple_matches_without_mutation(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    target = root / "a.txt"
    target.write_text("old old", encoding="utf-8")

    with pytest.raises(RuntimeError, match="multiple matches"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "a.txt",
            "old",
            "new",
            expected_total_matches=2,
            match_mode="unique_per_file",
        )
    assert target.read_text(encoding="utf-8") == "old old"


def test_expected_match_mismatch_rejects_entire_plan_without_mutation(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    target = root / "a.txt"
    target.write_text("old", encoding="utf-8")

    with pytest.raises(RuntimeError, match="expected_total_matches mismatch"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "a.txt",
            "old",
            "new",
            expected_total_matches=0,
        )
    assert target.read_text(encoding="utf-8") == "old"


def test_none_expected_match_count_is_allowed_for_preview_discovery(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_text("old old", encoding="utf-8")

    plan = plan_workspace_replace(
        workspace,
        workspace.settings,
        "a.txt",
        "old",
        "new",
        expected_total_matches=None,
    )

    assert plan.summary["match_count"] == 2
    assert plan.changes["a.txt"] == b"new new"


@pytest.mark.parametrize("invalid", [True, -1, 1.0, "1"])
def test_expected_total_matches_requires_an_exact_non_negative_integer(
    tmp_path: Path, invalid: object
) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_text("old", encoding="utf-8")
    with pytest.raises((TypeError, ValueError), match="expected_total_matches"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "a.txt",
            "old",
            "new",
            expected_total_matches=invalid,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("data", "message"),
    [(b"\xff", "UTF-8"), (b"old\x00text", "NUL")],
)
def test_binary_targets_are_rejected(tmp_path: Path, data: bytes, message: str) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_bytes(data)
    with pytest.raises(ValueError, match=message):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "a.txt",
            "old",
            "new",
            expected_total_matches=0,
        )


@pytest.mark.parametrize(("old", "new"), [("", "x"), ("x\x00", "y"), ("x", "y\x00")])
def test_invalid_text_inputs_are_rejected(
    tmp_path: Path, old: str, new: str
) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "a.txt",
            old,
            new,
            expected_total_matches=0,
        )


def test_request_limits_cover_traversal_matches_changes_and_retained_bytes(
    tmp_path: Path,
) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_text("old", encoding="utf-8")
    (root / "b.txt").write_text("old", encoding="utf-8")

    with pytest.raises(ValueError, match="file limit"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            ".",
            "old",
            "new",
            expected_total_matches=2,
            max_depth=1,
            max_files=1,
        )
    with pytest.raises(ValueError, match="match limit"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            ".",
            "old",
            "new",
            expected_total_matches=2,
            max_depth=1,
            max_matches=1,
        )
    with pytest.raises(ValueError, match="changed file limit"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            ".",
            "old",
            "new",
            expected_total_matches=2,
            max_depth=1,
            max_changed_files=1,
        )
    with pytest.raises(ValueError, match="snapshot and change bytes"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            ".",
            "old",
            "new",
            expected_total_matches=2,
            max_depth=1,
            max_total_bytes=10,
        )

    (root / "b.txt").write_text("none", encoding="utf-8")
    with pytest.raises(ValueError, match="byte limit"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            ".",
            "old",
            "new",
            expected_total_matches=1,
            max_depth=1,
            max_total_bytes=9,
        )


def test_oversize_output_is_rejected_before_replacement_is_constructed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, root = _workspace(
        tmp_path,
        max_text_file_bytes=1024,
        max_write_bytes=1024,
        max_workspace_search_results=1000,
    )
    (root / "a.txt").write_bytes(b"a" * 600)

    from windows_local_mcp import workspace_replace

    def fail_if_called(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("replacement output was constructed before byte admission")

    monkeypatch.setattr(workspace_replace, "_apply_literal_spans", fail_if_called)
    with pytest.raises(ValueError, match="max_write_bytes"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "a.txt",
            "a",
            "xx",
            expected_total_matches=600,
            max_matches=1000,
        )


def test_depth_zero_does_not_silently_scan_directory_contents(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    (root / "a.txt").write_text("old", encoding="utf-8")

    plan = plan_workspace_replace(
        workspace,
        workspace.settings,
        ".",
        "old",
        "new",
        expected_total_matches=0,
        max_depth=0,
    )

    assert plan.snapshots == {}
    assert plan.summary["scanned_entry_count"] == 0


def test_hardlinked_target_is_rejected(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    original = root / "original.txt"
    original.write_text("old", encoding="utf-8")
    linked = root / "linked.txt"
    try:
        os.link(original, linked)
    except OSError as error:
        pytest.skip(f"hard-link creation unavailable: {error}")

    with pytest.raises(PermissionError, match="hard link|multiple hard links"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            "linked.txt",
            "old",
            "new",
            expected_total_matches=1,
        )


def test_recursive_traversal_rejects_reparse_entries(tmp_path: Path) -> None:
    workspace, root = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("old", encoding="utf-8")
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")

    with pytest.raises(PermissionError, match="reparse"):
        plan_workspace_replace(
            workspace,
            workspace.settings,
            ".",
            "old",
            "new",
            expected_total_matches=0,
            max_depth=2,
        )
