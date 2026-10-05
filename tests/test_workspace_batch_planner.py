from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp import workspace_batch
from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.util import sha256_bytes
from windows_local_mcp.workspace_batch import plan_workspace_batch


def _workspace(tmp_path: Path, **limits: int) -> tuple[Workspace, Settings, Path]:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        **limits,
    )
    settings.ensure_directories()
    return Workspace(settings), settings, root


def test_plans_ordered_directory_create_replace_and_move_without_mutation(tmp_path: Path) -> None:
    workspace, settings, root = _workspace(tmp_path)

    plan = plan_workspace_batch(
        workspace,
        settings,
        [
            {"op": "mkdir", "path": "notes"},
            {"op": "create", "path": "notes/draft.txt", "content": "alpha"},
            {
                "op": "replace",
                "path": "notes/draft.txt",
                "old_text": "alpha",
                "new_text": "final",
                "expected_sha256": sha256_bytes(b"alpha"),
            },
            {
                "op": "move",
                "source": "notes/draft.txt",
                "destination": "notes/final.txt",
            },
        ],
    )

    assert plan.changes == {"notes/final.txt": b"final"}
    assert plan.deletions == set()
    assert plan.directories == {"notes"}
    assert plan.absent == {"notes", "notes/draft.txt", "notes/final.txt"}
    assert plan.summary["operation_count"] == 4
    assert plan.summary["change_paths"] == ["notes/final.txt"]
    assert not (root / "notes").exists()


def test_plans_binary_copy_existing_move_and_delete_with_snapshots(tmp_path: Path) -> None:
    workspace, settings, root = _workspace(tmp_path)
    binary = bytes(range(256))
    (root / "source.bin").write_bytes(binary)
    (root / "moving.txt").write_text("move", encoding="utf-8")
    (root / "delete.txt").write_text("delete", encoding="utf-8")

    plan = plan_workspace_batch(
        workspace,
        settings,
        [
            {
                "op": "copy",
                "source": "source.bin",
                "destination": "copy.bin",
                "expected_sha256": sha256_bytes(binary),
            },
            {"op": "move", "source": "moving.txt", "destination": "moved.txt"},
            {"op": "delete", "path": "delete.txt"},
        ],
    )

    assert plan.changes == {"copy.bin": binary, "moved.txt": b"move"}
    assert plan.deletions == {"moving.txt", "delete.txt"}
    assert set(plan.snapshots) == {"source.bin", "moving.txt", "delete.txt"}
    assert plan.absent == {"copy.bin", "moved.txt"}
    assert (root / "moving.txt").read_text(encoding="utf-8") == "move"
    assert (root / "delete.txt").exists()
    assert not (root / "copy.bin").exists()


def test_late_validation_failure_keeps_every_requested_mutation_unapplied(tmp_path: Path) -> None:
    workspace, settings, root = _workspace(tmp_path)
    original = root / "original.txt"
    original.write_text("only once", encoding="utf-8")

    with pytest.raises(RuntimeError, match="exactly once"):
        plan_workspace_batch(
            workspace,
            settings,
            [
                {"op": "mkdir", "path": "new"},
                {"op": "create", "path": "new/file.txt", "content": "content"},
                {
                    "op": "replace",
                    "path": "original.txt",
                    "old_text": "missing",
                    "new_text": "changed",
                },
            ],
        )

    assert not (root / "new").exists()
    assert original.read_text(encoding="utf-8") == "only once"


@pytest.mark.parametrize(
    "operations, error",
    [
        ([{"op": "create", "path": "missing/file.txt", "content": "x"}], FileNotFoundError),
        ([{"op": "create", "path": "a.txt", "content": "x", "extra": True}], ValueError),
        ([{"op": "create", "path": "a.txt", "content": "bad\x00text"}], ValueError),
        (
            [
                {"op": "create", "path": "a.txt", "content": "x"},
                {"op": "delete", "path": "a.txt"},
            ],
            ValueError,
        ),
        ([{"op": "create", "path": "dir/../a.txt", "content": "x"}], PermissionError),
    ],
)
def test_rejects_ambiguous_or_unsafe_requests_without_mutation(
    tmp_path: Path, operations: list[dict[str, object]], error: type[Exception]
) -> None:
    workspace, settings, root = _workspace(tmp_path)

    with pytest.raises(error):
        plan_workspace_batch(workspace, settings, operations)  # type: ignore[arg-type]

    assert list(root.iterdir()) == []


def test_rejects_modified_existing_file_as_copy_source_and_case_only_move(tmp_path: Path) -> None:
    workspace, settings, root = _workspace(tmp_path)
    (root / "File.txt").write_text("old", encoding="utf-8")

    with pytest.raises(ValueError, match="copy source"):
        plan_workspace_batch(
            workspace,
            settings,
            [
                {
                    "op": "replace",
                    "path": "File.txt",
                    "old_text": "old",
                    "new_text": "new",
                },
                {"op": "copy", "source": "File.txt", "destination": "copy.txt"},
            ],
        )

    with pytest.raises((ValueError, FileExistsError), match="case-colliding|already exists"):
        plan_workspace_batch(
            workspace,
            settings,
            [{"op": "move", "source": "File.txt", "destination": "file.txt"}],
        )
    assert (root / "File.txt").read_text(encoding="utf-8") == "old"


def test_enforces_operation_scope_and_intermediate_byte_limits(tmp_path: Path) -> None:
    workspace, settings, root = _workspace(
        tmp_path,
        max_high_level_files=2,
        max_high_level_total_bytes=1024,
    )

    with pytest.raises(ValueError, match="operation count"):
        plan_workspace_batch(
            workspace,
            settings,
            [
                {"op": "create", "path": "a.txt", "content": "a"},
                {"op": "create", "path": "b.txt", "content": "b"},
                {"op": "create", "path": "c.txt", "content": "c"},
            ],
        )

    payload = "x" * 700
    with pytest.raises(ValueError, match="max_high_level_total_bytes"):
        plan_workspace_batch(
            workspace,
            settings,
            [
                {"op": "create", "path": "draft.txt", "content": payload},
                {
                    "op": "replace",
                    "path": "draft.txt",
                    "old_text": payload,
                    "new_text": "y" * 700,
                },
            ],
        )
    assert list(root.iterdir()) == []


def test_caps_verified_snapshot_read_to_remaining_request_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, settings, root = _workspace(tmp_path, max_high_level_total_bytes=1024)
    (root / "large.bin").write_bytes(b"x" * 800)
    observed_limits: list[int] = []
    original_snapshot_file = workspace_batch.snapshot_file

    def recording_snapshot_file(current_workspace: Workspace, path: str, max_bytes: int) -> object:
        observed_limits.append(max_bytes)
        return original_snapshot_file(current_workspace, path, max_bytes)

    monkeypatch.setattr(workspace_batch, "snapshot_file", recording_snapshot_file)

    with pytest.raises(ValueError, match="byte limit"):
        plan_workspace_batch(
            workspace,
            settings,
            [
                {"op": "create", "path": "new.txt", "content": "n" * 300},
                {"op": "delete", "path": "large.bin"},
            ],
        )

    assert observed_limits == [724]
    assert not (root / "new.txt").exists()
    assert (root / "large.bin").read_bytes() == b"x" * 800
