from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

from windows_local_mcp.live_activity import project_operation
from windows_local_mcp.util import sha256_bytes
from windows_local_mcp.workspace_history import (
    finalize_workspace_transaction,
    prepare_selective_undo,
    restore_workspace_state,
)


def load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(root).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "approved_host_enabled = false",
                "max_write_bytes = 4096",
                "max_backup_bytes = 8192",
                "approval_manifest_max_bytes = 32768",
                "approval_manifest_max_files = 64",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    # This isolates the fixed Broker primitive from the independently tested
    # Approved Host authority service health gate.
    monkeypatch.setattr(server, "assert_control_plane_healthy", lambda _settings: None)
    return server, root


def apply_selective_undo(server, operation_id: str, undo_id: str) -> dict[str, object]:
    operation = server.runtime.audit.get_operation(operation_id, include_events=False)
    preview = prepare_selective_undo(
        server.runtime.settings,
        undo_id,
        str(operation["pre_workspace_path"]),
        str(operation["post_workspace_path"]),
    )
    assert preview["conflict_count"] == 0
    restore_operation_id = f"{undo_id}-apply"
    restore_workspace_state(
        server.runtime.settings,
        str(preview["expected_current_checkpoint"]),
        str(preview["target_checkpoint"]),
        operation_id=restore_operation_id,
    )
    finalize_workspace_transaction(server.runtime.settings, restore_operation_id)
    return preview


def test_filesystem_primitive_windows_e2e_audit_activity_and_undo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)

    created = server.make_directory("new/a/b", parents=True, reason="E2E directory")
    assert created["created_directories"] == ["new", "new/a", "new/a/b"]
    source = root / "new" / "a" / "b" / "source.bin"
    source.write_bytes(b"\x00safe-copy\xff")
    digest = sha256_bytes(source.read_bytes())

    copied = server.copy_file("new/a/b/source.bin", "new/a/b/copied.bin", digest)
    assert (root / "new/a/b/copied.bin").read_bytes() == source.read_bytes()
    assert copied["metadata_policy"] == "content_only"
    moved = server.move_file("new/a/b/copied.bin", "new/a/moved.bin", digest)
    assert not (root / "new/a/b/copied.bin").exists()
    assert (root / "new/a/moved.bin").read_bytes() == source.read_bytes()
    deleted = server.delete_file("new/a/moved.bin", digest)
    assert not (root / "new/a/moved.bin").exists()

    apply_selective_undo(server, deleted["operation_id"], "undo-delete")
    assert (root / "new/a/moved.bin").read_bytes() == b"\x00safe-copy\xff"

    for result, tool, label in (
        (created, "make_directory", "Created directory"),
        (copied, "copy_file", "Copied"),
        (moved, "move_file", "Moved"),
        (deleted, "delete_file", "Deleted"),
    ):
        operation = server.runtime.audit.get_operation(result["operation_id"], include_events=True)
        assert operation["tool_name"] == tool
        assert operation["tier"] == "broker"
        assert operation["status"] == "succeeded"
        assert operation["pre_workspace_path"]
        assert operation["post_workspace_path"]
        assert operation["result"]["execution_path"] == "broker_direct"
        projection = project_operation(operation)
        assert projection is not None
        assert projection.label == label


def test_move_copy_and_directory_selective_undo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "source.txt").write_bytes(b"source")
    digest = sha256_bytes(b"source")

    copied = server.copy_file("source.txt", "copy.txt", digest)
    apply_selective_undo(server, copied["operation_id"], "undo-copy")
    assert (root / "source.txt").read_bytes() == b"source"
    assert not (root / "copy.txt").exists()

    moved = server.move_file("source.txt", "renamed.txt", digest)
    apply_selective_undo(server, moved["operation_id"], "undo-move")
    assert (root / "source.txt").read_bytes() == b"source"
    assert not (root / "renamed.txt").exists()

    (root / "existing").mkdir()
    made = server.make_directory("existing/new/a", parents=True)
    apply_selective_undo(server, made["operation_id"], "undo-directory")
    assert (root / "existing").is_dir()
    assert not (root / "existing/new").exists()


@pytest.mark.parametrize("tool", ["move", "copy"])
def test_destination_collision_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "source.txt").write_bytes(b"source")
    (root / "destination.txt").write_bytes(b"keep")
    digest = sha256_bytes(b"source")

    function = server.move_file if tool == "move" else server.copy_file
    with pytest.raises(FileExistsError):
        function("source.txt", "destination.txt", digest)
    assert (root / "source.txt").read_bytes() == b"source"
    assert (root / "destination.txt").read_bytes() == b"keep"


@pytest.mark.parametrize("tool", ["move", "copy", "delete"])
def test_absent_source_or_target_fails_and_is_audited_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    digest = sha256_bytes(b"missing")
    with pytest.raises(FileNotFoundError):
        if tool == "move":
            server.move_file("missing.txt", "destination.txt", digest)
        elif tool == "copy":
            server.copy_file("missing.txt", "destination.txt", digest)
        else:
            server.delete_file("missing.txt", digest)
    operations = [
        item
        for item in server.runtime.audit.list_operations(limit=20)
        if item["tool_name"] == f"{tool}_file"
    ]
    assert len(operations) == 1
    assert operations[0]["status"] == "rejected"


def test_hash_binding_and_directory_type_are_mandatory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "target.txt").write_bytes(b"current")
    (root / "folder").mkdir()

    for function, arguments in (
        (server.move_file, ("target.txt", "moved.txt", sha256_bytes(b"stale"))),
        (server.copy_file, ("target.txt", "copy.txt", sha256_bytes(b"stale"))),
        (server.delete_file, ("target.txt", sha256_bytes(b"stale"))),
    ):
        with pytest.raises(RuntimeError, match="mismatch"):
            function(*arguments)
    with pytest.raises(IsADirectoryError):
        server.delete_file("folder", sha256_bytes(b""))
    assert (root / "target.txt").read_bytes() == b"current"
    assert (root / "folder").is_dir()


def test_make_directory_semantics_and_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "parent").mkdir()
    (root / "file").write_bytes(b"file")

    server.make_directory("parent/child")
    with pytest.raises(FileExistsError):
        server.make_directory("parent/child")
    with pytest.raises(FileNotFoundError):
        server.make_directory("missing/child", parents=False)
    with pytest.raises(NotADirectoryError):
        server.make_directory("file/child", parents=True)
    assert (root / "parent").is_dir()


@pytest.mark.parametrize(
    ("function_name", "arguments"),
    [
        ("move_file", ("../outside.txt", "inside.txt", "0" * 64)),
        ("copy_file", ("../outside.txt", "inside.txt", "0" * 64)),
        ("delete_file", ("../outside.txt", "0" * 64)),
        ("make_directory", ("../escaped", True)),
    ],
)
def test_workspace_escape_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
    arguments: tuple[object, ...],
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    (tmp_path / "outside.txt").write_bytes(b"outside")
    with pytest.raises(PermissionError):
        getattr(server, function_name)(*arguments)


def test_copy_rejects_hardlinked_source_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    source = root / "source.txt"
    source.write_bytes(b"source")
    alias = root / "alias.txt"
    try:
        alias.hardlink_to(source)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(PermissionError, match="hard links"):
        server.copy_file("source.txt", "copy.txt", sha256_bytes(b"source"))
    assert not (root / "copy.txt").exists()


def test_copy_resource_limit_fails_before_destination_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    source = root / "source.bin"
    source.write_bytes(b"x" * 64)
    server.runtime.settings.max_backup_bytes = 32
    with pytest.raises(ValueError, match="byte limit"):
        server.copy_file("source.bin", "copy.bin", sha256_bytes(source.read_bytes()))
    assert not (root / "copy.bin").exists()


def test_commit_failure_recovers_starting_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    source = root / "source.txt"
    source.write_bytes(b"source")

    def fail_commit(*_args, **_kwargs):
        raise OSError("forced transactional copy failure")

    monkeypatch.setattr(server.runtime.workspace, "commit_copy", fail_commit)
    with pytest.raises(server.WorkspaceMutationError) as captured:
        server.copy_file("source.txt", "copy.txt", sha256_bytes(b"source"))
    assert captured.value.recovery_state == "failed_recovered"
    assert source.read_bytes() == b"source"
    assert not (root / "copy.txt").exists()


def test_selective_undo_refuses_subsequent_delete_target_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "target.txt"
    target.write_bytes(b"before")
    deleted = server.delete_file("target.txt", sha256_bytes(b"before"))
    target.write_bytes(b"later-user-change")
    operation = server.runtime.audit.get_operation(deleted["operation_id"], include_events=False)
    preview = prepare_selective_undo(
        server.runtime.settings,
        "undo-conflict",
        str(operation["pre_workspace_path"]),
        str(operation["post_workspace_path"]),
    )
    assert preview["conflict_count"] == 1
    assert target.read_bytes() == b"later-user-change"


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive rename semantics")
def test_case_only_rename_is_transactional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "CaseName.txt"
    target.write_bytes(b"case")
    result = server.move_file("CaseName.txt", "CASENAME.TXT", sha256_bytes(b"case"))
    assert result["case_only_rename"] is True
    names = {entry.name for entry in root.iterdir()}
    assert "CASENAME.TXT" in names
    assert "CaseName.txt" not in names


def test_reparse_parent_is_rejected_for_all_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.txt").write_bytes(b"outside")
    link = root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks requires Windows developer mode or elevation")

    with pytest.raises(PermissionError):
        server.copy_file("linked/source.txt", "copy.txt", sha256_bytes(b"outside"))
    with pytest.raises(PermissionError):
        server.move_file("linked/source.txt", "move.txt", sha256_bytes(b"outside"))
    with pytest.raises(PermissionError):
        server.delete_file("linked/source.txt", sha256_bytes(b"outside"))
    with pytest.raises(PermissionError):
        server.make_directory("linked/new", parents=True)
    assert (outside / "source.txt").read_bytes() == b"outside"
    assert not (outside / "new").exists()
