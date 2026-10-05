"""Integration coverage for frozen plans and the real checkpoint/recovery boundary."""

import json
import os
import subprocess

import pytest
from test_high_level_operations import load_server

from windows_local_mcp import workspace_history as history
from windows_local_mcp import workspace_operations as operations
from windows_local_mcp.live_activity import project_operation
from windows_local_mcp.util import sha256_bytes


def test_batch_mixed_operations_are_one_logical_transaction(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "edit.txt").write_bytes(b"old")
    (root / "remove.bin").write_bytes(b"\x00\xff")
    (root / "source.bin").write_bytes(b"\x00\xffcopy")
    (root / "unrelated.txt").write_bytes(b"keep")
    result = server.workspace_batch(
        [
            {"op": "mkdir", "path": "out"},
            {"op": "create", "path": "out/new.txt", "content": "new"},
            {"op": "move", "source": "out/new.txt", "destination": "out/final.txt"},
            {"op": "replace", "path": "edit.txt", "old_text": "old", "new_text": "edited"},
            {"op": "copy", "source": "source.bin", "destination": "out/copy.bin"},
            {"op": "delete", "path": "remove.bin"},
        ]
    )
    assert (root / "out/final.txt").read_bytes() == b"new"
    assert (root / "out/copy.bin").read_bytes() == b"\x00\xffcopy"
    assert (root / "edit.txt").read_bytes() == b"edited"
    assert (root / "unrelated.txt").read_bytes() == b"keep"
    assert not (root / "remove.bin").exists()
    assert not (root / "out/new.txt").exists()
    rows = server.runtime.audit.list_operations()
    assert len(rows) == 1
    row = server.runtime.audit.get_operation(result["operation_id"])
    assert row["tool_name"] == "workspace_batch"
    assert row["rollback_state"] == "complete"
    assert project_operation(row).label == "Edited"
    assert row["timings"]["total_ns"] > 0
    assert server.operation_report(result["operation_id"])["status"] == "succeeded"


@pytest.mark.parametrize(
    "tail",
    [
        {"op": "create", "path": "fresh.txt", "content": "collision"},
        {"op": "delete", "path": "existing.txt", "expected_sha256": "0" * 64},
        {"op": "create", "path": "../outside", "content": "escape"},
        {"op": "create", "path": "huge.txt", "content": "x" * 4097},
    ],
)
def test_batch_preflight_rejection_does_not_mutate(tmp_path, monkeypatch, tail):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "existing.txt").write_bytes(b"keep")
    with pytest.raises((ValueError, RuntimeError, PermissionError, FileExistsError)):
        server.workspace_batch([{"op": "create", "path": "fresh.txt", "content": "first"}, tail])
    assert not (root / "fresh.txt").exists()
    assert (root / "existing.txt").read_bytes() == b"keep"


def test_preview_keeps_bytes_and_hashes_server_side_and_consumes_reference(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"private-content-old")
    preview = server.workspace_replace(".", "old", "new", 1, file_glob="*.txt", preview=True)
    assert (root / "a.txt").read_bytes() == b"private-content-old"
    assert "private-content" not in json.dumps(preview)
    assert sha256_bytes(b"private-content-old") not in json.dumps(preview)
    detail = server.runtime.audit.get_operation(preview["operation_id"])
    assert preview["plan_id"] not in json.dumps(detail)
    result = server.workspace_plan_apply(preview["plan_id"])
    assert result["status"] == "succeeded"
    assert (root / "a.txt").read_bytes() == b"private-content-new"
    with pytest.raises(ValueError, match="unknown|expired|consumed"):
        server.workspace_plan_apply(preview["plan_id"])


@pytest.mark.parametrize("change", ["content", "same_bytes_new_identity", "nonmatching_file"])
def test_replace_preview_rejects_stale_content_and_identity(tmp_path, monkeypatch, change):
    server, root = load_server(tmp_path, monkeypatch)
    first, other = root / "a.txt", root / "b.txt"
    first.write_bytes(b"old")
    other.write_bytes(b"unchanged")
    plan = server.workspace_replace(".", "old", "new", 1, preview=True)
    if change == "content":
        first.write_bytes(b"concurrent")
    elif change == "nonmatching_file":
        other.write_bytes(b"old")
    else:
        temporary = root / "replacement"
        temporary.write_bytes(b"old")
        os.replace(temporary, first)
    with pytest.raises((ValueError, RuntimeError), match="stale|byte limit"):
        server.workspace_plan_apply(plan["plan_id"])
    assert first.read_bytes() != b"new"


def test_batch_preview_rejects_newly_occupied_destination(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    preview = server.workspace_batch(
        [{"op": "create", "path": "a.txt", "content": "planned"}], preview=True
    )
    (root / "a.txt").write_bytes(b"concurrent")
    with pytest.raises((RuntimeError, NotADirectoryError), match="stale|collides"):
        server.workspace_plan_apply(preview["plan_id"])
    assert (root / "a.txt").read_bytes() == b"concurrent"


@pytest.mark.parametrize("mode", ["batch", "replace"])
def test_transaction_mid_failure_rolls_back_and_reconciles(tmp_path, monkeypatch, mode):
    server, root = load_server(tmp_path, monkeypatch)
    for name in ("a.txt", "b.txt"):
        (root / name).write_bytes(b"old")
    original = history.Workspace.commit_bytes
    calls = 0

    def fail_second(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("injected second commit failure")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(history.Workspace, "commit_bytes", fail_second)
    with pytest.raises(history.WorkspaceMutationError) as raised:
        if mode == "replace":
            server.workspace_replace(".", "old", "new", 2)
        else:
            server.workspace_batch(
                [
                    {"op": "replace", "path": name, "old_text": "old", "new_text": "new"}
                    for name in ("a.txt", "b.txt")
                ]
            )
    assert raised.value.recovery_state == "failed_recovered"
    assert all((root / name).read_bytes() == b"old" for name in ("a.txt", "b.txt"))
    assert not server.workspace_recovery_required(server.runtime.settings)
    row = server.runtime.audit.list_operations()[0]
    detail = server.runtime.audit.get_operation(row["id"])
    assert detail["rollback_state"] == "failed_recovered"
    assert detail["events"][-1]["payload"]["fallback_attempted"] is False


def test_failed_rollback_keeps_recovery_required(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    for name in ("a.txt", "b.txt"):
        (root / name).write_bytes(b"old")
    original = history.Workspace.commit_bytes
    calls = 0

    def fail_after_first(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise RuntimeError("injected commit and recovery failure")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(history.Workspace, "commit_bytes", fail_after_first)
    with pytest.raises(history.WorkspaceMutationError) as raised:
        server.workspace_replace(".", "old", "new", 2)
    assert raised.value.recovery_state == "recovery_required"
    assert server.workspace_recovery_required(server.runtime.settings)
    with pytest.raises(RuntimeError, match="requires recovery"):
        server.workspace_batch([{"op": "create", "path": "blocked.txt", "content": "x"}])
    assert not (root / "blocked.txt").exists()


def test_after_checkpoint_failure_rolls_back(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"old")
    original = operations.capture_workspace_state

    def fail_after(settings, oid, stage, **kwargs):
        if stage == "after":
            raise RuntimeError("injected post-write verification failure")
        return original(settings, oid, stage, **kwargs)

    monkeypatch.setattr(operations, "capture_workspace_state", fail_after)
    with pytest.raises(history.WorkspaceMutationError) as raised:
        server.workspace_replace(".", "old", "new", 1)
    assert raised.value.recovery_state == "failed_recovered"
    assert (root / "a.txt").read_bytes() == b"old"


def test_checkpoint_race_cannot_replace_preflight_cas(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"old")
    original = operations.capture_workspace_state

    def concurrent_before(settings, oid, stage, **kwargs):
        if stage == "before":
            (root / "a.txt").write_bytes(b"concurrent")
        return original(settings, oid, stage, **kwargs)

    monkeypatch.setattr(operations, "capture_workspace_state", concurrent_before)
    with pytest.raises(RuntimeError, match="stale"):
        server.workspace_replace(".", "old", "new", 1)
    assert (root / "a.txt").read_bytes() == b"concurrent"


def test_old_raw_hash_api_remains_available(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"old")
    server.text_file_apply("a.txt", sha256_bytes(b"old"), "old", "new")
    assert (root / "a.txt").read_bytes() == b"new"
    names = {item.name for item in server.mcp._tool_manager.list_tools()}
    assert {
        "workspace_batch",
        "workspace_replace",
        "workspace_plan_apply",
        "workspace_apply",
        "read_files",
        "artifact_import_file",
    } <= names


def test_preview_can_discover_count_but_direct_apply_requires_it(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"old old")
    with pytest.raises(ValueError, match="expected_total_matches"):
        server.workspace_replace(".", "old", "new")
    preview = server.workspace_replace(".", "old", "new", preview=True)
    assert preview["match_count"] == 2
    assert (
        project_operation(server.runtime.audit.get_operation(preview["operation_id"])).label
        == "Read"
    )
    server.workspace_plan_apply(preview["plan_id"])
    assert (root / "a.txt").read_bytes() == b"new new"


def test_no_match_is_success_without_workspace_transaction(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"unchanged")
    result = server.workspace_replace(".", "old", "new", 0)
    assert result["changed_file_count"] == 0
    assert (root / "a.txt").read_bytes() == b"unchanged"
    result = server.workspace_replace(".", "old", "new", 0, max_depth=0)
    assert result["changed_file_count"] == 0


def test_preview_parent_replacement_is_rejected(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "parent").mkdir()
    preview = server.workspace_batch(
        [
            {"op": "create", "path": "parent/new.txt", "content": "planned"},
        ],
        preview=True,
    )
    (root / "parent").rename(root / "prior-parent")
    (root / "parent").mkdir()
    with pytest.raises(RuntimeError, match="parent directory identity"):
        server.workspace_plan_apply(preview["plan_id"])
    assert not (root / "parent/new.txt").exists()


def test_batch_rollback_removes_new_directories_and_restores_deleted_file(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "old.txt").write_bytes(b"original")
    original = operations.capture_workspace_state

    def fail_after(settings, oid, stage, **kwargs):
        if stage == "after":
            raise RuntimeError("injected verification failure")
        return original(settings, oid, stage, **kwargs)

    monkeypatch.setattr(operations, "capture_workspace_state", fail_after)
    with pytest.raises(history.WorkspaceMutationError) as raised:
        server.workspace_batch(
            [
                {"op": "mkdir", "path": "newdir"},
                {"op": "create", "path": "newdir/new.txt", "content": "planned"},
                {"op": "delete", "path": "old.txt"},
            ]
        )
    assert raised.value.recovery_state == "failed_recovered"
    assert (root / "old.txt").read_bytes() == b"original"
    assert not (root / "newdir").exists()


def test_identity_change_during_staging_is_rejected_before_mutation(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "a.txt"
    target.write_bytes(b"old")
    original = history._stage_manifest_files
    swapped_identity = None

    def swap_after_staging(*args, **kwargs):
        nonlocal swapped_identity
        original(*args, **kwargs)
        other = root / "other"
        other.write_bytes(b"old")
        os.replace(other, target)
        swapped_identity = server.runtime.workspace.identity(target)

    monkeypatch.setattr(history, "_stage_manifest_files", swap_after_staging)
    # Windows can refuse the swap outright while a verified handle still binds the file.
    # Otherwise the staged identity comparison must reject it before the first commit.
    with pytest.raises((RuntimeError, PermissionError)):
        server.workspace_replace(".", "old", "new", 1)
    assert target.read_bytes() == b"old"
    if swapped_identity is not None:
        assert server.runtime.workspace.identity(target) == swapped_identity
    assert not server.workspace_recovery_required(server.runtime.settings)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction boundary")
def test_real_junction_cannot_escape_in_batch_or_replace(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_bytes(b"old")
    junction = root / "linked"
    created = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("junction creation is unavailable in this test environment")
    try:
        with pytest.raises(PermissionError, match="reparse|junction"):
            server.workspace_replace(".", "old", "new", 1)
        with pytest.raises(PermissionError, match="reparse|junction"):
            server.workspace_batch(
                [
                    {"op": "create", "path": "linked/new.txt", "content": "escape"},
                ]
            )
        assert (outside / "a.txt").read_bytes() == b"old"
        assert not (outside / "new.txt").exists()
    finally:
        # Remove only the synthetic junction itself; never recurse into its target.
        junction.rmdir()


def test_existing_backup_limit_is_preserved_before_batch_mutation(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "source.bin").write_bytes(b"x" * 2048)
    server.runtime.settings.max_backup_bytes = 1024
    with pytest.raises(ValueError, match="backup byte limit"):
        server.workspace_batch(
            [
                {"op": "create", "path": "first.txt", "content": "not published"},
                {"op": "copy", "source": "source.bin", "destination": "copy.bin"},
            ]
        )
    assert not (root / "first.txt").exists()
    assert not (root / "copy.bin").exists()


@pytest.mark.parametrize("failure", ["committed_event", "success_transition"])
def test_audit_completion_failure_restores_before_finalizing(tmp_path, monkeypatch, failure):
    server, root = load_server(tmp_path, monkeypatch)
    if failure == "committed_event":
        original_event = server.runtime.audit.add_event

        def fail_committed(oid, event_type, payload):
            if event_type == "high_level_operation_committed":
                raise RuntimeError("injected committed event persistence failure")
            return original_event(oid, event_type, payload)

        monkeypatch.setattr(server.runtime.audit, "add_event", fail_committed)
    else:
        original_transition = server.runtime.audit.transition_operation

        def reject_success(*args, **kwargs):
            if kwargs.get("status") == "succeeded":
                return False
            return original_transition(*args, **kwargs)

        monkeypatch.setattr(server.runtime.audit, "transition_operation", reject_success)
    with pytest.raises(history.WorkspaceMutationError) as raised:
        server.workspace_batch([{"op": "create", "path": "new.txt", "content": "temporary"}])
    assert raised.value.recovery_state == "failed_recovered"
    assert not (root / "new.txt").exists()
    assert not server.workspace_recovery_required(server.runtime.settings)
    detail = server.runtime.audit.list_operations()[0]
    assert detail["status"] == "failed"
    detail = server.runtime.audit.get_operation(detail["id"])
    assert detail["rollback_state"] == "failed_recovered"
    assert detail["result"]["status"] == "failed"


@pytest.mark.parametrize("with_child", [False, True])
def test_directory_creation_race_preserves_foreign_directory(tmp_path, monkeypatch, with_child):
    server, root = load_server(tmp_path, monkeypatch)
    original = history.Workspace.commit_directories

    def race_create(self, target, **kwargs):
        target.mkdir()
        if with_child:
            (target / "unplanned.txt").write_bytes(b"concurrent")
        return original(self, target, **kwargs)

    monkeypatch.setattr(history.Workspace, "commit_directories", race_create)
    with pytest.raises(history.WorkspaceMutationError) as raised:
        server.workspace_batch(
            [
                {"op": "mkdir", "path": "newdir"},
                {"op": "create", "path": "newdir/planned.txt", "content": "planned"},
            ]
        )
    assert raised.value.recovery_state == "recovery_required"
    assert (root / "newdir").is_dir()
    assert not (root / "newdir/planned.txt").exists()
    if with_child:
        assert (root / "newdir/unplanned.txt").read_bytes() == b"concurrent"
    assert server.workspace_recovery_required(server.runtime.settings)
