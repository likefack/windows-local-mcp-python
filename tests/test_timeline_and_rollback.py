import json
from pathlib import Path

import pytest

from windows_local_mcp.appcontainer import appcontainer_profile_name
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.network_isolation import (
    apply_safe_network_environment,
    safe_network_policy,
)
from windows_local_mcp.policy import NormalizedCommand
from windows_local_mcp.risk import command_risk_facts
from windows_local_mcp.timeline import timeline_entry, timeline_list
from windows_local_mcp.util import canonical_json, sha256_bytes, utc_now_iso
from windows_local_mcp.workspace_history import (
    WorkspaceMutationError,
    begin_single_file_write_transaction,
    capture_workspace_state,
    compare_workspace_states,
    incomplete_workspace_transactions,
    prepare_selective_undo,
    record_workspace_recovery_required,
    recover_incomplete_workspace_transaction,
    restore_workspace_state,
    verify_checkpoint_integrity,
    workspace_recovery_required,
)


def settings_for(tmp_path: Path) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def test_workspace_checkpoint_restores_new_and_changed_files(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_text("one\n", encoding="utf-8")
    first = capture_workspace_state(settings, "one", "after")

    target.write_text("two\n", encoding="utf-8")
    added = settings.workspace_root / "nested" / "b.txt"
    added.parent.mkdir()
    added.write_text("new\n", encoding="utf-8")
    second = capture_workspace_state(settings, "two", "after")

    restored = restore_workspace_state(settings, second.manifest_path, first.manifest_path)
    assert target.read_text(encoding="utf-8") == "one\n"
    assert not added.exists()
    assert "nested/b.txt" in restored["removed_files"]


def test_workspace_checkpoint_stops_on_external_change(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_text("one", encoding="utf-8")
    expected = capture_workspace_state(settings, "expected", "after")
    target.write_text("human change", encoding="utf-8")

    with pytest.raises(RuntimeError, match="rollback conflicts: a.txt"):
        restore_workspace_state(settings, expected.manifest_path, expected.manifest_path)
    assert target.read_text(encoding="utf-8") == "human change"


def test_timeline_exposes_diff_result_and_network_policy(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    audit = AuditStore(settings)
    operation_id = audit.create_operation(
        tool_name="execute_workspace_write",
        tier="safe_command",
        status="running",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"display_command": ["dart", "format", "."]}},
    )
    diff = settings.data_dir / "diffs" / f"{operation_id}.diff"
    diff.write_text("--- a/a.txt\n+++ b/a.txt\n-old\n+new\n", encoding="utf-8")
    policy = safe_network_policy("dart").as_dict()
    result = {
        "changed_files": ["a.txt"],
        "added_lines": 1,
        "removed_lines": 1,
        "stdout_preview": "Formatted 1 file",
        "stderr_preview": "",
    }
    audit.update_operation(
        operation_id,
        status="succeeded",
        finished_at=utc_now_iso(),
        diff_path=str(diff),
        rollback_state="complete",
        network_policy_json=canonical_json(policy),
        result_json=canonical_json(result),
    )

    entry = timeline_entry(settings, audit, operation_id)
    assert entry["command"] == ["dart", "format", "."]
    assert entry["changed_files"] == ["a.txt"]
    assert entry["added_lines"] == 1
    assert "+new" in entry["unified_diff"]
    assert entry["network_policy"]["internet"] == "deny"

    summary = next(
        item for item in timeline_list(settings, audit) if item["operation_id"] == operation_id
    )
    assert summary["changed_file_count"] == 1
    assert "unified_diff" not in summary
    assert "events" not in summary
    assert "changed_files" not in summary


def test_state_comparison_records_multifile_diff(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    (settings.workspace_root / "a.txt").write_text("old\n", encoding="utf-8")
    before = capture_workspace_state(settings, "compare", "before")
    (settings.workspace_root / "a.txt").write_text("new\n", encoding="utf-8")
    (settings.workspace_root / "b.txt").write_text("added\n", encoding="utf-8")
    after = capture_workspace_state(settings, "compare", "after")
    change = compare_workspace_states(
        settings, before.manifest_path, after.manifest_path, "compare"
    )
    assert change["changed_files"] == ["a.txt", "b.txt"]
    assert change["added_lines"] == 2
    assert change["removed_lines"] == 1


def test_safe_network_policy_preserves_only_adb_loopback() -> None:
    adb_environment: dict[str, str] = {}
    apply_safe_network_environment(adb_environment, "adb")
    assert adb_environment["ADB_SERVER_SOCKET"] == "tcp:127.0.0.1:5037"
    assert adb_environment["NO_PROXY"] == "127.0.0.1,localhost,::1"
    offline_environment: dict[str, str] = {}
    apply_safe_network_environment(offline_environment, "dart")
    assert offline_environment["NO_PROXY"] == ""
    assert offline_environment["PUB_HOSTED_URL"].startswith("http://127.0.0.1:")


def test_appcontainer_profiles_are_workspace_scoped_and_separate_adb(tmp_path: Path) -> None:
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    first = settings_for(tmp_path / "first")
    second = settings_for(tmp_path / "second")
    first_read = appcontainer_profile_name(first, "git")
    first_write = appcontainer_profile_name(first, "dart", workspace_write=True)
    first_adb = appcontainer_profile_name(first, "adb")
    second_read = appcontainer_profile_name(second, "git")
    assert len({first_read, first_write, first_adb, second_read}) == 4
    assert safe_network_policy("git").enforcement == "windows-appcontainer"
    assert (
        safe_network_policy("git", mode="compatibility").enforcement
        == "compatibility-command-and-environment-only"
    )


def test_approval_facts_do_not_treat_model_network_flag_as_os_fact() -> None:
    normalized = NormalizedCommand(
        executable="C:/tools/python.exe",
        args=["-m", "pytest"],
        cwd="C:/workspace",
        display_command=["python", "-m", "pytest"],
        program_key="python",
        network_expected=False,
    )
    facts = command_risk_facts(normalized, workspace_write=False, manifest={"mode": "staged-cwd"})
    assert "network_requested" not in facts["detected_requested_effects"]
    assert facts["effective_host_capabilities"]["direct_socket_api_os_possible"] is True
    assert facts["risk_level"] == "medium"


def test_content_addressed_checkpoint_deduplicates_identical_bytes(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    (settings.workspace_root / "same.txt").write_text("same content\n", encoding="utf-8")
    first = capture_workspace_state(settings, "dedup-one", "after")
    second = capture_workspace_state(settings, "dedup-two", "after")

    blobs = list((settings.data_dir / "workspace-history" / "blobs").glob("*.blob"))
    assert len(blobs) == 1
    assert verify_checkpoint_integrity(settings, first.manifest_path)
    assert verify_checkpoint_integrity(settings, second.manifest_path)


def test_restore_rehashes_blob_before_any_workspace_write(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_bytes(b"before\n")
    before = capture_workspace_state(settings, "integrity-before", "after")
    target.write_bytes(b"after\n")
    current = capture_workspace_state(settings, "integrity-current", "after")
    manifest = Path(before.manifest_path).read_text(encoding="utf-8")
    digest = json.loads(manifest)["files"][0]["blob"]
    (settings.data_dir / "workspace-history" / "blobs" / f"{digest}.blob").write_bytes(
        b"corrupt"
    )

    with pytest.raises(RuntimeError, match="integrity"):
        restore_workspace_state(settings, current.manifest_path, before.manifest_path)
    assert target.read_text(encoding="utf-8") == "after\n"


@pytest.mark.parametrize("unsafe_path", [r"..\..\outside.txt", r"C:\outside.txt"])
def test_restore_rejects_windows_manifest_path_before_staging(
    tmp_path: Path, unsafe_path: str
) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_text("safe\n", encoding="utf-8")
    state = capture_workspace_state(settings, "unsafe-manifest", "after")
    manifest_path = Path(state.manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = unsafe_path
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")

    with pytest.raises((PermissionError, ValueError)):
        verify_checkpoint_integrity(settings, state.manifest_path)
    assert not (tmp_path / "outside.txt").exists()


def test_restore_failure_recovers_starting_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_text("before\n", encoding="utf-8")
    desired = capture_workspace_state(settings, "recover-desired", "after")
    target.write_text("current\n", encoding="utf-8")
    current = capture_workspace_state(settings, "recover-current", "after")
    import windows_local_mcp.workspace_history as history

    original_apply = history._apply_manifest
    calls = 0

    def fail_first(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            target.write_text("partial\n", encoding="utf-8")
            raise OSError("injected apply failure")
        original_apply(*args, **kwargs)

    monkeypatch.setattr(history, "_apply_manifest", fail_first)
    with pytest.raises(WorkspaceMutationError) as caught:
        restore_workspace_state(
            settings,
            current.manifest_path,
            desired.manifest_path,
            operation_id="recover-operation",
        )
    assert caught.value.recovery_state == "failed_recovered"
    assert target.read_text(encoding="utf-8") == "current\n"


def test_single_file_recovery_failure_blocks_later_mutations(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    (settings.workspace_root / "a.txt").write_text("before\n", encoding="utf-8")
    before = capture_workspace_state(settings, "write-recovery", "before")
    journal = record_workspace_recovery_required(
        settings,
        "write-recovery",
        before.manifest_path,
        OSError("injected recovery failure"),
    )
    assert Path(journal).exists()
    assert workspace_recovery_required(settings) is True
    audit = AuditStore(settings)
    assert "write-recovery" in audit._protected_operation_ids()


def test_interrupted_single_file_write_recovers_from_write_ahead_journal(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_bytes(b"before\n")
    before = capture_workspace_state(settings, "write-interrupted", "before")
    begin_single_file_write_transaction(
        settings,
        "write-interrupted",
        before.manifest_path,
        "a.txt",
        before_sha256=sha256_bytes(b"before\n"),
        intended_after_sha256=sha256_bytes(b"after\n"),
    )
    assert workspace_recovery_required(settings) is True
    target.write_bytes(b"after\n")
    journal = incomplete_workspace_transactions(settings)[0]
    recovered = recover_incomplete_workspace_transaction(settings, journal)
    assert recovered["state"] == "failed_recovered"
    assert target.read_bytes() == b"before\n"


def test_selective_undo_preserves_independent_later_text_edit(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    before_lines = [f"line {index}\n" for index in range(12)]
    target.write_text("".join(before_lines), encoding="utf-8")
    before = capture_workspace_state(settings, "selective-target", "before")
    after_lines = list(before_lines)
    after_lines[1] = "operation change\n"
    target.write_text("".join(after_lines), encoding="utf-8")
    after = capture_workspace_state(settings, "selective-target", "after")
    current_lines = list(after_lines)
    current_lines[10] = "manual later change\n"
    target.write_text("".join(current_lines), encoding="utf-8")

    preview = prepare_selective_undo(
        settings, "selective-undo", before.manifest_path, after.manifest_path
    )
    assert preview["conflict_count"] == 0
    assert preview["automatic_merge_files"] == ["a.txt"]
    restore_workspace_state(
        settings,
        preview["expected_current_checkpoint"],
        preview["target_checkpoint"],
        operation_id="selective-undo-apply",
    )
    result = target.read_text(encoding="utf-8")
    assert "line 1\n" in result
    assert "manual later change\n" in result


def test_selective_undo_stops_on_overlapping_text_change(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "a.txt"
    target.write_text("base\n", encoding="utf-8")
    before = capture_workspace_state(settings, "conflict-target", "before")
    target.write_text("operation\n", encoding="utf-8")
    after = capture_workspace_state(settings, "conflict-target", "after")
    target.write_text("manual overlap\n", encoding="utf-8")

    preview = prepare_selective_undo(
        settings, "conflict-undo", before.manifest_path, after.manifest_path
    )
    assert preview["conflict_count"] == 1
    assert preview["conflicts"][0]["path"] == "a.txt"
    context = preview["conflicts"][0]["bounded_text_context"]
    assert context["before"].splitlines() == ["base"]
    assert context["operation_after"].splitlines() == ["operation"]
    assert context["current"].splitlines() == ["manual overlap"]
    assert target.read_text(encoding="utf-8") == "manual overlap\n"


def test_selective_undo_handles_create_delete_and_can_itself_be_undone(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path)
    deleted = settings.workspace_root / "deleted.txt"
    modified = settings.workspace_root / "modified.txt"
    deleted.write_text("restore me\n", encoding="utf-8")
    modified.write_text("old\n", encoding="utf-8")
    operation_before = capture_workspace_state(settings, "lifecycle", "before")
    deleted.unlink()
    created = settings.workspace_root / "created.txt"
    created.write_text("remove me\n", encoding="utf-8")
    modified.write_text("new\n", encoding="utf-8")
    operation_after = capture_workspace_state(settings, "lifecycle", "after")

    undo = prepare_selective_undo(
        settings,
        "lifecycle-undo",
        operation_before.manifest_path,
        operation_after.manifest_path,
    )
    assert undo["conflict_count"] == 0
    assert undo["changed_file_count"] == 3
    undo_before = undo["expected_current_checkpoint"]
    restore_workspace_state(
        settings,
        undo_before,
        undo["target_checkpoint"],
        operation_id="lifecycle-undo-apply",
    )
    assert deleted.read_text(encoding="utf-8") == "restore me\n"
    assert not created.exists()
    assert modified.read_text(encoding="utf-8") == "old\n"

    undo_the_undo = prepare_selective_undo(
        settings,
        "lifecycle-redo",
        undo_before,
        undo["target_checkpoint"],
    )
    assert undo_the_undo["conflict_count"] == 0
    restore_workspace_state(
        settings,
        undo_the_undo["expected_current_checkpoint"],
        undo_the_undo["target_checkpoint"],
        operation_id="lifecycle-redo-apply",
    )
    assert not deleted.exists()
    assert created.read_text(encoding="utf-8") == "remove me\n"
    assert modified.read_text(encoding="utf-8") == "new\n"
