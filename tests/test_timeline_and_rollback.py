from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.network_isolation import (
    apply_safe_network_environment,
    safe_network_policy,
)
from windows_local_mcp.policy import NormalizedCommand
from windows_local_mcp.risk import command_risk_facts
from windows_local_mcp.timeline import timeline_entry
from windows_local_mcp.util import canonical_json, utc_now_iso
from windows_local_mcp.workspace_history import (
    capture_workspace_state,
    compare_workspace_states,
    restore_workspace_state,
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
    assert facts["network_declared"] is False
    assert facts["network_access_possible"] is True
    assert facts["risk_level"] == "medium"
