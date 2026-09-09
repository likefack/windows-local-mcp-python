import base64
import importlib
import sys
from pathlib import Path

import pytest

from windows_local_mcp.live_activity import project_operation
from windows_local_mcp.util import sha256_bytes


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
                "max_text_file_bytes = 4096",
                "max_write_bytes = 4096",
                "max_high_level_total_bytes = 16384",
                "max_one_shot_artifact_bytes = 1024",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    monkeypatch.setattr(server, "assert_control_plane_healthy", lambda _settings: None)
    return server, root


def test_read_high_level_tools_are_one_operation_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "src").mkdir()
    (root / "src" / "a.txt").write_text("alpha needle\n", encoding="utf-8")
    (root / "src" / "b.txt").write_text("beta\n", encoding="utf-8")

    tree = server.workspace_tree("src", max_depth=2)
    search = server.workspace_search("src", "needle", file_glob="*.txt")
    batch = server.read_files(["src/a.txt", "src/b.txt"])

    assert tree["entry_count"] == 2
    assert search["matches"] == [{"path": "src/a.txt", "line": 1, "text": "alpha needle"}]
    assert [item["path"] for item in batch["files"]] == ["src/a.txt", "src/b.txt"]
    for result, tool in (
        (tree, "workspace_tree"),
        (search, "workspace_search"),
        (batch, "read_files"),
    ):
        operation = server.runtime.audit.get_operation(result["operation_id"])
        assert operation["tool_name"] == tool
        assert len([event for event in operation["events"] if event["event_type"] == "created"]) == 1


def test_workspace_apply_is_one_transaction_and_one_live_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    first = root / "first.txt"
    second = root / "second.txt"
    first.write_text("first old\n", encoding="utf-8")
    second.write_text("second old\n", encoding="utf-8")

    result = server.workspace_apply(
        [
            {
                "path": "first.txt",
                "expected_sha256": sha256_bytes(first.read_bytes()),
                "replacements": [{"old_text": "old", "new_text": "new"}],
            },
            {
                "path": "second.txt",
                "expected_sha256": sha256_bytes(second.read_bytes()),
                "replacements": [{"old_text": "old", "new_text": "new"}],
            },
        ]
    )

    assert first.read_text(encoding="utf-8") == "first new\n"
    assert second.read_text(encoding="utf-8") == "second new\n"
    operation = server.runtime.audit.get_operation(result["operation_id"])
    assert operation["tool_name"] == "workspace_apply"
    assert operation["status"] == "succeeded"
    assert {event["event_type"] for event in operation["events"]} >= {
        "high_level_preflight_started",
        "high_level_transaction_staged",
        "high_level_operation_committed",
    }
    projection = project_operation(operation)
    assert projection is not None
    assert projection.logical_id == f"operation:{result['operation_id']}"
    assert projection.label == "Edited"
    assert not any(
        item["tool_name"] in {"write_file", "structured_file_apply", "artifact_upload_commit"}
        for item in server.runtime.audit.list_operations(limit=20)
    )


def test_workspace_apply_binds_all_targets_to_existing_execution_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    first = root / "first.txt"
    second = root / "second.txt"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    real_lock = server.WorkspaceExecutionLock
    acquired: list[tuple[Path, ...]] = []

    def recording_lock(settings, **kwargs):
        targets = tuple(kwargs.get("targets") or ())
        acquired.append(targets)
        return real_lock(settings, **kwargs)

    monkeypatch.setattr(server, "WorkspaceExecutionLock", recording_lock)
    server.workspace_apply(
        [
            {
                "path": "first.txt",
                "expected_sha256": sha256_bytes(first.read_bytes()),
                "replacements": [{"old_text": "one", "new_text": "ONE"}],
            },
            {
                "path": "second.txt",
                "expected_sha256": sha256_bytes(second.read_bytes()),
                "replacements": [{"old_text": "two", "new_text": "TWO"}],
            },
        ]
    )

    assert len(acquired) == 1
    assert {target.resolve() for target in acquired[0]} == {first.resolve(), second.resolve()}


def test_workspace_apply_rejects_stale_or_ambiguous_input_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "target.txt"
    target.write_text("same same", encoding="utf-8")

    with pytest.raises(RuntimeError, match="expected_sha256 mismatch"):
        server.text_file_apply("target.txt", "0" * 64, "same", "new")
    assert target.read_text(encoding="utf-8") == "same same"

    expected = sha256_bytes(target.read_bytes())
    with pytest.raises(RuntimeError, match="exact replacement is ambiguous"):
        server.text_file_apply("target.txt", expected, "same", "new")
    assert target.read_text(encoding="utf-8") == "same same"
    rejected = [
        item
        for item in server.runtime.audit.list_operations(limit=20)
        if item["tool_name"] == "text_file_apply"
    ]
    assert len(rejected) == 2
    assert {item["status"] for item in rejected} == {"failed"}


def test_workspace_apply_recovers_post_mutation_failure_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "target.txt"
    target.write_text("before", encoding="utf-8")
    expected = sha256_bytes(target.read_bytes())
    real_capture = server.capture_workspace_state

    def fail_after(settings, operation_id, stage, *, paths=None):
        if stage == "after":
            raise RuntimeError("forced verification failure")
        return real_capture(settings, operation_id, stage, paths=paths)

    monkeypatch.setattr(server, "capture_workspace_state", fail_after)
    with pytest.raises(server.WorkspaceMutationError) as raised:
        server.text_file_apply("target.txt", expected, "before", "temporary")

    assert raised.value.recovery_state == "failed_recovered"
    assert target.read_text(encoding="utf-8") == "before"
    operation = server.runtime.audit.list_operations(limit=1)[0]
    assert operation["tool_name"] == "text_file_apply"
    detail = server.runtime.audit.get_operation(operation["id"])
    assert detail["rollback_state"] == "failed_recovered"
    failed = [
        event for event in detail["events"] if event["event_type"] == "high_level_operation_failed"
    ]
    assert failed[-1]["payload"]["fallback_attempted"] is False


def test_workspace_apply_preserves_recovery_required_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "target.txt"
    target.write_text("before", encoding="utf-8")
    expected = sha256_bytes(target.read_bytes())
    real_capture = server.capture_workspace_state

    def fail_after(settings, operation_id, stage, *, paths=None):
        if stage == "after":
            raise RuntimeError("forced verification failure")
        return real_capture(settings, operation_id, stage, paths=paths)

    def fail_recovery(_settings, operation_id):
        raise server.WorkspaceMutationError(
            "forced recovery failure",
            recovery_state="recovery_required",
            journal_path=str(operation_id),
        )

    monkeypatch.setattr(server, "capture_workspace_state", fail_after)
    monkeypatch.setattr(server, "rollback_applied_workspace_transaction", fail_recovery)
    with pytest.raises(server.WorkspaceMutationError) as raised:
        server.text_file_apply("target.txt", expected, "before", "temporary")

    assert raised.value.recovery_state == "recovery_required"
    operation = server.runtime.audit.list_operations(limit=1)[0]
    detail = server.runtime.audit.get_operation(operation["id"])
    assert detail["status"] == "failed"
    assert detail["rollback_state"] == "recovery_required"
    failure = [
        event for event in detail["events"] if event["event_type"] == "high_level_operation_failed"
    ][-1]
    assert failure["payload"]["fallback_attempted"] is False


def test_one_shot_artifact_round_trip_and_chunk_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    source = root / "source.bin"
    payload = bytes(range(256))
    source.write_bytes(payload)

    downloaded = server.artifact_download("source.bin")
    assert base64.b64decode(downloaded["base64"], validate=True) == payload
    assert downloaded["sha256"] == sha256_bytes(payload)
    uploaded = server.artifact_upload(
        "copy.bin",
        downloaded["base64"],
        downloaded["sha256"],
    )
    assert (root / "copy.bin").read_bytes() == payload
    assert uploaded["execution_path"] == "one_shot"

    source.write_bytes(b"x" * 1025)
    with pytest.raises(ValueError, match="chunked transfer is required.*artifact_download_begin"):
        server.artifact_download("source.bin")


def test_one_shot_upload_rejects_stale_cas_and_oversize_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "target.bin"
    target.write_bytes(b"current")
    replacement = b"replacement"
    encoded = base64.b64encode(replacement).decode("ascii")

    with pytest.raises(RuntimeError, match="expected_sha256 mismatch"):
        server.artifact_upload(
            "target.bin", encoded, sha256_bytes(replacement), expected_sha256="0" * 64
        )
    assert target.read_bytes() == b"current"

    oversized = b"x" * 1025
    with pytest.raises(ValueError, match="chunked transfer is required.*artifact_upload_begin"):
        server.artifact_upload(
            "target.bin",
            base64.b64encode(oversized).decode("ascii"),
            sha256_bytes(oversized),
            expected_sha256=sha256_bytes(target.read_bytes()),
        )
    assert target.read_bytes() == b"current"


def test_operation_report_aggregates_high_level_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "report.txt"
    target.write_text("old", encoding="utf-8")
    result = server.text_file_apply(
        "report.txt", sha256_bytes(target.read_bytes()), "old", "new"
    )

    report = server.operation_report(result["operation_id"])

    assert report["status"] == "succeeded"
    assert report["tool"] == "text_file_apply"
    assert report["high_level_operation"] == "text_file_apply"
    assert report["execution_route"] == "broker_direct"
    assert report["workspace_changes"]["changed_files"] == ["report.txt"]
    assert report["rollback"]["state"] == "complete"
    assert report["audit_activity"]["event_count"] >= 5
    bounded = server.operation_report(result["operation_id"], max_events=1)
    assert len(bounded["audit_activity"]["major_events"]) == 1
    assert bounded["audit_activity"]["events_truncated"] is True


def test_public_tool_surface_keeps_low_level_tools_and_adds_high_level_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    names = {tool.name for tool in server.mcp._tool_manager.list_tools()}

    assert {
        "workspace_tree",
        "workspace_search",
        "read_files",
        "text_file_apply",
        "workspace_apply",
        "artifact_download",
        "artifact_upload",
        "operation_report",
    } <= names
    assert {
        "list_directory",
        "read_file",
        "write_file",
        "structured_file_apply",
        "artifact_download_begin",
        "artifact_download_chunk",
        "artifact_upload_begin",
        "artifact_upload_chunk",
        "artifact_upload_commit",
        "audit_get",
        "activity_get",
    } <= names
