from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from windows_local_mcp.approval_ui import _format_activity
from windows_local_mcp.live_activity import (
    LiveActivityTracker,
    format_activity,
    project_operation,
    terminal_safe,
)


def test_live_activity_formats_read_edit_run_and_finish() -> None:
    common = {"updated_at": "2026-08-07T11:00:00+00:00", "request": {}}

    read = _format_activity(
        {
            **common,
            "tool_name": "read_file",
            "status": "succeeded",
            "request": {"path": "lib/main.dart"},
        }
    )
    edited = _format_activity(
        {
            **common,
            "tool_name": "write_file",
            "status": "succeeded",
            "request": {"path": "lib/main.dart"},
        }
    )
    running = _format_activity(
        {
            **common,
            "tool_name": "execute_readonly",
            "status": "running",
            "request": {"safe_request": {"program": "git", "args": ["status", "--short"]}},
        }
    )
    finished = _format_activity(
        {
            **common,
            "tool_name": "execute_readonly",
            "status": "succeeded",
            "request": {"safe_request": {"program": "git", "args": ["status", "--short"]}},
        }
    )

    assert read is not None and "Read" in read and "lib/main.dart" in read
    assert edited is not None and "Edited" in edited and "lib/main.dart" in edited
    assert running is not None and "Running" in running and "git status --short" in running
    assert finished is not None and "Finished" in finished and "[succeeded]" in finished


def test_live_activity_ignores_audit_poll_noise() -> None:
    assert (
        _format_activity(
            {
                "tool_name": "poll_job",
                "status": "succeeded",
                "updated_at": "2026-08-07T11:00:00+00:00",
                "request": {},
            }
        )
        is None
    )


def _operation(
    operation_id: str,
    tool_name: str,
    *,
    status: str = "succeeded",
    approval_status: str | None = None,
    path: str | None = None,
    request: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    events: list[dict[str, Any]] | None = None,
    tier: str = "broker",
) -> dict[str, Any]:
    operation_request = dict(request or {})
    if path is not None:
        operation_request.setdefault("path", path)
    return {
        "id": operation_id,
        "created_at": "2026-08-31T11:00:00+00:00",
        "updated_at": "2026-08-31T11:00:00+00:00",
        "tool_name": tool_name,
        "tier": tier,
        "status": status,
        "approval_status": approval_status,
        "request": operation_request,
        "result": dict(result or {}),
        "events": list(events or []),
    }


class _FakeAudit:
    """AuditStore の読み取り面だけを再現する tracker 用 fixture。"""

    def __init__(self, operations: list[dict[str, Any]]) -> None:
        self.operations = {str(item["id"]): deepcopy(item) for item in operations}
        self._order = [str(item["id"]) for item in operations]

    def list_operations(
        self, *, limit: int = 50, status: str | None = None, **_: object
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        matching_ids = [
            operation_id
            for operation_id in self._order
            if status is None or self.operations[operation_id].get("status") == status
        ]
        for operation_id in reversed(matching_ids[-limit:]):
            item = self.operations[operation_id]
            rows.append(
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"request", "result", "events"}
                }
            )
        return rows

    def get_operation(self, operation_id: str, *, include_events: bool = True) -> dict[str, Any]:
        item = deepcopy(self.operations[operation_id])
        if not include_events:
            item.pop("events", None)
        return item

    def add(self, item: dict[str, Any]) -> None:
        operation_id = str(item["id"])
        self.operations[operation_id] = deepcopy(item)
        if operation_id not in self._order:
            self._order.append(operation_id)


@pytest.mark.parametrize(
    ("tool_name", "expected_label"),
    [
        ("read_file", "Read"),
        ("list_directory", "Read"),
        ("get_image", "Read"),
        ("git_info", "Read"),
        ("write_file", "Edited"),
    ],
)
def test_activity_projection_keeps_basic_read_and_edit_categories(
    tool_name: str, expected_label: str
) -> None:
    line = format_activity(_operation("basic", tool_name, path="fixture.txt"))
    assert line is not None
    assert expected_label in line
    if tool_name != "git_info":
        assert "fixture.txt" in line
    assert tool_name not in line


def test_structured_inspect_and_edit_use_confirmed_format_metadata() -> None:
    inspect = format_activity(
        _operation(
            "inspect",
            "structured_file_inspect",
            path="table.xlsx",
            request={"format": "xlsx"},
        )
    )
    edit = format_activity(
        _operation(
            "edit",
            "structured_file_apply",
            status="running",
            path="table.xlsx",
            request={"format": "xlsx", "output_path": "table.xlsx"},
            tier="structured_processing",
        )
    )
    unknown_format = format_activity(
        _operation(
            "unknown-format",
            "structured_file_apply",
            path="table.xlsx",
            request={"format": "spreadsheet"},
            tier="structured_processing",
        )
    )
    assert inspect is not None and "Read" in inspect and "Excel" in inspect
    assert "table.xlsx" in inspect and "structured_file_inspect" not in inspect
    assert edit is not None and "Running" in edit and "Excel" in edit
    assert "structured_file_apply" not in edit
    assert unknown_format is not None and "構造化ファイル" in unknown_format
    assert "Excel" not in unknown_format


@pytest.mark.parametrize(
    ("tool_name", "expected_detail"),
    [
        ("zip_entry_read", "ZIP内部を読み取り"),
        ("zip_entry_extract", "ZIP内部を展開"),
        ("zip_extract_many", "ZIPを展開"),
    ],
)
def test_zip_operations_are_meaningful_without_exposing_protocol_names(
    tool_name: str, expected_detail: str
) -> None:
    request: dict[str, Any] = {"path": "bundle.zip", "entry": "notes/a.txt"}
    if tool_name == "zip_entry_extract":
        request["output_path"] = "notes/a.txt"
    if tool_name == "zip_extract_many":
        request["output_directory"] = "extracted"
    line = format_activity(_operation("zip", tool_name, path="bundle.zip", request=request))
    assert line is not None and expected_detail in line
    assert tool_name not in line


def test_transfer_begin_and_chunks_are_one_logical_lifecycle() -> None:
    begin = _operation(
        "download-op",
        "artifact_download_begin",
        result={"transfer_id": "transfer-1", "path": "report.xlsx", "bytes": 4},
    )
    audit = _FakeAudit([begin])
    tracker = LiveActivityTracker(audit)
    first = tracker.poll_once()
    assert len(first) == 1 and "Running" in first[0] and "report.xlsx" in first[0]

    # Chunk events append to the begin operation and do not change updated_at.
    audit.operations["download-op"]["events"].append(
        {
            "occurred_at": "2026-08-31T11:00:02+00:00",
            "event_type": "artifact_download_chunk",
            "payload": {"result": {"offset": 0, "bytes": 4, "complete": True}},
        }
    )
    second = tracker.poll_once()
    assert len(second) == 1 and "Downloaded" in second[0]
    assert tracker.poll_once() == []

    chunk = format_activity(
        _operation(
            "chunk-op",
            "artifact_download_chunk",
            status="succeeded",
            request={"transfer_id": "transfer-1", "offset": 0},
        ),
        transfer_paths={"transfer-1": "report.xlsx"},
    )
    assert chunk is None


def test_upload_commit_reuses_transfer_path_and_hides_begin_chunk_commit_noise() -> None:
    begin = _operation(
        "upload-begin",
        "artifact_upload_begin",
        result={"transfer_id": "transfer-2", "path": "result.bin", "total_bytes": 4},
    )
    audit = _FakeAudit([begin])
    tracker = LiveActivityTracker(audit)
    assert len(tracker.poll_once()) == 1
    audit.operations["upload-begin"]["events"].append(
        {
            "occurred_at": "2026-08-31T11:00:01+00:00",
            "event_type": "artifact_upload_chunk",
            "payload": {"result": {"received": 4, "complete": True}},
        }
    )
    audit.add(
        _operation(
            "upload-commit",
            "artifact_upload_commit",
            result={"transfer_id": "transfer-2", "path": "result.bin"},
            request={"transfer_id": "transfer-2", "path": "result.bin"},
        )
    )
    lines = tracker.poll_once()
    assert len(lines) == 1 and "Uploaded" in lines[0] and "result.bin" in lines[0]
    assert "artifact_upload" not in lines[0]


def test_upload_chunks_are_running_until_commit_and_completed_pair_is_not_replayed() -> None:
    begin = _operation(
        "upload-begin-paired",
        "artifact_upload_begin",
        result={"transfer_id": "transfer-paired", "path": "paired.bin", "total_bytes": 4},
    )
    commit = _operation(
        "upload-commit-paired",
        "artifact_upload_commit",
        result={"transfer_id": "transfer-paired", "path": "paired.bin"},
        request={"transfer_id": "transfer-paired", "path": "paired.bin"},
    )
    assert "Running" in (format_activity(begin) or "")
    audit = _FakeAudit([begin, commit])
    tracker = LiveActivityTracker(audit)
    # Both rows already represent a completed logical upload; baseline must not replay either.
    assert tracker.poll_once() == []
    assert tracker.poll_once() == []


def test_commit_arrival_does_not_duplicate_existing_logical_transfer_running_line() -> None:
    begin = _operation(
        "upload-begin-running",
        "artifact_upload_begin",
        result={"transfer_id": "transfer-running", "path": "running.bin", "total_bytes": 4},
        events=[
            {
                "occurred_at": "2026-08-31T11:00:01+00:00",
                "event_type": "artifact_upload_chunk",
                "payload": {"result": {"received": 4, "complete": True}},
            }
        ],
    )
    audit = _FakeAudit([begin])
    tracker = LiveActivityTracker(audit)
    first = tracker.poll_once()
    assert len(first) == 1 and "Running" in first[0]
    audit.add(
        _operation(
            "upload-commit-running",
            "artifact_upload_commit",
            status="running",
            request={"transfer_id": "transfer-running", "path": "running.bin"},
            result={"transfer_id": "transfer-running", "path": "running.bin"},
        )
    )
    assert tracker.poll_once() == []
    audit.operations["upload-commit-running"]["status"] = "succeeded"
    audit.operations["upload-commit-running"]["updated_at"] = "2026-08-31T11:00:03+00:00"
    lines = tracker.poll_once()
    assert len(lines) == 1 and "Uploaded" in lines[0]


def test_failed_upload_commit_stops_begin_lifecycle_without_replaying_running() -> None:
    begin = _operation(
        "upload-begin-failed",
        "artifact_upload_begin",
        result={"transfer_id": "transfer-failed", "path": "failed.bin", "total_bytes": 4},
    )
    commit = _operation(
        "upload-commit-failed",
        "artifact_upload_commit",
        status="failed",
        request={"transfer_id": "transfer-failed", "path": "failed.bin"},
        result={"transfer_id": "transfer-failed", "path": "failed.bin"},
    )
    baseline = LiveActivityTracker(_FakeAudit([begin, commit]))
    assert baseline.poll_once() == []

    audit = _FakeAudit([begin])
    tracker = LiveActivityTracker(audit)
    first = tracker.poll_once()
    assert len(first) == 1 and "Running" in first[0]
    audit.add(commit)
    lines = tracker.poll_once()
    assert len(lines) == 1
    assert "Failed" in lines[0] and "Running" not in lines[0]


@pytest.mark.parametrize(
    ("status", "expected_label"),
    [
        ("failed", "Failed"),
        ("rejected", "Rejected"),
        ("interrupted", "Interrupted"),
        ("timed_out", "Timed out"),
        ("conflict", "Conflict"),
    ],
)
def test_important_abnormal_terminal_states_remain_visible(
    status: str, expected_label: str
) -> None:
    line = format_activity(
        _operation(
            f"abnormal-{status}",
            "structured_file_apply",
            status=status,
            path="table.xlsx",
            request={"format": "xlsx"},
            tier="structured_processing",
        )
    )
    assert line is not None and expected_label in line and "table.xlsx" in line
    assert "structured_file_apply" not in line


@pytest.mark.parametrize("tool_name", ["request_selective_undo", "request_workspace_rollback"])
def test_undo_and_rollback_have_distinct_human_lifecycles(tool_name: str) -> None:
    operation_type = "selective_undo" if tool_name == "request_selective_undo" else "point_in_time_rollback"
    preview = {"changed_file_count": 2, "files_that_would_change": ["a.txt", "b.txt"]}
    pending = format_activity(
        _operation(
            "control-pending",
            tool_name,
            status="pending_approval",
            approval_status="pending",
            request={"operation_type": operation_type, "undo_preview": preview},
        )
    )
    running = format_activity(
        _operation(
            "control-running",
            tool_name,
            status="running",
            approval_status="approved",
            request={"operation_type": operation_type, "undo_preview": preview},
        )
    )
    done = format_activity(
        _operation(
            "control-done",
            tool_name,
            status="succeeded",
            request={"operation_type": operation_type, "undo_preview": preview},
        )
    )
    assert pending is not None and "Approval" in pending
    assert running is not None and "Running" in running
    assert done is not None
    if tool_name == "request_selective_undo":
        assert "Undone" in done and "Rolled back" not in done
        assert "変更を元に戻す" in pending
    else:
        assert "Rolled back" in done and "Undone" not in done
        assert "以前の状態へ復元" in pending
    assert "2ファイル" in pending
    assert "target=" not in pending


def test_undo_of_undo_uses_target_metadata_without_reading_file_contents() -> None:
    target = _operation(
        "undo-a",
        "request_selective_undo",
        status="succeeded",
        request={
            "operation_type": "selective_undo",
            "undo_preview": {"changed_file_count": 1, "files_that_would_change": ["a.txt"]},
        },
    )
    undo_of_undo = _operation(
        "undo-b",
        "request_selective_undo",
        request={
            "operation_type": "selective_undo",
            "target_operation_id": "undo-a",
            "undo_preview": {"changed_file_count": 1, "files_that_would_change": ["a.txt"]},
        },
    )
    projection = project_operation(undo_of_undo, target=target)
    assert projection is not None
    assert "Undoした変更を元に戻す" in projection.detail
    assert "undo-a" not in projection.detail


def test_meta_operations_stay_out_while_unknown_command_uses_bounded_safe_shape() -> None:
    assert format_activity(_operation("audit", "audit_get", request={"operation_id": "x"})) is None
    command = format_activity(
        _operation(
            "command",
            "future_command",
            status="running",
            request={
                "normalized_command": {
                    "display_command": ["tool", "--password", "hunter2", "--token", "sk-12345678901234567890"]
                },
                "stdout": "DO NOT PRINT",
                "stderr": "DO NOT PRINT",
            },
        )
    )
    assert command is not None and "Running" in command and "tool" in command
    assert "hunter2" not in command and "sk-12345678901234567890" not in command
    assert "DO NOT PRINT" not in command

    future_file_operation = format_activity(
        _operation("future-file", "future_file_transform", path="future.bin")
    )
    assert future_file_operation is not None
    assert "Finished" in future_file_operation and "future.bin" in future_file_operation
    assert "future_file_transform" not in future_file_operation


def test_unknown_future_operation_uses_only_safe_path_for_generic_projection() -> None:
    visible = format_activity(
        _operation(
            "future-path",
            "future_workspace_operation",
            status="running",
            path="fixture.txt",
            request={"payload": "DO NOT PRINT"},
        )
    )
    hidden = format_activity(
        _operation(
            "future-no-path",
            "future_workspace_operation",
            status="running",
            request={"payload": "DO NOT PRINT"},
        )
    )
    assert visible is not None and "Running" in visible and "fixture.txt" in visible
    assert "DO NOT PRINT" not in visible
    assert hidden is None


def test_terminal_safety_and_summary_bound_apply_to_request_derived_path() -> None:
    secret = "hunter2"
    malicious = f"name\n\r\x00\x1b[31m\u202e password={secret} " + ("x" * 500)
    line = format_activity(
        _operation(
            "safe",
            "read_file",
            path=malicious,
            result={
                "content": "FILE CONTENT MUST NOT APPEAR",
                "stdout": "STDOUT MUST NOT APPEAR",
                "stderr": "STDERR MUST NOT APPEAR",
                "diff": "DIFF MUST NOT APPEAR",
            },
        )
    )
    assert line is not None
    assert "\n" not in line and "\r" not in line and "\x1b" not in line
    assert "\u202e" not in line and secret not in line
    assert "FILE CONTENT" not in line and "STDOUT" not in line and "DIFF" not in line
    projection = project_operation(
        _operation("safe", "read_file", path=malicious, result={"content": "ignored"})
    )
    assert projection is not None and len(projection.detail) <= 200
    assert terminal_safe("x\ud800") == "x\\ud800"


def test_tracker_baseline_shows_only_important_active_work_and_deduplicates_states() -> None:
    audit = _FakeAudit(
        [
            _operation("old", "read_file", path="old.txt"),
            _operation(
                "queued",
                "execute_readonly",
                status="queued",
                request={"safe_request": {"program": "git", "args": ["status"]}},
            ),
            _operation(
                "approval",
                "request_selective_undo",
                status="pending_approval",
                approval_status="pending",
                request={"undo_preview": {"changed_file_count": 1, "files_that_would_change": ["a.txt"]}},
            ),
            _operation("meta", "audit_list"),
        ]
    )
    tracker = LiveActivityTracker(audit)
    lines = tracker.poll_once()
    assert len(lines) == 2
    assert any("Running" in line for line in lines)
    assert any("Approval" in line for line in lines)
    assert all("old.txt" not in line for line in lines)
    assert tracker.poll_once() == []

    audit.operations["queued"]["status"] = "running"
    audit.operations["queued"]["updated_at"] = "2026-08-31T11:00:01+00:00"
    assert tracker.poll_once() == []


def test_tracker_baseline_finds_active_operation_older_than_history_limit() -> None:
    old_active = _operation(
        "old-active",
        "execute_readonly",
        status="running",
        request={"safe_request": {"program": "git", "args": ["status"]}},
    )
    terminal_noise = [
        _operation(f"done-{index}", "audit_get", request={"operation_id": str(index)})
        for index in range(8)
    ]
    tracker = LiveActivityTracker(_FakeAudit([old_active, *terminal_noise]), limit=3)

    lines = tracker.poll_once()

    assert len(lines) == 1
    assert "Running" in lines[0] and "git status" in lines[0]


def test_tracker_recovers_missed_undo_transition_after_paused_poll() -> None:
    audit = _FakeAudit(
        [
            _operation(
                "undo",
                "request_selective_undo",
                status="pending_approval",
                approval_status="pending",
                request={"undo_preview": {"changed_file_count": 1, "files_that_would_change": ["a.txt"]}},
            )
        ]
    )
    tracker = LiveActivityTracker(audit)
    initial = tracker.poll_once()
    assert initial and "Approval" in initial[0]
    audit.operations["undo"]["status"] = "succeeded"
    audit.operations["undo"]["approval_status"] = "approved"
    audit.operations["undo"]["updated_at"] = "2026-08-31T11:00:03+00:00"
    assert tracker.poll_once(emit=False) == []
    lines = tracker.poll_once()
    assert len(lines) == 2
    assert "Running" in lines[0] and "Undone" in lines[1]
