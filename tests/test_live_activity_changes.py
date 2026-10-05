from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp import live_activity
from windows_local_mcp.config import Settings
from windows_local_mcp.live_activity import LiveActivityTracker, format_activity, project_operation
from windows_local_mcp.workspace_history import capture_workspace_state, compare_workspace_states

START = datetime(2026, 10, 6, tzinfo=UTC)


class _Clock:
    def __init__(self) -> None:
        self.seconds = 0.0

    def monotonic(self) -> float:
        return self.seconds

    def now(self) -> datetime:
        return START + timedelta(seconds=self.seconds)


class _Audit:
    """監査の読み取り面だけを持たせ、表示から状態を変更できないことも確認する。"""

    def __init__(self, *operations: dict[str, Any], settings: object = None) -> None:
        self.settings = settings if settings is not None else object()
        self.operations = {item["id"]: deepcopy(item) for item in operations}
        self.fail_next_read = False

    def list_operations(self, *, limit: int, status: str | None = None) -> list[dict[str, Any]]:
        values = [
            item for item in reversed(list(self.operations.values()))
            if status is None or item["status"] == status
        ][:limit]
        return [
            {key: value for key, value in item.items() if key not in {"request", "result", "events"}}
            for item in values
        ]

    def get_operation(self, operation_id: str, *, include_events: bool = True) -> dict[str, Any]:
        if self.fail_next_read:
            self.fail_next_read = False
            raise RuntimeError("temporary database read failure")
        operation = deepcopy(self.operations[operation_id])
        if not include_events:
            operation.pop("events", None)
        return operation

    def add(self, operation: dict[str, Any]) -> None:
        self.operations[operation["id"]] = deepcopy(operation)


def _operation(operation_id: str = "change", tool: str = "write_file", **extra: Any) -> dict[str, Any]:
    return {
        "id": operation_id,
        "tool_name": tool,
        "status": "succeeded",
        "created_at": START.isoformat(),
        "updated_at": START.isoformat(),
        "request": {"path": "notes.txt"},
        "result": {
            "changed_file_count": 1,
            "changed_directory_count": 0,
            "added_lines": 1,
            "removed_lines": 1,
        },
        "pre_workspace_path": "before/manifest.json",
        "post_workspace_path": "after/manifest.json",
        **extra,
    }


def _tracker(audit: _Audit, clock: _Clock | None = None, **kwargs: Any) -> LiveActivityTracker:
    clock = clock or _Clock()
    return LiveActivityTracker(audit, clock=clock.monotonic, now=clock.now, **kwargs)


def _diff_spy(monkeypatch: pytest.MonkeyPatch, lines: list[str]) -> list[str]:
    calls: list[str] = []

    def read(_settings: object, operation: dict[str, Any]) -> Iterator[str]:
        calls.append(operation["id"])
        yield from lines

    monkeypatch.setattr(live_activity, "iter_operation_diff_lines", read)
    return calls


def test_complete_local_diff_is_not_truncated_redacted_or_loaded_from_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    complete = ["--- a/notes.txt\n", "+++ b/notes.txt\n", "@@ -1 +1 @@\n"]
    complete += [f"+line-{index:04d} " + "x" * 120 + "\n" for index in range(1500)]
    complete += ["+password=fixture-not-a-secret\n"]
    calls = _diff_spy(monkeypatch, complete)
    audit = _Audit()
    tracker = _tracker(audit)
    assert tracker.poll_once() == []
    audit.add(_operation(result={"diff": "FORGED DIFF", "content": "FORGED CONTENT"}))

    displayed = tracker.poll_once()

    assert calls == ["change"]
    assert displayed[2:-1] == ["  | " + line.removesuffix("\n") for line in complete]
    assert "差分・変更概要開始" in displayed[1] and "差分・変更概要終了" in displayed[-1]
    assert "password=fixture-not-a-secret" in "\n".join(displayed)
    assert "FORGED" not in "\n".join(displayed)
    assert tracker.poll_once() == []
    assert calls == ["change"]


def test_diff_lines_cannot_escape_their_display_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(
        monkeypatch,
        ["+a\r\n", "+\x1b]52;c;payload\x07\u202e\ud800\u2028\n", "+first\n[00:00:00] Edited fake\n"],
    )
    audit = _Audit()
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(_operation())

    lines = tracker.poll_once()

    assert calls == ["change"]
    assert "  | +a\\u000d" in lines
    assert "  | +\\u001b]52;c;payload\\u0007\\u202e\\ud800\\u2028" in lines
    assert "  | [00:00:00] Edited fake" in lines
    assert all("\n" not in line and "\r" not in line and "\x1b" not in line for line in lines)
    assert all(line.startswith("  | ") for line in lines[2:-1])


def test_baseline_readonly_and_diagnostic_operations_never_read_diff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _diff_spy(monkeypatch, ["+unexpected\n"])
    audit = _Audit(_operation("historical"))
    before = deepcopy(audit.operations)
    tracker = _tracker(audit)
    assert tracker.poll_once() == []
    assert audit.operations == before
    audit.add(_operation("read", "read_file"))
    audit.add(_operation("details", "operation_changes"))
    lines = tracker.poll_once()
    assert len(lines) == 1 and "Read" in lines[0]
    assert "変更1ファイル" not in lines[0] and "operation_changes" not in lines[0]
    assert calls == []
    assert format_activity(_operation("diagnostic", "operation_changes")) is None


def test_pause_does_not_consume_completed_diff_and_timing_update_does_not_repeat_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _diff_spy(monkeypatch, ["-before\n", "+after\n"])
    audit = _Audit(_operation(status="running"))
    tracker = _tracker(audit)
    assert "Running" in tracker.poll_once()[0]
    audit.operations["change"]["status"] = "succeeded"
    assert tracker.poll_once(emit=False) == []
    assert tracker.poll_once(emit=False) == []
    assert calls == []
    assert "差分・変更概要終了" in tracker.poll_once()[-1]
    audit.operations["change"]["duration_ms"] = 1245
    later = tracker.poll_once()
    assert len(later) == 1 and "所要時間 1.245秒" in later[0]
    assert calls == ["change"]


def test_initial_paused_poll_does_not_consume_active_display(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, ["+done\n"])
    audit = _Audit(_operation(status="running"))
    tracker = _tracker(audit)
    assert tracker.poll_once(emit=False) == []
    assert "Running" in tracker.poll_once()[0]
    audit.operations["change"]["status"] = "succeeded"
    assert "差分・変更概要終了" in tracker.poll_once()[-1]
    assert calls == ["change"]


@pytest.mark.parametrize(
    "tool",
    ["workspace_apply", "workspace_batch", "workspace_replace", "workspace_plan_apply",
     "structured_file_apply", "zip_extract_many", "execute_workspace_write",
     "request_host_command", "request_sandbox_command", "request_selective_undo",
     "request_workspace_rollback"],
)
def test_high_level_operation_with_one_file_is_summary_only(
    tool: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _diff_spy(monkeypatch, ["+must not be shown\n"])
    audit = _Audit()
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(_operation(tool=tool, duration_ms=27))
    lines = tracker.poll_once()
    summary = lines[-1]
    assert "変更1ファイル" in summary and "追加1行/削除1行" in summary
    assert "operation_changes" in summary and "所要時間 27 ms" in summary
    assert summary.endswith("[op:change]")
    assert calls == [] and not any("差分・変更概要開始" in line for line in lines)


@pytest.mark.parametrize(
    "tool", ["write_file", "text_file_apply", "move_file", "copy_file", "delete_file",
             "make_directory", "artifact_upload", "artifact_upload_commit",
             "structured_file_upload_commit", "artifact_import_file", "zip_entry_extract"],
)
def test_local_operation_reads_complete_diff_once(tool: str, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, ["+confirmed\n"])
    audit = _Audit()
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(_operation(tool=tool))
    assert "  | +confirmed" in tracker.poll_once()
    assert tracker.poll_once() == [] and calls == ["change"]


@pytest.mark.parametrize(
    "extra",
    [{"status": "failed"}, {"status": "failed_recovered", "approval_status": "approved"},
     {"status": "rejected"}, {"status": "interrupted"},
     {"status": "cancelled"}, {"status": "conflict"}, {"status": "timed_out"},
     {"status": "recovery_required"}, {"status": "succeeded", "rollback_state": "recovery_required"},
     {"status": "succeeded", "result": {"rollback_state": "recovery_required"}}],
)
def test_unsuccessful_operation_never_claims_successful_changes(
    extra: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _diff_spy(monkeypatch, ["+must not be shown\n"])
    audit = _Audit(_operation(status="running"))
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.operations["change"].update(extra)
    # 監査一覧は更新時刻の変化を通知する。
    audit.operations["change"]["updated_at"] = (START + timedelta(seconds=1)).isoformat()
    lines = tracker.poll_once()
    text = "\n".join(lines)
    assert len(lines) == 1
    assert "Edited" not in text and "変更1ファイル" not in text and "差分・変更概要開始" not in text
    assert "rollback" not in text and calls == []


def test_diff_unavailable_discards_partial_output_and_is_reported_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def broken(_settings: object, operation: dict[str, Any]) -> Iterator[str]:
        calls.append(operation["id"])
        yield "+incomplete content\n"
        raise FileNotFoundError("internal path must not be shown")

    monkeypatch.setattr(live_activity, "iter_operation_diff_lines", broken)
    audit = _Audit()
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(_operation())
    lines = tracker.poll_once()
    assert len(lines) == 2
    assert "差分を読み出せませんでした" in lines[1] and "operation_changes" in lines[1]
    assert "incomplete content" not in "\n".join(lines) and "internal path" not in lines[1]
    assert tracker.poll_once() == [] and calls == ["change"]


def test_noop_has_no_false_text_diff(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, [])
    audit = _Audit()
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(_operation(result={"changed_file_count": 0, "changed_directory_count": 0}))
    lines = tracker.poll_once()
    assert "変更なし" in lines[0] and "内容の変更なし" in lines[1]
    assert calls == ["change"]


def test_long_target_does_not_hide_metrics_time_or_operation_id() -> None:
    operation = _operation(
        "complete-operation-id", "structured_file_apply", duration_ms=2567,
        request={"path": "x" * 500 + ".xlsx", "format": "xlsx"},
        result={"changed_file_count": 1, "changed_directory_count": 0,
                "nontext_file_count": 1, "bytes_before": 2000, "bytes_after": 2100},
    )
    projection = project_operation(operation)
    line = format_activity(operation)
    assert projection is not None and len(projection.detail) <= 200
    assert line is not None and "非テキスト1ファイル" in line and "2000→2100バイト" in line
    assert "所要時間 2.567秒" in line and line.endswith("[op:complete-operation-id]")


def test_elapsed_updates_are_throttled_and_stop_after_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, ["+done\n"])
    clock = _Clock()
    audit = _Audit(_operation(status="running", duration_ms=7))
    tracker = _tracker(audit, clock)
    initial = tracker.poll_once()
    assert len(initial) == 1 and "経過 0 ms" in initial[0] and "所要時間" not in initial[0]
    clock.seconds = 4.9
    assert tracker.poll_once() == []
    clock.seconds = 5
    assert "経過 5.000秒" in tracker.poll_once()[0]
    clock.seconds = 10
    assert tracker.poll_once(emit=False) == []
    assert "経過 10.000秒" in tracker.poll_once()[0]
    audit.operations["change"].update(status="succeeded", duration_ms=9876)
    terminal = tracker.poll_once()
    assert "所要時間 9.876秒" in terminal[0] and "経過" not in terminal[0]
    clock.seconds = 20
    assert tracker.poll_once() == [] and calls == ["change"]


def test_completed_long_operation_is_found_outside_history_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, ["+done\n"])
    audit = _Audit(_operation("old", status="running"))
    tracker = _tracker(audit, limit=1)
    assert "Running" in tracker.poll_once()[0]
    audit.operations["old"]["status"] = "succeeded"
    for index in range(4):
        audit.add(_operation(f"noise-{index}", "audit_get"))
    assert "  | +done" in tracker.poll_once()
    assert calls == ["old"]


def test_transient_full_row_read_failure_does_not_consume_diff(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, ["+done\n"])
    audit = _Audit()
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(_operation())
    audit.fail_next_read = True
    assert tracker.poll_once() == [] and calls == []
    assert "  | +done" in tracker.poll_once() and calls == ["change"]


def test_upload_has_one_commit_diff_and_separate_transfer_and_commit_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _diff_spy(monkeypatch, ["+uploaded\n"])
    begin = _operation(
        "begin", "artifact_upload_begin", duration_ms=11,
        result={"transfer_id": "transfer", "path": "notes.txt", "total_bytes": 8}, events=[],
    )
    audit = _Audit(begin)
    clock = _Clock()
    tracker = _tracker(audit, clock)
    initial = tracker.poll_once()
    assert len(initial) == 1 and "0/8バイト" in initial[0]
    assert "所要時間" not in initial[0]
    audit.operations["begin"]["events"].append({
        "event_type": "artifact_upload_chunk",
        "occurred_at": (START + timedelta(seconds=1)).isoformat(),
        "payload": {"result": {"received": 4}},
    })
    clock.seconds = 1
    assert tracker.poll_once() == []
    clock.seconds = 5
    assert "4/8バイト" in tracker.poll_once()[0]
    audit.add(_operation(
        "commit", "artifact_upload_commit", status="running",
        request={"transfer_id": "transfer", "path": "notes.txt"}, result={},
    ))
    assert tracker.poll_once() == []
    clock.seconds = 12
    audit.operations["commit"].update(
        status="succeeded", duration_ms=31, updated_at=clock.now().isoformat()
    )
    lines = tracker.poll_once()
    summaries = [line for line in lines if "Uploaded" in line]
    assert len(summaries) == 1 and summaries[0].endswith("[op:commit]")
    assert "転送経過 12.000秒" in summaries[0] and "確定処理 31 ms" in summaries[0]
    assert calls == ["commit"] and tracker.poll_once() == []


def test_download_retries_do_not_double_count_and_begin_duration_is_not_total() -> None:
    begin = _operation(
        "download", "artifact_download_begin", duration_ms=9,
        result={"transfer_id": "transfer", "path": "notes.txt", "bytes": 8}, events=[],
    )
    audit = _Audit(begin)
    clock = _Clock()
    tracker = _tracker(audit, clock)
    tracker.poll_once()
    chunks = audit.operations["download"]["events"]
    for offset in (0, 0):
        chunks.append({"event_type": "artifact_download_chunk",
                       "occurred_at": (START + timedelta(seconds=5)).isoformat(),
                       "payload": {"result": {"offset": offset, "bytes": 4}}})
    clock.seconds = 5
    assert "4/8バイト" in tracker.poll_once()[0]
    chunks.append({"event_type": "artifact_download_chunk",
                   "occurred_at": (START + timedelta(seconds=12)).isoformat(),
                   "payload": {"result": {"offset": 4, "bytes": 4}}})
    lines = tracker.poll_once()
    assert len(lines) == 1 and "Downloaded" in lines[0] and "8/8バイト" in lines[0]
    assert "転送経過 12.000秒" in lines[0] and "所要時間" not in lines[0]


def _settings(tmp_path: Path) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(workspace_root=root, data_dir=tmp_path / "data",
                        protect_data_dir_acl=False, max_diff_bytes=1024)
    settings.ensure_directories()
    return settings


def _checkpoint_operation(settings: Settings, before: bytes, after: bytes) -> dict[str, Any]:
    target = settings.workspace_root / "notes.txt"
    target.write_bytes(before)
    pre = capture_workspace_state(settings, "retained", "before", paths={"notes.txt"})
    target.write_bytes(after)
    post = capture_workspace_state(settings, "retained", "after", paths={"notes.txt"})
    changes = compare_workspace_states(settings, pre.manifest_path, post.manifest_path, "retained")
    return _operation("retained", pre_workspace_path=pre.manifest_path,
                      post_workspace_path=post.manifest_path, result=changes, duration_ms=49)


def test_real_retained_checkpoints_supply_full_diff_beyond_saved_preview(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    before = "".join(f"before-{index:04d}\n" for index in range(1300)).encode()
    after = "".join(f"after-{index:04d}\n" for index in range(1300)).encode()
    operation = _checkpoint_operation(settings, before, after)
    assert Path(operation["result"]["diff_path"]).stat().st_size <= settings.max_diff_bytes
    # 履歴にない現在のworkspace内容へ差分をすり替えない。
    (settings.workspace_root / "notes.txt").write_text("CURRENT WORKSPACE\n", encoding="utf-8")
    audit = _Audit(settings=settings)
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(operation)
    lines = tracker.poll_once()
    assert "  | -before-0000" in lines and "  | -before-1299" in lines
    assert "  | +after-0000" in lines and "  | +after-1299" in lines
    assert "追加1300行/削除1300行" in lines[0]
    assert "CURRENT WORKSPACE" not in "\n".join(lines)
    assert not any("truncated" in line for line in lines)
    assert "差分・変更概要終了" in lines[-1] and tracker.poll_once() == []


def test_real_nontext_change_has_size_summary_and_binary_marker(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    operation = _checkpoint_operation(settings, b"\x00old\xff", b"\x00new-content\xfe")
    audit = _Audit(settings=settings)
    tracker = _tracker(audit)
    tracker.poll_once()
    audit.add(operation)
    lines = tracker.poll_once()
    assert "非テキスト1ファイル" in lines[0] and "5→13バイト" in lines[0]
    assert "追加" not in lines[0] and "所要時間 49 ms" in lines[0]
    assert any("Binary files differ" in line and "notes.txt" in line for line in lines)
    assert any("operation_changes の before/after" in line for line in lines)
    assert not any("全内容" in line for line in lines)
    assert "\x00" not in "\n".join(lines)


def test_structured_summary_counts_known_operations_without_showing_values() -> None:
    operation = _operation(
        tool="structured_file_apply", request={
            "path": "table.xlsx", "format": "xlsx",
            "operations": ["cell_set", "cell_set", "resize", "UNTRUSTED\nTEXT",
                           {"op": "cell_set", "value": "MUST NOT SHOW"}],
        },
    )
    line = format_activity(operation)
    assert line is not None and "セル設定2件/サイズ変更1件" in line
    assert "UNTRUSTED" not in line and "MUST NOT SHOW" not in line
    operation["result"] = {"changed_file_count": 0, "changed_directory_count": 0}
    no_change = format_activity(operation)
    assert no_change is not None and "変更なし" in no_change and "操作: セル設定2件" in no_change
    operation["status"] = "running"
    running = format_activity(operation)
    assert running is not None and "予定: セル設定2件" in running and "変更なし" not in running


def test_waiting_time_is_rebased_when_execution_starts() -> None:
    clock = _Clock()
    audit = _Audit(_operation("approval", "execute_workspace_write",
                              status="pending_approval", approval_status="pending"))
    tracker = _tracker(audit, clock)
    assert "待機経過 0 ms" in tracker.poll_once()[0]
    clock.seconds = 20
    assert "待機経過 20.000秒" in tracker.poll_once()[0]
    audit.operations["approval"].update(status="queued", approval_status="approved")
    queued = tracker.poll_once()
    assert "Running" in queued[0] and "待機経過 20.000秒" in queued[0]
    clock.seconds = 21
    audit.operations["approval"].update(status="running", started_at=clock.now().isoformat())
    running = tracker.poll_once()
    assert len(running) == 1 and "経過 0 ms" in running[0] and "待機経過" not in running[0]
    clock.seconds = 26
    assert "経過 5.000秒" in tracker.poll_once()[0]


def test_recent_history_prunes_diff_and_progress_display_state(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _diff_spy(monkeypatch, ["+done\n"])
    audit = _Audit(_operation("old", status="running"))
    tracker = _tracker(audit, limit=1)
    tracker.poll_once()
    audit.operations["old"]["status"] = "succeeded"
    tracker.poll_once()
    assert "old" in tracker._diff_handled
    audit.add(_operation("current"))
    tracker.poll_once()
    assert tracker._diff_handled == {"current"}
    assert set(tracker._last_display_at) == {"operation:current"}
    assert tracker._activity_started == {}
    assert tracker.poll_once() == [] and calls == ["old", "current"]
