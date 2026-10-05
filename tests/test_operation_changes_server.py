"""公開API、実際の変更記録、Live Activity、承認付き取り消しの接続を確認する。"""

import base64
from pathlib import Path

import pytest
from test_high_level_operations import load_server

from windows_local_mcp.live_activity import LiveActivityTracker
from windows_local_mcp.util import sha256_bytes


def _content(server, operation_id: str, path: str, view: str) -> bytes:
    chunks = []
    offset = 0
    while True:
        page = server.operation_changes(
            operation_id, path=path, view=view, content_offset=offset, max_bytes=83
        )
        assert page["availability"] == "available"
        chunk = (
            base64.b64decode(page["content"], validate=True)
            if page["encoding"] == "base64" else page["content"].encode("utf-8")
        )
        assert sha256_bytes(chunk) == page["chunk_sha256"]
        chunks.append(chunk)
        if page["eof"]:
            result = b"".join(chunks)
            assert sha256_bytes(result) == page["sha256"]
            return result
        assert page["next_offset"] > offset
        offset = page["next_offset"]


def test_local_diff_uses_committed_history_and_detail_access_stays_out_of_live_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    server.runtime.settings.max_diff_bytes = 1024
    tracker = LiveActivityTracker(server.runtime.audit)
    assert tracker.poll_once() == []
    text = "".join(f"実変更{i:03d}\n" for i in range(180))
    (root / "large.txt").write_bytes(b"old")
    written = server.text_file_apply("large.txt", sha256_bytes(b"old"), "old", text)
    operation_id = written["operation_id"]
    # 完了後の手動変更が、表示や詳細取得の過去の実変更へ混入してはいけない。
    (root / "large.txt").write_bytes(b"later manual content")
    displayed = "\n".join(tracker.poll_once())
    assert "+実変更000" in displayed and "+実変更179" in displayed
    assert "later manual content" not in displayed
    assert f"[op:{operation_id}]" in displayed
    report = server.operation_report(operation_id)
    assert report["workspace_changes"]["diff_truncated"] is True
    assert report["workspace_changes"]["details"]["arguments"] == {"operation_id": operation_id}
    assert _content(server, operation_id, "large.txt", "after") == text.encode("utf-8")
    diff = _content(server, operation_id, "large.txt", "diff").decode("utf-8")
    assert "+実変更179" in diff
    assert tracker.poll_once() == []
    reads = [
        server.runtime.audit.get_operation(item["id"])
        for item in server.runtime.audit.list_operations(limit=200)
        if item["tool_name"] == "operation_changes"
    ]
    assert reads and all("content" not in item["result"] for item in reads)
    tool = server.mcp._tool_manager.get_tool("operation_changes")
    assert tool.annotations.read_only_hint is True


def test_high_level_summary_links_all_changes_and_existing_approval_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    tracker = LiveActivityTracker(server.runtime.audit)
    tracker.poll_once()
    paths = ["first.txt", "second.txt"]
    for path in paths:
        (root / path).write_bytes(b"old\n")
    changed = server.workspace_apply([
        {"path": path, "expected_sha256": sha256_bytes(b"old\n"),
         "replacements": [{"old_text": "old", "new_text": "new"}]}
        for path in paths
    ])
    operation_id = changed["operation_id"]
    lines = tracker.poll_once()
    assert len(lines) == 1 and "変更2ファイル" in lines[0]
    assert "operation_changes" in lines[0] and "+new" not in lines[0]
    first = server.operation_changes(operation_id, limit=1)
    second = server.operation_changes(operation_id, limit=1, offset=first["next_offset"])
    assert [first["changes"][0]["path"], second["changes"][0]["path"]] == paths
    assert second["eof"] is True
    for path in paths:
        assert _content(server, operation_id, path, "before") == b"old\n"
        assert _content(server, operation_id, path, "after") == b"new\n"
    report = server.operation_report(operation_id)
    assert report["rollback"]["requires_local_approval"] is True
    assert report["rollback"]["undo_request"] == {
        "tool": "request_selective_undo", "arguments": {"operation_id": operation_id}
    }
    pending = server.request_selective_undo(operation_id)
    assert pending["status"] == "pending"
    assert pending["preview"]["changed_file_count"] == 2
    # 承認要求だけで作業ファイルを戻さない既存の境界を維持する。
    assert all((root / path).read_bytes() == b"new\n" for path in paths)
    approval = server.runtime.audit.get_operation(pending["approval_id"])
    assert approval["status"] == "pending_approval"
    assert approval["request"]["target_operation_id"] == operation_id


def test_operation_change_rejection_is_audited_without_modifying_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    operation_id = server.write_file("kept.txt", "kept")["operation_id"]
    with pytest.raises((ValueError, PermissionError)):
        server.operation_changes(operation_id, path="../outside.txt")
    assert (root / "kept.txt").read_bytes() == b"kept"
    rejected = server.runtime.audit.list_operations(limit=1)[0]
    assert rejected["tool_name"] == "operation_changes"
    assert rejected["status"] == "rejected"


def test_summary_count_does_not_use_the_bounded_audit_path_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    # 監査本文の200件上限を超えても、独立に記録された実変更件数を保持する。
    operation_id = server._log_simple(
        tool_name="workspace_apply", request={},
        result={"changed_files": [f"item-{i}.txt" for i in range(205)],
                "changed_file_count": 205, "changed_directory_count": 0},
    )
    changes = server.operation_report(operation_id)["workspace_changes"]
    assert len(changes["changed_files"]) == 200
    assert changes["changed_file_count"] == 205
    assert changes["changed_file_list_truncated"] is True


@pytest.mark.parametrize("fail_transform", [False, True])
def test_structured_transform_is_visible_before_commit_and_finishes_one_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_transform: bool
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    original = b"name,value\nitem,1\n"
    (root / "table.csv").write_bytes(original)
    tracker = LiveActivityTracker(server.runtime.audit)
    tracker.poll_once()
    transform = server.transform_structured
    observed = []

    def inspect_running(*args, **kwargs):
        # sleepや別プロセスを使わず、重い変換に入った時点の監査と表示を確認する。
        active = server.runtime.audit.list_operations(limit=10, status="running")
        assert len(active) == 1
        observed.append(active[0]["id"])
        assert "Running" in "\n".join(tracker.poll_once())
        assert (root / "table.csv").read_bytes() == original
        if fail_transform:
            raise ValueError("test transform failed")
        return transform(*args, **kwargs)

    monkeypatch.setattr(server, "transform_structured", inspect_running)
    arguments = {
        "path": "table.csv", "expected_sha256": sha256_bytes(original),
        "operations": [{"op": "cell_set", "row": 1, "column": 1, "value": "2"}],
    }
    if fail_transform:
        with pytest.raises(ValueError, match="test transform failed"):
            server.structured_file_apply(**arguments)
        assert (root / "table.csv").read_bytes() == original
    else:
        result = server.structured_file_apply(**arguments)
        assert result["operation_id"] == observed[0]
        assert b"item,2" in (root / "table.csv").read_bytes()
    records = [
        row for row in server.runtime.audit.list_operations(limit=20)
        if row["tool_name"] == "structured_file_apply"
    ]
    assert len(records) == 1
    assert records[0]["status"] == ("failed" if fail_transform else "succeeded")
    assert not server.runtime.audit.list_operations(limit=20, status="running")
    assert ("Failed" if fail_transform else "Edited") in "\n".join(tracker.poll_once())
