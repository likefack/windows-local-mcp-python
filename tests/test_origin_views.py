"""発行元の表示は既存DBを変更せず、危険な表示文字列も残さない。"""

import sqlite3

from windows_local_mcp.activity_monitor import _read_operation, format_activity_line
from windows_local_mcp.live_activity import format_activity


def _operation():
    return {
        "id": "operation-a", "tool_name": "read_file", "tier": "broker",
        "status": "succeeded", "created_at": "2026-10-06T00:00:00+00:00",
        "request": {"path": "example.txt"},
        "session_id": "session-a", "client_name": "client-a", "task_id": "task-a",
    }


def test_activity_and_live_activity_display_origin_safely():
    operation = _operation()
    for formatter in (format_activity_line, format_activity):
        line = formatter(operation)
        assert all(value in line for value in ("session-a", "client-a", "task-a"))
        unsafe = {**operation, "client_name": "password=hidden\x1b\n", "task_id": "X" * 10000}
        line = formatter(unsafe)
        assert "hidden" not in line and "\x1b" not in line and "\n" not in line
        assert len(line) < 1000
        old = {key: value for key, value in operation.items() if key not in {"session_id", "client_name", "task_id"}}
        assert "session-a" not in formatter(old)


def test_monitor_reads_legacy_schema_without_migrating(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE operations (id TEXT, created_at TEXT, updated_at TEXT, "
                   "tool_name TEXT, tier TEXT, status TEXT, approval_status TEXT, request_json TEXT)")
        db.execute("INSERT INTO operations VALUES ('old','2026-10-06','','read_file','broker','succeeded',NULL,'{}')")
    before = path.read_bytes()
    operation = _read_operation(path, "old")
    assert operation is not None
    assert operation["session_id"] is None
    assert operation["task_id"] is None
    assert path.read_bytes() == before
