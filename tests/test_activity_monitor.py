from __future__ import annotations

import io
import json
import sqlite3
from pathlib import Path

from windows_local_mcp.activity_monitor import (
    LOG_BACKUP_COUNT,
    LOG_MAX_BYTES,
    ActivityMonitor,
    ActivitySink,
    format_activity_line,
    sanitize_display_text,
)


def _create_audit_db(data_dir: Path) -> Path:
    database_path = data_dir / "audit.db"
    with sqlite3.connect(database_path) as database:
        database.execute(
            """
            CREATE TABLE operations (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tier TEXT NOT NULL,
                status TEXT NOT NULL,
                approval_status TEXT,
                request_json TEXT NOT NULL
            )
            """
        )
    return database_path


def _insert_operation(
    database_path: Path,
    operation_id: str,
    *,
    status: str = "succeeded",
    approval_status: str | None = None,
    request: dict[str, object] | None = None,
) -> None:
    timestamp = "2026-08-30T00:00:00+00:00"
    with sqlite3.connect(database_path) as database:
        database.execute(
            "INSERT INTO operations "
            "(id, created_at, updated_at, tool_name, tier, status, approval_status, request_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                operation_id,
                timestamp,
                timestamp,
                "request_sandbox_command",
                "sandbox",
                status,
                approval_status,
                json.dumps(request or {}, ensure_ascii=False),
            ),
        )


def _update_status(database_path: Path, operation_id: str, *, status: str, approval: str | None) -> None:
    with sqlite3.connect(database_path) as database:
        database.execute(
            "UPDATE operations SET status=?, approval_status=?, "
            "updated_at=? WHERE id=?",
            (status, approval, "2026-08-30T00:00:01+00:00", operation_id),
        )


def test_monitor_baselines_existing_rows_and_reports_new_pending_operation_without_leaks(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database_path = _create_audit_db(data_dir)
    _insert_operation(database_path, "old-operation")

    output = io.StringIO()
    sink = ActivitySink(data_dir, stdout=output)
    monitor = ActivityMonitor(data_dir, sink=sink)
    try:
        assert monitor.poll_once() == []

        request = {
            "normalized_command": {
                "display_command": [
                    "python",
                    "--password",
                    "hunter2",
                    "--token",
                    "sk-12345678901234567890",
                ]
            },
            "path": "secret/path.txt",
            "content": "DO NOT PRINT THIS FILE CONTENT",
            "stdout_preview": "DO NOT PRINT THIS STDOUT",
            "stderr_preview": "DO NOT PRINT THIS STDERR",
        }
        _insert_operation(
            database_path,
            "pending-operation",
            status="pending_approval",
            approval_status="pending",
            request=request,
        )
        lines = monitor.poll_once()
    finally:
        sink.close()

    assert len(lines) == 1
    line = lines[0]
    assert "NEW" in line
    assert "pending-operation" in line
    assert "status=pending_approval" in line
    assert "approval_status=pending" in line
    assert "route=sandbox" in line
    assert "PENDING_APPROVAL" in line
    assert "要承認" in line
    assert "python" in line
    assert "hunter2" not in line
    assert "sk-12345678901234567890" not in line
    assert "DO NOT PRINT" not in line
    assert "request_json" not in line
    assert "\n" not in line and "\r" not in line

    logged = (data_dir / "logs" / "localmcp-activity.log").read_text(encoding="utf-8")
    assert logged.strip() == output.getvalue().strip() == line
    assert "hunter2" not in logged
    assert "DO NOT PRINT" not in logged


def test_monitor_reports_status_and_approval_status_changes_once(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database_path = _create_audit_db(data_dir)
    _insert_operation(
        database_path,
        "changing-operation",
        status="pending_approval",
        approval_status="pending",
        request={"path": "src/main.py"},
    )

    output = io.StringIO()
    sink = ActivitySink(data_dir, stdout=output)
    monitor = ActivityMonitor(data_dir, sink=sink)
    try:
        existing = monitor.poll_once()
        assert len(existing) == 1
        assert "CURRENT" in existing[0]
        assert "PENDING_APPROVAL" in existing[0]

        _update_status(database_path, "changing-operation", status="running", approval="approved")
        first_change = monitor.poll_once()
        assert len(first_change) == 1
        assert "UPDATE" in first_change[0]
        assert "status=running" in first_change[0]
        assert "approval_status=approved" in first_change[0]

        _update_status(database_path, "changing-operation", status="succeeded", approval="approved")
        second_change = monitor.poll_once()
        assert len(second_change) == 1
        assert "status=succeeded" in second_change[0]
        assert monitor.poll_once() == []
    finally:
        sink.close()


def test_monitor_waits_for_database_and_then_baselines_rows(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    output = io.StringIO()
    sink = ActivitySink(data_dir, stdout=output)
    monitor = ActivityMonitor(data_dir, sink=sink)
    try:
        assert monitor.poll_once() == []
        database_path = _create_audit_db(data_dir)
        _insert_operation(database_path, "created-before-first-readable-poll")
        assert monitor.poll_once() == []
        _insert_operation(database_path, "created-after-baseline", request={"path": "new.txt"})
        lines = monitor.poll_once()
    finally:
        sink.close()

    assert len(lines) == 1
    assert "created-after-baseline" in lines[0]
    assert "created-before-first-readable-poll" not in output.getvalue()


def test_sink_uses_utf8_five_mib_rotation_with_ten_backups(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    log_path = data_dir / "logs" / "localmcp-activity.log"
    log_path.parent.mkdir(parents=True)
    # Seed an oversized existing log so the next small write exercises rollover without
    # emitting a multi-megabyte line to the test capture stream.
    log_path.write_bytes(b"x" * (LOG_MAX_BYTES + 1))
    output = io.StringIO()
    sink = ActivitySink(data_dir, stdout=output)
    try:
        assert sink._handler.maxBytes == LOG_MAX_BYTES
        assert sink._handler.backupCount == LOG_BACKUP_COUNT
        sink.write_line("rotation-check-日本語")
    finally:
        sink.close()

    assert (data_dir / "logs" / "localmcp-activity.log.1").is_file()
    assert "rotation-check-日本語" in log_path.read_text(encoding="utf-8")


def test_terminal_controls_are_removed_from_line_and_summary_is_bounded() -> None:
    controls = "line\x00\n\r\x1b[31m\u202eend"
    assert sanitize_display_text(controls) == "line[31mend"

    long_path = "a" * 500
    line = format_activity_line(
        {
            "id": "control-operation\x1b",
            "created_at": "2026-08-30T00:00:00+00:00",
            "status": "succeeded",
            "approval_status": None,
            "tool_name": "read_file\n",
            "request": {"path": long_path + "\r\n"},
        },
        event_kind="new",
    )
    assert all(ord(character) >= 0x20 and not (0x7F <= ord(character) <= 0x9F) for character in line)
    assert "control-operation" in line
    assert "\x1b" not in line
    summary = line.split("summary=", 1)[1]
    assert len(summary) <= 200
