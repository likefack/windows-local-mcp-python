"""詳細計測付きの監査接続でも既存の改変検出用 SQL 追跡が保たれる。"""

import sqlite3

from windows_local_mcp import control_plane_guard
from windows_local_mcp.audit_connection import TimedAuditConnection
from windows_local_mcp.performance_trace import operation_trace


def test_timed_connection_keeps_guarded_sqlite_callback(tmp_path, monkeypatch):
    path = tmp_path / "audit.db"

    class RecordingGuard:
        def __init__(self):
            self.statements = []

        def record_statement(self, statement):
            self.statements.append(statement)

    guard = RecordingGuard()
    identity = control_plane_guard._database_identity(path)
    monkeypatch.setitem(control_plane_guard._ACTIVE_AUDIT_GUARDS, identity, guard)
    connection = control_plane_guard._guarded_sqlite_connect(
        path, factory=TimedAuditConnection
    )
    try:
        connection.execute("CREATE TABLE operations(id TEXT)")
        with operation_trace() as trace, connection:
            connection.execute("INSERT INTO operations VALUES (?)", ("test-operation",))
        assert connection.execute("SELECT * FROM operations").fetchall() == [("test-operation",)]
        assert any(s.startswith("INSERT INTO operations") for s in guard.statements)
        assert "COMMIT" in guard.statements
        assert "audit_commit" in {p["name"] for p in trace.to_payload()["phases"]}
        assert isinstance(connection, sqlite3.Connection)
    finally:
        connection.close()
