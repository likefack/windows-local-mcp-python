"""監査の時間記録が DB の成功・失敗と人間向け表示を変えないことを確認する。"""

import base64
import sqlite3

import pytest
from test_server_operations import load_server

from windows_local_mcp.audit_connection import TimedAuditConnection
from windows_local_mcp.performance_trace import operation_trace, phase
from windows_local_mcp.util import sha256_bytes


def test_sqlite_commit_rollback_and_trace_callback_are_preserved():
    db = sqlite3.connect(":memory:", factory=TimedAuditConnection)
    statements = []
    db.set_trace_callback(statements.append)
    try:
        db.execute("CREATE TABLE example(value TEXT)")
        with operation_trace() as trace:
            with db:
                db.execute("INSERT INTO example VALUES (?)", ("private-content",))
            with pytest.raises(RuntimeError), db:
                db.execute("INSERT INTO example VALUES (?)", ("must-rollback",))
                raise RuntimeError("original-error")
        timing = trace.to_payload()
        names = {item["name"] for item in timing["phases"]}
        assert {"audit_sql_execute", "audit_commit", "audit_rollback"} <= names
        assert db.execute("SELECT value FROM example").fetchall() == [("private-content",)]
        assert "COMMIT" in statements and "ROLLBACK" in statements
        assert "private-content" not in str(timing)
        assert "original-error" not in str(timing)
    finally:
        db.close()


def test_sqlite_deferred_commit_failure_still_rolls_back():
    db = sqlite3.connect(":memory:", factory=TimedAuditConnection)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
        db.execute(
            "CREATE TABLE child(id INTEGER REFERENCES parent(id) "
            "DEFERRABLE INITIALLY DEFERRED)"
        )
        with operation_trace() as trace, pytest.raises(sqlite3.IntegrityError), db:
            db.execute("INSERT INTO child VALUES (1)")
        assert db.execute("SELECT * FROM child").fetchall() == []
        assert not db.in_transaction
        commit = next(p for p in trace.to_payload()["phases"] if p["name"] == "audit_commit")
        assert commit["status"] == "failed"
    finally:
        db.close()


def test_explicit_commit_and_rollback_are_measured_once():
    db = sqlite3.connect(":memory:", factory=TimedAuditConnection)
    try:
        db.execute("CREATE TABLE example(value INTEGER)")
        with operation_trace() as trace, db:
            db.execute("INSERT INTO example VALUES (1)")
            db.commit()
            db.execute("INSERT INTO example VALUES (2)")
            db.rollback()
        phases = trace.to_payload()["phases"]
        assert sum(p["name"] == "audit_commit" for p in phases) == 1
        assert sum(p["name"] == "audit_rollback" for p in phases) == 1
        assert db.execute("SELECT * FROM example").fetchall() == [(1,)]
    finally:
        db.close()


def test_broker_storage_details_and_live_activity_are_separate(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"before")
    result = server.write_file("a.txt", "after", expected_sha256=sha256_bytes(b"before"))
    saved = server.runtime.audit.get_operation(result["operation_id"])
    timing = saved["timings"]
    assert timing["schema_version"] == 2
    names = {item["name"] for item in timing["phase_summary"]}
    assert {
        "workspace_lock_wait", "control_plane_lock_wait", "audit_lock_wait",
        "audit_connect", "audit_sql_execute", "audit_commit", "audit_capacity_check",
        "control_plane_health_check", "backup_write", "checkpoint_hash",
        "checkpoint_blob_store", "checkpoint_manifest_write",
    } <= names
    # Detailed diagnostics never become lifecycle events or Timeline fields.
    assert not any("phase" in e["event_type"] for e in saved["events"])
    assert "phase_summary" not in str(server.activity_timeline())
    assert (root / "a.txt").read_bytes() == b"after"


def test_one_shot_artifact_trace_includes_encoding_and_validation(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    payload = b"audit timing binary\x00"
    result = server.artifact_upload(
        "a.bin", base64.b64encode(payload).decode("ascii"), sha256_bytes(payload)
    )
    timing = server.runtime.audit.get_operation(result["operation_id"])["timings"]
    assert "artifact_decoding" in {p["name"] for p in timing["phase_summary"]}
    result = server.artifact_download("a.bin")
    timing = server.runtime.audit.get_operation(result["operation_id"])["timings"]
    assert "artifact_encoding" in {p["name"] for p in timing["phase_summary"]}
    assert (root / "a.bin").read_bytes() == payload


def test_trace_summary_survives_many_small_phases():
    with operation_trace() as trace, phase("operation_body"):
        for _ in range(400):
            with phase("source_hash"):
                pass
        with phase("audit_commit"):
            pass
    timing = trace.to_payload()
    summary = {p["name"]: p for p in timing["phase_summary"]}
    assert summary["source_hash"]["count"] == 400
    assert summary["audit_commit"]["count"] == 1
    assert timing["dropped_phase_count"] > 0
