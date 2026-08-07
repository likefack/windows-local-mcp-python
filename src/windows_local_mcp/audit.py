from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from typing import Any

from .config import Settings
from .util import canonical_json, utc_now_iso


TERMINAL_STATUSES = {
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "rejected",
    "expired",
}


class AuditStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path = settings.data_dir / "audit.db"
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _init_db(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    session_id TEXT,
                    tool_name TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    cwd TEXT,
                    request_json TEXT NOT NULL,
                    request_hash TEXT,
                    approval_status TEXT,
                    approval_by TEXT,
                    approval_note TEXT,
                    approved_at TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    worker_pid INTEGER,
                    child_pid INTEGER,
                    exit_code INTEGER,
                    stdout_path TEXT,
                    stderr_path TEXT,
                    pre_git_path TEXT,
                    post_git_path TEXT,
                    diff_path TEXT,
                    backup_path TEXT,
                    result_json TEXT,
                    error TEXT,
                    duration_ms INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_operations_created
                    ON operations(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_operations_status
                    ON operations(status);
                CREATE INDEX IF NOT EXISTS idx_operations_approval
                    ON operations(approval_status, created_at);

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(id)
                );

                CREATE INDEX IF NOT EXISTS idx_events_operation
                    ON events(operation_id, id);
                """
            )

    def create_operation(
        self,
        *,
        tool_name: str,
        tier: str,
        status: str,
        cwd: str | None,
        request: dict[str, Any],
        request_hash: str | None = None,
        approval_status: str | None = None,
        session_id: str | None = None,
    ) -> str:
        operation_id = str(uuid.uuid4())
        now = utc_now_iso()
        with self._lock, self._connect() as db:
            db.execute(
                """
                INSERT INTO operations (
                    id, created_at, updated_at, session_id, tool_name, tier,
                    status, cwd, request_json, request_hash, approval_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    now,
                    now,
                    session_id,
                    tool_name,
                    tier,
                    status,
                    cwd,
                    canonical_json(request),
                    request_hash,
                    approval_status,
                ),
            )
            db.execute(
                """
                INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (operation_id, now, "created", canonical_json({"status": status})),
            )
        return operation_id

    def update_operation(self, operation_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now_iso()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [operation_id]
        with self._lock, self._connect() as db:
            cursor = db.execute(
                f"UPDATE operations SET {assignments} WHERE id = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise KeyError(f"操作が見つかりません: {operation_id}")

    def add_event(
        self,
        operation_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """
                INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    operation_id,
                    utc_now_iso(),
                    event_type,
                    canonical_json(payload or {}),
                ),
            )

    def get_operation(self, operation_id: str, *, include_events: bool = True) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM operations WHERE id = ?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"操作が見つかりません: {operation_id}")
            result = dict(row)
            result["request"] = json.loads(result.pop("request_json"))
            if result.get("result_json"):
                result["result"] = json.loads(result["result_json"])
            if include_events:
                event_rows = db.execute(
                    """
                    SELECT id, occurred_at, event_type, payload_json
                    FROM events WHERE operation_id = ? ORDER BY id
                    """,
                    (operation_id,),
                ).fetchall()
                result["events"] = [
                    {
                        "id": event["id"],
                        "occurred_at": event["occurred_at"],
                        "event_type": event["event_type"],
                        "payload": json.loads(event["payload_json"]),
                    }
                    for event in event_rows
                ]
            return result

    def list_operations(
        self,
        *,
        limit: int = 50,
        status: str | None = None,
        approval_status: str | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        clauses: list[str] = []
        values: list[Any] = []
        if status:
            clauses.append("status = ?")
            values.append(status)
        if approval_status:
            clauses.append("approval_status = ?")
            values.append(approval_status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self._connect() as db:
            rows = db.execute(
                f"""
                SELECT id, created_at, updated_at, tool_name, tier, status, cwd,
                       approval_status, approval_by, approved_at, exit_code,
                       duration_ms, error
                FROM operations
                {where}
                ORDER BY created_at DESC
                LIMIT ?
                """,
                values,
            ).fetchall()
        return [dict(row) for row in rows]

    def list_pending_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM operations
                WHERE approval_status = 'pending'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["request"] = json.loads(item.pop("request_json"))
            result.append(item)
        return result

    def decide_approval(
        self,
        operation_id: str,
        *,
        approved: bool,
        approver: str,
        note: str = "",
    ) -> dict[str, Any]:
        now = utc_now_iso()
        new_approval = "approved" if approved else "rejected"
        new_status = "approved" if approved else "rejected"
        with self._lock, self._connect() as db:
            cursor = db.execute(
                """
                UPDATE operations
                SET approval_status = ?, status = ?, approval_by = ?,
                    approval_note = ?, approved_at = ?, updated_at = ?
                WHERE id = ? AND approval_status = 'pending'
                """,
                (
                    new_approval,
                    new_status,
                    approver,
                    note,
                    now,
                    now,
                    operation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("承認待ちではないか、すでに別の決定が行われています")
            db.execute(
                """
                INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    operation_id,
                    now,
                    new_approval,
                    canonical_json({"approver": approver, "note": note}),
                ),
            )
        return self.get_operation(operation_id)

    def claim_approved(self, operation_id: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self._lock, self._connect() as db:
            cursor = db.execute(
                """
                UPDATE operations
                SET status = 'queued', updated_at = ?
                WHERE id = ? AND approval_status = 'approved' AND status = 'approved'
                """,
                (now, operation_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("未承認、拒否済み、期限切れ、またはすでに実行済みです")
            db.execute(
                """
                INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, 'execution_claimed', '{}')
                """,
                (operation_id, now),
            )
        return self.get_operation(operation_id)
