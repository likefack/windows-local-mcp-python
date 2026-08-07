from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import Settings
from .resources import prune_artifacts
from .util import canonical_json, utc_now_iso

TERMINAL_STATUSES = {
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "rejected",
    "expired",
    "interrupted",
}


class AuditStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path = settings.data_dir / "audit.db"
        self._lock = threading.RLock()
        self._init_db()
        self._prune_database()
        prune_artifacts(settings, protected_ids=self._protected_operation_ids())

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
                    request_expires_at TEXT,
                    approval_expires_at TEXT,
                    claimed_at TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    worker_pid INTEGER,
                    worker_create_time REAL,
                    worker_executable TEXT,
                    child_pid INTEGER,
                    child_create_time REAL,
                    child_executable TEXT,
                    process_nonce TEXT,
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
            existing = {
                row["name"] for row in db.execute("PRAGMA table_info(operations)").fetchall()
            }
            migrations = {
                "request_expires_at": "TEXT",
                "approval_expires_at": "TEXT",
                "claimed_at": "TEXT",
                "worker_create_time": "REAL",
                "worker_executable": "TEXT",
                "child_create_time": "REAL",
                "child_executable": "TEXT",
                "process_nonce": "TEXT",
            }
            for name, sql_type in migrations.items():
                if name not in existing:
                    db.execute(f"ALTER TABLE operations ADD COLUMN {name} {sql_type}")

    def _prune_database(self) -> None:
        with self._lock, self._connect() as db:
            keep = self.settings.retention_max_operations
            stale_rows = db.execute(
                """
                SELECT id FROM operations
                WHERE status IN ('succeeded','failed','cancelled','timed_out','rejected','expired','interrupted')
                ORDER BY created_at DESC LIMIT -1 OFFSET ?
                """,
                (keep,),
            ).fetchall()
            stale = [row["id"] for row in stale_rows]
            if stale:
                placeholders = ",".join("?" for _ in stale)
                db.execute(f"DELETE FROM events WHERE operation_id IN ({placeholders})", stale)
                db.execute(f"DELETE FROM operations WHERE id IN ({placeholders})", stale)

    def _protected_operation_ids(self) -> set[str]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT id FROM operations
                WHERE status NOT IN ('succeeded','failed','cancelled','timed_out',
                                     'rejected','expired','interrupted')
                """
            ).fetchall()
        return {str(row["id"]) for row in rows}

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
        operation_id: str | None = None,
        request_expires_at: str | None = None,
    ) -> str:
        operation_id = operation_id or str(uuid.uuid4())
        now = utc_now_iso()
        request_json = canonical_json(request)
        if len(request_json.encode("utf-8")) > self.settings.max_audit_record_bytes:
            raise ValueError("audit request exceeds max_audit_record_bytes")
        with self._lock, self._connect() as db:
            db.execute(
                """
                INSERT INTO operations (
                    id, created_at, updated_at, session_id, tool_name, tier,
                    status, cwd, request_json, request_hash, approval_status,
                    request_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    request_json,
                    request_hash,
                    approval_status,
                    request_expires_at,
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
        result_json = fields.get("result_json")
        if isinstance(result_json, str) and len(result_json.encode("utf-8")) > self.settings.max_audit_record_bytes:
            raise ValueError("audit result exceeds max_audit_record_bytes")
        fields["updated_at"] = utc_now_iso()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [operation_id]
        with self._lock, self._connect() as db:
            cursor = db.execute(f"UPDATE operations SET {assignments} WHERE id = ?", values)
            if cursor.rowcount != 1:
                raise KeyError(f"operation not found: {operation_id}")

    def add_event(
        self,
        operation_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        payload_json = canonical_json(payload or {})
        if len(payload_json.encode("utf-8")) > self.settings.max_audit_record_bytes:
            payload_json = canonical_json({"truncated": True, "original_bytes": len(payload_json.encode("utf-8"))})
        with self._lock, self._connect() as db:
            db.execute(
                """
                INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (operation_id, utc_now_iso(), event_type, payload_json),
            )

    def get_operation(self, operation_id: str, *, include_events: bool = True) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM operations WHERE id = ?", (operation_id,)).fetchone()
            if row is None:
                raise KeyError(f"operation not found: {operation_id}")
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
                       approval_status, approval_by, approved_at, request_expires_at,
                       approval_expires_at, claimed_at, exit_code, duration_ms, error
                FROM operations {where}
                ORDER BY created_at DESC LIMIT ?
                """,
                values,
            ).fetchall()
        return [dict(row) for row in rows]

    def list_active_operations(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM operations
                WHERE status IN ('queued', 'running')
                ORDER BY created_at ASC
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["request"] = json.loads(item.pop("request_json"))
            result.append(item)
        return result

    def list_pending_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        self.expire_pending()
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM operations
                WHERE approval_status = 'pending' AND status = 'pending_approval'
                ORDER BY created_at ASC LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["request"] = json.loads(item.pop("request_json"))
            result.append(item)
        return result

    def expire_pending(self) -> int:
        now = utc_now_iso()
        with self._lock, self._connect() as db:
            rows = db.execute(
                """
                SELECT id FROM operations
                WHERE approval_status = 'pending' AND request_expires_at <= ?
                """,
                (now,),
            ).fetchall()
            ids = [row["id"] for row in rows]
            db.execute(
                """
                UPDATE operations SET approval_status='expired', status='expired',
                    updated_at=?, finished_at=?, error='approval request expired'
                WHERE approval_status='pending' AND request_expires_at <= ?
                """,
                (now, now, now),
            )
            for operation_id in ids:
                db.execute(
                    """INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                    VALUES (?, ?, 'expired', '{}')""",
                    (operation_id, now),
                )
        return len(ids)

    def decide_approval(
        self,
        operation_id: str,
        *,
        approved: bool,
        approver: str,
        note: str = "",
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        approval_expires = (now + timedelta(seconds=self.settings.approval_execution_ttl_seconds)).isoformat()
        new_approval = "approved" if approved else "rejected"
        new_status = "approved" if approved else "rejected"
        with self._lock, self._connect() as db:
            cursor = db.execute(
                """
                UPDATE operations SET approval_status=?, status=?, approval_by=?,
                    approval_note=?, approved_at=?, approval_expires_at=?, updated_at=?,
                    finished_at=CASE WHEN ?='rejected' THEN ? ELSE finished_at END
                WHERE id=? AND approval_status='pending' AND status='pending_approval'
                    AND request_expires_at > ?
                """,
                (
                    new_approval,
                    new_status,
                    approver,
                    note,
                    now_iso,
                    approval_expires if approved else None,
                    now_iso,
                    new_approval,
                    now_iso,
                    operation_id,
                    now_iso,
                ),
            )
            if cursor.rowcount != 1:
                self._expire_one_locked(db, operation_id, now_iso)
                db.commit()
                raise RuntimeError("approval is not pending or has expired")
            db.execute(
                """INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, ?, ?)""",
                (
                    operation_id,
                    now_iso,
                    new_approval,
                    canonical_json({"approver": approver, "note": note}),
                ),
            )
        return self.get_operation(operation_id)

    def approve_and_claim(
        self, operation_id: str, *, approver: str, note: str = ""
    ) -> dict[str, Any]:
        """Atomically approve a fresh request and consume its one execution grant."""
        now_value = datetime.now(UTC)
        now = now_value.isoformat()
        grant_expires = (
            now_value + timedelta(seconds=self.settings.approval_execution_ttl_seconds)
        ).isoformat()
        with self._lock, self._connect() as db:
            cursor = db.execute(
                """
                UPDATE operations SET approval_status='approved', status='queued',
                    approval_by=?, approval_note=?, approved_at=?, approval_expires_at=?,
                    claimed_at=?, updated_at=?
                WHERE id=? AND approval_status='pending' AND status='pending_approval'
                    AND request_expires_at > ?
                """,
                (approver, note, now, grant_expires, now, now, operation_id, now),
            )
            if cursor.rowcount != 1:
                self._expire_one_locked(db, operation_id, now)
                db.commit()
                raise RuntimeError("approval is not pending or has expired")
            db.execute(
                """INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, 'approved_and_claimed', ?)""",
                (operation_id, now, canonical_json({"approver": approver, "note": note})),
            )
        return self.get_operation(operation_id)

    def claim_approved(self, operation_id: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self._lock, self._connect() as db:
            cursor = db.execute(
                """
                UPDATE operations SET status='queued', claimed_at=?, updated_at=?
                WHERE id=? AND approval_status='approved' AND status='approved'
                    AND approval_expires_at > ? AND claimed_at IS NULL
                """,
                (now, now, operation_id, now),
            )
            if cursor.rowcount != 1:
                db.execute(
                    """
                    UPDATE operations SET approval_status='expired', status='expired',
                        finished_at=?, updated_at=?, error='approval execution grant expired'
                    WHERE id=? AND approval_status='approved' AND status='approved'
                        AND approval_expires_at <= ?
                    """,
                    (now, now, operation_id, now),
                )
                db.commit()
                raise RuntimeError("approval is expired, already claimed, or not approved")
            db.execute(
                """INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, 'execution_claimed', '{}')""",
                (operation_id, now),
            )
        return self.get_operation(operation_id)

    @staticmethod
    def _expire_one_locked(db: sqlite3.Connection, operation_id: str, now: str) -> None:
        db.execute(
            """
            UPDATE operations SET approval_status='expired', status='expired',
                finished_at=?, updated_at=?, error='approval request expired'
            WHERE id=? AND approval_status='pending' AND request_expires_at <= ?
            """,
            (now, now, operation_id, now),
        )
