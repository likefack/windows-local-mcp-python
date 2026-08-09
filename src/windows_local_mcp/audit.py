from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

from .config import Settings
from .redaction import redact_text, redact_value
from .resources import NamedControlPlaneLock, WorkspaceExecutionLock, prune_artifacts
from .util import canonical_json, utc_now_iso
from .workspace_history import (
    capture_workspace_state,
    finalize_workspace_transaction,
    incomplete_workspace_transactions,
    mark_workspace_transaction_audit_reconciled,
    mark_workspace_transaction_recovery_required,
    recover_incomplete_workspace_transaction,
    verify_checkpoint_integrity,
)

TERMINAL_STATUSES = {
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "rejected",
    "expired",
    "interrupted",
    "conflict",
}


def _serialized_audit_mutation(function: Any) -> Any:
    @wraps(function)
    def locked(store: AuditStore, *args: Any, **kwargs: Any) -> Any:
        with NamedControlPlaneLock(store.settings, "audit-state"):
            return function(store, *args, **kwargs)

    return locked


class AuditStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path = settings.data_dir / "audit.db"
        self._lock = threading.RLock()
        self._init_db()
        self._reconcile_workspace_transactions()
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
                    duration_ms INTEGER,
                    pre_workspace_path TEXT,
                    post_workspace_path TEXT,
                    rollback_state TEXT,
                    network_policy_json TEXT
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
                "pre_workspace_path": "TEXT",
                "post_workspace_path": "TEXT",
                "rollback_state": "TEXT",
                "network_policy_json": "TEXT",
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
                WHERE status IN ('succeeded','failed','cancelled','timed_out','rejected','expired','interrupted','conflict')
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
                                     'rejected','expired','interrupted','conflict')
                """
            ).fetchall()
        protected = {str(row["id"]) for row in rows}
        protected.update(
            str(journal.get("operation_id"))
            for journal in incomplete_workspace_transactions(self.settings)
            if journal.get("operation_id")
        )
        return protected

    def _reconcile_workspace_transactions(self) -> None:
        """Surface interrupted mutation journals instead of silently treating them as complete."""
        for journal in incomplete_workspace_transactions(self.settings):
            operation_id = str(journal.get("operation_id") or "")
            state = str(journal.get("state") or "unknown")
            if not operation_id:
                continue
            recovery_error: str | None = None
            reconciled_after_path: str | None = None
            if state in {
                "preflight",
                "staged",
                "applying",
                "recovering",
                "applied_verified",
                "complete",
            }:
                try:
                    with WorkspaceExecutionLock(self.settings):
                        journal = recover_incomplete_workspace_transaction(
                            self.settings, journal
                        )
                        if journal.get("state") in {"applied_verified", "complete"}:
                            after_path = (
                                self.settings.data_dir
                                / "workspace-history"
                                / "operations"
                                / operation_id
                                / "after"
                                / "manifest.json"
                            )
                            if after_path.exists():
                                verify_checkpoint_integrity(
                                    self.settings, str(after_path)
                                )
                                reconciled_after_path = str(after_path.resolve(strict=True))
                            else:
                                reconciled_after_path = capture_workspace_state(
                                    self.settings, operation_id, "after"
                                ).manifest_path
                    state = str(journal.get("state") or state)
                except Exception as error:  # noqa: BLE001 - persist and block mutations
                    recovery_error = f"{type(error).__name__}: {error}"[:2000]
                    if journal.get("journal_error"):
                        state = "recovery_required"
                    else:
                        mark_workspace_transaction_recovery_required(journal, error)
                        state = "recovery_required"
            recovery_state = (
                "failed_recovered"
                if state == "failed_recovered"
                else "recovery_required"
                if state == "recovery_required"
                else "interrupted"
            )
            now = utc_now_iso()
            with self._lock, self._connect() as db:
                row = db.execute(
                    "SELECT status, post_workspace_path FROM operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    if state in {"failed_preflight", "failed_recovered", "complete"}:
                        mark_workspace_transaction_audit_reconciled(
                            self.settings, operation_id
                        )
                    continue
                if (
                    row["status"] in TERMINAL_STATUSES
                    and state not in {"applied_verified", "complete"}
                    and state not in {
                    "failed_recovered",
                    "recovery_required",
                    "failed_preflight",
                    }
                ):
                    mark_workspace_transaction_audit_reconciled(
                        self.settings, operation_id
                    )
                    continue
                applied_but_unrecorded = state in {"applied_verified", "complete"}
                reconciled_status = "succeeded" if applied_but_unrecorded else "interrupted"
                reconciled_rollback = (
                    "complete"
                    if applied_but_unrecorded
                    else "failed_preflight"
                    if state == "failed_preflight"
                    else recovery_state
                )
                db.execute(
                    """
                    UPDATE operations SET status=?, rollback_state=?,
                        finished_at=?, updated_at=?, error=?,
                        pre_workspace_path=COALESCE(pre_workspace_path, ?),
                        post_workspace_path=CASE WHEN ? THEN ? ELSE post_workspace_path END
                    WHERE id=?
                    """,
                    (
                        reconciled_status,
                        reconciled_rollback,
                        now,
                        now,
                        recovery_error
                        if recovery_error
                        else None
                        if applied_but_unrecorded
                        else f"incomplete workspace mutation detected in state {state}",
                        journal.get("before_manifest"),
                        applied_but_unrecorded,
                        reconciled_after_path or journal.get("target_manifest"),
                        operation_id,
                    ),
                )
                db.execute(
                    """INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                    VALUES (?, ?, 'workspace_mutation_interrupted', ?)""",
                    (
                        operation_id,
                        now,
                        canonical_json(
                            {
                                "journal_path": journal.get("journal_path"),
                                "state": state,
                                "recovery_state": (
                                    reconciled_rollback
                                ),
                            }
                        ),
                    ),
                )
            # SQLite context above has committed before the journal is terminalized.
            if state == "applied_verified":
                finalize_workspace_transaction(self.settings, operation_id)
            else:
                mark_workspace_transaction_audit_reconciled(self.settings, operation_id)

    @_serialized_audit_mutation
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
        request_json = canonical_json(redact_value(request))
        if len(request_json.encode("utf-8")) > self.settings.max_audit_record_bytes:
            raise ValueError("audit request exceeds max_audit_record_bytes")
        self._ensure_audit_capacity(len(request_json.encode("utf-8")) + 8192)
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

    @_serialized_audit_mutation
    def update_operation(self, operation_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields = self._prepare_update_fields(fields)
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [operation_id]
        with self._lock, self._connect() as db:
            cursor = db.execute(f"UPDATE operations SET {assignments} WHERE id = ?", values)
            if cursor.rowcount != 1:
                raise KeyError(f"operation not found: {operation_id}")

    @_serialized_audit_mutation
    def transition_operation(
        self,
        operation_id: str,
        *,
        from_statuses: set[str],
        **fields: Any,
    ) -> bool:
        """Atomically move operation state without allowing terminal-state rollback."""
        if "status" not in fields:
            raise ValueError("transition_operation requires a target status")
        if not from_statuses:
            raise ValueError("transition_operation requires source statuses")
        fields = self._prepare_update_fields(fields)
        assignments = ", ".join(f"{key} = ?" for key in fields)
        placeholders = ", ".join("?" for _ in from_statuses)
        values = [*fields.values(), operation_id, *sorted(from_statuses)]
        with self._lock, self._connect() as db:
            cursor = db.execute(
                f"UPDATE operations SET {assignments} WHERE id = ? AND status IN ({placeholders})",
                values,
            )
            return cursor.rowcount == 1

    def _prepare_update_fields(self, fields: dict[str, Any]) -> dict[str, Any]:
        fields = dict(fields)
        if isinstance(fields.get("error"), str):
            fields["error"] = redact_text(str(fields["error"]))
        result_json = fields.get("result_json")
        if isinstance(result_json, str):
            try:
                fields["result_json"] = canonical_json(
                    redact_value(json.loads(result_json))
                )
                result_json = fields["result_json"]
            except ValueError:
                fields["result_json"] = redact_text(result_json)
                result_json = fields["result_json"]
        if (
            isinstance(result_json, str)
            and len(result_json.encode("utf-8")) > self.settings.max_audit_record_bytes
        ):
            raise ValueError("audit result exceeds max_audit_record_bytes")
        fields["updated_at"] = utc_now_iso()
        self._ensure_audit_capacity(
            sum(len(str(value).encode("utf-8", errors="replace")) for value in fields.values())
            + 4096
        )
        return fields

    @_serialized_audit_mutation
    def add_event(
        self,
        operation_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        payload_json = canonical_json(redact_value(payload or {}))
        if len(payload_json.encode("utf-8")) > self.settings.max_audit_record_bytes:
            payload_json = canonical_json(
                {"truncated": True, "original_bytes": len(payload_json.encode("utf-8"))}
            )
        self._ensure_audit_capacity(len(payload_json.encode("utf-8")) + 4096)
        with self._lock, self._connect() as db:
            db.execute(
                """
                INSERT INTO events(operation_id, occurred_at, event_type, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (operation_id, utc_now_iso(), event_type, payload_json),
            )

    def _ensure_audit_capacity(self, incoming_bytes: int) -> None:
        """Keep long-lived audit/WAL growth inside a reserved share of data_dir."""
        budget = max(
            256 * 1024,
            min(self.settings.max_data_dir_bytes // 4, 128 * 1024 * 1024),
        )
        with self._lock:
            if self._audit_storage_bytes() + incoming_bytes <= budget:
                return
            self._prune_database()
            for _ in range(20):
                if self._audit_storage_bytes() + incoming_bytes <= budget:
                    return
                with self._connect() as db:
                    rows = db.execute(
                        """
                        SELECT id FROM operations
                        WHERE status IN ('succeeded','failed','cancelled','timed_out',
                                         'rejected','expired','interrupted','conflict')
                        ORDER BY COALESCE(finished_at, updated_at), created_at
                        LIMIT 100
                        """
                    ).fetchall()
                    ids = [str(row["id"]) for row in rows]
                    if not ids:
                        break
                    placeholders = ",".join("?" for _ in ids)
                    db.execute(
                        f"DELETE FROM events WHERE operation_id IN ({placeholders})", ids
                    )
                    db.execute(f"DELETE FROM operations WHERE id IN ({placeholders})", ids)
                with self._connect() as db:
                    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    db.execute("VACUUM")
            if self._audit_storage_bytes() + incoming_bytes > budget:
                raise RuntimeError(
                    "audit storage budget is exhausted by active or pending operations"
                )

    def _audit_storage_bytes(self) -> int:
        return sum(
            path.stat().st_size if path.exists() else 0
            for path in (
                self.db_path,
                self.db_path.with_name(self.db_path.name + "-wal"),
                self.db_path.with_name(self.db_path.name + "-shm"),
            )
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
            if result.get("network_policy_json"):
                result["network_policy"] = json.loads(result["network_policy_json"])
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

    def latest_workspace_checkpoint(self) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT * FROM operations WHERE post_workspace_path IS NOT NULL
                   AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC, created_at DESC LIMIT 1"""
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["request"] = json.loads(item.pop("request_json"))
        return item

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

    @_serialized_audit_mutation
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

    @_serialized_audit_mutation
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
        approval_expires = (
            now + timedelta(seconds=self.settings.approval_execution_ttl_seconds)
        ).isoformat()
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

    @_serialized_audit_mutation
    def approve_and_claim(
        self,
        operation_id: str,
        *,
        approver: str,
        note: str = "",
        expected_request_hash: str | None = None,
    ) -> dict[str, Any]:
        """Atomically approve a fresh request and consume its one execution grant."""
        now_value = datetime.now(UTC)
        now = now_value.isoformat()
        grant_expires = (
            now_value + timedelta(seconds=self.settings.approval_execution_ttl_seconds)
        ).isoformat()
        with self._lock, self._connect() as db:
            hash_clause = " AND request_hash=?" if expected_request_hash is not None else ""
            parameters: list[object] = [
                approver,
                note,
                now,
                grant_expires,
                now,
                now,
                operation_id,
                now,
            ]
            if expected_request_hash is not None:
                parameters.append(expected_request_hash)
            cursor = db.execute(
                f"""
                UPDATE operations SET approval_status='approved', status='queued',
                    approval_by=?, approval_note=?, approved_at=?, approval_expires_at=?,
                    claimed_at=?, updated_at=?
                WHERE id=? AND approval_status='pending' AND status='pending_approval'
                    AND request_expires_at > ?{hash_clause}
                """,
                parameters,
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

    @_serialized_audit_mutation
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
