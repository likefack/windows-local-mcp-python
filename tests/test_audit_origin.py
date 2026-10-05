from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import windows_local_mcp.audit as audit_module
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.request_origin import (
    RequestOrigin,
    current_origin,
    origin_fields,
    use_origin,
)

ORIGIN_COLUMNS = (
    "session_id", "server_instance_id", "origin_scope", "client_name",
    "client_version", "request_id", "task_id",
)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root, data_dir=tmp_path / "data", protect_data_dir_acl=False
    )
    settings.ensure_directories()
    return settings


def origin(session: str, task: str | None = "task-one") -> RequestOrigin:
    return RequestOrigin(session, "server-one", "connection", "test-client", "1.0", "req", task)


def create(store: AuditStore, **kwargs: object) -> str:
    return store.create_operation(
        tool_name="test", tier="broker", status=str(kwargs.pop("status", "succeeded")),
        cwd=None, request={}, **kwargs,
    )


def test_operation_and_each_event_keep_their_own_origin(settings: Settings) -> None:
    store = AuditStore(settings)
    first, second = origin("session-one"), origin("session-two", "task-two")
    with use_origin(first):
        operation_id = create(store, status="running")
    with use_origin(second):
        store.update_operation(operation_id, status="succeeded")
        store.add_event(operation_id, "polled", {"value": 1})
        assert store.add_event_if_operation_exists(operation_id, "retried")
        assert not store.add_event_if_operation_exists("missing-operation", "retried")
    saved = store.get_operation(operation_id)
    assert {key: saved[key] for key in ORIGIN_COLUMNS} == origin_fields(first)
    assert [event["origin"] for event in saved["events"]] == [
        origin_fields(first), origin_fields(second), origin_fields(second),
    ]
    assert saved["events"][1]["payload"] == {"value": 1}
    assert "events" not in store.get_operation(operation_id, include_events=False)


def test_process_origin_and_explicit_session_compatibility(settings: Settings) -> None:
    store = AuditStore(settings)
    operation_id = create(store)
    process_origin = origin_fields(current_origin())
    saved = store.get_operation(operation_id)
    assert saved["session_id"]
    assert saved["origin_scope"] == "process"
    assert saved["events"][0]["origin"] == process_origin
    with use_origin(origin("connection")):
        explicit_id = create(store, session_id="explicit-session")
    explicit = store.get_operation(explicit_id)
    assert explicit["session_id"] == "explicit-session"
    assert explicit["events"][0]["origin"]["session_id"] == "explicit-session"


@pytest.mark.parametrize("legacy_session", [None, "legacy-session"])
def test_legacy_migration_preserves_unknown_origins(
    settings: Settings, legacy_session: str | None,
) -> None:
    store = AuditStore(settings)
    operation_id = create(store)
    # 旧DBと同じnullable schemaを再現し、当時存在しなかった情報を補完しないことを確認する。
    with sqlite3.connect(store.db_path) as db:
        db.execute("DROP INDEX idx_operations_session_created")
        db.execute("DROP INDEX idx_operations_task_created")
        for column in (*ORIGIN_COLUMNS[1:], "execution_owner_json"):
            db.execute(f"ALTER TABLE operations DROP COLUMN {column}")
        db.execute("ALTER TABLE events DROP COLUMN origin_json")
        db.execute("UPDATE operations SET session_id=? WHERE id=?", (legacy_session, operation_id))
    upgraded = AuditStore(settings)
    saved = upgraded.get_operation(operation_id)
    assert saved["session_id"] == legacy_session
    assert all(saved[column] is None for column in ORIGIN_COLUMNS[1:])
    assert saved["execution_owner_json"] is None
    assert saved["events"][0]["origin"] is None
    assert upgraded.list_operations()[0]["session_id"] == legacy_session
    assert AuditStore(settings).get_operation(operation_id) == saved


def test_two_stores_initialize_and_create_concurrently(settings: Settings) -> None:
    barrier = threading.Barrier(2)

    def populate(label: str) -> list[str]:
        barrier.wait(timeout=5)
        store = AuditStore(settings)
        with use_origin(origin(label, f"task-{label}")):
            return [create(store) for _ in range(6)]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(populate, label) for label in ("one", "two")]
        ids = [future.result(timeout=20) for future in futures]
    store = AuditStore(settings)
    assert len(store.list_operations()) == 12
    for label, operation_ids in zip(("one", "two"), ids, strict=True):
        rows = store.list_operations(session_id=label, task_id=f"task-{label}")
        assert {row["id"] for row in rows} == set(operation_ids)
        for row in rows:
            assert {key: row[key] for key in ORIGIN_COLUMNS} == origin_fields(
                origin(label, f"task-{label}")
            )


def test_two_processes_migrate_and_write_one_legacy_database(settings: Settings) -> None:
    store = AuditStore(settings)
    with sqlite3.connect(store.db_path) as db:
        db.execute("DROP INDEX idx_operations_session_created")
        db.execute("DROP INDEX idx_operations_task_created")
        for column in (*ORIGIN_COLUMNS[1:], "execution_owner_json"):
            db.execute(f"ALTER TABLE operations DROP COLUMN {column}")
        db.execute("ALTER TABLE events DROP COLUMN origin_json")
    # 独立したPythonプロセスで起動し、スレッド用ロックだけでは通らない移行を確認する。
    script = """
import json, sys
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.request_origin import current_origin, use_origin
settings = Settings(workspace_root=Path(sys.argv[2]), data_dir=Path(sys.argv[3]),
                    protect_data_dir_acl=False)
store = AuditStore(settings)
with use_origin(replace(current_origin(), task_id=sys.argv[4])):
    ids = [store.create_operation(tool_name="test", tier="broker", status="succeeded",
                                  cwd=None, request={}) for _ in range(3)]
print(json.dumps(ids))
"""
    source = str(Path(audit_module.__file__).resolve().parents[1])
    processes = []
    try:
        for label in ("one", "two"):
            processes.append(subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", script, source,
                 str(settings.workspace_root), str(settings.data_dir), label],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                encoding="utf-8", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ))
        process_ids = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr
            process_ids.append(json.loads(stdout))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    store = AuditStore(settings)
    rows = store.list_operations()
    assert {row["id"] for row in rows} == {item for ids in process_ids for item in ids}
    assert len({row["server_instance_id"] for row in rows}) == 2
    assert {row["task_id"] for row in rows} == {"one", "two"}
    assert all(row["origin_scope"] == "process" for row in rows)


def test_origin_filters_are_exact_and_applied_before_limit(settings: Settings) -> None:
    store = AuditStore(settings)
    entries = [
        ("one", "wanted", "failed"), ("one", "wanted", "succeeded"),
        ("one", "wanted-extra", "succeeded"), ("two", "wanted", "succeeded"),
        ("one", "other", "succeeded"),
    ]
    ids = []
    for index, (session, task, status) in enumerate(entries):
        with use_origin(origin(session, task)):
            operation_id = create(store, status=status)
        # 時計の解像度に依存せず、対象より新しい無関係な行が先に並ぶようにする。
        with sqlite3.connect(store.db_path) as db:
            db.execute(
                "UPDATE operations SET created_at=? WHERE id=?",
                (f"2026-01-01T00:00:0{index}+00:00", operation_id),
            )
        ids.append(operation_id)
    rows = store.list_operations(limit=1, session_id="one", task_id="wanted", status="succeeded")
    assert [row["id"] for row in rows] == [ids[1]]
    assert [row["id"] for row in store.list_operations(limit=2, task_id="wanted")] == [ids[3], ids[1]]
    assert store.list_operations(session_id="") == []
    assert store.list_operations(task_id="") == []
    assert store.list_operations(task_id="wanted' OR 1=1 --") == []


@pytest.mark.parametrize("field", [*ORIGIN_COLUMNS, "SESSION_ID", '"session_id"'])
@pytest.mark.parametrize("method", ["update", "transition"])
def test_origin_cannot_be_changed(settings: Settings, field: str, method: str) -> None:
    store = AuditStore(settings)
    with use_origin(origin("original")):
        operation_id = create(store, status="running")
    before = store.get_operation(operation_id)
    with pytest.raises(ValueError):
        if method == "update":
            store.update_operation(operation_id, **{field: "changed", "status": "failed"})
        else:
            store.transition_operation(
                operation_id, from_statuses={"running"}, **{field: "changed", "status": "failed"},
            )
    assert store.get_operation(operation_id) == before


def test_origin_redaction_and_capacity_are_enforced(settings: Settings, monkeypatch) -> None:
    store = AuditStore(settings)
    with use_origin(replace(origin("one"), client_name="api_key=private-value")):
        operation_id = create(store)
        store.add_event(operation_id, "checked")
    saved = store.get_operation(operation_id)
    assert saved["client_name"] == "api_key=<redacted>"
    assert all(event["origin"]["client_name"] == saved["client_name"] for event in saved["events"])
    with pytest.raises(ValueError, match="audit origin exceeds"):
        create(store, session_id="x" * (settings.max_audit_record_bytes + 1))
    assert len(store.list_operations()) == 1

    def no_capacity(_incoming: int) -> None:
        raise RuntimeError("audit storage budget is exhausted")

    monkeypatch.setattr(store, "_ensure_audit_capacity", no_capacity)
    with pytest.raises(RuntimeError, match="storage budget"):
        store.add_event(operation_id, "must-not-write")
    assert len(store.get_operation(operation_id)["events"]) == 2


def test_execution_owner_is_internal_and_survives_updates(settings: Settings) -> None:
    store = AuditStore(settings)
    with use_origin(origin("creator")):
        operation_id = create(store, status="queued")
    before = store.get_operation(operation_id)
    owner = json.loads(before["execution_owner_json"])
    assert owner["pid"] == os.getpid()
    with use_origin(origin("worker")):
        assert store.transition_operation(operation_id, from_statuses={"queued"}, status="running")
        store.update_operation(operation_id, status="succeeded")
    saved = store.get_operation(operation_id)
    assert saved["execution_owner_json"] == before["execution_owner_json"]
    assert saved["session_id"] == "creator"
    assert "execution_owner_json" not in saved["events"][0]["origin"]


def test_concurrent_queued_admission_reserves_one_slot(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_concurrent_jobs": 1})
    stores = [AuditStore(settings), AuditStore(settings)]
    barrier = threading.Barrier(2)

    def admit(store: AuditStore) -> str:
        barrier.wait(timeout=5)
        try:
            return create(store, status="queued")
        except RuntimeError as error:
            assert str(error) == "concurrent job admission limit exceeded"
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(admit, store) for store in stores]
        results = [future.result(timeout=10) for future in futures]
    assert results.count("rejected") == 1
    assert len(stores[0].list_operations()) == 1
    # 同期処理のrunning作成まで新たなジョブ上限で拒否しない。
    create(stores[0], status="running")


@pytest.mark.parametrize("method", ["approve_and_claim", "claim_approved"])
def test_claim_capacity_failure_preserves_approval_and_origin(settings: Settings, method: str) -> None:
    settings = settings.model_copy(update={"max_concurrent_jobs": 1})
    store = AuditStore(settings)
    expires = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
    with use_origin(origin("requester")):
        operation_id = create(
            store, status="pending_approval", approval_status="pending", request_expires_at=expires,
        )
    if method == "claim_approved":
        store.decide_approval(operation_id, approved=True, approver="local-user")
    busy = create(store, status="queued")
    before = store.get_operation(operation_id)
    with pytest.raises(RuntimeError, match="concurrent job admission"):
        if method == "approve_and_claim":
            store.approve_and_claim(operation_id, approver="local-user")
        else:
            store.claim_approved(operation_id)
    assert store.get_operation(operation_id) == before
    store.update_operation(busy, status="succeeded")
    with use_origin(origin("approval-ui")):
        claimed = (
            store.approve_and_claim(operation_id, approver="local-user")
            if method == "approve_and_claim" else store.claim_approved(operation_id)
        )
    assert claimed["status"] == "queued"
    assert claimed["session_id"] == "requester"
    assert json.loads(claimed["execution_owner_json"])["pid"] == os.getpid()


def test_reconciliation_skips_busy_workspace_without_rewriting_journal(settings: Settings, monkeypatch) -> None:
    store = AuditStore(settings)
    operation_id = create(store, status="running")
    transaction = settings.data_dir / "workspace-history" / "transactions" / operation_id
    transaction.mkdir(parents=True)
    journal = transaction / "journal.json"
    journal.write_text(json.dumps({"operation_id": operation_id, "state": "applying"}), encoding="utf-8")
    before = journal.read_text(encoding="utf-8")
    before_operation = store.get_operation(operation_id)

    class BusyLock:
        def __init__(self, _settings):
            pass

        def __enter__(self):
            raise TimeoutError("workspace execution lock timed out")

        def __exit__(self, *_args):
            raise AssertionError("unacquired lock must not exit")

    monkeypatch.setattr(audit_module, "WorkspaceExecutionLock", BusyLock)
    store._reconcile_workspace_transactions()
    assert journal.read_text(encoding="utf-8") == before
    assert store.get_operation(operation_id) == before_operation


def test_reconciliation_rechecks_journals_after_lock_acquisition(settings: Settings, monkeypatch) -> None:
    store = AuditStore(settings)
    operation_id = create(store, status="succeeded")
    transaction = settings.data_dir / "workspace-history" / "transactions" / operation_id
    transaction.mkdir(parents=True)
    journal = transaction / "journal.json"
    journal.write_text(json.dumps({"operation_id": operation_id, "state": "applying"}), encoding="utf-8")
    before_operation = store.get_operation(operation_id)

    class CompletedWhileWaiting:
        def __init__(self, _settings):
            pass

        def __enter__(self):
            # 先行プロセスがロックを解放するまでの間にjournalを確定した状況を再現する。
            journal.write_text(json.dumps({
                "operation_id": operation_id, "state": "complete", "audit_reconciled": True,
            }), encoding="utf-8")
            return self

        def __exit__(self, *_args):
            return False

    def unexpected_recovery(*_args):
        raise AssertionError("a finalized journal must not be recovered from a stale snapshot")

    monkeypatch.setattr(audit_module, "WorkspaceExecutionLock", CompletedWhileWaiting)
    monkeypatch.setattr(audit_module, "recover_incomplete_workspace_transaction", unexpected_recovery)
    store._reconcile_workspace_transactions()
    assert json.loads(journal.read_text(encoding="utf-8"))["state"] == "complete"
    assert store.get_operation(operation_id) == before_operation


def test_timeout_during_recovery_still_records_recovery_required(settings: Settings, monkeypatch) -> None:
    store = AuditStore(settings)
    operation_id = create(store, status="running")
    transaction = settings.data_dir / "workspace-history" / "transactions" / operation_id
    transaction.mkdir(parents=True)
    journal = transaction / "journal.json"
    journal.write_text(json.dumps({"operation_id": operation_id, "state": "applying"}), encoding="utf-8")

    def recovery_timeout(*_args):
        raise TimeoutError("recovery itself failed")

    monkeypatch.setattr(audit_module, "recover_incomplete_workspace_transaction", recovery_timeout)
    store._reconcile_workspace_transactions()
    assert json.loads(journal.read_text(encoding="utf-8"))["state"] == "recovery_required"
    assert store.get_operation(operation_id)["rollback_state"] == "recovery_required"
