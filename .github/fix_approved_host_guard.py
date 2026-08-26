from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    "from .runtime_trust import capture_runtime_dependency_state\n",
    "",
)

replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''    runtime_state = (
        capture_runtime_dependency_state(
            max_files=settings.approval_manifest_max_files,
            max_bytes=settings.approval_manifest_max_bytes,
        )
        if os.name == "nt"
        else None
    )
    runtime_startup_state = _capture_runtime_startup_state() if os.name == "nt" else None
    audit_snapshot, audit_bytes = _audit_state_snapshot(settings)
    acl_digest, acl_bytes = _acl_state_digest(settings, roots)
    runtime_bytes = int(runtime_state["bytes"]) if runtime_state is not None else 0
    runtime_digest = str(runtime_state["digest"]) if runtime_state is not None else None
''',
    '''    # Approved Host runtime content is admitted by the execution-time immutable-runtime
    # gate before this worker is launched. Re-hashing that complete dependency closure here
    # would duplicate the gate and can consume the command runtime budget before child start.
    # This guard therefore protects mutable control-plane state and Python startup state.
    runtime_startup_state = _capture_runtime_startup_state() if os.name == "nt" else None
    audit_snapshot, audit_bytes = _audit_state_snapshot(settings)
    acl_digest, acl_bytes = _acl_state_digest(settings, roots)
    runtime_bytes = 0
    runtime_digest = None
''',
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''    runtime_file_count = (
        int(runtime_state["file_count"]) if runtime_state is not None else 0
    )
''',
    '''    runtime_file_count = 0
''',
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''            expected_state=state,
''',
    '''            expected_state=dict(state),
''',
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _deactivate_audit_guard(database_identity: str) -> None:
''',
    '''def expected_critical_state(settings: Settings, operation_id: str) -> dict[str, Any]:
    """Return the trusted-worker mirror state without mutating the original preflight snapshot."""
    database_identity = _database_identity(settings.data_dir / "audit.db")
    with _AUDIT_GUARDS_LOCK:
        guard = _ACTIVE_AUDIT_GUARDS.get(database_identity)
        if guard is None:
            raise RuntimeError("Approved Host audit guard is not active")
        if guard.operation_id != operation_id:
            raise RuntimeError("Approved Host audit guard is bound to another operation")
        if guard.tracking_error is not None:
            raise RuntimeError(
                "trusted audit mutation tracking failed during Approved Host execution: "
                f"{guard.tracking_error}"
            )
        return dict(guard.expected_state)


def _deactivate_audit_guard(database_identity: str) -> None:
''',
)

replace_once(
    "src/windows_local_mcp/process_utils.py",
    '''        create_time=process.create_time(),
''',
    '''        # sqlite3 trace callbacks stringify bound REAL values to about 15 significant
        # digits. Persist 10-microsecond precision so trusted audit replay is bit-stable;
        # process verification already uses a 10-millisecond tolerance plus PID/exe/nonce.
        create_time=round(float(process.create_time()), 5),
''',
)

replace_once(
    "src/windows_local_mcp/worker.py",
    '''from .control_plane_guard import (
    capture_critical_state,
    mark_control_plane_tamper,
)
''',
    '''from .control_plane_guard import (
    capture_critical_state,
    expected_critical_state,
    mark_control_plane_tamper,
)
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''    max_runtime = int(request["max_runtime_seconds"])
    deadline = operation_started + max_runtime
''',
    '''    max_runtime = int(request["max_runtime_seconds"])
    deadline: float | None = None
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''        if time.monotonic() >= deadline:
            raise OperationDeadlineExceeded(
                f"operation deadline exceeded before child start: {max_runtime} seconds"
            )
        if operation["tier"] == "codex_sandbox":
''',
    '''        # max_runtime_seconds is the admitted child/finalization budget. Trusted
        # preflight work happens before this point and must not consume that command budget.
        deadline = time.monotonic() + max_runtime
        if operation["tier"] == "codex_sandbox":
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''                untracked_processes = wait_for_untracked_current_user_processes(
                    host_user_process_baseline,
                    deadline=deadline,
                    excluded_pids={os.getpid()},
                )
''',
    '''                if deadline is None:
                    raise RuntimeError("Approved Host execution deadline was not initialized")
                untracked_processes = wait_for_untracked_current_user_processes(
                    host_user_process_baseline,
                    deadline=deadline,
                    excluded_pids={os.getpid()},
                )
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''            if int(fresh_operation.get("worker_pid") or 0) != os.getpid():
                raise RuntimeError("Approved Host changed the worker process binding")
''',
    '''            if (
                int(fresh_operation.get("worker_pid") or 0) != worker_identity.pid
                or float(fresh_operation.get("worker_create_time") or 0)
                != worker_identity.create_time
                or str(fresh_operation.get("worker_executable") or "")
                != worker_identity.executable
            ):
                raise RuntimeError("Approved Host changed the worker process binding")
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''            host_control_after = capture_critical_state(settings, operation_id)
            if host_control_after != host_control_state:
                marker = mark_control_plane_tamper(
                    settings, operation_id, host_control_state, host_control_after
                )
''',
    '''            host_control_expected = expected_critical_state(settings, operation_id)
            host_control_after = capture_critical_state(settings, operation_id)
            if host_control_after != host_control_expected:
                marker = mark_control_plane_tamper(
                    settings, operation_id, host_control_expected, host_control_after
                )
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''                    {"before": host_control_state, "after": host_control_after},
''',
    '''                    {"before": host_control_expected, "after": host_control_after},
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''            marker = mark_control_plane_tamper(
                settings,
                operation_id,
                host_control_state,
                {"capture_error": f"{type(guard_error).__name__}: {guard_error}"},
            )
''',
    '''            marker = mark_control_plane_tamper(
                settings,
                operation_id,
                host_control_state,
                {"capture_error": f"{type(guard_error).__name__}: {guard_error}"},
            )
''',
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''    if time.monotonic() > deadline and status == "succeeded":
''',
    '''    if deadline is not None and time.monotonic() > deadline and status == "succeeded":
''',
)

replace_once(
    "tests/test_broker_architecture.py",
    '''from windows_local_mcp.control_plane_guard import capture_critical_state
''',
    '''from windows_local_mcp.control_plane_guard import (
    capture_critical_state,
    expected_critical_state,
)
''',
)
replace_once(
    "tests/test_broker_architecture.py",
    '''    audit.update_operation(operation, request_hash="b" * 64)

    assert capture_critical_state(settings, operation) != before
''',
    '''    audit.update_operation(operation, request_hash="b" * 64)

    expected = expected_critical_state(settings, operation)
    assert before != expected
    assert capture_critical_state(settings, operation) == expected
''',
)
