import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
from windows_local_mcp.process_utils import (
    ProcessIdentity,
    process_identity_matches,
    terminate_process_tree,
    wait_for_untracked_current_user_processes,
)
from windows_local_mcp.resources import (
    BoundedStreamCapture,
    WorkspaceExecutionLock,
    enforce_data_quota,
    scan_directory_bounded,
)


def make_settings(tmp_path: Path) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def test_actual_large_child_output_is_bounded(tmp_path: Path) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdout.write('A' * 1000000)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    assert process.stdout is not None
    destination = tmp_path / "bounded.log"
    capture = BoundedStreamCapture(process.stdout, destination, 8192)
    capture.start()
    assert process.wait(timeout=30) == 0
    capture.join()
    assert capture.total_bytes == 1_000_000
    assert capture.truncated
    assert destination.stat().st_size < 9000
    assert "truncated" in capture.preview(2000)


def test_pid_reuse_identity_mismatch_never_terminates_current_process() -> None:
    fake = ProcessIdentity(
        pid=os.getpid(),
        create_time=0.0,
        executable="C:\\not-the-current-process.exe",
        nonce="wrong",
    )
    assert terminate_process_tree(fake) is False


def test_process_identity_matches_stable_worker_not_redirector_bootstrap(
    monkeypatch,
) -> None:
    stable_executable = os.path.normcase(str(Path(sys.executable).resolve()))

    class FakeProcess:
        def create_time(self) -> float:
            return 20.0

        def exe(self) -> str:
            return sys.executable

        def environ(self) -> dict[str, str]:
            return {"WINDOWS_LOCAL_MCP_JOB_NONCE": "nonce"}

    monkeypatch.setattr("windows_local_mcp.process_utils.psutil.Process", lambda _pid: FakeProcess())
    stable = ProcessIdentity(4321, 20.0, stable_executable, "nonce")
    redirector = ProcessIdentity(4321, 10.0, r"C:\runtime\Scripts\python.exe", "nonce")

    assert process_identity_matches(stable)
    assert not process_identity_matches(redirector)
    assert not process_identity_matches(ProcessIdentity(4321, 20.0, stable_executable, "wrong"))


def test_wait_for_untracked_current_user_processes_waits_for_new_process_to_exit(
    monkeypatch,
) -> None:
    baseline = {(1, 1.0)}
    snapshots = iter(({(1, 1.0), (2, 2.0)}, baseline))
    monkeypatch.setattr(
        "windows_local_mcp.process_utils.capture_current_user_processes",
        lambda: next(snapshots),
    )

    assert (
        wait_for_untracked_current_user_processes(
            baseline,
            deadline=time.monotonic() + 1,
        )
        == set()
    )


def test_wait_for_untracked_current_user_processes_fails_closed_at_deadline(
    monkeypatch,
) -> None:
    baseline = {(1, 1.0)}
    untracked = {(1, 1.0), (2, 2.0)}
    monkeypatch.setattr(
        "windows_local_mcp.process_utils.capture_current_user_processes",
        lambda: untracked,
    )

    assert wait_for_untracked_current_user_processes(
        baseline,
        deadline=time.monotonic() - 1,
    ) == {(2, 2.0)}


def test_stale_job_is_reconciled_without_pid_only_termination(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    operation_id = store.create_operation(
        tool_name="execute",
        tier="safe_command",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    store.update_operation(
        operation_id,
        worker_pid=os.getpid(),
        worker_create_time=0.0,
        worker_executable="C:\\reused.exe",
        process_nonce="wrong",
    )
    Executor(settings, store)
    operation = store.get_operation(operation_id)
    assert operation["status"] == "interrupted"
    assert operation["events"][-1]["event_type"] == "stale_job_reconciled"


def test_stable_worker_identity_drives_reconciliation_and_stop_after_redirector_handoff(
    tmp_path: Path, monkeypatch
) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    operation_id = store.create_operation(
        tool_name="execute",
        tier="safe_command",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    stable_identity = ProcessIdentity(
        pid=4321,
        create_time=20.0,
        executable=r"C:\Python314\python.exe",
        nonce="nonce",
    )
    store.update_operation(
        operation_id,
        worker_pid=stable_identity.pid,
        worker_create_time=stable_identity.create_time,
        worker_executable=stable_identity.executable,
        process_nonce=stable_identity.nonce,
    )
    matched: list[ProcessIdentity] = []
    terminated: list[ProcessIdentity] = []

    def identity_matches(identity: ProcessIdentity) -> bool:
        matched.append(identity)
        return identity == stable_identity

    def terminate(identity: ProcessIdentity) -> bool:
        terminated.append(identity)
        return identity == stable_identity

    monkeypatch.setattr("windows_local_mcp.executor.process_identity_matches", identity_matches)
    monkeypatch.setattr("windows_local_mcp.executor.terminate_process_tree", terminate)

    executor = Executor(settings, store)
    assert store.get_operation(operation_id, include_events=False)["status"] == "running"
    assert matched == [stable_identity]
    assert executor.stop(operation_id)["status"] == "cancelled"
    assert terminated == [stable_identity]


def test_late_bootstrap_capture_cannot_overwrite_worker_self_binding(
    tmp_path: Path, monkeypatch
) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    executor = Executor(settings, store)
    operation_id = store.create_operation(
        tool_name="execute",
        tier="safe_command",
        status="queued",
        cwd=str(settings.workspace_root),
        request={},
    )
    stable_executable = r"C:\Python314\python.exe"
    redirector_executable = r"C:\runtime\Scripts\python.exe"

    class FakeLauncher:
        pid = 4321

    def fake_popen(*_args, **kwargs) -> FakeLauncher:
        nonce = kwargs["env"]["WINDOWS_LOCAL_MCP_JOB_NONCE"]
        assert store.transition_operation(
            operation_id,
            from_statuses={"queued"},
            status="running",
            worker_pid=4321,
            worker_create_time=20.0,
            worker_executable=stable_executable,
            process_nonce=nonce,
        )
        return FakeLauncher()

    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "windows_local_mcp.executor.create_worker_context",
        lambda *_args, **_kwargs: (tmp_path / "context.json", "a" * 64),
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_worker_argv",
        lambda *_args, **_kwargs: ["python"],
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.capture_process_identity",
        lambda pid, nonce: ProcessIdentity(pid, 10.0, redirector_executable, nonce),
    )

    assert executor.launch(operation_id, 0)["status"] == "running"
    operation = store.get_operation(operation_id, include_events=True)
    assert operation["worker_pid"] == 4321
    assert operation["worker_create_time"] == 20.0
    assert operation["worker_executable"] == stable_executable
    spawned = next(event for event in operation["events"] if event["event_type"] == "worker_spawned")
    assert spawned["payload"]["identity_role"] == "bootstrap_launcher"
    assert spawned["payload"]["launcher_create_time"] == 10.0
    assert spawned["payload"]["launcher_executable"] == redirector_executable
    assert spawned["payload"]["operation_identity_updated"] is False


def test_stop_retries_stable_identity_when_worker_self_binding_wins_race(
    tmp_path: Path, monkeypatch
) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    executor = Executor(settings, store)
    operation_id = store.create_operation(
        tool_name="execute",
        tier="safe_command",
        status="queued",
        cwd=str(settings.workspace_root),
        request={},
    )
    bootstrap = ProcessIdentity(4321, 10.0, r"C:\runtime\Scripts\python.exe", "nonce")
    stable = ProcessIdentity(4321, 20.0, r"C:\Python314\python.exe", "nonce")
    store.update_operation(
        operation_id,
        worker_pid=bootstrap.pid,
        worker_create_time=bootstrap.create_time,
        worker_executable=bootstrap.executable,
        process_nonce=bootstrap.nonce,
    )
    attempts: list[ProcessIdentity] = []

    def terminate(identity: ProcessIdentity) -> bool:
        attempts.append(identity)
        if identity == bootstrap:
            assert store.transition_operation(
                operation_id,
                from_statuses={"queued"},
                status="running",
                worker_pid=stable.pid,
                worker_create_time=stable.create_time,
                worker_executable=stable.executable,
                process_nonce=stable.nonce,
            )
            return False
        return identity == stable

    monkeypatch.setattr("windows_local_mcp.executor.terminate_process_tree", terminate)

    assert executor.stop(operation_id)["status"] == "cancelled"
    assert attempts == [bootstrap, stable]


def test_reconciliation_retries_when_worker_self_binding_wins_race(
    tmp_path: Path, monkeypatch
) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    operation_id = store.create_operation(
        tool_name="execute",
        tier="safe_command",
        status="queued",
        cwd=str(settings.workspace_root),
        request={},
    )
    bootstrap = ProcessIdentity(4321, 10.0, r"C:\runtime\Scripts\python.exe", "nonce")
    stable = ProcessIdentity(4321, 20.0, r"C:\Python314\python.exe", "nonce")
    store.update_operation(
        operation_id,
        worker_pid=bootstrap.pid,
        worker_create_time=bootstrap.create_time,
        worker_executable=bootstrap.executable,
        process_nonce=bootstrap.nonce,
    )
    attempts: list[ProcessIdentity] = []

    def identity_matches(identity: ProcessIdentity) -> bool:
        attempts.append(identity)
        if identity == bootstrap:
            assert store.transition_operation(
                operation_id,
                from_statuses={"queued"},
                status="running",
                worker_pid=stable.pid,
                worker_create_time=stable.create_time,
                worker_executable=stable.executable,
                process_nonce=stable.nonce,
            )
            return False
        return identity == stable

    monkeypatch.setattr("windows_local_mcp.executor.process_identity_matches", identity_matches)

    Executor(settings, store)
    assert store.get_operation(operation_id, include_events=False)["status"] == "running"
    assert attempts == [bootstrap, stable]


def test_data_dir_quota_rejects_additional_artifacts(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    settings.max_data_dir_bytes = 1024 * 1024
    payload = settings.data_dir / "outputs" / "large.bin"
    payload.write_bytes(b"x" * (1024 * 1024))
    try:
        enforce_data_quota(settings, incoming_bytes=1)
    except RuntimeError as error:
        assert "quota exceeded" in str(error)
    else:
        raise AssertionError("data_dir quota must reject additional bytes")


def test_bounded_directory_scan_stops_on_entry_count(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    for index in range(5):
        (runtime / f"{index}.txt").write_bytes(b"")
    scan = scan_directory_bounded(
        runtime,
        stop_after_bytes=1024,
        stop_after_entries=3,
        collect_files=True,
    )
    assert scan.entry_count == 4
    assert len(scan.files) <= 3


def test_bounded_directory_scan_rejects_named_stream(monkeypatch, tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "output.txt").write_text("ok", encoding="utf-8")
    monkeypatch.setattr(
        "windows_local_mcp.resources._has_named_data_stream", lambda path: path == runtime
    )
    with pytest.raises(RuntimeError, match="alternate data stream"):
        scan_directory_bounded(
            runtime,
            stop_after_bytes=1024,
            stop_after_entries=10,
            reject_alternate_streams=True,
        )


def test_target_write_lock_allows_different_targets_and_blocks_conflicts(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    target_a = settings.workspace_root / "a.txt"
    target_b = settings.workspace_root / "b.txt"
    counter = 0
    while WorkspaceExecutionLock._target_slot(target_a) == WorkspaceExecutionLock._target_slot(
        target_b
    ):
        counter += 1
        target_b = settings.workspace_root / f"b-{counter}.txt"

    def attempt(lock: WorkspaceExecutionLock, result: list[str]) -> None:
        try:
            with lock:
                result.append("acquired")
        except TimeoutError:
            result.append("timeout")

    with WorkspaceExecutionLock(settings, target=target_a):
        # A different canonical target maps to a different slot and can proceed immediately.
        with WorkspaceExecutionLock(settings, target=target_b, timeout=0.5):
            pass

        same_target_result: list[str] = []
        same_target_thread = threading.Thread(
            target=attempt,
            args=(WorkspaceExecutionLock(settings, target=target_a, timeout=0.2), same_target_result),
        )
        same_target_thread.start()
        same_target_thread.join(timeout=2)
        assert same_target_result == ["timeout"]

        workspace_result: list[str] = []
        workspace_thread = threading.Thread(
            target=attempt,
            args=(WorkspaceExecutionLock(settings, timeout=0.2), workspace_result),
        )
        workspace_thread.start()
        workspace_thread.join(timeout=2)
        assert workspace_result == ["timeout"]

    # Once the target write finishes, a workspace-wide writer can acquire every slot.
    with WorkspaceExecutionLock(settings, timeout=0.5):
        pass


def test_multi_target_lock_blocks_each_bound_path_without_becoming_workspace_wide(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    target_a = settings.workspace_root / "source.bin"
    target_b = settings.workspace_root / "result.bin"
    unrelated = settings.workspace_root / "unrelated.bin"
    while WorkspaceExecutionLock._target_slot(unrelated) in {
        WorkspaceExecutionLock._target_slot(target_a),
        WorkspaceExecutionLock._target_slot(target_b),
    }:
        unrelated = unrelated.with_name(f"x-{unrelated.name}")

    result: list[str] = []

    def attempt_source() -> None:
        try:
            with WorkspaceExecutionLock(settings, target=target_a, timeout=0.2):
                result.append("acquired")
        except TimeoutError:
            result.append("timeout")

    with WorkspaceExecutionLock(settings, targets=(target_b, target_a)):
        with WorkspaceExecutionLock(settings, target=unrelated, timeout=0.5):
            pass
        thread = threading.Thread(target=attempt_source)
        thread.start()
        thread.join(timeout=2)

    assert result == ["timeout"]
