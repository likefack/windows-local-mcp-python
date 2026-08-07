import os
import subprocess
import sys
from pathlib import Path

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
from windows_local_mcp.process_utils import ProcessIdentity, terminate_process_tree
from windows_local_mcp.resources import BoundedStreamCapture, enforce_data_quota


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
