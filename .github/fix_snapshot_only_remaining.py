from __future__ import annotations

import re
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected 1 exact match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.DOTALL)
    if count != 1:
        raise RuntimeError(f"{label}: expected 1 regex match, found {count}")
    return updated


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8", newline="\n")


# SQLite trace callbacks expand bound REAL values into SQL text before the trusted audit
# mirror replays them. Persist process creation times at millisecond precision, which is
# materially finer than the existing 10ms process-identity tolerance and round-trips exactly
# enough for the mirror without weakening the effective PID-reuse boundary.
path = "src/windows_local_mcp/process_utils.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(
    text,
    'ProcessKey = tuple[int, float]\n\n\nclass _HeldArgv',
    'ProcessKey = tuple[int, float]\n_PROCESS_CREATE_TIME_DIGITS = 3\n\n\ndef _durable_process_create_time(value: float) -> float:\n    """Normalize durable process identity timestamps below the verification tolerance."""\n\n    return round(float(value), _PROCESS_CREATE_TIME_DIGITS)\n\n\nclass _HeldArgv',
    "durable process create time helper",
)
text = replace_once(
    text,
    '        create_time=process.create_time(),',
    '        create_time=_durable_process_create_time(process.create_time()),',
    "capture durable process create time",
)
write(path, text)


# Keep the Approved Host immutable approval-row binding explicit and independently testable.
path = "src/windows_local_mcp/worker.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(
    text,
    'class RuntimeStoragePolicyError(RuntimeError):\n    pass\n\ndef run_operation',
    'class RuntimeStoragePolicyError(RuntimeError):\n    pass\n\n\ndef _approved_host_operation_binding(operation: dict[str, Any]) -> dict[str, Any]:\n    """Return approval fields that an Approved Host child must never change."""\n\n    return {\n        "id": operation["id"],\n        "tier": operation["tier"],\n        "request_hash": operation.get("request_hash"),\n        "claimed_at": operation.get("claimed_at"),\n        "approval_status": operation.get("approval_status"),\n        "request": operation["request"],\n    }\n\n\ndef run_operation',
    "approved host binding helper",
)
old_binding = '''            host_operation_binding = {
                "id": operation["id"],
                "tier": operation["tier"],
                "request_hash": operation.get("request_hash"),
                "claimed_at": operation.get("claimed_at"),
                "approval_status": operation.get("approval_status"),
                "request": operation["request"],
            }
'''
text = replace_once(
    text,
    old_binding,
    '            host_operation_binding = _approved_host_operation_binding(operation)\n',
    "preflight host binding",
)
old_fresh = '''            fresh_binding = {
                "id": fresh_operation["id"],
                "tier": fresh_operation["tier"],
                "request_hash": fresh_operation.get("request_hash"),
                "claimed_at": fresh_operation.get("claimed_at"),
                "approval_status": fresh_operation.get("approval_status"),
                "request": fresh_operation["request"],
            }
'''
text = replace_once(
    text,
    old_fresh,
    '            fresh_binding = _approved_host_operation_binding(fresh_operation)\n',
    "postflight host binding",
)
write(path, text)


# The control-plane digest deliberately tracks trusted worker audit writes. Test immutable
# approval-row binding through the same dedicated projection used by worker postflight.
path = "tests/test_broker_architecture.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(
    text,
    'from windows_local_mcp.resources import prune_artifacts\n',
    'from windows_local_mcp.resources import prune_artifacts\nfrom windows_local_mcp.worker import _approved_host_operation_binding\n',
    "worker binding import",
)
old_test = '''def test_host_guard_binds_current_operation_approval_state(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    audit = AuditStore(settings)
    operation = audit.create_operation(
        tool_name="host",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"program_key": "python"}},
        request_hash="a" * 64,
        approval_status="approved",
    )
    before = capture_critical_state(settings, operation)

    audit.update_operation(operation, request_hash="b" * 64)

    assert capture_critical_state(settings, operation) != before
'''
new_test = '''def test_host_guard_binds_current_operation_approval_state(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    audit = AuditStore(settings)
    operation_id = audit.create_operation(
        tool_name="host",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"program_key": "python"}},
        request_hash="a" * 64,
        approval_status="approved",
    )
    before = _approved_host_operation_binding(
        audit.get_operation(operation_id, include_events=False)
    )

    audit.update_operation(operation_id, request_hash="b" * 64)
    after = _approved_host_operation_binding(
        audit.get_operation(operation_id, include_events=False)
    )

    assert after != before
    assert before["request_hash"] == "a" * 64
    assert after["request_hash"] == "b" * 64
'''
text = replace_once(text, old_test, new_test, "stale host binding test")
write(path, text)


# Verify the timestamp normalization itself and preserve the existing 10ms identity check.
path = "tests/test_resources_and_processes.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(
    text,
    '    ProcessIdentity,\n    process_identity_matches,',
    '    ProcessIdentity,\n    capture_process_identity,\n    process_identity_matches,',
    "capture process identity import",
)
marker = '''def test_process_identity_matches_stable_worker_not_redirector_bootstrap(
    monkeypatch,
) -> None:
'''
extra = '''def test_capture_process_identity_uses_durable_millisecond_timestamp(monkeypatch) -> None:
    stable_executable = os.path.normcase(str(Path(sys.executable).resolve()))

    class FakeProcess:
        def create_time(self) -> float:
            return 1_787_770_728.976036

        def exe(self) -> str:
            return sys.executable

        def environ(self) -> dict[str, str]:
            return {"WINDOWS_LOCAL_MCP_JOB_NONCE": "nonce"}

    monkeypatch.setattr("windows_local_mcp.process_utils.psutil.Process", lambda _pid: FakeProcess())

    identity = capture_process_identity(4321, "nonce")

    assert identity.create_time == 1_787_770_728.976
    assert identity.executable == stable_executable
    assert process_identity_matches(identity)


'''
text = replace_once(text, marker, extra + marker, "durable process identity test")
write(path, text)


# A one-second end-to-end Approved Host deadline expires during the intentionally expensive
# production control-plane preflight. Test descendant termination at the Windows Job Object
# boundary directly instead of conflating preflight time with child runtime.
path = "tests/test_approval_execution_integration.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(
    text,
    'from windows_local_mcp.tool_safety import capture_executable_identity\n',
    'from windows_local_mcp.tool_safety import capture_executable_identity\nfrom windows_local_mcp.windows_job import WindowsSandboxJob\n',
    "Windows Job import",
)
pattern = r'''@pytest\.mark\.skipif\(os\.name != "nt", reason="Approved Host descendant Job Object is Windows-only"\)\ndef test_approved_host_terminates_descendants_at_runtime_limit\(tmp_path: Path, monkeypatch\) -> None:.*?    assert not late_write\.exists\(\)'''
replacement = '''@pytest.mark.skipif(os.name != "nt", reason="Approved Host descendant Job Object is Windows-only")
def test_approved_host_job_terminates_descendants_at_runtime_limit(tmp_path: Path) -> None:
    late_write = tmp_path / "after-timeout.txt"
    descendant = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(2.0)\n"
        f"Path({str(late_write)!r}).write_text('escaped', encoding='utf-8')\n"
    )
    parent = (
        "import subprocess, sys\n"
        f"descendant={descendant!r}\n"
        "subprocess.Popen([sys.executable, '-I', '-c', descendant], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True)\n"
    )

    job = WindowsSandboxJob()
    try:
        child = job.popen(
            [sys.executable, "-I", "-c", parent],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        assert child.wait(timeout=10) == 0
        assert not job.wait_empty(timeout=0.2)
        assert job.terminate()
        assert job.wait_empty(timeout=10)
    finally:
        job.close()

    time.sleep(2.1)
    assert not late_write.exists()'''
text = regex_once(text, pattern, replacement, "Approved Host runtime-limit responsibility test")
write(path, text)
