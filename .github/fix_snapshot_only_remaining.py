from __future__ import annotations

import re
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected 1 exact match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(
        pattern, lambda _match: replacement, text, count=1, flags=re.DOTALL
    )
    if count != 1:
        raise RuntimeError(f"{label}: expected 1 regex match, found {count}")
    return updated


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8", newline="\n")


# Mutable-checkout integration tests intentionally exercise controls after the production
# Approved Host runtime gate. The executor spawns a new isolated Python worker, so the test
# runtime evidence must be injected into that worker as well as the parent executor.
path = "tests/conftest.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(
    text,
    '        "file_count": 0,\n        "directory_count": 0,\n',
    '        "file_count": 0,\n        "bytes": 0,\n        "directory_count": 0,\n',
    "trusted runtime evidence bytes",
)
text = replace_once(
    text,
    '\n\n@pytest.fixture(autouse=True)\ndef _isolate_downstream_approved_host_integration(\n',
    '''\n\ndef _isolated_worker_argv_with_trusted_runtime_state(
    settings: Any,
    *,
    operation_id: str,
    context_path: Path,
    context_sha256: str,
) -> list[str]:
    from windows_local_mcp.control_plane import isolated_worker_argv

    argv = isolated_worker_argv(
        settings,
        operation_id=operation_id,
        context_path=context_path,
        context_sha256=context_sha256,
    )
    command_index = argv.index("-c") + 1
    bootstrap = argv[command_index]
    marker = "runpy.run_module('windows_local_mcp.worker',run_name='__main__')"
    if marker not in bootstrap:
        raise RuntimeError("isolated worker bootstrap shape changed")
    runtime_patch = (
        "import windows_local_mcp.control_plane_guard as _guard;"
        f"_guard.capture_runtime_dependency_state=lambda **_kwargs:{_trusted_runtime_evidence()!r};"
    )
    argv[command_index] = bootstrap.replace(marker, runtime_patch + marker, 1)
    return argv


@pytest.fixture(autouse=True)
def _isolate_downstream_approved_host_integration(
''',
    "isolated worker runtime fixture helper",
)
text = replace_once(
    text,
    '''    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _trusted_runtime_evidence,
    )
''',
    '''    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _trusted_runtime_evidence,
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_worker_argv",
        _isolated_worker_argv_with_trusted_runtime_state,
    )
''',
    "isolated worker runtime fixture install",
)
write(path, text)


# capture_critical_state returns the guard's live expected-state object. Trusted AuditStore
# mutations intentionally advance that object. Keep an immutable copy to prove the approval
# row change is tracked rather than expecting the live object itself to stay frozen.
path = "tests/test_broker_architecture.py"
text = Path(path).read_text(encoding="utf-8")
text = replace_once(text, "import json\nimport os\n", "import copy\nimport json\nimport os\n", "copy import")
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
new_test = '''def test_host_guard_tracks_trusted_operation_approval_state(tmp_path: Path) -> None:
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
    original = copy.deepcopy(before)

    audit.update_operation(operation, request_hash="b" * 64)
    after = capture_critical_state(settings, operation)

    assert after == before
    assert after != original
'''
text = replace_once(text, old_test, new_test, "trusted audit guard regression")
write(path, text)


# A one-second end-to-end Approved Host deadline can expire in production preflight before a
# child exists. Verify descendant termination at the Windows Job Object boundary directly;
# preflight behavior remains covered independently by Approved Host integration tests.
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
        "import time\\n"
        "from pathlib import Path\\n"
        "time.sleep(2.0)\\n"
        f"Path({str(late_write)!r}).write_text('escaped', encoding='utf-8')\\n"
    )
    parent = (
        "import subprocess, sys\\n"
        f"descendant={descendant!r}\\n"
        "subprocess.Popen([sys.executable, '-I', '-c', descendant], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True)\\n"
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
text = regex_once(text, pattern, replacement, "Approved Host Job termination regression")
text = replace_once(
    text,
    '    assert result["status"] == "succeeded", operation\n    assert "SNAPSHOT RUNS INDEPENDENTLY" in result["stdout_preview"]',
    '    assert result["status"] == "succeeded", {\n        "error": operation.get("error"),\n        "result": operation.get("result"),\n        "events": [event["event_type"] for event in operation["events"]],\n    }\n    assert "SNAPSHOT RUNS INDEPENDENTLY" in result["stdout_preview"]',
    "snapshot positive diagnostic",
)
text = replace_once(
    text,
    '    assert result["status"] == "succeeded", operation\n    assert time.monotonic() - started >= 0.4',
    '    assert result["status"] == "succeeded", {\n        "error": operation.get("error"),\n        "result": operation.get("result"),\n        "events": [event["event_type"] for event in operation["events"]],\n    }\n    assert time.monotonic() - started >= 0.4',
    "descendant positive diagnostic",
)
write(path, text)
