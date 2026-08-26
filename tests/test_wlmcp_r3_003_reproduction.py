import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from windows_local_mcp.approval import prepare_approval_bundle
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.control_plane import control_plane_generation
from windows_local_mcp.control_plane_guard import assert_control_plane_healthy
from windows_local_mcp.executor import Executor
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import NormalizedCommand, approved_request_hash
from windows_local_mcp.tool_safety import capture_executable_identity

_PENDING_GUARD_NAME = "approved-host-postflight-pending.json"


def _write_config(workspace: Path, data: Path, config: Path) -> None:
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
            ]
        ),
        encoding="utf-8",
    )


def _trusted_runtime_evidence() -> dict[str, object]:
    return {
        "version": 1,
        "scope": "complete-runtime",
        "path_count": 0,
        "file_count": 0,
        "directory_count": 0,
        "ancestor_directory_count": 0,
        "digest": "0" * 64,
        "distributions": [],
    }


def _outside_job_helper_source() -> str:
    return "\n".join(
        [
            "import ctypes",
            "import sqlite3",
            "import sys",
            "import time",
            "from ctypes import wintypes",
            "from pathlib import Path",
            "worker_pid = int(sys.argv[1])",
            "pending = Path(sys.argv[2])",
            "database = Path(sys.argv[3])",
            "operation_id = sys.argv[4]",
            "done = Path(sys.argv[5])",
            "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)",
            "kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]",
            "kernel32.OpenProcess.restype = wintypes.HANDLE",
            "kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]",
            "kernel32.TerminateProcess.restype = wintypes.BOOL",
            "kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]",
            "kernel32.WaitForSingleObject.restype = wintypes.DWORD",
            "kernel32.CloseHandle.argtypes = [wintypes.HANDLE]",
            "kernel32.CloseHandle.restype = wintypes.BOOL",
            "handle = kernel32.OpenProcess(0x00100001, False, worker_pid)",
            "if not handle:",
            "    raise OSError(ctypes.get_last_error(), 'OpenProcess failed')",
            "try:",
            "    if not kernel32.TerminateProcess(handle, 23):",
            "        raise OSError(ctypes.get_last_error(), 'TerminateProcess failed')",
            "    kernel32.WaitForSingleObject(handle, 5000)",
            "finally:",
            "    kernel32.CloseHandle(handle)",
            "deadline = time.monotonic() + 10.0",
            "while True:",
            "    try:",
            "        pending.unlink()",
            "        break",
            "    except OSError:",
            "        if time.monotonic() >= deadline:",
            "            raise",
            "        time.sleep(0.05)",
            "deadline = time.monotonic() + 10.0",
            "while True:",
            "    try:",
            "        with sqlite3.connect(database, timeout=0.25) as connection:",
            "            connection.execute(",
            "                \"UPDATE operations SET approval_note='forged after worker kill' WHERE id=?\",",
            "                (operation_id,),",
            "            )",
            "            connection.commit()",
            "        break",
            "    except sqlite3.OperationalError:",
            "        if time.monotonic() >= deadline:",
            "            raise",
            "        time.sleep(0.05)",
            "done.write_text('marker-deleted-and-audit-tampered', encoding='utf-8')",
        ]
    )


def _approved_host_parent_source(
    *,
    helper: Path,
    pending: Path,
    database: Path,
    operation_id: str,
    done: Path,
) -> str:
    return "\n".join(
        [
            "import os",
            "import subprocess",
            "import sys",
            "import time",
            "from pathlib import Path",
            "worker_pid = os.getppid()",
            "base_python = Path(sys.base_prefix) / 'python.exe'",
            "command_line = subprocess.list2cmdline([",
            "    str(base_python),",
            "    '-I',",
            f"    {str(helper)!r},",
            "    str(worker_pid),",
            f"    {str(pending)!r},",
            f"    {str(database)!r},",
            f"    {operation_id!r},",
            f"    {str(done)!r},",
            "])",
            "$marker = None" if False else "powershell_command = (",
            "    \"$ErrorActionPreference='Stop'; \"",
            "    \"$process = [wmiclass]'Win32_Process'; \"",
            "    \"$inParams = $process.GetMethodParameters('Create'); \"",
            "    \"$inParams.CommandLine = '\" + command_line.replace(chr(39), chr(39) * 2) + \"'; \"",
            "    \"$outParams = $process.InvokeMethod('Create', $inParams, $null); \"",
            "    \"if ([int]$outParams.ReturnValue -ne 0) { exit [int]$outParams.ReturnValue }\"",
            ")",
            "completed = subprocess.run([",
            "    'powershell.exe', '-NoProfile', '-NonInteractive', '-Command', powershell_command",
            "], capture_output=True, text=True)",
            "if completed.returncode != 0:",
            "    raise RuntimeError(completed.stderr or completed.stdout)",
            "time.sleep(30)",
        ]
    )


def _prepare_operation(
    *,
    workspace: Path,
    data: Path,
    operation_id: str,
    script_text: str,
) -> tuple[Settings, AuditStore, Executor]:
    script = workspace / "main.py"
    script.write_text(script_text, encoding="utf-8")
    settings = Settings(
        workspace_root=workspace,
        data_dir=data,
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings.ensure_directories()
    store = AuditStore(settings)
    executor = Executor(settings, store)
    command = NormalizedCommand(
        executable=sys.executable,
        args=["main.py"],
        cwd=str(workspace),
        display_command=[sys.executable, "main.py"],
        program_key="python",
        executable_identity=capture_executable_identity(
            sys.executable, provenance="r3-003-reproduction"
        ),
    )
    _, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    request = {
        "approval_binding_version": 3,
        "control_plane_generation": control_plane_generation(settings),
        "normalized_command": command.model_dump(),
        "approval_manifest_digest": digest,
        "approval_manifest_summary": {"mode": manifest["mode"]},
        "workspace_write": False,
        "max_runtime_seconds": 30,
        "execution_tier": "approved_host",
    }
    store.create_operation(
        operation_id=operation_id,
        tool_name="request_host_command",
        tier="approved_host",
        status="pending_approval",
        cwd=str(workspace),
        request=request,
        request_hash=approved_request_hash(request),
        approval_status="pending",
        request_expires_at=expires,
    )
    return settings, store, executor


def _require_local_wmi() -> None:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$ErrorActionPreference='Stop'; "
                "$process = [wmiclass]'Win32_Process'; "
                "$process.GetMethodParameters('Create') | Out-Null"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, (
        "local Win32_Process WMI provider is required for R3-003 live reproduction: "
        f"{completed.stderr.strip()[:300]}"
    )


@pytest.mark.skipif(os.name != "nt", reason="WLMCP-R3-003 reproduction is Windows-only")
def test_wmi_survivor_can_delete_postflight_marker_after_worker_termination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_local_wmi()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _trusted_runtime_evidence,
    )

    operation_id = "wlmcp-r3-003-live-reproduction"
    pending = data / "control-plane" / _PENDING_GUARD_NAME
    database = data / "audit.db"
    done = tmp_path / "outside-job-helper-done.txt"
    helper = tmp_path / "outside-job-helper.py"
    helper.write_text(_outside_job_helper_source(), encoding="utf-8")
    script = _approved_host_parent_source(
        helper=helper,
        pending=pending,
        database=database,
        operation_id=operation_id,
        done=done,
    )

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id=operation_id,
        script_text=script,
    )
    store.approve_and_claim(operation_id, approver="r3-003-live-test")
    executor.launch(operation_id, 2)

    deadline = time.monotonic() + 15.0
    while not done.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert done.read_text(encoding="utf-8") == "marker-deleted-and-audit-tampered"
    assert not pending.exists()

    restarted = AuditStore(settings)
    Executor(settings, restarted)
    operation = restarted.get_operation(operation_id, include_events=False)
    assert operation["status"] == "interrupted"
    assert operation["approval_note"] == "forged after worker kill"

    assert_control_plane_healthy(settings)
    assert isinstance(control_plane_generation(settings), str)
