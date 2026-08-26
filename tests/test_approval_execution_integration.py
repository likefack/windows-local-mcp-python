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
from windows_local_mcp.executor import Executor
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import NormalizedCommand, approved_request_hash
from windows_local_mcp.tool_safety import capture_executable_identity


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


def _prepare_operation(
    *,
    workspace: Path,
    data: Path,
    operation_id: str,
    script_text: str,
    max_runtime_seconds: int = 30,
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
            sys.executable, provenance="integration-test"
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
        "max_runtime_seconds": max_runtime_seconds,
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


def _wmi_late_process_script(path: Path) -> str:
    late_code = (
        "import time; from pathlib import Path; time.sleep(1.0); "
        f"Path({path.as_posix()!r}).write_text('wmi late tamper', encoding='utf-8')"
    )
    # WMI must create the stable base interpreter directly. A venv launcher can exit before
    # its redirected child starts, which makes this outside-Job regression nondeterministic.
    base_python = Path(sys.base_prefix) / "python.exe"
    command_line = subprocess.list2cmdline([str(base_python), "-I", "-c", late_code])
    powershell_command = (
        "$ErrorActionPreference='Stop'; "
        "$process = [wmiclass]'Win32_Process'; "
        "$inParams = $process.GetMethodParameters('Create'); "
        f"$inParams.CommandLine = '{command_line.replace(chr(39), chr(39) * 2)}'; "
        "$outParams = $process.InvokeMethod('Create', $inParams, $null); "
        "if ([int]$outParams.ReturnValue -ne 0) { exit [int]$outParams.ReturnValue }"
    )
    return (
        "import subprocess\n"
        f"powershell_command={powershell_command!r}\n"
        "completed=subprocess.run([\n"
        "    'powershell.exe', '-NoProfile', '-NonInteractive', '-Command', powershell_command\n"
        "], capture_output=True, text=True)\n"
        "if completed.returncode != 0:\n"
        "    raise SystemExit(completed.returncode)\n"
    )


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
    if completed.returncode != 0:
        pytest.skip(
            "local Win32_Process WMI provider is unavailable: "
            f"{completed.stderr.strip()[:300]}"
        )


def test_local_approval_rejects_changed_transitive_live_workspace_input(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    payload = workspace / "payload.py"
    payload.write_text("print('APPROVED PAYLOAD')", encoding="utf-8")

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="approval-execution-integration",
        script_text=(
            "from pathlib import Path\n"
            f"exec(Path({str(payload)!r}).read_text(encoding='utf-8'))\n"
        ),
    )
    payload.write_text("print('REPLACED PAYLOAD')", encoding="utf-8")
    store.approve_and_claim("approval-execution-integration", approver="integration-test")
    result = executor.launch("approval-execution-integration", 30)
    operation = store.get_operation("approval-execution-integration")

    assert result["status"] == "failed"
    assert operation["child_pid"] is None
    assert "workspace behavior inputs changed" in str(operation["error"])
    assert "REPLACED PAYLOAD" not in result.get("stdout_preview", "")
    assert operation["claimed_at"] is not None
    assert settings.data_dir == data.resolve()


def test_snapshot_execution_succeeds_when_bound_workspace_is_unchanged(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    _, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="snapshot-bound-workspace",
        script_text="print('SNAPSHOT RUNS INDEPENDENTLY')",
    )
    store.approve_and_claim("snapshot-bound-workspace", approver="integration-test")
    result = executor.launch("snapshot-bound-workspace", 30)
    operation = store.get_operation("snapshot-bound-workspace")

    assert result["status"] == "succeeded", operation
    assert "SNAPSHOT RUNS INDEPENDENTLY" in result["stdout_preview"]


def test_expired_claim_is_rejected_immediately_before_child_start(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    _, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="approval-expired-before-child",
        script_text="print('MUST NOT RUN')",
    )
    store.approve_and_claim("approval-expired-before-child", approver="integration-test")
    store.update_operation(
        "approval-expired-before-child",
        approval_expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    )

    result = executor.launch("approval-expired-before-child", 30)
    operation = store.get_operation("approval-expired-before-child")

    assert result["status"] == "expired"
    assert operation["approval_status"] == "expired"
    assert operation["child_pid"] is None
    assert "expired before child start" in str(operation["error"])
    assert any(
        event["event_type"] == "approval_expired_before_child_start"
        for event in operation["events"]
    )
    stdout_path = operation.get("stdout_path")
    assert not stdout_path or not os.path.exists(stdout_path)


def test_approved_host_control_plane_tamper_is_detected_and_blocks_future_work(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    operation_id = "approved-host-control-plane-tamper"
    database = data / "audit.db"
    script = (
        "import sqlite3\n"
        f"database={str(database)!r}\n"
        f"operation_id={operation_id!r}\n"
        "connection=sqlite3.connect(database)\n"
        "connection.execute('UPDATE operations SET request_hash=? WHERE id=?', "
        "('f'*64, operation_id))\n"
        "connection.commit()\n"
    )

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id=operation_id,
        script_text=script,
    )
    store.approve_and_claim(operation_id, approver="integration-test")
    result = executor.launch(operation_id, 30)
    operation = store.get_operation(operation_id)

    assert result["status"] == "failed"
    assert operation["result"]["failure_class"] == "control_plane_tamper_unknown"
    assert "could not be verified" in str(operation["error"])
    assert (settings.data_dir / "control-plane" / "tamper-detected.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Approved Host descendant Job Object is Windows-only")
def test_approved_host_waits_for_descendants_before_control_plane_postflight(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    operation_id = "approved-host-late-descendant-tamper"
    late_write = data / "control-plane" / "late-write.txt"
    descendant = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(1.0)\n"
        f"Path({str(late_write)!r}).write_text('late tamper', encoding='utf-8')\n"
    )
    script = (
        "import subprocess, sys\n"
        f"descendant={descendant!r}\n"
        "subprocess.Popen([sys.executable, '-I', '-c', descendant], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True)\n"
        "print('parent exited')\n"
    )

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id=operation_id,
        script_text=script,
    )
    store.approve_and_claim(operation_id, approver="integration-test")
    result = executor.launch(operation_id, 30)
    deadline = time.monotonic() + 3
    while not late_write.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    operation = store.get_operation(operation_id)

    assert late_write.read_text(encoding="utf-8") == "late tamper"
    assert result["status"] == "failed"
    assert operation["result"]["failure_class"] == "control_plane_tamper"
    assert (settings.data_dir / "control-plane" / "tamper-detected.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Approved Host WMI process boundary is Windows-only")
def test_approved_host_detects_wmi_process_outside_job_before_postflight(
    tmp_path: Path, monkeypatch
) -> None:
    _require_local_wmi()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    operation_id = "approved-host-wmi-late-tamper"
    late_write = data / "control-plane" / "wmi-late-write.txt"
    script = _wmi_late_process_script(late_write)

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id=operation_id,
        script_text=script,
    )
    store.approve_and_claim(operation_id, approver="integration-test")
    result = executor.launch(operation_id, 30)
    deadline = time.monotonic() + 3
    while not late_write.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    operation = store.get_operation(operation_id)

    assert late_write.read_text(encoding="utf-8") == "wmi late tamper"
    assert result["status"] == "failed"
    assert operation["result"]["failure_class"] == "control_plane_tamper"
    assert (settings.data_dir / "control-plane" / "tamper-detected.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Approved Host descendant Job Object is Windows-only")
def test_approved_host_allows_legitimate_descendant_to_finish(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    output = data / "outputs" / "descendant-result.txt"
    descendant = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(0.5)\n"
        f"Path({str(output)!r}).write_text('finished', encoding='utf-8')\n"
    )
    script = (
        "import subprocess, sys\n"
        f"descendant={descendant!r}\n"
        "subprocess.Popen([sys.executable, '-I', '-c', descendant], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True)\n"
    )

    _, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="approved-host-legitimate-descendant",
        script_text=script,
    )
    store.approve_and_claim("approved-host-legitimate-descendant", approver="integration-test")
    started = time.monotonic()
    result = executor.launch("approved-host-legitimate-descendant", 30)
    operation = store.get_operation("approved-host-legitimate-descendant")

    assert result["status"] == "succeeded", operation
    assert time.monotonic() - started >= 0.4
    assert output.read_text(encoding="utf-8") == "finished"


@pytest.mark.skipif(os.name != "nt", reason="Approved Host descendant Job Object is Windows-only")
def test_approved_host_terminates_descendants_at_runtime_limit(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    late_write = data / "control-plane" / "after-timeout.txt"
    descendant = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(2.0)\n"
        f"Path({str(late_write)!r}).write_text('escaped', encoding='utf-8')\n"
    )
    script = (
        "import subprocess, sys\n"
        f"descendant={descendant!r}\n"
        "subprocess.Popen([sys.executable, '-I', '-c', descendant], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True)\n"
    )

    _, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="approved-host-descendant-timeout",
        script_text=script,
        max_runtime_seconds=1,
    )
    store.approve_and_claim("approved-host-descendant-timeout", approver="integration-test")
    result = executor.launch("approved-host-descendant-timeout", 10)
    time.sleep(1.5)
    operation = store.get_operation("approved-host-descendant-timeout")

    assert result["status"] == "timed_out", operation
    assert result["failure_class"] == "runtime_limit"
    assert not late_write.exists()
