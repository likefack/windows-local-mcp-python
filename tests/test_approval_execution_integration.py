import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from windows_local_mcp.approval import prepare_approval_bundle
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.control_plane import control_plane_generation
from windows_local_mcp.executor import Executor
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import NormalizedCommand, approved_request_hash
from windows_local_mcp.resources import WorkspaceExecutionLock
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


def test_local_approval_launches_immutable_snapshot_once(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="approval-execution-integration",
        script_text="print('APPROVED SNAPSHOT')",
    )
    script = workspace / "main.py"
    script.write_text("print('REPLACED SOURCE')", encoding="utf-8")
    store.approve_and_claim("approval-execution-integration", approver="integration-test")
    result = executor.launch("approval-execution-integration", 30)
    assert result["status"] == "succeeded"
    assert "APPROVED SNAPSHOT" in result["stdout_preview"]
    assert "REPLACED SOURCE" not in result["stdout_preview"]
    assert store.get_operation("approval-execution-integration")["claimed_at"] is not None
    assert os.path.exists(result["stdout_path"])
    assert settings.data_dir == data.resolve()


def test_snapshot_execution_does_not_wait_for_workspace_write_lock(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id="snapshot-with-workspace-lock-held",
        script_text="print('SNAPSHOT RUNS INDEPENDENTLY')",
    )
    store.approve_and_claim("snapshot-with-workspace-lock-held", approver="integration-test")

    # Simulate an unrelated workspace write that holds the exclusive mutation lock.
    # Snapshot-backed execution works only from data_dir, so it must not wait for this lock.
    with WorkspaceExecutionLock(settings):
        result = executor.launch("snapshot-with-workspace-lock-held", 5)

    assert result["status"] == "succeeded"
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
