import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from windows_local_mcp.approval import prepare_approval_bundle
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import NormalizedCommand


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
    )
    _, _, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    store.create_operation(
        operation_id=operation_id,
        tool_name="request_host_command",
        tier="host_approval",
        status="pending_approval",
        cwd=str(workspace),
        request={
            "normalized_command": command.model_dump(),
            "approval_manifest_digest": digest,
            "max_runtime_seconds": 30,
        },
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
