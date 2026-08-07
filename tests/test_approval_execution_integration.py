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


def test_local_approval_launches_immutable_snapshot_once(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
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
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    script = workspace / "main.py"
    script.write_text("print('APPROVED SNAPSHOT')", encoding="utf-8")
    settings = Settings(
        workspace_root=workspace,
        data_dir=data,
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings.ensure_directories()
    store = AuditStore(settings)
    executor = Executor(settings, store)
    operation_id = "approval-execution-integration"
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
    script.write_text("print('REPLACED SOURCE')", encoding="utf-8")
    store.approve_and_claim(operation_id, approver="integration-test")
    result = executor.launch(operation_id, 30)
    assert result["status"] == "succeeded"
    assert "APPROVED SNAPSHOT" in result["stdout_preview"]
    assert "REPLACED SOURCE" not in result["stdout_preview"]
    assert store.get_operation(operation_id)["claimed_at"] is not None
    assert os.path.exists(result["stdout_path"])
