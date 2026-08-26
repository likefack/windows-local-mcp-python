from pathlib import Path

import pytest

from windows_local_mcp import runtime_immutability
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        approved_host_enabled=True,
    )
    settings.ensure_directories()
    return settings


def test_production_runtime_gate_reports_approved_host_unavailable() -> None:
    with pytest.raises(PermissionError, match="Approved Host execution is unavailable"):
        runtime_immutability.assert_approved_host_runtime_immutable()


def test_executor_rejects_stale_approved_host_before_worker_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="request_host_command",
        tier="approved_host",
        status="queued",
        cwd=str(settings.workspace_root),
        request={},
        approval_status="approved",
    )
    spawned = False

    def forbidden_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal spawned
        spawned = True
        raise AssertionError("Approved Host worker must not spawn")

    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", forbidden_spawn)

    with pytest.raises(PermissionError, match="Approved Host execution is unavailable"):
        executor.launch(operation_id, 0)

    assert spawned is False
    events = audit.get_operation(operation_id, include_events=True)["events"]
    assert any(
        event["event_type"] == "approved_host_runtime_immutability_failed"
        for event in events
    )
