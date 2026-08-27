from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor


def test_runtime_user_stop_cannot_terminate_active_approved_host_monitor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        approved_host_enabled=True,
    )
    settings.ensure_directories()
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="request_host_command",
        tier="approved_host",
        status="running",
        cwd=str(workspace),
        request={},
        approval_status="approved",
    )

    class ForbiddenAuthority:
        def __init__(self) -> None:
            raise AssertionError("stop must not obtain an authority cancellation surface")

    monkeypatch.setattr(
        "windows_local_mcp.executor.ApprovedHostAuthorityClient",
        ForbiddenAuthority,
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.terminate_process_tree",
        lambda _identity: (_ for _ in ()).throw(
            AssertionError("runtime user must not terminate Approved Host worker")
        ),
    )

    with pytest.raises(PermissionError, match="cannot be stopped"):
        executor.stop(operation_id)

    operation = audit.get_operation(operation_id, include_events=False)
    assert operation["status"] == "running"
