from pathlib import Path

import pytest

from windows_local_mcp import approved_host_policy, runtime_immutability
from windows_local_mcp.approved_host_policy import APPROVED_HOST_UNAVAILABLE_REASON
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


def test_runtime_verification_only_does_not_enable_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {"scope": "complete-runtime", "digest": "test"}
    monkeypatch.setattr(
        approved_host_policy,
        "_LOWER_LEVEL_RUNTIME_CHECK",
        lambda: evidence,
    )

    assert approved_host_policy.verify_approved_host_runtime_immutability_only() == evidence
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
    failure_events = [
        event
        for event in events
        if event["event_type"] == "approved_host_runtime_immutability_failed"
    ]
    assert len(failure_events) == 1
    assert APPROVED_HOST_UNAVAILABLE_REASON in str(failure_events[0]["payload"])
