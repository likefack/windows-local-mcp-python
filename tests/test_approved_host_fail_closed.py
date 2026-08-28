from __future__ import annotations

import os
import sys
from pathlib import Path

import psutil
import pytest

from windows_local_mcp import approved_host_policy, runtime_immutability
from windows_local_mcp.approved_host_authority import (
    AuthorityLaunchResult,
    AuthorityWorkerIdentity,
)
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


def _runtime_evidence() -> dict[str, object]:
    return {
        "version": 1,
        "digest": "runtime-digest",
        "file_count": 1,
        "directory_count": 1,
    }


def test_runtime_verification_is_no_longer_globally_replaced_by_capability_reduction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {"scope": "complete-runtime", "digest": "test"}
    monkeypatch.setattr(
        runtime_immutability,
        "assert_approved_host_runtime_immutable",
        lambda: evidence,
    )

    assert approved_host_policy.verify_approved_host_runtime_immutability_only() == evidence
    assert not bool(
        getattr(
            runtime_immutability.assert_approved_host_runtime_immutable,
            "__wlmcp_approved_host_fail_closed__",
            False,
        )
    )


def test_executor_rejects_approved_host_when_system_authority_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _runtime_evidence,
    )

    def unavailable() -> dict[str, object]:
        raise PermissionError("SYSTEM authority unavailable")

    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_authority_available",
        unavailable,
    )

    def forbidden_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal spawned
        spawned = True
        raise AssertionError("same-user Approved Host worker must not spawn")

    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", forbidden_spawn)

    with pytest.raises(PermissionError, match="SYSTEM authority unavailable"):
        executor.launch(operation_id, 0)

    assert spawned is False
    events = audit.get_operation(operation_id, include_events=True)["events"]
    assert any(
        event["event_type"] == "approved_host_authority_preflight_failed"
        for event in events
    )


@pytest.mark.parametrize("tier", ["approved_host", "host_approval"])
def test_executor_delegates_approved_host_worker_to_system_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tier: str,
) -> None:
    settings = _settings(tmp_path)
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="request_host_command",
        tier=tier,
        status="queued",
        cwd=str(settings.workspace_root),
        request={},
        approval_status="approved",
    )
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _runtime_evidence,
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_authority_available",
        lambda: {"healthy": True, "service_epoch": "epoch-1"},
    )

    class FakeAuthority:
        def launch(self, **kwargs: object) -> AuthorityLaunchResult:
            calls.append(dict(kwargs))
            process = psutil.Process(os.getpid())
            return AuthorityLaunchResult(
                worker=AuthorityWorkerIdentity(
                    pid=os.getpid(),
                    create_time=float(process.create_time()),
                    executable=str(Path(sys.executable).resolve()),
                ),
                service_epoch="epoch-1",
            )

    monkeypatch.setattr(
        "windows_local_mcp.executor.ApprovedHostAuthorityClient",
        FakeAuthority,
    )
    # The test forbids executor-side Popen. Avoid coupling that monkeypatch to the
    # global subprocess module used by the SCM existence probe during context creation.
    monkeypatch.setattr(
        "windows_local_mcp.approved_host_policy._authority_service_installed",
        lambda: False,
    )

    def forbidden_spawn(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Approved Host must not use same-user subprocess.Popen")

    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", forbidden_spawn)

    result = executor.launch(operation_id, 0)

    assert result["status"] == "queued"
    assert len(calls) == 1
    assert calls[0]["operation_id"] == operation_id
    assert calls[0]["requester_pid"] == os.getpid()
    operation = audit.get_operation(operation_id, include_events=True)
    spawned = [event for event in operation["events"] if event["event_type"] == "worker_spawned"]
    assert len(spawned) == 1
    assert spawned[0]["payload"]["identity_role"] == "system_authority_worker"
    assert spawned[0]["payload"]["authority_separated"] is True
