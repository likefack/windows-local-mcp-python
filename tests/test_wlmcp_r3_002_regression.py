from __future__ import annotations

import os
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from windows_local_mcp.approval import (
    materialize_execution_copy,
    prepare_approval_bundle,
    verify_approval_bundle,
)
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.control_plane import control_plane_generation
from windows_local_mcp.executor import Executor
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import NormalizedCommand, approved_request_hash
from windows_local_mcp.tool_safety import capture_executable_identity


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings.ensure_directories()
    return settings


def _non_loader_command(settings: Settings, executable: Path) -> NormalizedCommand:
    cwd = settings.workspace_root / "app"
    cwd.mkdir(exist_ok=True)
    shared = settings.workspace_root / "shared"
    shared.mkdir(exist_ok=True)
    (shared / "input.txt").write_text("approved", encoding="utf-8")
    return NormalizedCommand(
        executable=str(executable),
        args=[str(shared / "input.txt")],
        cwd=str(cwd),
        display_command=[str(executable), str(shared / "input.txt")],
        program_key="hostname",
    )


def test_non_loader_readonly_materializes_bound_workspace_projection(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"trusted tool")
    command = _non_loader_command(settings, executable)

    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="non-loader-readonly",
        normalized=command,
        workspace_write=False,
    )
    verified = verify_approval_bundle(
        settings=settings,
        operation_id="non-loader-readonly",
        expected_digest=digest,
    )
    runtime = materialize_execution_copy(
        settings=settings,
        operation_id="non-loader-readonly",
        normalized=verified,
    )

    assert manifest["mode"] == "staged-host-workspace"
    run_cwd = Path(runtime.cwd)
    run_workspace = run_cwd.parent
    assert run_cwd.name == "app"
    assert (run_workspace / "shared" / "input.txt").read_text(encoding="utf-8") == "approved"
    assert runtime.args == [str(run_workspace / "shared" / "input.txt")]
    assert str(settings.workspace_root).casefold() not in runtime.args[0].casefold()


def test_non_loader_readonly_rejects_stale_workspace_before_materialization(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"trusted tool")
    command = _non_loader_command(settings, executable)
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="non-loader-stale",
        normalized=command,
        workspace_write=False,
    )
    (settings.workspace_root / "shared" / "input.txt").write_text(
        "changed after approval", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="workspace behavior inputs changed"):
        verify_approval_bundle(
            settings=settings,
            operation_id="non-loader-stale",
            expected_digest=digest,
        )


@pytest.mark.skipif(os.name != "nt", reason="Approved Host worker integration is Windows-only")
def test_approved_host_non_loader_default_readonly_reaches_child_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostname = shutil.which("hostname.exe") or shutil.which("hostname")
    if hostname is None:
        pytest.skip("hostname executable is unavailable")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "input.txt").write_text("bound input", encoding="utf-8")
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

    settings = Settings(
        workspace_root=workspace,
        data_dir=data,
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings.ensure_directories()
    store = AuditStore(settings)
    executor = Executor(settings, store)
    executable = Path(hostname).resolve(strict=True)
    command = NormalizedCommand(
        executable=str(executable),
        args=[],
        cwd=str(workspace),
        display_command=[str(executable)],
        program_key="hostname",
        executable_identity=capture_executable_identity(
            executable, provenance="integration-test"
        ),
    )
    operation_id = "approved-host-non-loader-readonly"
    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
        workspace_write=False,
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
    store.approve_and_claim(operation_id, approver="integration-test")

    result = executor.launch(operation_id, 30)
    deadline = time.monotonic() + 20.0
    while result["status"] in {"queued", "running"} and time.monotonic() < deadline:
        time.sleep(0.05)
        result = executor.poll(operation_id)
    operation = store.get_operation(operation_id)

    assert result["status"] == "succeeded", operation
    assert operation["child_pid"] is not None
    assert result.get("stdout_preview", "").strip()
