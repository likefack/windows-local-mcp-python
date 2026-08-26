from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import windows_local_mcp.config as config_module
from windows_local_mcp.approval import prepare_approval_bundle
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import load_settings
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


def test_load_settings_rejects_config_replacement_during_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    replacement = tmp_path / "replacement.toml"
    _write_config(workspace, data, config)
    replacement.write_text(
        config.read_text(encoding="utf-8").replace(
            "git_enabled = false", "git_enabled = true"
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    original_load = config_module.tomllib.load

    def replace_during_parse(file: object) -> dict[str, object]:
        os.replace(replacement, config)
        return original_load(file)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(config_module.tomllib, "load", replace_during_parse)

    with pytest.raises((PermissionError, RuntimeError)):
        load_settings()


def test_real_approved_host_config_tamper_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    settings = load_settings()
    assert settings.selection_info()["config_source"] == "LOCAL_MCP_CONFIG"
    assert settings.selection_info()["config_path"] == str(config.resolve(strict=True))
    assert getattr(settings, "_config_file_identity", None) is not None

    operation_id = "approved-host-active-config-tamper"
    script = workspace / "main.py"
    script.write_text(
        "from pathlib import Path\n"
        f"path = Path({str(config)!r})\n"
        "text = path.read_text(encoding='utf-8')\n"
        "path.write_text(text.replace('git_enabled = false', 'git_enabled = true'), "
        "encoding='utf-8')\n",
        encoding="utf-8",
    )

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
    store.approve_and_claim(operation_id, approver="integration-test")

    result = executor.launch(operation_id, 30)
    operation = store.get_operation(operation_id)
    marker = settings.data_dir / "control-plane" / "tamper-detected.json"

    diagnostic = {"result": result, "operation": operation}
    assert config.read_text(encoding="utf-8").find("git_enabled = true") >= 0, diagnostic
    assert result["status"] == "failed", diagnostic
    assert operation["result"]["failure_class"] == "control_plane_tamper_unknown"
    assert marker.is_file()
    with pytest.raises(RuntimeError, match="tampering was previously detected"):
        control_plane_generation(settings)
