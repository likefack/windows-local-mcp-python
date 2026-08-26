from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from windows_local_mcp import control_plane
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.control_plane_guard import assert_control_plane_healthy
from windows_local_mcp.executor import Executor


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


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    os.environ["LOCAL_MCP_CONFIG"] = str(config)
    os.environ.pop("LOCAL_MCP_ROOT", None)
    settings = Settings(
        workspace_root=workspace,
        data_dir=data,
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings._config_selection_source = "LOCAL_MCP_CONFIG"
    settings._config_path = str(config.resolve(strict=True))
    settings._workspace_selection_source = "explicit_config"
    settings._ambient_root_present = False
    settings.ensure_directories()
    return settings


def _running_host_operation(store: AuditStore, settings: Settings, operation_id: str) -> None:
    store.create_operation(
        operation_id=operation_id,
        tool_name="request_host_command",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"program_key": "python"}},
        request_hash="a" * 64,
        approval_status="approved",
    )


def _guard_process(settings: Settings, operation_id: str, ready: Path) -> subprocess.Popen[bytes]:
    code = "\n".join(
        [
            "import os",
            "import time",
            "from pathlib import Path",
            "from windows_local_mcp.config import load_settings",
            "from windows_local_mcp.control_plane_guard import capture_critical_state",
            f"os.environ['LOCAL_MCP_CONFIG'] = {str(settings._config_path)!r}",
            "os.environ.pop('LOCAL_MCP_ROOT', None)",
            "settings = load_settings()",
            f"capture_critical_state(settings, {operation_id!r})",
            f"Path({str(ready)!r}).write_text('armed', encoding='utf-8')",
            "time.sleep(60)",
        ]
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy(),
    )


def _wait_for_ready(process: subprocess.Popen[bytes], ready: Path) -> None:
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if ready.is_file():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(
                "guard helper exited before arming: "
                f"stdout={stdout.decode(errors='replace')!r} "
                f"stderr={stderr.decode(errors='replace')!r}"
            )
        time.sleep(0.05)
    raise AssertionError("guard helper did not arm before timeout")


def test_control_plane_tamper_is_admitted_after_lost_postflight(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = AuditStore(settings)
    operation_id = "approved-host-lost-postflight-baseline"
    _running_host_operation(store, settings, operation_id)
    ready = tmp_path / "guard-armed.txt"
    process = _guard_process(settings, operation_id, ready)
    try:
        _wait_for_ready(process, ready)
        security_state = settings.data_dir / "control-plane" / "security-state.json"
        security_state.write_text('{"forged":true}', encoding="utf-8")
        with sqlite3.connect(settings.data_dir / "audit.db") as connection:
            connection.execute(
                "UPDATE operations SET approval_note='forged after guard arm' WHERE id=?",
                (operation_id,),
            )
            connection.commit()
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)

    restarted = AuditStore(settings)
    Executor(settings, restarted)

    operation = restarted.get_operation(operation_id, include_events=False)
    assert operation["status"] == "interrupted"
    assert operation["approval_note"] == "forged after guard arm"
    assert security_state.read_text(encoding="utf-8") == '{"forged":true}'

    assert_control_plane_healthy(settings)
    generation = control_plane.control_plane_generation(settings)
    assert isinstance(generation, int)
