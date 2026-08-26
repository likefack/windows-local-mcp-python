import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.control_plane import control_plane_generation
from windows_local_mcp.control_plane_guard import (
    assert_control_plane_healthy,
    capture_critical_state,
    expected_critical_state,
)
from windows_local_mcp.executor import Executor


_PENDING_GUARD_NAME = "approved-host-postflight-pending.json"


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


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
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


def test_stale_approved_host_before_guard_arm_does_not_create_recovery_latch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, monkeypatch)
    store = AuditStore(settings)
    operation_id = "approved-host-stale-before-guard"
    _running_host_operation(store, settings, operation_id)

    restarted = AuditStore(settings)
    Executor(settings, restarted)

    assert restarted.get_operation(operation_id, include_events=False)["status"] == "interrupted"
    assert not (settings.data_dir / "control-plane" / _PENDING_GUARD_NAME).exists()
    assert_control_plane_healthy(settings)


def test_completed_approved_host_guard_clears_pending_recovery_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, monkeypatch)
    store = AuditStore(settings)
    operation_id = "approved-host-guard-complete"
    _running_host_operation(store, settings, operation_id)

    before = capture_critical_state(settings, operation_id)
    pending = settings.data_dir / "control-plane" / _PENDING_GUARD_NAME
    assert pending.is_file()

    expected = expected_critical_state(settings, operation_id)
    after = capture_critical_state(settings, operation_id)

    assert after == expected
    assert before == expected
    assert not pending.exists()
    assert_control_plane_healthy(settings)


def test_lost_approved_host_postflight_remains_fail_closed_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, monkeypatch)
    store = AuditStore(settings)
    operation_id = "approved-host-lost-postflight"
    _running_host_operation(store, settings, operation_id)
    ready = tmp_path / "guard-armed.txt"
    process = _guard_process(settings, operation_id, ready)
    try:
        _wait_for_ready(process, ready)
        pending = settings.data_dir / "control-plane" / _PENDING_GUARD_NAME
        assert pending.is_file()

        if os.name == "nt":
            with pytest.raises(OSError):
                pending.unlink()

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

    assert restarted.get_operation(operation_id, include_events=False)["status"] == "interrupted"
    assert pending.is_file()
    with pytest.raises(RuntimeError, match="postflight|recovery|tamper"):
        assert_control_plane_healthy(settings)
    with pytest.raises(RuntimeError, match="postflight|recovery|tamper"):
        control_plane_generation(settings)

    restarted_again = AuditStore(settings)
    Executor(settings, restarted_again)
    assert pending.is_file()
    with pytest.raises(RuntimeError, match="postflight|recovery|tamper"):
        assert_control_plane_healthy(settings)
