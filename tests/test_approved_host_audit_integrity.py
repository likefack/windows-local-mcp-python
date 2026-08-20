import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from windows_local_mcp.approval import prepare_approval_bundle
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
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
    return settings, store, executor


def _tamper_script(database: Path, operation_id: str, attack: str) -> str:
    return (
        "import sqlite3\n"
        f"database={str(database)!r}\n"
        f"operation_id={operation_id!r}\n"
        f"attack={attack!r}\n"
        "connection=sqlite3.connect(database)\n"
        "if attack == 'delete_event':\n"
        "    connection.execute(\n"
        "        \"DELETE FROM events WHERE operation_id=? AND event_type='created'\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "elif attack == 'modify_event':\n"
        "    connection.execute(\n"
        "        \"UPDATE events SET payload_json='{\\\"forged\\\":true}' \"\n"
        "        \"WHERE operation_id=? AND event_type='approved_and_claimed'\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "elif attack == 'insert_event':\n"
        "    connection.execute(\n"
        "        \"INSERT INTO events(operation_id, occurred_at, event_type, payload_json) \"\n"
        "        \"VALUES (?, '2000-01-01T00:00:00+00:00', 'forged_child_event', '{}')\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "elif attack == 'replace_event':\n"
        "    connection.execute(\n"
        "        \"DELETE FROM events WHERE operation_id=? AND event_type='created'\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "    connection.execute(\n"
        "        \"INSERT INTO events(operation_id, occurred_at, event_type, payload_json) \"\n"
        "        \"VALUES (?, '2000-01-01T00:00:00+00:00', 'forged_replacement', '{}')\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "elif attack == 'move_event':\n"
        "    connection.execute(\n"
        "        \"UPDATE events SET operation_id='forged-other-operation' \"\n"
        "        \"WHERE operation_id=? AND event_type='created'\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "elif attack == 'modify_metadata':\n"
        "    connection.execute(\n"
        "        \"UPDATE operations SET approval_note='forged by child' WHERE id=?\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "elif attack == 'transient_event':\n"
        "    connection.execute(\n"
        "        \"INSERT INTO events(operation_id, occurred_at, event_type, payload_json) \"\n"
        "        \"VALUES (?, '2000-01-01T00:00:00+00:00', 'transient_forgery', '{}')\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "    connection.execute(\n"
        "        \"DELETE FROM events WHERE operation_id=? AND event_type='transient_forgery'\",\n"
        "        (operation_id,),\n"
        "    )\n"
        "else:\n"
        "    raise RuntimeError(f'unknown attack: {attack}')\n"
        "connection.commit()\n"
    )


def _assert_tamper_was_applied(database: Path, operation_id: str, attack: str) -> None:
    with sqlite3.connect(database) as connection:
        if attack == "delete_event":
            row = connection.execute(
                "SELECT 1 FROM events WHERE operation_id=? AND event_type='created'",
                (operation_id,),
            ).fetchone()
            assert row is None
        elif attack == "modify_event":
            row = connection.execute(
                "SELECT payload_json FROM events "
                "WHERE operation_id=? AND event_type='approved_and_claimed'",
                (operation_id,),
            ).fetchone()
            assert row == ('{\"forged\":true}',)
        elif attack == "insert_event":
            row = connection.execute(
                "SELECT 1 FROM events WHERE operation_id=? AND event_type='forged_child_event'",
                (operation_id,),
            ).fetchone()
            assert row is not None
        elif attack == "replace_event":
            created = connection.execute(
                "SELECT 1 FROM events WHERE operation_id=? AND event_type='created'",
                (operation_id,),
            ).fetchone()
            replacement = connection.execute(
                "SELECT 1 FROM events WHERE operation_id=? AND event_type='forged_replacement'",
                (operation_id,),
            ).fetchone()
            assert created is None
            assert replacement is not None
        elif attack == "move_event":
            moved = connection.execute(
                "SELECT 1 FROM events "
                "WHERE operation_id='forged-other-operation' AND event_type='created'"
            ).fetchone()
            assert moved is not None
        elif attack == "modify_metadata":
            row = connection.execute(
                "SELECT approval_note FROM operations WHERE id=?", (operation_id,)
            ).fetchone()
            assert row == ("forged by child",)
        elif attack == "transient_event":
            row = connection.execute(
                "SELECT 1 FROM events WHERE operation_id=? AND event_type='transient_forgery'",
                (operation_id,),
            ).fetchone()
            assert row is None


@pytest.mark.parametrize(
    "attack",
    [
        "delete_event",
        "modify_event",
        "insert_event",
        "replace_event",
        "move_event",
        "modify_metadata",
        "transient_event",
    ],
)
def test_approved_host_current_audit_tamper_is_detected(
    tmp_path: Path, monkeypatch, attack: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    operation_id = f"approved-host-audit-{attack}"
    database = data / "audit.db"

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id=operation_id,
        script_text=_tamper_script(database, operation_id, attack),
    )
    store.approve_and_claim(operation_id, approver="integration-test")

    result = executor.launch(operation_id, 30)
    operation = store.get_operation(operation_id)

    _assert_tamper_was_applied(database, operation_id, attack)
    assert result["status"] == "failed"
    assert operation["result"]["failure_class"] == "control_plane_tamper"
    assert "modified security-critical control-plane state" in str(operation["error"])
    assert (settings.data_dir / "control-plane" / "tamper-detected.json").is_file()


def test_approved_host_trusted_audit_updates_remain_valid(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    _write_config(workspace, data, config)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    operation_id = "approved-host-trusted-audit-updates"

    settings, store, executor = _prepare_operation(
        workspace=workspace,
        data=data,
        operation_id=operation_id,
        script_text="print('trusted audit updates remain valid')",
    )
    store.approve_and_claim(operation_id, approver="integration-test")

    result = executor.launch(operation_id, 30)
    operation = store.get_operation(operation_id)
    event_types = [event["event_type"] for event in operation["events"]]

    assert result["status"] == "succeeded"
    assert "approved_host_control_plane_guard_armed" in event_types
    assert "network_policy_applied" in event_types
    assert "child_started" in event_types
    assert "worker_finished" in event_types
    assert not (settings.data_dir / "control-plane" / "tamper-detected.json").exists()
