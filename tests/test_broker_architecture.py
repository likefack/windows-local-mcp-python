from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.config_binding import export_config_binding
from windows_local_mcp.control_plane import (
    control_plane_generation,
    create_worker_context,
    load_worker_context,
    verify_control_plane_generation,
)
from windows_local_mcp.control_plane_guard import capture_critical_state
from windows_local_mcp.redaction import redact_command_args, redact_text, redact_value
from windows_local_mcp.resources import prune_artifacts
from windows_local_mcp.workspace_history import (
    capture_workspace_state,
    verify_checkpoint_integrity,
)


def settings_for(tmp_path: Path) -> Settings:
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


def settings_with_active_config(tmp_path: Path) -> tuple[Settings, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{settings.workspace_root.as_posix()}"',
                f'data_dir = "{settings.data_dir.as_posix()}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
            ]
        ),
        encoding="utf-8",
    )
    settings._config_selection_source = "LOCAL_MCP_CONFIG"
    settings._config_path = str(config.resolve(strict=True))
    settings._workspace_selection_source = "explicit_config"
    settings._ambient_root_present = False
    settings.ensure_directories()
    return settings, config


def test_worker_context_is_digest_bound_and_ignores_ambient_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    path, digest = create_worker_context(settings, "worker-context-test")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("LOCAL_MCP_ROOT", str(other))

    loaded = load_worker_context(str(path), digest, "worker-context-test")
    assert loaded.workspace_root == settings.workspace_root
    assert loaded.data_dir == settings.data_dir

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["settings"]["workspace_root"] = str(other)
    path.chmod(0o644)
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="digest mismatch"):
        load_worker_context(str(path), digest, "worker-context-test")


def test_worker_context_preserves_active_config_identity(tmp_path: Path) -> None:
    settings, config = settings_with_active_config(tmp_path)
    expected_binding = export_config_binding(settings)
    path, digest = create_worker_context(settings, "active-config-worker-context")

    loaded = load_worker_context(str(path), digest, "active-config-worker-context")

    assert export_config_binding(loaded) == expected_binding
    selection = loaded.selection_info()
    assert selection["config_source"] == "LOCAL_MCP_CONFIG"
    assert selection["config_path"] == str(config.resolve(strict=True))
    assert selection["workspace_source"] == "explicit_config"


def test_worker_context_rejects_same_content_active_config_replacement(tmp_path: Path) -> None:
    settings, config = settings_with_active_config(tmp_path)
    path, digest = create_worker_context(settings, "active-config-replacement")
    replacement = tmp_path / "replacement.toml"
    replacement.write_bytes(config.read_bytes())
    os.replace(replacement, config)

    with pytest.raises(RuntimeError, match="file identity changed before use"):
        load_worker_context(str(path), digest, "active-config-replacement")


def test_approved_host_guard_rejects_active_config_content_tamper(tmp_path: Path) -> None:
    settings, config = settings_with_active_config(tmp_path)
    audit = AuditStore(settings)
    operation = audit.create_operation(
        tool_name="host-config-tamper",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"program_key": "python"}},
        request_hash="a" * 64,
        approval_status="approved",
    )
    before = capture_critical_state(settings, operation)
    assert before["config_binding"]["config_path"] == str(config.resolve(strict=True))

    config.write_text(
        config.read_text(encoding="utf-8") + "\nfilesystem_enabled = false\n",
        encoding="utf-8",
    )

    with pytest.raises((PermissionError, RuntimeError)):
        capture_critical_state(settings, operation)


def test_environment_only_worker_context_does_not_require_config_file(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    settings._config_selection_source = "environment_only"
    settings._config_path = None
    settings._workspace_selection_source = "LOCAL_MCP_ROOT"
    settings._ambient_root_present = True
    path, digest = create_worker_context(settings, "environment-only-worker-context")

    loaded = load_worker_context(str(path), digest, "environment-only-worker-context")
    binding = export_config_binding(loaded)

    assert binding["config_source"] == "environment_only"
    assert binding["config_path"] is None
    assert binding["config_file_identity"] is None
    assert loaded.selection_info()["workspace_source"] == "LOCAL_MCP_ROOT"


def test_build_or_policy_change_invalidates_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    generation = control_plane_generation(settings)
    monkeypatch.setattr(
        "windows_local_mcp.control_plane._tree_digest", lambda _root: "f" * 64
    )
    with pytest.raises(RuntimeError, match="changed after the operation"):
        verify_control_plane_generation(settings, generation)


def test_data_namespace_cannot_be_reused_by_another_workspace(tmp_path: Path) -> None:
    first = settings_for(tmp_path)
    other = tmp_path / "other-workspace"
    other.mkdir()
    second = Settings(
        workspace_root=other,
        data_dir=first.data_dir,
        protect_data_dir_acl=False,
    )
    with pytest.raises(PermissionError, match="different workspace"):
        second.ensure_directories()


def test_copied_control_plane_namespace_is_bound_to_data_directory_identity(
    tmp_path: Path,
) -> None:
    first = settings_for(tmp_path)
    copied_data = tmp_path / "copied-data"
    shutil.copytree(first.data_dir, copied_data)
    copied = Settings(
        workspace_root=first.workspace_root,
        data_dir=copied_data,
        sandbox_scratch_dir=first.sandbox_scratch_dir,
        protect_data_dir_acl=False,
    )

    with pytest.raises(PermissionError, match="different workspace"):
        copied.ensure_directories()


def test_terminal_state_cannot_be_rewound_by_completion_race(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    audit = AuditStore(settings)
    operation = audit.create_operation(
        tool_name="race",
        tier="codex_sandbox",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    assert audit.transition_operation(
        operation, from_statuses={"running"}, status="cancelled"
    )
    assert not audit.transition_operation(
        operation, from_statuses={"running"}, status="succeeded"
    )
    assert audit.get_operation(operation, include_events=False)["status"] == "cancelled"


def test_host_guard_binds_current_operation_approval_state(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    audit = AuditStore(settings)
    operation = audit.create_operation(
        tool_name="host",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"program_key": "python"}},
        request_hash="a" * 64,
        approval_status="approved",
    )
    before = capture_critical_state(settings, operation)

    audit.update_operation(operation, request_hash="b" * 64)

    assert capture_critical_state(settings, operation) != before


def test_secret_redaction_keeps_command_shape() -> None:
    value = redact_value(
        {
            "command": [
                "tool.exe",
                "--url=https://user:password@example.test/path",
                "--token=sk-abcdefghijklmnopqrstuvwxyz012345",
            ],
            "Authorization": "Bearer abc.def.ghi",
        }
    )
    assert value["command"][0] == "tool.exe"
    assert "password" not in value["command"][1]
    assert "sk-" not in value["command"][2]
    assert value["Authorization"] == "<redacted>"
    assert redact_text("password=hunter2 action=deploy").endswith("action=deploy")


def test_secret_redaction_covers_separate_command_argument_values() -> None:
    arguments = [
        "deploy",
        "--password",
        "hunter2",
        "--token",
        "hunter3",
        "--output",
        "result.json",
    ]

    expected = [
        "deploy",
        "--password",
        "<redacted>",
        "--token",
        "<redacted>",
        "--output",
        "result.json",
    ]
    assert redact_command_args(arguments) == expected
    assert redact_value(arguments) == expected


def test_checkpoint_creation_and_gc_are_serialized(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    (settings.workspace_root / "a.txt").write_text("one", encoding="utf-8")
    states = []
    failures: list[BaseException] = []

    def capture() -> None:
        try:
            states.append(capture_workspace_state(settings, "concurrent-capture", "before"))
        except BaseException as error:  # noqa: BLE001 - thread evidence
            failures.append(error)

    def collect() -> None:
        try:
            prune_artifacts(settings)
        except BaseException as error:  # noqa: BLE001 - thread evidence
            failures.append(error)

    threads = [threading.Thread(target=capture), threading.Thread(target=collect)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures
    assert len(states) == 1
    assert verify_checkpoint_integrity(settings, states[0].manifest_path)["a.txt"]
