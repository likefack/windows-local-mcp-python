from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
from windows_local_mcp.process_utils import ProcessIdentity


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


@pytest.mark.parametrize("tier", ["broker", "safe_command", "safe_sandbox"])
def test_git_operations_use_dedicated_worker_for_current_and_legacy_tiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tier: str
) -> None:
    settings = _settings(tmp_path)
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="execute_readonly",
        tier=tier,
        status="queued",
        cwd=str(settings.workspace_root),
        request={
            "normalized_command": {"program_key": "git"},
            "safe_request": {"program": "git", "args": ["status"], "cwd": "."},
        },
    )
    launched: list[list[str]] = []

    monkeypatch.setattr(
        "windows_local_mcp.executor.create_worker_context",
        lambda _settings, _operation_id: (tmp_path / "context.json", "a" * 64),
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_git_broker_worker_argv",
        lambda *_args, **_kwargs: ["git-worker"],
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_worker_argv",
        lambda *_args, **_kwargs: ["standard-worker"],
    )

    def fake_popen(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        launched.append(argv)
        return SimpleNamespace(pid=4321)

    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "windows_local_mcp.executor.capture_process_identity",
        lambda _pid, nonce: ProcessIdentity(
            pid=4321,
            create_time=10.0,
            executable=r"C:\Python\python.exe",
            nonce=nonce,
        ),
    )

    result = executor.launch(operation_id, 0)

    assert result["status"] == "queued"
    assert launched == [["git-worker"]]
    operation = audit.get_operation(operation_id, include_events=True)
    spawned = next(
        event for event in operation["events"] if event["event_type"] == "worker_spawned"
    )
    assert spawned["payload"]["worker_route"] == "git_broker_sandbox"


def test_non_git_legacy_operation_does_not_enter_git_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="legacy",
        tier="safe_command",
        status="queued",
        cwd=str(settings.workspace_root),
        request={"normalized_command": {"program_key": "adb"}},
    )
    launched: list[list[str]] = []

    monkeypatch.setattr(
        "windows_local_mcp.executor.create_worker_context",
        lambda _settings, _operation_id: (tmp_path / "context.json", "a" * 64),
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_git_broker_worker_argv",
        lambda *_args, **_kwargs: ["git-worker"],
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_worker_argv",
        lambda *_args, **_kwargs: ["standard-worker"],
    )

    def fake_popen(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        launched.append(argv)
        return SimpleNamespace(pid=4321)

    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "windows_local_mcp.executor.capture_process_identity",
        lambda _pid, nonce: ProcessIdentity(
            pid=4321,
            create_time=10.0,
            executable=r"C:\Python\python.exe",
            nonce=nonce,
        ),
    )

    executor.launch(operation_id, 0)

    assert launched == [["standard-worker"]]
