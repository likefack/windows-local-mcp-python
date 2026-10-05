from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
from windows_local_mcp.operation_owner import (
    capture_execution_owner,
    execution_owner_liveness,
)
from windows_local_mcp.process_utils import ProcessIdentity
from windows_local_mcp.util import canonical_json


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


def _operation(store: AuditStore, status: str) -> str:
    return store.create_operation(
        tool_name="execute_readonly" if status == "queued" else "git_info",
        tier="broker",
        status=status,
        cwd=str(store.settings.workspace_root),
        request={},
    )


def test_execution_owner_json_round_trip_matches_current_process() -> None:
    owner = capture_execution_owner()
    assert execution_owner_liveness(owner) == "alive"
    assert execution_owner_liveness(canonical_json(owner)) == "alive"


@pytest.mark.parametrize("status", ["queued", "running"])
def test_another_process_startup_preserves_live_owner_without_worker(
    tmp_path: Path, status: str
) -> None:
    settings = _settings(tmp_path)
    store = AuditStore(settings)
    operation_id = _operation(store, status)
    # 別プロセスから同じ DB を起動して、PID 再確認も含む経路を通す。
    source_root = Path(__file__).resolve().parents[1] / "src"
    program = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
settings = Settings(workspace_root=Path(sys.argv[2]), data_dir=Path(sys.argv[3]),
                    protect_data_dir_acl=False)
store = AuditStore(settings)
Executor(settings, store)
print(store.get_operation(sys.argv[4], include_events=False)["status"])
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            program,
            str(source_root),
            str(settings.workspace_root),
            str(settings.data_dir),
            operation_id,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert completed.stdout.strip() == status
    operation = store.get_operation(operation_id)
    assert operation["status"] == status
    assert not any(
        event["event_type"] == "stale_job_reconciled" for event in operation["events"]
    )


@pytest.mark.parametrize("owner_kind", ["legacy_null", "reused_pid", "dead_process"])
def test_startup_reconciles_missing_or_dead_execution_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner_kind: str
) -> None:
    settings = _settings(tmp_path)
    store = AuditStore(settings)
    operation_id = _operation(store, "queued")
    owner = capture_execution_owner()
    if owner_kind == "legacy_null":
        stored_owner = None
    elif owner_kind == "reused_pid":
        owner["create_time"] = float(owner["create_time"]) - 1.0
        stored_owner = canonical_json(owner)
    else:
        stored_owner = canonical_json(owner)

        def gone(_pid: int) -> None:
            raise psutil.NoSuchProcess(_pid)

        monkeypatch.setattr("windows_local_mcp.operation_owner.psutil.Process", gone)
    store.update_operation(operation_id, execution_owner_json=stored_owner)
    Executor(settings, store)
    operation = store.get_operation(operation_id)
    assert operation["status"] == "interrupted"
    assert operation["events"][-1]["event_type"] == "stale_job_reconciled"


@pytest.mark.parametrize("status", ["queued", "running"])
def test_startup_defers_owner_whose_identity_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    settings = _settings(tmp_path)
    store = AuditStore(settings)
    operation_id = _operation(store, status)

    def inaccessible(pid: int) -> None:
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr("windows_local_mcp.operation_owner.psutil.Process", inaccessible)
    Executor(settings, store)
    assert store.get_operation(operation_id, include_events=False)["status"] == status


@pytest.mark.parametrize("partial_identity", [False, True])
def test_live_owner_does_not_preserve_a_stale_recorded_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, partial_identity: bool
) -> None:
    settings = _settings(tmp_path)
    store = AuditStore(settings)
    operation_id = _operation(store, "running")
    worker_fields = {"worker_pid": 4242}
    if not partial_identity:
        worker_fields.update(
            worker_create_time=1.0,
            worker_executable=str(Path(sys.executable).resolve()),
            process_nonce="stale-worker",
        )
    store.update_operation(operation_id, **worker_fields)
    monkeypatch.setattr("windows_local_mcp.executor.process_identity_matches", lambda _: False)
    Executor(settings, store)
    assert store.get_operation(operation_id, include_events=False)["status"] == "interrupted"


@pytest.mark.parametrize("changed_field", ["create_time", "executable"])
def test_owner_identity_change_is_not_treated_as_the_original_process(
    changed_field: str,
) -> None:
    owner = capture_execution_owner()
    if changed_field == "create_time":
        owner[changed_field] = float(owner[changed_field]) - 1.0
    else:
        owner[changed_field] = str(owner[changed_field]) + ".different"
    assert execution_owner_liveness(json.dumps(owner)) == "dead"


@pytest.mark.parametrize("timeout", [0, 1])
def test_owner_tracking_preserves_foreground_and_background_launch_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timeout: int
) -> None:
    settings = _settings(tmp_path)
    store = AuditStore(settings)
    executor = Executor(settings, store)
    operation_id = _operation(store, "queued")
    monkeypatch.setattr(
        "windows_local_mcp.executor.create_worker_context",
        lambda *_args: (tmp_path / "context.json", "a" * 64),
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.isolated_worker_argv", lambda *_args, **_kwargs: ["python"]
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.subprocess.Popen", lambda *_args, **_kwargs: SimpleNamespace(pid=4242)
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.capture_process_identity",
        lambda pid, nonce: ProcessIdentity(pid, 1.0, sys.executable, nonce),
    )
    waited: list[float] = []

    def finish_while_waiting(duration: float) -> None:
        waited.append(duration)
        store.transition_operation(
            operation_id,
            from_statuses={"queued"},
            status="succeeded",
            exit_code=0,
        )

    monkeypatch.setattr("windows_local_mcp.executor.time.sleep", finish_while_waiting)
    result = executor.launch(operation_id, timeout)
    assert result["status"] == ("queued" if timeout == 0 else "succeeded")
    assert bool(waited) is bool(timeout)
    if timeout == 0:
        assert result["job_id"] == operation_id
    else:
        assert result["exit_code"] == 0
